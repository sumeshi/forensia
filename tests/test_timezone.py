"""End-to-end contracts for timezone persistence, rendering, and inference."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.questions import extract_time_qualifiers
from forensia.normalize.timezone import infer_timezone
from forensia.report.answers.answer_store import add_local_time_columns
from forensia.report.render.markdown import (
    local_time_from_utc,
    render_timestamp_with_timezone,
    tz_offset_str,
)
from forensia.report.report_brief import build_report_brief


class CaseTimezoneTests(unittest.TestCase):
    def test_timezone_persists_and_defaults_to_utc(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            custom = Case.init(Path(tmpdir) / "custom", source_timezone="Asia/Tokyo")
            manifest = yaml.safe_load(custom.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual("Asia/Tokyo", manifest["source_timezone"])
            self.assertEqual("Asia/Tokyo", Case.open(custom.path).source_timezone)
            self.assertEqual("UTC", Case.init(Path(tmpdir) / "default").source_timezone)

            legacy_path = Path(tmpdir) / "legacy"
            legacy_path.mkdir()
            (legacy_path / "manifest.yaml").write_text(
                yaml.safe_dump({"case_name": "legacy", "created_at": "now"}),
                encoding="utf-8",
            )
            self.assertEqual("UTC", Case.open(legacy_path).source_timezone)


class TimestampRenderingTests(unittest.TestCase):
    def test_rendering_and_offsets_cover_utc_and_local_zones(self) -> None:
        timestamp = "2026-03-25 15:31:00"
        utc = render_timestamp_with_timezone(
            timestamp, Case(path=Path("/x"), source_timezone="UTC")
        )
        new_york = render_timestamp_with_timezone(
            timestamp, Case(path=Path("/x"), source_timezone="America/New_York")
        )
        tokyo = render_timestamp_with_timezone(
            timestamp, Case(path=Path("/x"), source_timezone="Asia/Tokyo")
        )
        self.assertEqual("2026-03-25 15:31:00 UTC", utc)
        self.assertIn("11:31:00", new_york)
        self.assertIn("UTC-4", new_york)
        self.assertIn("00:31:00", tokyo)
        self.assertIn("UTC+9", tokyo)
        self.assertEqual("unknown", render_timestamp_with_timezone(None, None))
        self.assertEqual("UTC", tz_offset_str("UTC"))

    def test_local_conversion_matrix(self) -> None:
        for zone, expected in (
            ("America/New_York", "2026-03-25 11:31:00"),
            ("Asia/Tokyo", "2026-03-26 00:31:00"),
            ("UTC", None),
            ("Invalid/Zone", None),
        ):
            with self.subTest(zone=zone):
                self.assertEqual(
                    expected, local_time_from_utc("2026-03-25 15:31:00", zone)
                )

    def test_structured_answers_add_local_columns_only_when_needed(self) -> None:
        rows = [{"shutdown_time": "2026-03-25 15:31:00", "computer": "PC1"}]
        columns = ["shutdown_time", "computer"]
        localized, localized_columns = add_local_time_columns(
            rows, columns, Case(path=Path("/x"), source_timezone="America/New_York")
        )
        self.assertEqual("2026-03-25 11:31:00", localized[0]["shutdown_time_local"])
        self.assertIn("shutdown_time_local", localized_columns)

        unchanged, unchanged_columns = add_local_time_columns(
            rows, columns, Case(path=Path("/x"), source_timezone="UTC")
        )
        self.assertEqual((rows, columns), (unchanged, unchanged_columns))


class TimeQualifierTests(unittest.TestCase):
    def test_hour_and_date_qualifiers_preserve_their_time_basis(self) -> None:
        local_hours = extract_time_qualifiers(
            "between 09:00 and 17:00", tz_name="America/New_York"
        )
        utc_hours = extract_time_qualifiers("between 09:00 and 17:00")
        dates = extract_time_qualifiers(
            "between 2026-03-01 and 2026-03-31", tz_name="America/New_York"
        )
        self.assertIn("local time", local_hours["timezone_note"])
        self.assertEqual(
            ("09:00", "17:00", "UTC"),
            (utc_hours["hour_from"], utc_hours["hour_to"], utc_hours["basis"]),
        )
        self.assertEqual(
            ("2026-03-01", "2026-03-31"), (dates["date_from"], dates["date_to"])
        )


class ReportBriefTimezoneTests(unittest.TestCase):
    def test_report_brief_exposes_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case", source_timezone="America/New_York")
            with CaseDB(case) as db:
                brief = build_report_brief(db, case)
        self.assertEqual("America/New_York", brief["source_timezone"])
        self.assertIn("timezone_offset", brief)


class TimezoneInferenceTests(unittest.TestCase):
    def test_inference_requires_repeated_consistent_observations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self.assertIsNone(infer_timezone(db)[0])
                raw = json.dumps(
                    {
                        "Event": {
                            "EventData": {
                                "Data": [{"Name": "TimeZoneBias", "Text": "-300"}]
                            }
                        }
                    }
                )
                db.execute(
                    "INSERT INTO evtx_events (event_id, raw_json, timestamp) VALUES (4616, ?, ?)",
                    (raw, datetime.now(UTC)),
                )
                self.assertIsNone(infer_timezone(db)[0])
                for _ in range(3):
                    db.execute(
                        "INSERT INTO evtx_events (timestamp, message, event_id) VALUES (?, ?, 1)",
                        (
                            "2026-03-25 15:00:00",
                            "Event occurred at 2026-03-25 10:00:00 (local)",
                        ),
                    )
                offset, basis = infer_timezone(db)
        self.assertEqual(-300, offset)
        self.assertTrue("source" in basis or "timestamp" in basis)
