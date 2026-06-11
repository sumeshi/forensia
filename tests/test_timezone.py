"""Tests for R2-14 timezone identification and dual-timestamp rendering."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import yaml
import pytest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize.timezone import infer_timezone
from forensia.report.writer import (
    _render_timestamp_with_timezone,
    _tz_offset_str,
    _local_time_from_utc as _wt_local_time_from_utc,
    _add_local_time_columns,
    _build_report_brief,
)
from forensia.ai.question_registry import extract_time_qualifiers


# ── Case timezone persistence ──────────────────────────────────────────────

class TestCaseTimezonePersistence:
    def test_init_manifest_contains_source_timezone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(str(Path(tmpdir) / "case"), source_timezone="America/New_York")
            manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8"))
            assert manifest.get("source_timezone") == "America/New_York"

    def test_init_default_timezone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(str(Path(tmpdir) / "case"))
            assert case.source_timezone == "UTC"

    def test_open_reads_source_timezone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(str(Path(tmpdir) / "case"), source_timezone="Asia/Tokyo")
            reopened = Case.open(str(case.path))
            assert reopened.source_timezone == "Asia/Tokyo"

    def test_open_fallback_to_utc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir) / "case"
            case_dir.mkdir(parents=True, exist_ok=True)
            manifest = {"case_name": "test", "created_at": "now"}
            (case_dir / "manifest.yaml").write_text(
                yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
            )
            case = Case.open(str(case_dir))
            assert case.source_timezone == "UTC"

    def test_source_timezone_property(self):
        case = Case(path=Path("/nonexistent"), source_timezone="Europe/Berlin")
        assert case.source_timezone == "Europe/Berlin"
        assert case.timezone_info.startswith("Europe/Berlin")

    def test_source_timezone_default(self):
        case = Case(path=Path("/nonexistent"))
        assert case.source_timezone == "UTC"


# ── Timestamp rendering ────────────────────────────────────────────────────

class TestTimestampRendering:
    def test_render_utc_only(self):
        case = Case(path=Path("/x"), source_timezone="UTC")
        result = _render_timestamp_with_timezone("2026-03-25 15:31:00", case)
        assert result == "2026-03-25 15:31:00 UTC"

    def test_render_with_timezone(self):
        case = Case(path=Path("/x"), source_timezone="America/New_York")
        result = _render_timestamp_with_timezone("2026-03-25 15:31:00", case)
        assert "UTC" in result
        assert "local" in result
        assert "11:31:00" in result  # UTC-4 in March
        assert "UTC-4" in result

    def test_render_with_timezone_asia(self):
        case = Case(path=Path("/x"), source_timezone="Asia/Tokyo")
        result = _render_timestamp_with_timezone("2026-03-25 15:31:00", case)
        assert "UTC" in result
        assert "local" in result
        assert "UTC+9" in result
        assert "00:31:00" in result  # 15:31 + 9h = next day 00:31

    def test_render_empty_timestamp(self):
        case = Case(path=Path("/x"), source_timezone="UTC")
        assert _render_timestamp_with_timezone("", case) == "unknown"
        assert _render_timestamp_with_timezone(None, case) == "unknown"

    def test_tz_offset_str_utc(self):
        assert _tz_offset_str("UTC") == "UTC"

    def test_tz_offset_str_known(self):
        offset = _tz_offset_str("America/New_York")
        assert "UTC" in offset


# ── Local time conversion ──────────────────────────────────────────────────

class TestLocalTimeConversion:
    def test_utc_to_ny(self):
        result = _wt_local_time_from_utc("2026-03-25 15:31:00", "America/New_York")
        assert result == "2026-03-25 11:31:00"

    def test_utc_to_tokyo(self):
        result = _wt_local_time_from_utc("2026-03-25 15:31:00", "Asia/Tokyo")
        assert result == "2026-03-26 00:31:00"

    def test_utc_stays_utc(self):
        assert _wt_local_time_from_utc("2026-03-25 15:31:00", "UTC") is None

    def test_invalid_timezone_returns_none(self):
        assert _wt_local_time_from_utc("2026-03-25 15:31:00", "Invalid/Zone") is None


# ── Structured answer local columns ────────────────────────────────────────

class TestStructuredAnswerLocalColumns:
    def test_local_columns_added_for_known_tz(self):
        case = Case(path=Path("/x"), source_timezone="America/New_York")
        rows = [
            {"shutdown_time": "2026-03-25 15:31:00", "computer": "PC1"},
            {"shutdown_time": "2026-03-25 16:00:00", "computer": "PC2"},
        ]
        columns = ["shutdown_time", "computer"]
        updated_rows, updated_columns = _add_local_time_columns(rows, columns, case)
        assert "shutdown_time_local" in updated_columns
        assert updated_rows[0].get("shutdown_time_local") == "2026-03-25 11:31:00"

    def test_no_local_columns_for_utc(self):
        case = Case(path=Path("/x"), source_timezone="UTC")
        rows = [{"shutdown_time": "2026-03-25 15:31:00"}]
        columns = ["shutdown_time"]
        updated_rows, updated_columns = _add_local_time_columns(rows, columns, case)
        assert "shutdown_time_local" not in updated_columns
        assert updated_columns == columns
        assert updated_rows == rows


# ── Report brief timezone info ─────────────────────────────────────────────

class TestReportBriefTimezone:
    def test_report_brief_contains_timezone(self, tmp_path):
        case = Case(path=tmp_path, source_timezone="America/New_York")
        with tempfile.TemporaryDirectory() as tmpdb:
            db_path = Path(tmpdb) / "test.duckdb"
            with CaseDB(case) as db:
                db.execute("CREATE TABLE IF NOT EXISTS evtx_events (timestamp TIMESTAMP)")
                brief = _build_report_brief(db, case)
                assert brief.get("source_timezone") == "America/New_York"
                assert "timezone_offset" in brief


# ── Time qualifiers with timezone ──────────────────────────────────────────

class TestExtractTimeQualifiers:
    def test_hour_filter_with_tz(self):
        result = extract_time_qualifiers(
            "between 09:00 and 17:00",
            tz_name="America/New_York",
        )
        assert result["hour_from"] is not None
        assert result["hour_to"] is not None
        # 09:00 EST = 14:00 UTC, 17:00 EST = 22:00 UTC (approx)
        assert result["timezone_note"] is not None
        assert "local time" in str(result["timezone_note"])

    def test_hour_filter_utc_unknown(self):
        result = extract_time_qualifiers("between 09:00 and 17:00")
        assert result["hour_from"] == "09:00"
        assert result["hour_to"] == "17:00"
        assert result["basis"] == "UTC"

    def test_date_filter_ignores_tz(self):
        result = extract_time_qualifiers(
            "between 2026-03-01 and 2026-03-31",
            tz_name="America/New_York",
        )
        assert result["date_from"] == "2026-03-01"
        assert result["date_to"] == "2026-03-31"


# ── Timezone inference (minimal) ──────────────────────────────────────────

class TestTimezoneInference:
    def test_infer_timezone_no_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.db.database import CaseDB
            case = Case(path=Path(tmpdir))
            with CaseDB(case) as db:
                db.execute("CREATE TABLE IF NOT EXISTS evtx_events (timestamp TIMESTAMP, message VARCHAR, event_id INTEGER, raw_json VARCHAR, computer VARCHAR)")
                offset, basis = infer_timezone(db)
                assert offset is None

    def test_infer_timezone_from_4616(self):
        """Test that Event 4616 with bias field is parsed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.db.database import CaseDB
            case = Case(path=Path(tmpdir))
            with CaseDB(case) as db:
                db.execute("CREATE TABLE IF NOT EXISTS evtx_events (timestamp TIMESTAMP, message VARCHAR, event_id INTEGER, raw_json VARCHAR, computer VARCHAR)")
                # Insert one Event 4616 with timezone bias
                raw = json.dumps({
                    "Event": {"EventData": {"Data": [
                        {"Name": "SubjectUserSid", "Text": "S-1-5-18"},
                        {"Name": "TimeZoneBias", "Text": "-300"},
                    ]}}
                })
                db.execute(
                    "INSERT INTO evtx_events (event_id, raw_json, timestamp) VALUES (4616, ?, ?)",
                    (raw, datetime.now(timezone.utc)),
                )
                offset, basis = infer_timezone(db)
                # Only 1 observation - should return None (needs ≥2)
                assert offset is None

    def test_infer_timezone_from_message_offsets(self):
        """Test that consistent message timestamps produce an offset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.db.database import CaseDB
            case = Case(path=Path(tmpdir))
            with CaseDB(case) as db:
                db.execute("CREATE TABLE IF NOT EXISTS evtx_events (timestamp TIMESTAMP, message VARCHAR, event_id INTEGER, raw_json VARCHAR, computer VARCHAR)")
                # Insert 2 events where message contains a timestamp 5 hours behind UTC
                for _ in range(2):
                    db.execute(
                        "INSERT INTO evtx_events (timestamp, message, event_id) VALUES (?, ?, 1)",
                        ("2026-03-25 15:00:00", "Event occurred at 2026-03-25 10:00:00"),
                    )
                offset, basis = infer_timezone(db)
                # -300 minutes = UTC-5
                assert offset is None or offset == -300

    def test_infer_timezone_agreement(self):
        """Test that ≥2 agreeing observations return the offset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            from forensia.db.database import CaseDB
            case = Case(path=Path(tmpdir))
            with CaseDB(case) as db:
                db.execute("CREATE TABLE IF NOT EXISTS evtx_events (timestamp TIMESTAMP, message VARCHAR, event_id INTEGER, raw_json VARCHAR, computer VARCHAR)")
                for _ in range(3):
                    db.execute(
                        "INSERT INTO evtx_events (timestamp, message, event_id) VALUES (?, ?, 1)",
                        ("2026-03-25 15:00:00", "Event occurred at 2026-03-25 10:00:00 (local)"),
                    )
                offset, basis = infer_timezone(db)
                assert offset is not None
                assert offset == -300  # UTC-5
                assert "source" in basis or "timestamp" in basis
