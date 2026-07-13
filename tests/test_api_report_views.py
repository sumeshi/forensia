from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from forensia.api.dto import (
    AttackCoverageRowDTO,
    EventVolumePointDTO,
    ReportSectionDTO,
    SectionQuestionDTO,
)
from forensia.api.service import (
    aggregate_event_volume,
    build_range_filter,
    entity_card_summary,
    list_attack_coverage_dto,
    list_entity_cards_dto,
    list_section_questions_dto,
    normalize_volume_rows,
    trunc_key,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.section_views import list_report_sections_dto


def _make_mock_result(columns, rows):
    mock = MagicMock()
    mock.description = [(c,) for c in columns]
    mock.fetchall.return_value = rows
    mock.fetchone.return_value = rows[0] if rows else None
    return mock


_EVTX_COLS = [
    "finding_id",
    "rule_id",
    "title",
    "summary",
    "severity",
    "confidence",
    "status",
    "tags",
    "attack",
    "evidence",
    "ai_summary",
    "missing_checks",
    "created_at",
]
_HYP_COLS = [
    "hypothesis_id",
    "description",
    "status",
    "verdict",
    "summary",
    "origin",
    "created_session",
    "resolved_session",
    "created_at",
    "updated_at",
]
_REASON_COLS = [
    "entry_id",
    "hypothesis_id",
    "session_id",
    "iteration",
    "phase",
    "verdict",
    "query_id",
    "body",
    "created_at",
]
_REASON_WITH_COLS = _REASON_COLS + ["reasoning_count", "latest_iteration"]
_STATS_COLS = [
    "evtx_rows",
    "mft_entries",
    "channel_count",
    "host_count",
    "prefetch_rows",
]
_FINDINGS_STATS_COLS = ["findings_accepted", "findings_suppressed"]


class TestAggregateEventVolume(unittest.TestCase):
    def test_rebuckets_hourly_to_daily(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3),
            EventVolumePointDTO(bucket="2024-01-01T11:00:00", series="a", count=4),
            EventVolumePointDTO(bucket="2024-01-02T10:00:00", series="a", count=5),
        ]
        result = aggregate_event_volume(items, "day")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].bucket, "2024-01-01T00:00:00")
        self.assertEqual(result[0].count, 7)
        self.assertEqual(result[1].bucket, "2024-01-02T00:00:00")
        self.assertEqual(result[1].count, 5)

    def test_returns_input_for_invalid_bucket(self):
        items = [EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3)]
        result = aggregate_event_volume(items, "invalid")
        self.assertEqual(result, items)

    def test_returns_empty_list(self):
        result = aggregate_event_volume([], "day")
        self.assertEqual(result, [])

    def test_filters_by_start(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3),
            EventVolumePointDTO(bucket="2024-01-02T10:00:00", series="a", count=4),
        ]
        result = aggregate_event_volume(items, "hour", start="2024-01-02T00:00:00")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-02T10:00:00")

    def test_filters_by_end(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3),
            EventVolumePointDTO(bucket="2024-01-02T10:00:00", series="a", count=4),
        ]
        result = aggregate_event_volume(items, "hour", end="2024-01-02T00:00:00")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01T10:00:00")

    def test_filters_by_start_and_end(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3),
            EventVolumePointDTO(bucket="2024-01-02T10:00:00", series="a", count=4),
            EventVolumePointDTO(bucket="2024-01-03T10:00:00", series="a", count=5),
        ]
        result = aggregate_event_volume(
            items, "hour", start="2024-01-02T00:00:00", end="2024-01-03T00:00:00"
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-02T10:00:00")

    def test_skips_out_of_range_years(self):
        items = [
            EventVolumePointDTO(bucket="1970-01-01T00:00:00", series="a", count=5),
            EventVolumePointDTO(bucket="2024-01-01T00:00:00", series="a", count=3),
        ]
        result = aggregate_event_volume(items, "day")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01T00:00:00")

    def test_groups_by_series_within_bucket(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=3),
            EventVolumePointDTO(bucket="2024-01-01T11:00:00", series="a", count=4),
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="b", count=1),
            EventVolumePointDTO(bucket="2024-01-01T11:00:00", series="b", count=2),
        ]
        result = aggregate_event_volume(items, "day")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].bucket, "2024-01-01T00:00:00")
        self.assertEqual(result[0].series, "a")
        self.assertEqual(result[0].count, 7)
        self.assertEqual(result[1].series, "b")
        self.assertEqual(result[1].count, 3)

    def test_sorts_by_bucket_then_series(self):
        items = [
            EventVolumePointDTO(bucket="2024-01-02T10:00:00", series="z", count=1),
            EventVolumePointDTO(bucket="2024-01-01T10:00:00", series="a", count=1),
        ]
        result = aggregate_event_volume(items, "hour")
        self.assertEqual(result[0].bucket, "2024-01-01T10:00:00")
        self.assertEqual(result[1].bucket, "2024-01-02T10:00:00")


class TestNormalizeVolumeRows(unittest.TestCase):
    def test_normalizes_and_strips_timezone_suffix(self):
        rows = [
            {"bucket": "2024-01-01 00:00:00+00:00", "series": "Security", "count": 10}
        ]
        result = normalize_volume_rows(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")

    def test_handles_empty_list(self):
        result = normalize_volume_rows([])
        self.assertEqual(result, [])

    def test_sorts_by_bucket_then_series(self):
        rows = [
            {"bucket": "2024-01-02 00:00:00", "series": "Sys", "count": 2},
            {"bucket": "2024-01-01 00:00:00", "series": "Sec", "count": 1},
        ]
        result = normalize_volume_rows(rows)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")
        self.assertEqual(result[1].bucket, "2024-01-02 00:00:00")


class TestBuildRangeFilter(unittest.TestCase):
    def test_no_start_end(self):
        sql, params = build_range_filter(None, None)
        self.assertIn("EXTRACT(year FROM timestamp)", sql)
        self.assertEqual(params, [])

    def test_with_start(self):
        sql, params = build_range_filter("2024-01-01", None)
        self.assertIn("timestamp >= ?", sql)
        self.assertIn("2024-01-01", params)

    def test_with_end(self):
        sql, params = build_range_filter(None, "2024-06-01")
        self.assertIn("timestamp < ?", sql)
        self.assertIn("2024-06-01", params)

    def test_with_both(self):
        sql, params = build_range_filter("2024-01-01", "2024-06-01")
        self.assertIn("timestamp >= ?", sql)
        self.assertIn("timestamp < ?", sql)
        self.assertEqual(len([p for p in params if isinstance(p, str)]), 2)


class TestTruncKey(unittest.TestCase):
    def test_year(self):
        self.assertEqual(
            trunc_key("2024-06-15T10:30:00", "year"), "2024-01-01T00:00:00"
        )

    def test_month(self):
        self.assertEqual(
            trunc_key("2024-06-15T10:30:00", "month"), "2024-06-01T00:00:00"
        )

    def test_day(self):
        self.assertEqual(trunc_key("2024-06-15T10:30:00", "day"), "2024-06-15T00:00:00")

    def test_hour(self):
        self.assertEqual(
            trunc_key("2024-06-15T10:30:00", "hour"), "2024-06-15T10:00:00"
        )

    def test_replaces_space_with_t(self):
        self.assertEqual(
            trunc_key("2024-06-15 10:30:00", "hour"), "2024-06-15T10:00:00"
        )


class TestListAttackCoverageDto(unittest.TestCase):
    def test_returns_coverage_rows(self):
        db = MagicMock(spec=CaseDB)
        attack_json = json.dumps(
            [
                {
                    "tactic": "execution",
                    "technique_id": "T1059",
                    "technique_name": "PowerShell",
                }
            ]
        )
        db.execute.return_value = _make_mock_result(
            ["attack", "status"],
            [(attack_json, "accepted")],
        )
        result = list_attack_coverage_dto(db)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], AttackCoverageRowDTO)
        self.assertEqual(result[0].tactic, "execution")
        self.assertEqual(result[0].technique_id, "T1059")
        self.assertEqual(result[0].count, 1)
        self.assertEqual(result[0].accepted, 1)
        self.assertEqual(result[0].suppressed, 0)

    def test_aggregates_multiple_entries(self):
        db = MagicMock(spec=CaseDB)
        attack_json = json.dumps(
            [
                {
                    "tactic": "execution",
                    "technique_id": "T1059",
                    "technique_name": "PowerShell",
                }
            ]
        )
        db.execute.return_value = _make_mock_result(
            ["attack", "status"],
            [(attack_json, "accepted"), (attack_json, "suppressed")],
        )
        result = list_attack_coverage_dto(db)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].count, 2)
        self.assertEqual(result[0].accepted, 1)
        self.assertEqual(result[0].suppressed, 1)

    def test_empty_when_no_attack_data(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(["attack", "status"], [])
        result = list_attack_coverage_dto(db)
        self.assertEqual(result, [])

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_attack_coverage_dto(db)


class TestListReportSectionsDto(unittest.TestCase):
    def test_returns_sections(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "section_key",
                "title",
                "body",
                "confidence",
                "status",
                "update_count",
                "gaps",
                "last_filled_session",
                "last_filled_at",
            ],
            [
                (
                    "overview",
                    "Overview",
                    "body text",
                    0.8,
                    "human_reviewed",
                    3,
                    '["gap1"]',
                    "S1",
                    "2024-01-01T00:00:00",
                )
            ],
        )
        result = list_report_sections_dto(db)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], ReportSectionDTO)
        self.assertEqual(result[0].section_key, "overview")
        self.assertEqual(result[0].status, "human_reviewed")
        self.assertEqual(result[0].gap_count, 1)
        self.assertEqual(len(result[0].gap_hypothesis_ids), 1)

    def test_empty_list(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "section_key",
                "title",
                "body",
                "confidence",
                "status",
                "update_count",
                "gaps",
                "last_filled_session",
                "last_filled_at",
            ],
            [],
        )
        result = list_report_sections_dto(db)
        self.assertEqual(result, [])

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_report_sections_dto(db)


class TestListReportSectionsDtoBodyHtml(unittest.TestCase):
    def test_table_body_renders_as_html_table(self):
        db = MagicMock(spec=CaseDB)
        body = "| Col1 | Col2 |\n|------|------|\n| A    | B    |"
        db.execute.return_value = _make_mock_result(
            [
                "section_key",
                "title",
                "body",
                "confidence",
                "status",
                "update_count",
                "gaps",
                "last_filled_session",
                "last_filled_at",
            ],
            [
                (
                    "overview",
                    "Overview",
                    body,
                    0.8,
                    "human_reviewed",
                    3,
                    "[]",
                    "S1",
                    "2024-01-01T00:00:00",
                )
            ],
        )
        result = list_report_sections_dto(db)
        self.assertIn("<table>", result[0].body_html)
        self.assertIn("<th>Col1</th>", result[0].body_html)
        self.assertIn("<td>A</td>", result[0].body_html)

    def test_body_html_empty_when_body_empty(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "section_key",
                "title",
                "body",
                "confidence",
                "status",
                "update_count",
                "gaps",
                "last_filled_session",
                "last_filled_at",
            ],
            [
                (
                    "overview",
                    "Overview",
                    "",
                    0.8,
                    "human_reviewed",
                    3,
                    "[]",
                    "S1",
                    "2024-01-01T00:00:00",
                )
            ],
        )
        result = list_report_sections_dto(db)
        self.assertEqual(result[0].body_html, "")

    @patch("forensia.report.section_views.build_evidence_map")
    def test_body_html_contains_evidence_ref_links(self, mock_build_evidence_map):
        mock_build_evidence_map.return_value = {
            "evtx-security-000000000120": {
                "source": "evtx_events",
                "timestamp": "2024-01-01T10:00:00",
                "summary": "Event 4624",
            }
        }
        db = MagicMock(spec=CaseDB)
        body = "Suspicious logon detected: evtx-security-000000000120"
        db.execute.return_value = _make_mock_result(
            [
                "section_key",
                "title",
                "body",
                "confidence",
                "status",
                "update_count",
                "gaps",
                "last_filled_session",
                "last_filled_at",
            ],
            [
                (
                    "overview",
                    "Overview",
                    body,
                    0.8,
                    "human_reviewed",
                    3,
                    "[]",
                    "S1",
                    "2024-01-01T00:00:00",
                )
            ],
        )
        result = list_report_sections_dto(db)
        self.assertIn('class="evidence-ref"', result[0].body_html)
        self.assertIn("evtx-security-000000000120", result[0].body_html)


class TestListSectionQuestionsDto(unittest.TestCase):
    def test_returns_section_questions(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "question_id",
                "section_key",
                "block_heading",
                "question_text",
                "question_type",
                "answer_spec",
                "intent",
                "confidence",
                "matched_rule",
                "required_evidence",
                "status",
                "created_at",
                "updated_at",
            ],
            [
                (
                    "q1",
                    "6_appendix",
                    "Last shutdown",
                    "When was shutdown?",
                    "investigation_window",
                    "last_shutdown_event",
                    "Return latest shutdown",
                    0.9,
                    "investigation_window",
                    '{"required_fields":["shutdown_time"]}',
                    "answered",
                    "2024-01-01T00:00:00",
                    "2024-01-01T00:01:00",
                )
            ],
        )
        result = list_section_questions_dto(db)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], SectionQuestionDTO)
        self.assertEqual(result[0].answer_spec, "last_shutdown_event")
        self.assertEqual(
            result[0].required_evidence["required_fields"], ["shutdown_time"]
        )

    def test_applies_section_filter(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "question_id",
                "section_key",
                "block_heading",
                "question_text",
                "question_type",
                "answer_spec",
                "intent",
                "confidence",
                "matched_rule",
                "required_evidence",
                "status",
                "created_at",
                "updated_at",
            ],
            [],
        )
        self.assertEqual(list_section_questions_dto(db, section_key="6_appendix"), [])
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("WHERE section_key = ?", actual_sql)
        self.assertEqual(db.execute.call_args[0][1], ("6_appendix",))


class TestEntityCardSummary(unittest.TestCase):
    """Entity cards drive the Top Entities UI tile; the summary is what makes the panel useful at a glance."""

    def _write(self, body: str) -> Path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        )
        tmp.write(body)
        tmp.close()
        return Path(tmp.name)

    def test_extracts_role_and_notes_from_investigator_template(self):
        path = self._write(
            "# user: alice\n"
            "\n"
            "- type: user\n"
            "- name: alice\n"
            "- role: attacker\n"
            "- notes: created malicious scheduled task at 03:14 UTC\n"
        )
        self.assertEqual(
            entity_card_summary(path),
            "role: attacker · created malicious scheduled task at 03:14 UTC",
        )

    def test_falls_back_to_body_when_role_and_notes_missing(self):
        path = self._write(
            "# host: WIN10\n\nSeen on 4624 logon spike\nSecondary line\n"
        )
        self.assertEqual(
            entity_card_summary(path), "Seen on 4624 logon spike · Secondary line"
        )

    def test_returns_none_for_card_with_only_heading(self):
        path = self._write("# user: alice\n\n- type: user\n- name: alice\n")
        self.assertIsNone(entity_card_summary(path))


class TestListEntityCardsDto(unittest.TestCase):
    def test_returns_cards_with_summary_extracted_from_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp)
            entities = case_path / "memory" / "entities" / "user"
            entities.mkdir(parents=True)
            (entities / "alice.md").write_text(
                "# user: alice\n\n- type: user\n- name: alice\n- role: victim\n- notes: lost session token\n",
                encoding="utf-8",
            )
            case = Case(path=case_path)
            result = list_entity_cards_dto(case)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].kind, "user")
            self.assertEqual(result[0].name, "alice")
            self.assertEqual(result[0].summary, "role: victim · lost session token")

    def test_returns_empty_when_entities_dir_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Case(path=Path(tmp))
            self.assertEqual(list_entity_cards_dto(case), [])


if __name__ == "__main__":
    unittest.main()
