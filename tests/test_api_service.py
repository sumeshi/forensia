from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, MagicMock, call, patch

import yaml

from forensia.api.dto import (
    AttackCoverageRowDTO,
    CaseDTO,
    CaseStatsDTO,
    EventVolumePointDTO,
    FindingDTO,
    HypothesisDTO,
    HypothesisReasoningEntryDTO,
    HypothesesResponseDTO,
    ReportSectionDTO,
    SectionQuestionDTO,
)
from forensia.api.service import (
    _build_range_filter,
    _entity_card_summary,
    _normalize_volume_rows,
    _trunc_key,
    aggregate_event_volume,
    get_case_dto,
    get_case_stats_dto,
    list_attack_coverage_dto,
    list_entity_cards_dto,
    list_event_volume_dto,
    list_findings_dto,
    list_hypotheses_dto,
    list_hypothesis_reasoning_dto,
    list_report_sections_dto,
    list_section_questions_dto,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


def _make_mock_result(columns, rows):
    mock = MagicMock()
    mock.description = [(c,) for c in columns]
    mock.fetchall.return_value = rows
    mock.fetchone.return_value = rows[0] if rows else None
    return mock


_EVTX_COLS = [
    "finding_id", "rule_id", "title", "summary", "severity", "confidence",
    "status", "tags", "attack", "evidence", "ai_summary", "missing_checks",
    "created_at",
]
_HYP_COLS = [
    "hypothesis_id", "description", "status", "verdict", "summary",
    "origin", "created_session", "resolved_session", "created_at", "updated_at",
]
_REASON_COLS = [
    "entry_id", "hypothesis_id", "session_id", "iteration", "phase",
    "verdict", "query_id", "body", "created_at",
]
_REASON_WITH_COLS = _REASON_COLS + ["reasoning_count", "latest_iteration"]
_STATS_COLS = ["evtx_rows", "mft_entries", "channel_count", "host_count"]
_FINDINGS_STATS_COLS = ["findings_accepted", "findings_suppressed"]


class TestGetCaseDto(unittest.TestCase):
    def test_returns_case_dto_with_manifest(self):
        case = MagicMock(spec=Case)
        case.path = MagicMock()
        case.path.name = "test_case"
        manifest = {"case_name": "test_case", "paths": {"raw": "raw/"}}
        case.manifest_path.read_text.return_value = yaml.safe_dump(manifest)
        result = get_case_dto(case)
        self.assertIsInstance(result, CaseDTO)
        self.assertEqual(result.case_name, "test_case")
        self.assertEqual(result.paths, {"raw": "raw/"})
        self.assertEqual(result.manifest, manifest)

    def test_returns_empty_paths_when_manifest_has_no_paths(self):
        case = MagicMock(spec=Case)
        case.path = MagicMock()
        case.path.name = "empty_case"
        case.manifest_path.read_text.return_value = yaml.safe_dump({"case_name": "empty_case"})
        result = get_case_dto(case)
        self.assertEqual(result.paths, {})
        self.assertEqual(result.manifest, {"case_name": "empty_case"})

    def test_handles_empty_manifest_file(self):
        case = MagicMock(spec=Case)
        case.path = MagicMock()
        case.path.name = "bare"
        case.manifest_path.read_text.return_value = ""
        result = get_case_dto(case)
        self.assertEqual(result.paths, {})
        self.assertEqual(result.manifest, {})


class TestGetCaseStatsDto(unittest.TestCase):
    def test_returns_stats_dto(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(_STATS_COLS, [(100, 50, 5, 3)]),
            _make_mock_result(_FINDINGS_STATS_COLS, [(30, 2)]),
            _make_mock_result(["active_hypotheses", "resolved_hypotheses"], [(10, 5)]),
            _make_mock_result(["open_gaps", "report_human_reviewed", "report_ai_exhausted"], [(3, 1, 0)]),
            _make_mock_result(["sessions", "total_iterations"], [(2, 15)]),
        ]
        result = get_case_stats_dto(db)
        self.assertIsInstance(result, CaseStatsDTO)
        self.assertEqual(result.evtx_rows, 100)
        self.assertEqual(result.mft_entries, 50)
        self.assertEqual(result.channel_count, 5)
        self.assertEqual(result.host_count, 3)
        self.assertEqual(result.findings_accepted, 30)
        self.assertEqual(result.findings_suppressed, 2)
        self.assertEqual(result.active_hypotheses, 10)
        self.assertEqual(result.resolved_hypotheses, 5)
        self.assertEqual(result.open_gaps, 3)
        self.assertEqual(result.sessions, 2)
        self.assertEqual(result.total_iterations, 15)
        self.assertEqual(result.report_human_reviewed, 1)
        self.assertEqual(result.report_ai_exhausted, 0)

    def test_returns_zeroes_when_db_returns_none(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(_STATS_COLS, [(None, None, None, None)]),
            _make_mock_result(_FINDINGS_STATS_COLS, [(None, None)]),
            _make_mock_result(["active_hypotheses", "resolved_hypotheses"], [(None, None)]),
            _make_mock_result(["open_gaps", "report_human_reviewed", "report_ai_exhausted"], [(None, None, None)]),
            _make_mock_result(["sessions", "total_iterations"], [(None, None)]),
        ]
        result = get_case_stats_dto(db)
        self.assertEqual(result.evtx_rows, 0)
        self.assertEqual(result.mft_entries, 0)
        self.assertEqual(result.channel_count, 0)
        self.assertEqual(result.host_count, 0)
        self.assertEqual(result.open_gaps, 0)
        self.assertEqual(result.sessions, 0)
        self.assertEqual(result.total_iterations, 0)

    def test_propagates_db_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db down")
        with self.assertRaises(RuntimeError):
            get_case_stats_dto(db)


class TestListFindingsDto(unittest.TestCase):
    def test_returns_findings(self):
        db = MagicMock(spec=CaseDB)
        row = ("F1", "R1", "Logon", "Admin logon", "high", 0.9,
               "accepted", None, None, None, None, None, "2024-01-01T00:00:00")
        db.execute.return_value = _make_mock_result(_EVTX_COLS, [row])
        result = list_findings_dto(db)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], FindingDTO)
        self.assertEqual(result[0].finding_id, "F1")
        self.assertEqual(result[0].title, "Logon")
        self.assertEqual(result[0].severity, "high")

    def test_returns_empty_list(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(_EVTX_COLS, [])
        result = list_findings_dto(db)
        self.assertEqual(result, [])

    def test_applies_status_filter(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(_EVTX_COLS, [])
        result = list_findings_dto(db, status="accepted")
        self.assertEqual(result, [])
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("WHERE", actual_sql)
        self.assertIn("status = ?", actual_sql)
        actual_params = db.execute.call_args[0][1]
        self.assertIn("accepted", actual_params)

    def test_applies_severity_and_limit(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(_EVTX_COLS, [])
        result = list_findings_dto(db, severity="high", limit=5, offset=10)
        self.assertEqual(result, [])
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("severity = ?", actual_sql)
        self.assertIn("LIMIT ? OFFSET ?", actual_sql)
        actual_params = db.execute.call_args[0][1]
        self.assertEqual(actual_params[-2], 5)
        self.assertEqual(actual_params[-1], 10)

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("query failed")
        with self.assertRaises(RuntimeError):
            list_findings_dto(db)


class TestListHypothesesDto(unittest.TestCase):
    def test_returns_partitioned_hypotheses(self):
        db = MagicMock(spec=CaseDB)
        reason_rows = [
            ("R1", "H-001", "S1", 1, "plan", "confirmed", "Q1", "body1", "2024-01-01T00:00:00", 5, 2),
            ("R2", "H-001", "S1", 2, "check", "confirmed", "Q2", "body2", "2024-01-01T01:00:00", 5, 2),
            ("R3", "H-002", "S1", 1, "plan", "inconclusive", "Q3", "body3", "2024-01-02T00:00:00", 2, 1),
        ]
        hyp_rows = [
            ("H-001", "Suspicious logon", "active", None, "summary1", "broad_plan", "S1", None, "2024-01-01T00:00:00", "2024-01-01T02:00:00"),
            ("H-002", "Lateral move", "confirmed", "confirmed", "summary2", "broad_plan", "S1", "S1", "2024-01-02T00:00:00", "2024-01-02T01:00:00"),
        ]
        db.execute.side_effect = [
            _make_mock_result(_REASON_WITH_COLS, reason_rows),
            _make_mock_result(_HYP_COLS, hyp_rows),
        ]
        result = list_hypotheses_dto(db)
        self.assertIsInstance(result, HypothesesResponseDTO)
        self.assertEqual(len(result.active), 1)
        self.assertEqual(len(result.resolved), 1)
        self.assertEqual(result.active[0].hypothesis_id, "H-001")
        self.assertEqual(result.active[0].status, "active")
        self.assertEqual(result.active[0].reasoning_count, 5)
        self.assertEqual(result.active[0].latest_iteration, 2)
        self.assertEqual(len(result.active[0].latest_reasoning), 2)
        self.assertEqual(result.resolved[0].hypothesis_id, "H-002")
        self.assertEqual(result.resolved[0].status, "confirmed")

    def test_returns_empty_when_no_hypotheses(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(_REASON_WITH_COLS, []),
            _make_mock_result(_HYP_COLS, []),
        ]
        result = list_hypotheses_dto(db)
        self.assertEqual(result.active, [])
        self.assertEqual(result.resolved, [])

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_hypotheses_dto(db)


class TestListHypothesisReasoningDto(unittest.TestCase):
    def test_returns_reasoning_entries(self):
        db = MagicMock(spec=CaseDB)
        rows = [
            ("E1", "H-001", "S1", 1, "plan", "confirmed", "Q1", "body1", "2024-01-01T00:00:00"),
            ("E2", "H-001", "S1", 2, "check", "confirmed", "Q2", "body2", "2024-01-01T01:00:00"),
        ]
        db.execute.return_value = _make_mock_result(_REASON_COLS, rows)
        result = list_hypothesis_reasoning_dto(db, "H-001")
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], HypothesisReasoningEntryDTO)
        self.assertEqual(result[0].hypothesis_id, "H-001")
        self.assertEqual(result[0].iteration, 1)
        self.assertEqual(result[1].iteration, 2)

    def test_returns_empty_list(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(_REASON_COLS, [])
        result = list_hypothesis_reasoning_dto(db, "H-999")
        self.assertEqual(result, [])

    def test_passes_hypothesis_id_and_limit(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(_REASON_COLS, [])
        result = list_hypothesis_reasoning_dto(db, "H-001", limit=5)
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("WHERE hypothesis_id = ?", actual_sql)
        self.assertIn("LIMIT ?", actual_sql)
        params = db.execute.call_args[0][1]
        self.assertIn("H-001", params)
        self.assertIn(5, params)

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("query failed")
        with self.assertRaises(RuntimeError):
            list_hypothesis_reasoning_dto(db, "H-001")


class TestListEventVolumeDto(unittest.TestCase):
    def test_detected_source_returns_detected_volume(self):
        db = MagicMock(spec=CaseDB)
        evidence_json = json.dumps([{"timestamp": "2024-01-15T10:30:00"}])
        db.execute.return_value = _make_mock_result(
            ["evidence", "created_at"],
            [(evidence_json, "2024-01-15T12:00:00")],
        )
        result = list_event_volume_dto(db, bucket="day", source="detected")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].series, "detected")
        self.assertEqual(result[0].bucket, "2024-01-15T00:00:00")
        self.assertEqual(result[0].count, 1)

    def test_detected_uses_created_at_fallback(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["evidence", "created_at"],
            [("[]", "2024-06-01T12:00:00")],
        )
        result = list_event_volume_dto(db, bucket="month", source="detected")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-06-01T00:00:00")

    def test_detected_empty_when_no_findings(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(["evidence", "created_at"], [])
        result = list_event_volume_dto(db, bucket="day", source="detected")
        self.assertEqual(result, [])

    def test_evtx_source_queries_evtx_events(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["bucket", "series", "count"],
            [("2024-01-01 00:00:00", "Security", 10)],
        )
        result = list_event_volume_dto(db, bucket="day", source="evtx")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].series, "Security")
        self.assertEqual(result[0].count, 10)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")

    def test_evtx_empty(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(["bucket", "series", "count"], [])
        result = list_event_volume_dto(db, bucket="day", source="evtx")
        self.assertEqual(result, [])

    def test_mft_source_queries_mft_timeline(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["bucket", "series", "count"],
            [("2024-01-01 00:00:00", "mft:modified", 5)],
        )
        result = list_event_volume_dto(db, bucket="day", source="mft")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].series, "mft:modified")

    def test_all_source_combines_evtx_and_mft(self):
        db = MagicMock(spec=CaseDB)
        evtx_row = ("2024-01-01 00:00:00", "Security", 10)
        mft_row = ("2024-01-01 00:00:00", "mft:modified", 5)
        db.execute.side_effect = [
            _make_mock_result(["bucket", "series", "count"], [evtx_row]),
            _make_mock_result(["bucket", "series", "count"], [mft_row]),
        ]
        result = list_event_volume_dto(db, bucket="day", source="all")
        self.assertEqual(len(result), 2)
        series_set = {r.series for r in result}
        self.assertIn("Security", series_set)
        self.assertIn("mft:modified", series_set)

    def test_all_source_empty_both(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(["bucket", "series", "count"], []),
            _make_mock_result(["bucket", "series", "count"], []),
        ]
        result = list_event_volume_dto(db, bucket="day", source="all")
        self.assertEqual(result, [])

    def test_falls_back_to_day_for_invalid_bucket(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            ["bucket", "series", "count"],
            [("2024-01-01 00:00:00", "Security", 1)],
        )
        result = list_event_volume_dto(db, bucket="invalid", source="evtx")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")

    def test_passes_start_end_to_range_filter(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(["bucket", "series", "count"], [])
        list_event_volume_dto(db, bucket="day", source="evtx", start="2024-01-01", end="2024-02-01")
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("timestamp >= ?", actual_sql)
        self.assertIn("timestamp < ?", actual_sql)

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_event_volume_dto(db, bucket="day", source="evtx")


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
        result = aggregate_event_volume(items, "hour", start="2024-01-02T00:00:00", end="2024-01-03T00:00:00")
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
        rows = [{"bucket": "2024-01-01 00:00:00+00:00", "series": "Security", "count": 10}]
        result = _normalize_volume_rows(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")

    def test_handles_empty_list(self):
        result = _normalize_volume_rows([])
        self.assertEqual(result, [])

    def test_sorts_by_bucket_then_series(self):
        rows = [
            {"bucket": "2024-01-02 00:00:00", "series": "Sys", "count": 2},
            {"bucket": "2024-01-01 00:00:00", "series": "Sec", "count": 1},
        ]
        result = _normalize_volume_rows(rows)
        self.assertEqual(result[0].bucket, "2024-01-01 00:00:00")
        self.assertEqual(result[1].bucket, "2024-01-02 00:00:00")


class TestBuildRangeFilter(unittest.TestCase):
    def test_no_start_end(self):
        sql, params = _build_range_filter(None, None)
        self.assertIn("EXTRACT(year FROM timestamp)", sql)
        self.assertEqual(params, [])

    def test_with_start(self):
        sql, params = _build_range_filter("2024-01-01", None)
        self.assertIn("timestamp >= ?", sql)
        self.assertIn("2024-01-01", params)

    def test_with_end(self):
        sql, params = _build_range_filter(None, "2024-06-01")
        self.assertIn("timestamp < ?", sql)
        self.assertIn("2024-06-01", params)

    def test_with_both(self):
        sql, params = _build_range_filter("2024-01-01", "2024-06-01")
        self.assertIn("timestamp >= ?", sql)
        self.assertIn("timestamp < ?", sql)
        self.assertEqual(len([p for p in params if isinstance(p, str)]), 2)


class TestTruncKey(unittest.TestCase):
    def test_year(self):
        self.assertEqual(_trunc_key("2024-06-15T10:30:00", "year"), "2024-01-01T00:00:00")

    def test_month(self):
        self.assertEqual(_trunc_key("2024-06-15T10:30:00", "month"), "2024-06-01T00:00:00")

    def test_day(self):
        self.assertEqual(_trunc_key("2024-06-15T10:30:00", "day"), "2024-06-15T00:00:00")

    def test_hour(self):
        self.assertEqual(_trunc_key("2024-06-15T10:30:00", "hour"), "2024-06-15T10:00:00")

    def test_replaces_space_with_t(self):
        self.assertEqual(_trunc_key("2024-06-15 10:30:00", "hour"), "2024-06-15T10:00:00")


class TestListAttackCoverageDto(unittest.TestCase):
    def test_returns_coverage_rows(self):
        db = MagicMock(spec=CaseDB)
        attack_json = json.dumps([{"tactic": "execution", "technique_id": "T1059", "technique_name": "PowerShell"}])
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
        attack_json = json.dumps([{"tactic": "execution", "technique_id": "T1059", "technique_name": "PowerShell"}])
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
            ["section_key", "title", "body", "confidence", "status", "update_count", "gaps", "last_filled_session", "last_filled_at"],
            [("overview", "Overview", "body text", 0.8, "human_reviewed", 3, '["gap1"]', "S1", "2024-01-01T00:00:00")],
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
            ["section_key", "title", "body", "confidence", "status", "update_count", "gaps", "last_filled_session", "last_filled_at"],
            [],
        )
        result = list_report_sections_dto(db)
        self.assertEqual(result, [])

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_report_sections_dto(db)


class TestListSectionQuestionsDto(unittest.TestCase):
    def test_returns_section_questions(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "question_id", "section_key", "block_heading", "question_text", "question_type",
                "answer_spec", "intent", "confidence", "matched_rule", "required_evidence",
                "status", "created_at", "updated_at",
            ],
            [
                (
                    "q1", "6_appendix", "Last shutdown", "When was shutdown?",
                    "investigation_window", "last_shutdown_event", "Return latest shutdown",
                    0.9, "investigation_window", '{"required_fields":["shutdown_time"]}',
                    "answered", "2024-01-01T00:00:00", "2024-01-01T00:01:00",
                )
            ],
        )
        result = list_section_questions_dto(db)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], SectionQuestionDTO)
        self.assertEqual(result[0].answer_spec, "last_shutdown_event")
        self.assertEqual(result[0].required_evidence["required_fields"], ["shutdown_time"])

    def test_applies_section_filter(self):
        db = MagicMock(spec=CaseDB)
        db.execute.return_value = _make_mock_result(
            [
                "question_id", "section_key", "block_heading", "question_text", "question_type",
                "answer_spec", "intent", "confidence", "matched_rule", "required_evidence",
                "status", "created_at", "updated_at",
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
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8")
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
            _entity_card_summary(path),
            "role: attacker · created malicious scheduled task at 03:14 UTC",
        )

    def test_falls_back_to_body_when_role_and_notes_missing(self):
        path = self._write("# host: WIN10\n\nSeen on 4624 logon spike\nSecondary line\n")
        self.assertEqual(_entity_card_summary(path), "Seen on 4624 logon spike · Secondary line")

    def test_returns_none_for_card_with_only_heading(self):
        path = self._write("# user: alice\n\n- type: user\n- name: alice\n")
        self.assertIsNone(_entity_card_summary(path))


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
