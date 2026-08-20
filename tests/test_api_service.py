from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

import yaml

from forensia.api.dto import (
    CaseDTO,
    CaseStatsDTO,
    FindingDTO,
    HypothesesResponseDTO,
    HypothesisReasoningEntryDTO,
    RuntimeConfigDTO,
)
from forensia.api.service import (
    get_case_dto,
    get_case_stats_dto,
    get_runtime_config_dto,
    list_event_volume_dto,
    list_findings_dto,
    list_hypotheses_dto,
    list_hypothesis_reasoning_dto,
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
        case.manifest_path.read_text.return_value = yaml.safe_dump(
            {"case_name": "empty_case"}
        )
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


class TestGetRuntimeConfigDto(unittest.TestCase):
    def test_returns_effective_non_secret_settings(self):
        with patch("forensia.config.settings") as settings:
            settings.llm_base_url = "http://172.16.0.10:8080"
            settings.llm_model = "test-model"
            settings.llm_max_tokens = 8192
            settings.llm_output_language = "ja"
            settings.llm_report_max_queries_per_section = 4
            settings.llm_outage_wall_clock_budget_s = 600
            settings.llm_outage_probe_interval_s = 15

            result = get_runtime_config_dto()

        self.assertIsInstance(result, RuntimeConfigDTO)
        self.assertEqual(result.llm_base_url, "http://172.16.0.10:8080")
        self.assertEqual(result.llm_model, "test-model")
        self.assertEqual(result.llm_max_tokens, 8192)


class TestGetCaseStatsDto(unittest.TestCase):
    def test_returns_stats_dto(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(_STATS_COLS, [(100, 50, 5, 3, 7)]),
            _make_mock_result(_FINDINGS_STATS_COLS, [(30, 2)]),
            _make_mock_result(
                [
                    "active_hypotheses",
                    "resolved_hypotheses",
                    "confirmed_hypotheses",
                    "refuted_hypotheses",
                    "untestable_hypotheses",
                ],
                [(10, 5, 2, 2, 1)],
            ),
            _make_mock_result(
                ["open_gaps", "report_human_reviewed", "report_ai_exhausted"],
                [(3, 1, 0)],
            ),
            _make_mock_result(["sessions", "total_iterations"], [(2, 15)]),
            _make_mock_result(
                ["name", "first_seen", "last_seen", "event_count"],
                [
                    (
                        "37L4247F27-25",
                        "2010-11-21 03:58:31",
                        "2015-03-25 10:18:29",
                        745,
                    ),
                    (
                        "informant-PC",
                        "2015-03-22 14:33:53",
                        "2015-03-25 15:31:00",
                        4454,
                    ),
                ],
            ),
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
        self.assertEqual(result.confirmed_hypotheses, 2)
        self.assertEqual(result.refuted_hypotheses, 2)
        self.assertEqual(result.untestable_hypotheses, 1)
        self.assertEqual(result.open_gaps, 3)
        self.assertEqual(result.sessions, 2)
        self.assertEqual(result.total_iterations, 15)
        self.assertEqual(result.report_human_reviewed, 1)
        self.assertEqual(result.report_ai_exhausted, 0)
        # Hosts are returned in first-seen order (rename timeline).
        self.assertEqual(
            [h.name for h in result.hosts], ["37L4247F27-25", "informant-PC"]
        )
        self.assertEqual(result.hosts[0].first_seen, "2010-11-21 03:58:31")

    def test_returns_zeroes_when_db_returns_none(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = [
            _make_mock_result(_STATS_COLS, [(None, None, None, None, None)]),
            _make_mock_result(_FINDINGS_STATS_COLS, [(None, None)]),
            _make_mock_result(
                [
                    "active_hypotheses",
                    "resolved_hypotheses",
                    "confirmed_hypotheses",
                    "refuted_hypotheses",
                    "untestable_hypotheses",
                ],
                [(None, None, None, None, None)],
            ),
            _make_mock_result(
                ["open_gaps", "report_human_reviewed", "report_ai_exhausted"],
                [(None, None, None)],
            ),
            _make_mock_result(["sessions", "total_iterations"], [(None, None)]),
            _make_mock_result(["name", "first_seen", "last_seen", "event_count"], []),
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
        row = (
            "F1",
            "R1",
            "Logon",
            "Admin logon",
            "high",
            0.9,
            "accepted",
            None,
            None,
            None,
            None,
            None,
            "2024-01-01T00:00:00",
        )
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
            (
                "R1",
                "H-001",
                "S1",
                1,
                "plan",
                "confirmed",
                "Q1",
                "body1",
                "2024-01-01T00:00:00",
                5,
                2,
            ),
            (
                "R2",
                "H-001",
                "S1",
                2,
                "check",
                "confirmed",
                "Q2",
                "body2",
                "2024-01-01T01:00:00",
                5,
                2,
            ),
            (
                "R3",
                "H-002",
                "S1",
                1,
                "plan",
                "inconclusive",
                "Q3",
                "body3",
                "2024-01-02T00:00:00",
                2,
                1,
            ),
        ]
        hyp_rows = [
            (
                "H-001",
                "Suspicious logon",
                "active",
                None,
                "summary1",
                "broad_plan",
                "S1",
                None,
                "2024-01-01T00:00:00",
                "2024-01-01T02:00:00",
            ),
            (
                "H-002",
                "Lateral move",
                "confirmed",
                "confirmed",
                "summary2",
                "broad_plan",
                "S1",
                "S1",
                "2024-01-02T00:00:00",
                "2024-01-02T01:00:00",
            ),
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
            (
                "E1",
                "H-001",
                "S1",
                1,
                "plan",
                "confirmed",
                "Q1",
                "body1",
                "2024-01-01T00:00:00",
            ),
            (
                "E2",
                "H-001",
                "S1",
                2,
                "check",
                "confirmed",
                "Q2",
                "body2",
                "2024-01-01T01:00:00",
            ),
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
        list_hypothesis_reasoning_dto(db, "H-001", limit=5)
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
        list_event_volume_dto(
            db, bucket="day", source="evtx", start="2024-01-01", end="2024-02-01"
        )
        actual_sql = db.execute.call_args[0][0]
        self.assertIn("timestamp >= ?", actual_sql)
        self.assertIn("timestamp < ?", actual_sql)

    def test_propagates_exception(self):
        db = MagicMock(spec=CaseDB)
        db.execute.side_effect = RuntimeError("db error")
        with self.assertRaises(RuntimeError):
            list_event_volume_dto(db, bucket="day", source="evtx")


if __name__ == "__main__":
    unittest.main()
