from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import DEFAULT, MagicMock, patch

from forensia.api.cache import (
    _snapshot_dir,
    _write_json,
    clear_api_snapshots,
    load_snapshot,
    write_api_snapshots,
)


class _MockDTO:
    def __init__(self, data=None):
        self._data = data if data is not None else {}
        self.session_id = None

    def model_dump(self, mode="json"):
        return self._data


def _mock_dto_list(count=1):
    return [_MockDTO({"idx": i}) for i in range(count)]


class TestSnapshotDir(unittest.TestCase):
    def test_returns_reports_dir_slash_api(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            result = _snapshot_dir(case)
            self.assertEqual(result, Path(td) / "api")

    def test_creates_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td) / "nonexistent"
            result = _snapshot_dir(case)
            self.assertTrue(result.exists())

    def test_returns_existing_directory(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "api").mkdir(parents=True)
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            result = _snapshot_dir(case)
            self.assertEqual(result, Path(td) / "api")


class TestWriteJson(unittest.TestCase):
    def test_writes_json_to_path(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.json"
            data = {"a": 1, "b": [2, 3]}
            _write_json(path, data)
            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), data)

    def test_writes_with_indent(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pretty.json"
            _write_json(path, {"x": 1})
            text = path.read_text(encoding="utf-8")
            self.assertIn("\n", text)

    def test_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test.json"
            path.write_text('"old"', encoding="utf-8")
            _write_json(path, {"new": "data"})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")), {"new": "data"}
            )


class TestLoadSnapshot(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            data = {"key": "value", "num": 42}
            _write_json(_snapshot_dir(case) / "test.json", data)
            result = load_snapshot(case, "test.json")
            self.assertEqual(result, data)

    def test_returns_none_when_missing(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            result = load_snapshot(case, "nonexistent.json")
            self.assertIsNone(result)

    def test_returns_list_from_written_list(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            data = [{"id": 1}, {"id": 2}]
            _write_json(_snapshot_dir(case) / "list.json", data)
            result = load_snapshot(case, "list.json")
            self.assertEqual(result, data)


class TestClearApiSnapshots(unittest.TestCase):
    def test_removes_all_json_files(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            snap_dir = _snapshot_dir(case)
            (snap_dir / "a.json").write_text("{}", encoding="utf-8")
            (snap_dir / "b.json").write_text("{}", encoding="utf-8")
            (snap_dir / "c.txt").write_text("x", encoding="utf-8")
            clear_api_snapshots(case)
            self.assertFalse((snap_dir / "a.json").exists())
            self.assertFalse((snap_dir / "b.json").exists())
            self.assertFalse((snap_dir / "c.txt").exists())

    def test_keeps_subdirectories(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            snap_dir = _snapshot_dir(case)
            (snap_dir / "nested").mkdir()
            (snap_dir / "nested" / "f.json").write_text("{}", encoding="utf-8")
            (snap_dir / "f.json").write_text("{}", encoding="utf-8")
            clear_api_snapshots(case)
            self.assertTrue((snap_dir / "nested").exists())
            self.assertTrue((snap_dir / "nested" / "f.json").exists())

    def test_no_error_on_empty_directory(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)
            _snapshot_dir(case)
            clear_api_snapshots(case)


class TestWriteApiSnapshots(unittest.TestCase):
    def test_writes_all_snapshot_files(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)

            with patch.multiple(
                "forensia.api.cache",
                get_case_dto=DEFAULT,
                get_case_stats_dto=DEFAULT,
                list_findings_dto=DEFAULT,
                list_hypotheses_dto=DEFAULT,
                list_sessions_dto=DEFAULT,
                list_hypothesis_reasoning_map_dto=DEFAULT,
                list_latest_hypothesis_reasoning_dto=DEFAULT,
                list_steps_dto=DEFAULT,
                list_report_sections_dto=DEFAULT,
                list_section_questions_dto=DEFAULT,
                list_claims_dto=DEFAULT,
                list_mft_timeline_dto=DEFAULT,
                list_event_volume_dto=DEFAULT,
                list_entity_cards_dto=DEFAULT,
                list_attack_coverage_dto=DEFAULT,
                list_ai_reviews_dto=DEFAULT,
                write_report_brief=DEFAULT,
                list_progress_events=DEFAULT,
            ) as mocks:
                mocks["get_case_dto"].return_value = _MockDTO({"id": "case1"})
                mocks["get_case_stats_dto"].return_value = _MockDTO({"total": 100})
                mocks["list_findings_dto"].return_value = _mock_dto_list(2)
                hyp = _MockDTO({"hypotheses": [{"id": "H1"}]})
                hyp.model_dump = lambda mode="json": {"hypotheses": [{"id": "H1"}]}
                mocks["list_hypotheses_dto"].return_value = hyp
                session = MagicMock(session_id="s1")
                session.model_dump = lambda mode="json": {"session_id": "s1"}
                mocks["list_sessions_dto"].return_value = [session]
                mocks["list_hypothesis_reasoning_map_dto"].return_value = {"H1": []}
                mocks[
                    "list_latest_hypothesis_reasoning_dto"
                ].return_value = _mock_dto_list(1)
                mocks["list_steps_dto"].return_value = _mock_dto_list(1)
                mocks["list_report_sections_dto"].return_value = _mock_dto_list(1)
                mocks["list_section_questions_dto"].return_value = _mock_dto_list(1)
                mocks["list_claims_dto"].return_value = _mock_dto_list(1)
                mocks["list_mft_timeline_dto"].return_value = _mock_dto_list(1)
                mocks["list_event_volume_dto"].return_value = _mock_dto_list(1)
                mocks["list_entity_cards_dto"].return_value = _mock_dto_list(1)
                mocks["list_attack_coverage_dto"].return_value = _mock_dto_list(1)
                mocks["list_ai_reviews_dto"].return_value = _mock_dto_list(1)
                mocks["write_report_brief"].return_value = {"summary": "brief"}
                mocks["list_progress_events"].return_value = _mock_dto_list(1)

                write_api_snapshots(case, MagicMock())

            snap_dir = _snapshot_dir(case)
            expected_files = [
                "case.json",
                "stats.json",
                "findings.json",
                "hypotheses.json",
                "sessions.json",
                "hypothesis_reasoning.json",
                "hypotheses_reasoning_latest.json",
                "session_steps.json",
                "report_sections.json",
                "section_questions.json",
                "claims.json",
                "mft_timeline.json",
                "entities.json",
                "attack_coverage.json",
                "ai_reviews.json",
                "report_brief.json",
                "progress_events.json",
            ]
            for bucket in ("year", "month", "day", "hour"):
                for source in ("all", "detected"):
                    expected_files.append(f"event_volume_{bucket}_{source}.json")
            for name in expected_files:
                self.assertTrue(
                    (snap_dir / name).exists(),
                    f"Missing snapshot file: {name}",
                )

    def test_calls_progress_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)

            with patch.multiple(
                "forensia.api.cache",
                get_case_dto=DEFAULT,
                get_case_stats_dto=DEFAULT,
                list_findings_dto=DEFAULT,
                list_hypotheses_dto=DEFAULT,
                list_sessions_dto=DEFAULT,
                list_hypothesis_reasoning_map_dto=DEFAULT,
                list_latest_hypothesis_reasoning_dto=DEFAULT,
                list_steps_dto=DEFAULT,
                list_report_sections_dto=DEFAULT,
                list_section_questions_dto=DEFAULT,
                list_claims_dto=DEFAULT,
                list_mft_timeline_dto=DEFAULT,
                list_event_volume_dto=DEFAULT,
                list_entity_cards_dto=DEFAULT,
                list_attack_coverage_dto=DEFAULT,
                list_ai_reviews_dto=DEFAULT,
                write_report_brief=DEFAULT,
                list_progress_events=DEFAULT,
            ) as mocks:
                mocks["get_case_dto"].return_value = _MockDTO({"id": "case1"})
                mocks["get_case_stats_dto"].return_value = _MockDTO({"total": 100})
                mocks["list_findings_dto"].return_value = []
                hyp = _MockDTO({"hypotheses": []})
                hyp.model_dump = lambda mode="json": {"hypotheses": []}
                mocks["list_hypotheses_dto"].return_value = hyp
                mocks["list_sessions_dto"].return_value = []
                mocks["list_hypothesis_reasoning_map_dto"].return_value = {}
                mocks["list_latest_hypothesis_reasoning_dto"].return_value = []
                mocks["list_steps_dto"].return_value = []
                mocks["list_report_sections_dto"].return_value = []
                mocks["list_section_questions_dto"].return_value = []
                mocks["list_claims_dto"].return_value = []
                mocks["list_mft_timeline_dto"].return_value = []
                mocks["list_event_volume_dto"].return_value = []
                mocks["list_entity_cards_dto"].return_value = []
                mocks["list_attack_coverage_dto"].return_value = []
                mocks["list_ai_reviews_dto"].return_value = []
                mocks["write_report_brief"].return_value = {}
                mocks["list_progress_events"].return_value = []

                write_api_snapshots(case, MagicMock())

            mocks["list_progress_events"].assert_called_once()

    def test_empty_lists_do_not_cause_errors(self):
        with tempfile.TemporaryDirectory() as td:
            case = MagicMock(spec=["reports_dir"])
            case.reports_dir = Path(td)

            with patch.multiple(
                "forensia.api.cache",
                get_case_dto=DEFAULT,
                get_case_stats_dto=DEFAULT,
                list_findings_dto=DEFAULT,
                list_hypotheses_dto=DEFAULT,
                list_sessions_dto=DEFAULT,
                list_hypothesis_reasoning_map_dto=DEFAULT,
                list_latest_hypothesis_reasoning_dto=DEFAULT,
                list_steps_dto=DEFAULT,
                list_report_sections_dto=DEFAULT,
                list_section_questions_dto=DEFAULT,
                list_claims_dto=DEFAULT,
                list_mft_timeline_dto=DEFAULT,
                list_event_volume_dto=DEFAULT,
                list_entity_cards_dto=DEFAULT,
                list_attack_coverage_dto=DEFAULT,
                list_ai_reviews_dto=DEFAULT,
                write_report_brief=DEFAULT,
                list_progress_events=DEFAULT,
            ) as mocks:
                mocks["get_case_dto"].return_value = _MockDTO({})
                mocks["get_case_stats_dto"].return_value = _MockDTO({})
                mocks["list_findings_dto"].return_value = []
                hyp = _MockDTO({})
                hyp.model_dump = lambda mode="json": {}
                mocks["list_hypotheses_dto"].return_value = hyp
                mocks["list_sessions_dto"].return_value = []
                mocks["list_hypothesis_reasoning_map_dto"].return_value = {}
                mocks["list_latest_hypothesis_reasoning_dto"].return_value = []
                mocks["list_steps_dto"].return_value = []
                mocks["list_report_sections_dto"].return_value = []
                mocks["list_section_questions_dto"].return_value = []
                mocks["list_claims_dto"].return_value = []
                mocks["list_mft_timeline_dto"].return_value = []
                mocks["list_event_volume_dto"].return_value = []
                mocks["list_entity_cards_dto"].return_value = []
                mocks["list_attack_coverage_dto"].return_value = []
                mocks["list_ai_reviews_dto"].return_value = []
                mocks["write_report_brief"].return_value = {}
                mocks["list_progress_events"].return_value = []

                write_api_snapshots(case, MagicMock())

            snap_dir = _snapshot_dir(case)
            self.assertTrue((snap_dir / "case.json").exists())
            self.assertTrue((snap_dir / "progress_events.json").exists())
