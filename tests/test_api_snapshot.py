"""Tests for report/api_snapshot.py and unified snapshot writers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import DEFAULT, MagicMock, patch

from forensia.api.cache import snapshot_dir
from forensia.report.api_snapshot import (
    write_all_snapshots,
    write_report_api_snapshots,
    write_volatile_snapshots,
)


def _mock_case(tmp_dir: str) -> MagicMock:
    case = MagicMock(spec=["reports_dir"])
    case.reports_dir = Path(tmp_dir)
    return case


def _patch_report_deps():
    """Return a context manager that mocks report-layer dependencies."""
    return patch.multiple(
        "forensia.report.api_snapshot",
        list_report_sections_dto=DEFAULT,
        write_report_brief=DEFAULT,
    )


def _patch_cache_deps():
    """Return a context manager that mocks platform-layer dependencies."""
    return patch.multiple(
        "forensia.api.cache",
        get_case_dto=DEFAULT,
        get_case_stats_dto=DEFAULT,
        list_findings_dto=DEFAULT,
        list_hypotheses_dto=DEFAULT,
        list_sessions_dto=DEFAULT,
        list_hypothesis_reasoning_map_dto=DEFAULT,
        list_latest_hypothesis_reasoning_dto=DEFAULT,
        list_steps_dto=DEFAULT,
        list_section_questions_dto=DEFAULT,
        list_claims_dto=DEFAULT,
        list_mft_timeline_dto=DEFAULT,
        list_event_volume_dto=DEFAULT,
        list_entity_cards_dto=DEFAULT,
        list_attack_coverage_dto=DEFAULT,
        list_ai_reviews_dto=DEFAULT,
        list_progress_events=DEFAULT,
    )


class TestWriteReportApiSnapshots(unittest.TestCase):
    def test_full_mode_writes_sections_and_brief(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = _mock_case(td)
            snap_dir = snapshot_dir(case)

            with _patch_report_deps() as mocks:
                mock_dto = MagicMock()
                mock_dto.model_dump.return_value = {"key": "val"}
                mocks["list_report_sections_dto"].return_value = [mock_dto]
                mocks["write_report_brief"].return_value = {"brief": True}

                write_report_api_snapshots(case, MagicMock())

            assert (snap_dir / "report_sections.json").exists()
            assert (snap_dir / "report_brief.json").exists()

    def test_volatile_mode_writes_sections_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = _mock_case(td)
            snap_dir = snapshot_dir(case)

            with _patch_report_deps() as mocks:
                mock_dto = MagicMock()
                mock_dto.model_dump.return_value = {"key": "val"}
                mocks["list_report_sections_dto"].return_value = [mock_dto]
                mocks["write_report_brief"].return_value = {"brief": True}

                write_report_api_snapshots(case, MagicMock(), volatile=True)

            assert (snap_dir / "report_sections.json").exists()
            assert not (snap_dir / "report_brief.json").exists()

    def test_empty_sections_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = _mock_case(td)

            with _patch_report_deps() as mocks:
                mocks["list_report_sections_dto"].return_value = []
                mocks["write_report_brief"].return_value = {}

                write_report_api_snapshots(case, MagicMock())

            snap_dir = snapshot_dir(case)
            content = (snap_dir / "report_sections.json").read_text()
            assert json.loads(content) == []


import json


class TestWriteAllSnapshots(unittest.TestCase):
    def test_writes_core_and_report_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = _mock_case(td)
            snap_dir = snapshot_dir(case)

            with (
                _patch_cache_deps() as core_mocks,
                _patch_report_deps() as report_mocks,
            ):
                dto = MagicMock()
                dto.model_dump.return_value = {}
                dto.model_dump.side_effect = lambda **kw: {}

                for v in core_mocks.values():
                    v.return_value = dto if hasattr(dto, "session_id") else []
                core_mocks["get_case_dto"].return_value = MagicMock(model_dump=lambda **kw: {})
                core_mocks["get_case_stats_dto"].return_value = MagicMock(model_dump=lambda **kw: {})
                hyp = MagicMock()
                hyp.model_dump.return_value = {}
                core_mocks["list_hypotheses_dto"].return_value = hyp
                session = MagicMock(session_id="s1")
                session.model_dump.return_value = {}
                core_mocks["list_sessions_dto"].return_value = [session]
                core_mocks["list_hypothesis_reasoning_map_dto"].return_value = {}
                core_mocks["list_progress_events"].return_value = []

                mock_dto = MagicMock()
                mock_dto.model_dump.return_value = {}
                report_mocks["list_report_sections_dto"].return_value = [mock_dto]
                report_mocks["write_report_brief"].return_value = {"brief": True}

                write_all_snapshots(case, MagicMock())

            assert (snap_dir / "case.json").exists(), "core snapshot missing"
            assert (snap_dir / "report_sections.json").exists(), "report snapshot missing"
            assert (snap_dir / "report_brief.json").exists(), "report brief missing"


class TestWriteVolatileSnapshots(unittest.TestCase):
    def test_volatile_writes_sections_no_brief(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            case = _mock_case(td)
            snap_dir = snapshot_dir(case)

            with (
                _patch_cache_deps() as core_mocks,
                _patch_report_deps() as report_mocks,
            ):
                core_mocks["list_hypotheses_dto"].return_value = MagicMock(model_dump=lambda: {})
                core_mocks["get_case_stats_dto"].return_value = MagicMock(model_dump=lambda: {})
                core_mocks["list_findings_dto"].return_value = []
                core_mocks["list_attack_coverage_dto"].return_value = []
                core_mocks["list_section_questions_dto"].return_value = []
                core_mocks["list_hypothesis_reasoning_map_dto"].return_value = {}
                core_mocks["list_latest_hypothesis_reasoning_dto"].return_value = []
                core_mocks["list_entity_cards_dto"].return_value = []

                mock_dto = MagicMock()
                mock_dto.model_dump.return_value = {}
                report_mocks["list_report_sections_dto"].return_value = [mock_dto]
                report_mocks["write_report_brief"].return_value = {}

                write_volatile_snapshots(case, MagicMock())

            assert (snap_dir / "report_sections.json").exists()
            assert not (snap_dir / "report_brief.json").exists()
