from __future__ import annotations

import pytest

from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.db.views import case_snapshot
from forensia.tui import _command, _format_header


def test_tui_command_boundary_maps_to_runtime_operations() -> None:
    assert _command("/stop") == ("stop", {})
    assert _command("/resume") == ("resume", {})
    assert _command("/add /tmp/evidence") == ("add", {"input_dir": "/tmp/evidence"})
    assert _command("/add /tmp/evidence dir") == (
        "add",
        {"input_dir": "/tmp/evidence dir"},
    )
    assert _command(r"/add C:\Evidence Sets\case 1") == (
        "add",
        {"input_dir": r"C:\Evidence Sets\case 1"},
    )
    assert _command("/report") == ("report", {"write": False})
    assert _command("/report --write") == ("report", {"write": True})
    assert _command("/detail evidence evtx-1") == (
        "detail",
        {"kind": "evidence", "id": "evtx-1"},
    )
    assert _command("/detail") == ("detail_close", {})
    assert _command("Prioritize host HOST-1") == (
        "steer",
        {"text": "Prioritize host HOST-1"},
    )


def test_tui_rejects_unknown_commands() -> None:
    for value in ("/shell whoami", "/stop now", "/resume later", "/quit"):
        with pytest.raises(ValueError, match="/help"):
            _command(value)


def test_header_shows_running_for_ingest_without_session(tmp_path) -> None:
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        record_progress_event(
            db,
            progress_event(
                "pipeline.ingest",
                "running",
                stage="ingest",
                summary="Scanning input files",
            ),
        )
        snapshot = case_snapshot(case, db)

    header = _format_header(snapshot)
    assert snapshot["session"] is None
    assert "· running ·" in header
    assert "Current work: Scanning input files" in header


def test_header_hides_old_session_stop_reason_during_ingest(tmp_path) -> None:
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.investigation_sessions "
            "(session_id, started_at, finished_at, status, terminal_reason) "
            "VALUES ('old-session', now() - INTERVAL 1 DAY, now(), 'stopped', 'operator_stop')"
        )
        record_progress_event(
            db,
            progress_event(
                "pipeline.normalize",
                "running",
                stage="normalize",
                summary="Normalizing new files",
            ),
        )
        snapshot = case_snapshot(case, db)

    header = _format_header(snapshot)
    assert "· running ·" in header
    assert "Current work: Normalizing new files" in header
    assert "Reason:" not in header
