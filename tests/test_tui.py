from __future__ import annotations

import asyncio

import pytest

from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.db.views import case_snapshot
from forensia.tui import CaseApp, InfoWindow, _command, _format_header, _format_sidebar


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
    assert _command("/more") == ("more", {})
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
                scope="pipeline_stage",
                run_id="test-run",
                summary="Scanning input files",
            ),
        )
        snapshot = case_snapshot(case, db)

    header = _format_header(snapshot).plain
    assert snapshot["session"] is None
    assert "running / ingest" in header
    assert "elapsed 00:" in header
    assert "Findings" not in header
    assert "Findings" in _format_sidebar(snapshot).plain


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
                scope="pipeline_stage",
                run_id="test-run",
                summary="Normalizing new files",
            ),
        )
        snapshot = case_snapshot(case, db)

    header = _format_header(snapshot).plain
    assert "running / normalize" in header
    assert "Reason:" not in _format_sidebar(snapshot).plain


def test_tui_windows_keep_refresh_and_log_navigation_working(tmp_path) -> None:
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.progress_events (event_index, kind, status, severity, refs, payload, created_at) SELECT i, 'earlier.event', 'completed', 'info', '{}', '{}', now() FROM range(1, 6) AS r(i)"
        )
        record_progress_event(
            db,
            progress_event(
                "finding.created",
                "completed",
                severity="success",
                summary="Recorded findings",
                refs={"evidence_ids": [f"private-reference-{i}" for i in range(800)]},
            ),
        )
        db.execute(
            "INSERT INTO trace.progress_events (event_index, kind, status, severity, refs, payload, created_at) SELECT i, 'later.event', 'completed', 'info', '{}', '{}', now() FROM range(7, 46) AS r(i)"
        )

    async def exercise() -> None:
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)) as pilot:
            assert app._sidebar.region.x < app._log.region.x
            assert app._connections.region.y > app._sidebar.region.y
            assert "Read     OK" in app._connections.content.plain
            assert app._events[0]["event_index"] == 6
            assert app._events[-1]["event_index"] == 45
            log_lines = len(app._log.lines)
            assert "private-reference" not in "".join(
                line.text for line in app._log.lines
            )
            await pilot.press("f1")
            assert isinstance(app.screen, InfoWindow)
            await app._refresh()
            assert not app._runtime_lost
            assert len(app._log.lines) == log_lines
            await pilot.press("escape")
            assert not isinstance(app.screen, InfoWindow)

            app._log.scroll_home(animate=False)
            await pilot.pause()
            await pilot.click("#event-log", offset=(3, 1))
            assert isinstance(app.screen, InfoWindow)
            assert app.screen.query_one("#info-more").display
            first_page = app._detail["offset"]
            await pilot.click("#info-more")
            assert app._detail["offset"] > first_page
            await pilot.press("escape")

            app._prompt.value = "/older"
            await pilot.click("#prompt")
            await pilot.press("enter")
            assert [event["event_index"] for event in app._events] == list(range(1, 6))
            app._prompt.value = "/newer"
            await pilot.press("enter")
            assert app._following
            assert app._events[-1]["event_index"] == 45

            await pilot.resize_terminal(64, 32)
            assert app.screen.has_class("narrow")
            assert app._log.region.y > app._sidebar.region.y
            await app._refresh()
            assert "Read     OK" in app._connections.content.plain
            assert (
                app._log.virtual_size.width <= app._log.scrollable_content_region.width
            )

    asyncio.run(exercise())
