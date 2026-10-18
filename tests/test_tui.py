from __future__ import annotations

import asyncio
import json
import subprocess

import pytest

from forensia.config import Settings
from forensia.core.case import Case
from forensia.core.ownership import case_lock
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB, CaseDBBusyError
from forensia.db.progress import record_progress_event
from forensia.db.views import case_snapshot
from forensia.runtime import probe_runtime, start_runtime
from forensia.tui import CaseApp, InfoWindow, _command, _format_header, _format_sidebar


@pytest.mark.parametrize("command", ["ctrl+q", "/quit", "/kill", "/detach"])
def test_tui_exit_controls_real_runtime_lifetime(tmp_path, command) -> None:
    case = Case.init(tmp_path / "exit-case")
    with CaseDB(case):
        pass
    owner = start_runtime(case.path, timeout=10)
    process = owner._process
    assert process is not None

    async def exercise() -> None:
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)) as pilot:
            if command == "ctrl+q":
                await pilot.press(command)
            else:
                app._prompt.value = command
                await pilot.press("enter")
            await pilot.pause()
            if command == "/detach":
                assert probe_runtime(case.path)
                assert process.poll() is None
            else:
                await asyncio.to_thread(process.wait, timeout=3)
                assert not probe_runtime(case.path)
                with case_lock(case.path):
                    pass
            assert app._closed

    try:
        asyncio.run(exercise())
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def test_tui_command_boundary_maps_to_runtime_operations() -> None:
    assert _command("/stop") == ("stop", {})
    assert _command("/quit") == ("quit", {})
    assert _command("/kill") == ("kill", {})
    assert _command("/detach") == ("detach", {})
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
    for value in (
        "/shell whoami",
        "/stop now",
        "/resume later",
        "/quit now",
        "/kill all",
    ):
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


@pytest.mark.parametrize(
    ("status", "http_status", "expected"),
    [
        ("open", None, "Waiting"),
        ("success", 200, "Responded"),
        ("parse_error", 200, "Responded"),
        ("timeout", None, "Timed out"),
        ("transport_error", None, "Connection error"),
        ("provider_error", 401, "HTTP 401"),
        ("provider_error", 503, "HTTP 503"),
        ("application_discard", None, "Interrupted"),
    ],
)
def test_sidebar_projects_observed_llm_connection(
    tmp_path, status, http_status, expected
):
    case = Case.init(tmp_path / "provider-case")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.llm_provider_attempts (attempt_id,endpoint,model,status,http_status,start_time) "
            "VALUES ('attempt','http://inference.example:9123/v1/chat/completions','independent-model',?,?,now())",
            [status, http_status],
        )
        snapshot = case_snapshot(case, db)
    sidebar = _format_sidebar(snapshot).plain
    assert "http://inference.example:9123" in sidebar
    assert "independent-model" in sidebar
    assert f"Last I/O {expected}" in sidebar
    assert "Seen     " in sidebar
    assert "Recorded connection" in sidebar


def test_llm_view_does_not_reuse_another_targets_success_or_expose_url_credentials(
    tmp_path,
):
    case = Case.init(tmp_path / "provider-case")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.llm_provider_attempts (attempt_id,endpoint,model,status,http_status,start_time) "
            "VALUES ('old','http://inference.example:9123/v1/chat/completions','old-model','success',200,now())"
        )
        for endpoint, model in [
            ("http://inference.example:9123", "new-model"),
            ("http://other.example:9199", "old-model"),
        ]:
            view = case_snapshot(
                case,
                db,
                settings=Settings(
                    llm_base_url=endpoint, llm_model=model, llm_api_key="private-key"
                ),
            )
            assert view["llm"]["base_url"] == endpoint
            assert view["llm"]["model"] == model
            assert view["llm"]["status"] == "not_checked"
            assert view["llm"]["observed_at"] is None
            assert "private-key" not in json.dumps(view)
        assert (
            case_snapshot(case, db, settings=Settings())["llm"]["status"]
            == "not_configured"
        )
        db.execute(
            "UPDATE trace.llm_provider_attempts SET endpoint='https://login:password@inference.example:9443/v1/chat/completions?token=private-token#private-fragment'"
        )
        saved = case_snapshot(case, db)["llm"]
        assert saved["base_url"] == "https://inference.example:9443"
        assert all(
            secret not in json.dumps(saved)
            for secret in ("login", "password", "private-token", "private-fragment")
        )


def test_tui_shows_saved_llm_target_and_status_at_wide_and_narrow_sizes(tmp_path):
    case = Case.init(tmp_path / "connection-view")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.llm_provider_attempts (attempt_id,endpoint,model,status,http_status,start_time) "
            "VALUES ('attempt','http://127.0.0.1:9251/v1/chat/completions','independent-local-model','success',200,now())"
        )

    async def exercise():
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)) as pilot:
            for size in ((120, 40), (64, 32)):
                await pilot.resize_terminal(*size)
                await app._refresh()
                content = app._sidebar.content.plain
                assert "http://127.0.0.1:9251" in content
                assert "independent-local-model" in content
                assert "Last I/O Responded" in content
                assert (
                    app._sidebar.virtual_size.width
                    <= app._sidebar.scrollable_content_region.width
                )

    asyncio.run(exercise())


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
            assert app._sidebar.region.x > app._log.region.x
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
            assert app._log.region.y < app._sidebar.region.y
            await app._refresh()
            assert "Read     OK" in app._connections.content.plain
            assert (
                app._log.virtual_size.width <= app._log.scrollable_content_region.width
            )

    asyncio.run(exercise())


def test_tui_retains_runtime_and_last_view_on_read_failure(
    tmp_path, monkeypatch
) -> None:
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        snapshot = case_snapshot(case, db)

    class Client:
        failure: Exception | None = None
        released = False

        def claim_control(self):
            pass

        def release_control(self):
            self.released = True

        def request(self, request):
            if self.failure:
                raise self.failure
            return snapshot if request["type"] == "snapshot" else []

    client = Client()
    monkeypatch.setattr("forensia.tui.probe_runtime", lambda _: True)
    monkeypatch.setattr("forensia.tui.RuntimeClient", lambda _: client)

    async def exercise() -> None:
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)):
            header = app._header.content.plain
            for failure, status in (
                (CaseDBBusyError("Case database is busy"), "busy"),
                (TimeoutError("Runtime response delayed"), "timeout"),
                (RuntimeError("Query failed"), "unavailable"),
            ):
                client.failure = failure
                await app._refresh()
                assert app.client is client
                assert not app._runtime_lost
                assert not client.released
                assert app._header.content.plain == header
                assert f"Read     {status} (stale)" in app._connections.content.plain
                assert "Updated" in app._connections.content.plain
                line_count = len(app._log.lines)
                await app._refresh()
                assert len(app._log.lines) == line_count

            client.failure = None
            await app._refresh()
            assert "Read     OK" in app._connections.content.plain
            client.failure = EOFError("Runtime closed")
            await app._refresh()
            assert app._runtime_lost
            assert app.client is None
            assert client.released

    asyncio.run(exercise())


def test_tui_quit_keeps_screen_and_control_when_stop_times_out(
    tmp_path, monkeypatch
) -> None:
    case = Case.init(tmp_path / "waiting-case")
    with CaseDB(case) as db:
        snapshot = case_snapshot(case, db)

    class Client:
        released = False

        def claim_control(self):
            pass

        def release_control(self):
            self.released = True

        def request(self, request):
            return snapshot if request["type"] == "snapshot" else []

        def shutdown(self, *, force):
            raise TimeoutError("Still waiting; use /kill to force termination")

    client = Client()
    monkeypatch.setattr("forensia.tui.probe_runtime", lambda _: True)
    monkeypatch.setattr("forensia.tui.RuntimeClient", lambda _: client)

    async def exercise() -> None:
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)) as pilot:
            app._prompt.value = "/quit"
            await pilot.press("enter")
            await pilot.pause()
            assert not app._closed
            assert app.client is client
            assert not client.released
            assert any("/kill" in line.text for line in app._log.lines)
            app._prompt.value = "/detach"
            await pilot.press("enter")
        assert client.released

    asyncio.run(exercise())
