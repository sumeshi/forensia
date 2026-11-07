from __future__ import annotations

import json
import multiprocessing
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensia.core.case import Case
from forensia.core.ownership import case_lock
from forensia.db.database import CaseDB, CaseDBBusyError
from forensia.runtime import RuntimeClient, start_runtime
from forensia.runtime.ipc import (
    RuntimeServer,
    _key_path,
    probe_runtime,
    runtime_address,
)


class _Engine:
    def snapshot(self):
        return {"status": "idle"}

    def events(self, *, after_index, limit):
        return [after_index, limit]

    def detail(self, kind, item_id, *, limit, offset=0):
        return [kind, item_id, limit, offset]

    def command(self, command_id, operation, payload):
        return [command_id, operation, payload]

    def close(self):
        pass


def _serve_test_runtime(case_dir: str) -> None:
    lock = case_lock(case_dir).acquire()
    RuntimeServer(case_dir, _Engine(), lock).serve_forever()


def _serve_busy_test_runtime(case_dir: str, busy, release) -> None:
    from forensia.core.progress_event import progress_event
    from forensia.db.progress import record_progress_event
    from forensia.runtime.engine import RuntimeEngine

    case = Case.open(case_dir)
    engine = RuntimeEngine(case.path)
    engine.prepare()
    engine._open_active_db()
    worker = threading.Thread(target=engine.run)
    worker.start()

    def hold_transaction() -> None:
        with CaseDB(case) as db:
            with db.transaction():
                db.execute(
                    "INSERT INTO findings (finding_id, title) VALUES ('pending-finding', 'New finding')"
                )
                record_progress_event(
                    db,
                    progress_event(
                        "finding.created", "completed", summary="New finding"
                    ),
                )
                busy.set()
                release.wait(10)

    holder = threading.Thread(target=hold_transaction)
    holder.start()
    busy.wait(10)
    lock = case_lock(case_dir).acquire()
    RuntimeServer(case_dir, engine, lock).serve_forever()
    release.set()
    holder.join(timeout=2)
    worker.join(timeout=2)


def test_case_lock_is_process_owned_and_outside_case(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    with case_lock(case):
        with pytest.raises(RuntimeError, match="already has a Runtime owner"):
            case_lock(case).acquire()
    with case_lock(case):
        assert list(case.iterdir()) == []


def test_public_runtime_start_rejects_symlink_overwrite_without_touching_target(
    tmp_path,
):
    target = Case.init(tmp_path / "real-case")
    with CaseDB(target):
        pass
    marker = target.path / "manifest.yaml"
    before = marker.read_bytes()
    link = tmp_path / "case-link"
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target.path)],
            check=True,
            capture_output=True,
        )
        assert link.is_junction()
    else:
        link.symlink_to(target.path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked case"):
        start_runtime(link, input_dir=tmp_path, overwrite=True)
    assert marker.read_bytes() == before


def test_public_runtime_start_rejects_nonempty_unowned_directory(tmp_path):
    target = tmp_path / "not-a-case"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="already contains data"):
        start_runtime(target, input_dir=tmp_path / "input")
    assert marker.read_text(encoding="utf-8") == "keep"


def test_runtime_ipc_and_lock_cross_process(tmp_path):
    case = tmp_path / "case"
    process = multiprocessing.get_context("spawn").Process(
        target=_serve_test_runtime, args=(str(case),)
    )
    process.start()
    try:
        for _ in range(100):
            if probe_runtime(case):
                break
            time.sleep(0.01)
        assert probe_runtime(case)
        with pytest.raises(RuntimeError, match="already has a Runtime owner"):
            case_lock(case).acquire()
        client = RuntimeClient(case)
        assert client.request({"type": "snapshot"}) == {"status": "idle"}
        assert client.request({"type": "events", "after_index": 2, "limit": 3}) == [
            2,
            3,
        ]
        assert client.request({"type": "detail", "kind": "task", "id": "t1"}) == [
            "task",
            "t1",
            100,
            0,
        ]
        assert client.request(
            {"type": "detail", "kind": "llm_attempt", "id": "pa-1", "offset": 16384}
        ) == ["llm_attempt", "pa-1", 100, 16384]
        with pytest.raises(RuntimeError, match="Invalid detail request"):
            client.request(
                {"type": "detail", "kind": "step", "id": "s-1", "offset": -1}
            )
        assert client.request(
            {"type": "command", "command_id": "c1", "operation": "stop"}
        ) == ["c1", "stop", {}]
        client.claim_control()
        other = RuntimeClient(case)
        with pytest.raises(RuntimeError, match="already has a Runtime owner"):
            other.claim_control()
        with pytest.raises(RuntimeError, match="Another TUI currently controls"):
            other.request({"type": "command", "command_id": "c2", "operation": "stop"})
        with pytest.raises(RuntimeError, match="Another TUI currently controls"):
            other.shutdown(force=True)
        with pytest.raises(RuntimeError, match="Runtime was replaced"):
            client.request({"type": "kill", "startup_id": "previous-owner"})
        assert probe_runtime(case)
        client.release_control()
        with pytest.raises(ValueError, match="Unsupported Runtime request"):
            client.request({"type": "arbitrary"})
    finally:
        process.terminate()
        process.join(timeout=2)
        Path(runtime_address(case)).unlink(missing_ok=True)
        _key_path(case).unlink(missing_ok=True)
    assert process.exitcode is not None
    with case_lock(case):
        pass


def test_runtime_ipc_reads_committed_state_during_writes(tmp_path):
    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    context = multiprocessing.get_context("spawn")
    busy = context.Event()
    release = context.Event()
    process = context.Process(
        target=_serve_busy_test_runtime,
        args=(str(case.path), busy, release),
    )
    process.start()
    client = RuntimeClient(case.path, timeout=1)
    try:
        assert busy.wait(5)
        for _ in range(100):
            if probe_runtime(case.path):
                break
            time.sleep(0.01)
        assert probe_runtime(case.path)

        before = client.request({"type": "snapshot"})
        assert before["counts"]["findings"] == 0
        assert not any(
            event.get("summary") == "New finding"
            for event in client.request({"type": "events"})
        )
        assert (
            client.request(
                {"type": "detail", "kind": "finding", "id": "pending-finding"}
            )
            is None
        )
        assert client.request({"type": "status"})["ready"] is True

        release.set()
        snapshot = None
        for _ in range(100):
            try:
                snapshot = client.request({"type": "snapshot"})
                if snapshot["counts"]["findings"] == 1:
                    break
            except CaseDBBusyError:
                pass
            time.sleep(0.01)
        assert snapshot["case_name"] == case.path.name
        assert snapshot["counts"]["findings"] == 1
        assert snapshot["event_highwater"] > before["event_highwater"]
        assert any(
            event.get("summary") == "New finding"
            for event in client.request({"type": "events"})
        )
        assert (
            client.request(
                {"type": "detail", "kind": "finding", "id": "pending-finding"}
            )["title"]
            == "New finding"
        )

        receipt = client.request(
            {
                "type": "command",
                "command_id": "stop-after-busy-read",
                "operation": "stop",
            }
        )
        assert receipt["status"] == "accepted"
        for _ in range(100):
            receipt = client.request(
                {
                    "type": "command",
                    "command_id": "stop-after-busy-read",
                    "operation": "stop",
                }
            )
            if receipt["status"] == "applied":
                break
            time.sleep(0.01)
        assert receipt["status"] == "applied"
        assert client.request({"type": "retire"})["retired"] is True
        process.join(timeout=3)
        assert not process.is_alive()
        assert process.exitcode == 0
    finally:
        release.set()
        process.join(timeout=3)
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        if sys.platform != "win32":
            Path(runtime_address(case.path)).unlink(missing_ok=True)
        _key_path(case.path).unlink(missing_ok=True)


def test_runtime_kill_during_write_preserves_committed_state(tmp_path):
    case = Case.init(tmp_path / "interrupted-write")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO findings (finding_id, rule_id, title, severity) "
            "VALUES ('saved-finding', 'fixture', 'Saved finding', 'info')"
        )
    context = multiprocessing.get_context("spawn")
    busy = context.Event()
    release = context.Event()
    process = context.Process(
        target=_serve_busy_test_runtime,
        args=(str(case.path), busy, release),
    )
    process.start()
    try:
        assert busy.wait(5)
        for _ in range(100):
            if probe_runtime(case.path):
                break
            time.sleep(0.01)
        RuntimeClient(case.path).shutdown(force=True)
        process.join(timeout=3)
        assert process.exitcode == 1
        assert not release.is_set()
        assert not probe_runtime(case.path)
        with case_lock(case.path), CaseDB(case, read_only=True) as db:
            assert db.execute("SELECT finding_id FROM findings").fetchall() == [
                ("saved-finding",)
            ]
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=3)
        if sys.platform != "win32":
            Path(runtime_address(case.path)).unlink(missing_ok=True)
        _key_path(case.path).unlink(missing_ok=True)


def test_probe_runtime_treats_endpoint_eof_as_disconnected(monkeypatch, tmp_path):
    def endpoint_closed(_client, _request):
        raise EOFError("Runtime pipe closed during authentication")

    monkeypatch.setattr(RuntimeClient, "request", endpoint_closed)

    assert not probe_runtime(tmp_path / "case")


def test_windows_pipe_contention_is_timeout_and_missing_pipe_is_disconnection(
    monkeypatch, tmp_path
):
    import forensia.runtime.ipc as ipc

    client = RuntimeClient(tmp_path / "case")
    key = tmp_path / "key"
    key.write_bytes(b"test-key")
    monkeypatch.setattr(ipc, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ipc, "_key_path", lambda _: key)

    def unavailable_pipe(*args, **kwargs):
        raise failure

    monkeypatch.setattr(ipc, "Client", unavailable_pipe)
    for code in (121, 231):
        failure = OSError("Named pipe is busy")
        failure.winerror = code
        with pytest.raises(TimeoutError, match="pipe remained busy"):
            client.request({"type": "status"})

    failure = FileNotFoundError("Runtime pipe is gone")
    failure.winerror = 2
    with pytest.raises(FileNotFoundError):
        client.request({"type": "status"})


def test_command_receipt_is_durable_and_idempotent(tmp_path):
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    with pytest.raises(ValueError, match="write must be a boolean"):
        engine.command("invalid-report-write", "report", {"write": "false"})
    with pytest.raises(ValueError, match="Unexpected report payload fields"):
        engine.command("invalid-report-key", "report", {"write": False, "extra": 1})
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        first = engine.command("cmd-1", "stop", {})
        assert first["status"] == "accepted"
        for _ in range(100):
            receipt = engine.command("cmd-1", "stop", {})
            if receipt["status"] == "applied":
                break
            time.sleep(0.01)
        assert receipt["status"] == "applied"
        with pytest.raises(ValueError, match="different content"):
            engine.command("cmd-1", "resume", {})
    finally:
        engine.close()
        worker.join(timeout=2)
    assert not worker.is_alive()
    with CaseDB(case, read_only=True) as db:
        row = db.execute(
            "SELECT status FROM trace.runtime_commands WHERE command_id = 'cmd-1'"
        ).fetchone()
    assert row == ("applied",)


def test_prepare_recovers_applying_and_requeues_by_acceptance_event_order(tmp_path):
    from forensia.core.progress_event import progress_event
    from forensia.db.progress import record_progress_event
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        for command_id, status in (
            ("interrupted", "applying"),
            ("z-first", "accepted"),
            ("a-second", "accepted"),
        ):
            db.execute(
                "INSERT INTO trace.runtime_commands "
                "(command_id, operation, payload, status, created_at, updated_at) "
                "VALUES (?, 'resume', '{}', ?, current_timestamp, current_timestamp)",
                [command_id, status],
            )
        for command_id in ("z-first", "a-second"):
            record_progress_event(
                db,
                progress_event(
                    "runtime.command",
                    "running",
                    command_id=command_id,
                    operation="resume",
                ),
            )

    engine = RuntimeEngine(case.path)
    engine.prepare()
    assert [engine._commands.get_nowait(), engine._commands.get_nowait()] == [
        "z-first",
        "a-second",
    ]
    with CaseDB(case, read_only=True) as db:
        row = db.execute(
            "SELECT status, reason FROM trace.runtime_commands WHERE command_id = 'interrupted'"
        ).fetchone()
    assert row == (
        "failed",
        "Runtime exited while applying; outcome not replayed",
    )


def test_steer_uses_adopted_settings_telemetry_budget_and_command_receipt(
    tmp_path, monkeypatch
):
    from forensia.config import Settings, get_settings
    from forensia.db.database import CaseDB
    from forensia.investigation import intervention
    from forensia.llm.telemetry import get_active_telemetry
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    engine._settings = Settings(
        llm_base_url="http://local.test",
        llm_model="test-model",
        llm_api_key="do-not-persist",
        max_llm_calls=7,
    )
    observed = {}

    def classify(*_args, **_kwargs):
        observed["settings"] = get_settings()
        observed["telemetry"] = get_active_telemetry()
        return {
            "action": "update_policy",
            "policy_updates": {
                "objective": "Determine whether approved maintenance occurred."
            },
        }

    monkeypatch.setattr(intervention, "request_llm_json", classify)
    assert (
        engine.command("steer-1", "steer", {"text": "Ask about maintenance."})["status"]
        == "accepted"
    )
    engine._apply_command_inner("steer-1")

    assert observed["settings"] == engine._settings
    assert observed["telemetry"].max_logical_calls == 7
    with CaseDB(case, read_only=True) as db:
        command = db.execute(
            "SELECT status, result FROM trace.runtime_commands WHERE command_id = 'steer-1'"
        ).fetchone()
        trace_input = db.execute(
            "SELECT input_json FROM trace.investigation_steps "
            "WHERE phase = 'human-intervention'"
        ).fetchone()[0]
        steer_session = db.execute(
            "SELECT status, terminal_reason FROM trace.investigation_sessions "
            "WHERE session_id = 'steer-steer-1'"
        ).fetchone()
        assert (
            db.execute(
                "SELECT objective FROM investigation_state WHERE state_id = 'case'"
            ).fetchone()[0]
            == "Determine whether approved maintenance occurred."
        )
    assert command[0] == "applied"
    assert steer_session[0] == "completed"
    assert steer_session[1]
    assert '"llm_api_key"' not in trace_input
    assert "do-not-persist" not in trace_input
    engine.close()


def test_start_runtime_runs_real_idle_process_and_accepts_commands(tmp_path):
    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    client = start_runtime(case.path, timeout=10)
    process = client._process
    try:
        snapshot = client.request({"type": "snapshot"})
        assert snapshot["case_name"] == "case"
        first = client.request(
            {"type": "command", "command_id": "runtime-stop", "operation": "stop"}
        )
        assert first["status"] == "accepted"
        for _ in range(100):
            receipt = client.request(
                {"type": "command", "command_id": "runtime-stop", "operation": "stop"}
            )
            if receipt["status"] == "applied":
                break
            time.sleep(0.02)
        assert receipt["status"] == "applied"
        assert client.request({"type": "retire"}) == {"retired": True}
        process.wait(timeout=3)
        with case_lock(case.path):
            pass
    finally:
        assert process is not None
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)
        Path(runtime_address(case.path)).unlink(missing_ok=True)
        _key_path(case.path).unlink(missing_ok=True)


def test_runtime_refuses_retirement_while_command_is_active(tmp_path):
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    engine._active = True
    assert engine.retire_if_idle() is False
    engine._active = False
    assert engine.retire_if_idle() is True
    engine.close()


def test_runtime_refuses_retirement_before_initial_job_starts(tmp_path):
    from forensia.runtime.engine import RuntimeEngine

    case_dir = tmp_path / "case"
    source = tmp_path / "input"
    source.mkdir()
    engine = RuntimeEngine(case_dir)
    engine.prepare(
        input_dir=source,
        settings={"llm_base_url": "http://127.0.0.1:1", "llm_model": "test"},
    )
    assert engine.retire_if_idle() is False
    engine.close()


def test_stop_interrupts_an_applying_command(tmp_path):
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    engine._applying = True
    assert engine.command("stop-applying", "stop", {})["status"] == "accepted"
    assert engine.stop_requested.is_set()
    engine.close()


def test_stop_queued_before_resume_starts_is_not_cleared(tmp_path, monkeypatch):
    from forensia.config import Settings
    from forensia.core.control import InvestigationStopped
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    monkeypatch.setattr(engine, "_resume_settings", lambda: Settings(llm_model="test"))
    reached_investigation = threading.Event()

    def investigate(*_args, **_kwargs):
        assert engine.stop_requested.is_set()
        reached_investigation.set()
        raise InvestigationStopped

    monkeypatch.setattr(engine, "_investigate", investigate)
    assert engine.command("queued-resume", "resume", {})["status"] == "accepted"
    assert engine.command("queued-stop", "stop", {})["status"] == "accepted"
    assert engine.stop_requested.is_set()

    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert reached_investigation.wait(2)
        engine._commands.put(None)
        worker.join(timeout=3)
        assert not worker.is_alive()
        with CaseDB(case, read_only=True) as db:
            rows = db.execute(
                "SELECT command_id, status FROM trace.runtime_commands "
                "WHERE command_id IN ('queued-resume', 'queued-stop')"
            ).fetchall()
        statuses = dict(rows)
        assert statuses == {"queued-resume": "interrupted", "queued-stop": "applied"}
    finally:
        engine.close()
        worker.join(timeout=3)
    assert not worker.is_alive()


def test_active_steer_pause_clears_its_stop_and_keeps_applied_receipt(
    tmp_path, monkeypatch
):
    from forensia.config import Settings
    from forensia.core.control import InvestigationStopped
    from forensia.investigation import intervention
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    settings = Settings(llm_base_url="http://127.0.0.1:1", llm_model="test")
    monkeypatch.setattr(engine, "_resume_settings", lambda: settings)
    first_investigation = threading.Event()
    continuation_attempted = threading.Event()
    investigations = 0

    def investigate(*_args, **_kwargs):
        nonlocal investigations
        investigations += 1
        if investigations == 1:
            engine._active = True
            engine._investigating = True
            first_investigation.set()
            try:
                assert engine.stop_requested.wait(3)
                raise InvestigationStopped
            finally:
                engine._active = False
                engine._investigating = False
        continuation_attempted.set()
        raise RuntimeError("follow-up failed")

    def apply(*_args, **_kwargs):
        assert not engine.stop_requested.is_set()
        return {"status": "applied"}

    monkeypatch.setattr(engine, "_investigate", investigate)
    monkeypatch.setattr(intervention, "apply_intervention", apply)
    assert engine.command("active-resume", "resume", {})["status"] == "accepted"
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert first_investigation.wait(2)
        steer = engine.command(
            "active-steer", "steer", {"text": "Focus on approved maintenance."}
        )
        assert steer["status"] == "accepted"
        assert continuation_attempted.wait(4)
        engine._commands.put(None)
        worker.join(timeout=4)
        assert not worker.is_alive()
    finally:
        engine.close()
        worker.join(timeout=3)
    with CaseDB(case, read_only=True) as db:
        receipts = dict(
            db.execute(
                "SELECT command_id, status FROM trace.runtime_commands "
                "WHERE command_id IN ('active-resume', 'active-steer')"
            ).fetchall()
        )
        follow_up_failure = db.execute(
            "SELECT COUNT(*) FROM trace.progress_events "
            "WHERE kind = 'runtime.investigation' AND status = 'failed'"
        ).fetchone()[0]
    assert receipts == {"active-resume": "interrupted", "active-steer": "applied"}
    assert follow_up_failure == 1


def _control_engine(tmp_path, monkeypatch):
    from forensia.config import Settings
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
    settings = Settings(llm_base_url="http://127.0.0.1:1", llm_model="test")
    engine._settings = settings
    monkeypatch.setattr(engine, "_resume_settings", lambda: settings)
    return case, engine


@pytest.mark.parametrize(
    ("outcome", "expected_status"),
    [
        ("applied", "applied"),
        ("rejected", "rejected"),
        ("failed", "failed"),
        ("raise", "failed"),
        ("unknown_status", "failed"),
        ("unknown_shape", "failed"),
    ],
)
def test_active_direction_retains_outcome_and_continues_without_retry(
    tmp_path, monkeypatch, outcome, expected_status
):
    import forensia.pipeline
    from forensia.core.control import InvestigationStopped
    from forensia.db.progress import list_progress_events
    from forensia.investigation import intervention

    case, engine = _control_engine(tmp_path, monkeypatch)
    started = threading.Event()
    continued = threading.Event()
    investigation_calls = []
    intervention_calls = []

    def investigate(*_args, **kwargs):
        investigation_calls.append(kwargs)
        if len(investigation_calls) == 1:
            started.set()
            assert kwargs["stop_requested"].wait(3)
            raise InvestigationStopped
        continued.set()

    def apply(*_args, **_kwargs):
        intervention_calls.append(outcome)
        assert not engine.stop_requested.is_set()
        if outcome == "raise":
            raise RuntimeError("instruction processing failed")
        if outcome == "unknown_shape":
            return None
        if outcome == "unknown_status":
            return {"status": "unexpected"}
        return {"status": outcome, "reason": f"host_{outcome}", "refs": {}}

    monkeypatch.setattr(forensia.pipeline, "run_investigation", investigate)
    monkeypatch.setattr(intervention, "apply_intervention", apply)
    engine.command("start", "resume", {})
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert started.wait(3)
        engine.command("direction", "steer", {"text": "Check approved maintenance."})
        assert continued.wait(4)
    finally:
        engine.close()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert len(investigation_calls) == 2
    assert investigation_calls[-1]["manual_resume"] is True
    assert intervention_calls == [outcome]
    with CaseDB(case, read_only=True) as db:
        status, result = db.execute(
            "SELECT status, result FROM trace.runtime_commands WHERE command_id = 'direction'"
        ).fetchone()
        result = json.loads(result)
        events = [
            event
            for event in list_progress_events(db)
            if event["refs"].get("command_id") == "direction"
        ]
    assert status == result["status"] == expected_status
    assert result["continuation"]["status"] == "resuming"
    assert result["intervention_session_id"] == "steer-direction"
    assert [event["payload"]["command_status"] for event in events] == [
        "accepted",
        "applying",
        expected_status,
    ]
    assert all(
        event["payload"]["instruction"] == "Check approved maintenance."
        for event in events
    )
    assert all(event["payload"]["result_summary"] for event in events)
    assert events[-1]["payload"]["continuation"] == "resuming"


@pytest.mark.parametrize("last_status", ["applied", "failed", "rejected"])
def test_queued_directions_apply_before_one_autonomous_continuation(
    tmp_path, monkeypatch, last_status
):
    import forensia.pipeline
    from forensia.core.control import InvestigationStopped
    from forensia.investigation import intervention

    case, engine = _control_engine(tmp_path, monkeypatch)
    started = threading.Event()
    release_pause = threading.Event()
    continued = threading.Event()
    applied = []
    investigations = []

    def investigate(*_args, **kwargs):
        investigations.append(kwargs)
        if len(investigations) == 1:
            started.set()
            assert kwargs["stop_requested"].wait(3)
            assert release_pause.wait(3)
            raise InvestigationStopped
        assert applied == ["First direction", "Second direction"]
        continued.set()

    def apply(_case, _db, text, **_kwargs):
        assert not engine.stop_requested.is_set()
        applied.append(text)
        return {"status": last_status if text == "Second direction" else "applied"}

    monkeypatch.setattr(forensia.pipeline, "run_investigation", investigate)
    monkeypatch.setattr(intervention, "apply_intervention", apply)
    engine.command("start", "resume", {})
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert started.wait(3)
        engine.command("direction-1", "steer", {"text": "First direction"})
        engine.command("direction-2", "steer", {"text": "Second direction"})
        release_pause.set()
        assert continued.wait(4)
    finally:
        release_pause.set()
        engine.close()
        worker.join(timeout=3)
    assert len(investigations) == 2
    with CaseDB(case, read_only=True) as db:
        rows = db.execute(
            "SELECT command_id, status, result FROM trace.runtime_commands "
            "WHERE operation = 'steer' ORDER BY created_at"
        ).fetchall()
    assert [row[1] for row in rows] == ["applied", last_status]
    assert [json.loads(row[2])["continuation"]["status"] for row in rows] == [
        "after_pending_commands",
        "resuming",
    ]


def test_direction_received_during_continuation_start_is_applied_first(
    tmp_path, monkeypatch
):
    import forensia.pipeline
    from forensia.core.control import InvestigationStopped
    from forensia.investigation import intervention

    _case, engine = _control_engine(tmp_path, monkeypatch)
    settings = engine._settings
    started = threading.Event()
    preparing_continuation = threading.Event()
    release_settings = threading.Event()
    continued = threading.Event()
    settings_calls = []
    investigations = []
    applied = []

    def resume_settings():
        settings_calls.append(True)
        if len(settings_calls) == 2:
            preparing_continuation.set()
            assert release_settings.wait(3)
        return settings

    def investigate(*_args, **kwargs):
        investigations.append(kwargs)
        if len(investigations) == 1:
            started.set()
            assert kwargs["stop_requested"].wait(3)
            raise InvestigationStopped
        assert applied == ["First direction", "Second direction"]
        continued.set()

    def apply(_case, _db, text, **_kwargs):
        applied.append(text)
        return {"status": "applied"}

    monkeypatch.setattr(engine, "_resume_settings", resume_settings)
    monkeypatch.setattr(forensia.pipeline, "run_investigation", investigate)
    monkeypatch.setattr(intervention, "apply_intervention", apply)
    engine.command("start", "resume", {})
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert started.wait(3)
        engine.command("direction-1", "steer", {"text": "First direction"})
        assert preparing_continuation.wait(3)
        engine.command("direction-2", "steer", {"text": "Second direction"})
        release_settings.set()
        assert continued.wait(4)
    finally:
        release_settings.set()
        engine.close()
        worker.join(timeout=3)
    assert len(investigations) == 2


def test_explicit_stop_during_direction_prevents_autonomous_continuation(
    tmp_path, monkeypatch
):
    import forensia.pipeline
    from forensia.core.control import InvestigationStopped
    from forensia.investigation import intervention

    case, engine = _control_engine(tmp_path, monkeypatch)
    started = threading.Event()
    applying = threading.Event()
    release_apply = threading.Event()
    investigations = []

    def investigate(*_args, **kwargs):
        investigations.append(kwargs)
        started.set()
        assert kwargs["stop_requested"].wait(3)
        raise InvestigationStopped

    def apply(*_args, **_kwargs):
        applying.set()
        assert release_apply.wait(3)
        return {"status": "applied"}

    monkeypatch.setattr(forensia.pipeline, "run_investigation", investigate)
    monkeypatch.setattr(intervention, "apply_intervention", apply)
    engine.command("start", "resume", {})
    worker = threading.Thread(target=engine.run)
    worker.start()
    try:
        assert started.wait(3)
        engine.command("direction", "steer", {"text": "Check maintenance."})
        assert applying.wait(3)
        # The applying receipt contains its actual intervention session owner.
        receipt = engine.detail("command_receipt", "direction")
        assert receipt["result"]["intervention_session_id"] == "steer-direction"
        engine.command("stop", "stop", {})
        release_apply.set()
        for _ in range(100):
            receipt = engine.command("stop", "stop", {})
            if receipt["status"] == "applied":
                break
            time.sleep(0.01)
        assert receipt["status"] == "applied"
    finally:
        release_apply.set()
        engine.close()
        worker.join(timeout=3)
    assert len(investigations) == 1
    with CaseDB(case, read_only=True) as db:
        (result,) = db.execute(
            "SELECT result FROM trace.runtime_commands WHERE command_id = 'direction'"
        ).fetchone()
    assert json.loads(result)["continuation"]["status"] == "stopped"


def test_idle_direction_failure_is_not_success_and_does_not_start_investigation(
    tmp_path, monkeypatch
):
    from forensia.investigation import intervention

    case, engine = _control_engine(tmp_path, monkeypatch)

    def classify(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    def unexpected_investigation(*_args, **_kwargs):
        pytest.fail("An idle direction must not start an autonomous investigation")

    monkeypatch.setattr(intervention, "request_llm_json", classify)
    monkeypatch.setattr(engine, "_investigate", unexpected_investigation)
    engine.command("direction", "steer", {"text": "Check maintenance."})
    engine._apply_command_inner("direction")
    with CaseDB(case, read_only=True) as db:
        status, result = db.execute(
            "SELECT status, result FROM trace.runtime_commands WHERE command_id = 'direction'"
        ).fetchone()
        (session_status,) = db.execute(
            "SELECT status FROM trace.investigation_sessions WHERE session_id = 'steer-direction'"
        ).fetchone()
    engine.close()
    assert status == session_status == "failed"
    assert json.loads(result)["status"] == "failed"
    assert json.loads(result)["continuation"]["status"] == "not_requested"


def test_rejected_direction_rolls_back_partial_case_changes(tmp_path, monkeypatch):
    from forensia.investigation import intervention

    case, engine = _control_engine(tmp_path, monkeypatch)
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *_args, **_kwargs: {
            "action": "update_policy",
            "policy_updates": {"objective": "Check maintenance."},
        },
    )

    def reject_partial_change(db, *_args):
        db.execute(
            "INSERT INTO findings (finding_id, title) VALUES ('partial', 'Must roll back')"
        )
        raise ValueError("policy update rejected")

    monkeypatch.setattr(intervention, "_apply_policy", reject_partial_change)
    engine.command("direction", "steer", {"text": "Check maintenance."})
    engine._apply_command_inner("direction")
    with CaseDB(case, read_only=True) as db:
        status, result = db.execute(
            "SELECT status, result FROM trace.runtime_commands WHERE command_id = 'direction'"
        ).fetchone()
        assert (
            db.execute(
                "SELECT count(*) FROM findings WHERE finding_id = 'partial'"
            ).fetchone()[0]
            == 0
        )
    engine.close()
    assert status == json.loads(result)["status"] == "rejected"


def test_overwrite_preflight_passes_template_as_report_spec(tmp_path, monkeypatch):
    import forensia.pipeline
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    source = tmp_path / "input"
    source.mkdir()
    template = tmp_path / "report.md"
    template.write_text("---\ntitle: Test\n---\n# Summary\n", encoding="utf-8")
    seen = {}

    def capture_overwrite(case_dir, input_dir, inputs, status):
        seen.update(inputs)

    monkeypatch.setattr(forensia.pipeline, "_overwrite_case", capture_overwrite)
    engine = RuntimeEngine(case.path)
    engine.prepare(
        input_dir=source,
        overwrite=True,
        settings={"llm_base_url": "http://127.0.0.1:1", "llm_model": "test"},
        template=template,
    )
    assert seen["report_spec"] == template.resolve()
    assert seen["template_dir"] is None
