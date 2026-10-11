from __future__ import annotations

import multiprocessing
import threading
import time
from pathlib import Path

import pytest

from forensia.core.case import Case
from forensia.core.ownership import case_lock
from forensia.db.database import CaseDB
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

    def detail(self, kind, item_id, *, limit):
        return [kind, item_id, limit]

    def command(self, command_id, operation, payload):
        return [command_id, operation, payload]

    def close(self):
        pass


def _serve_test_runtime(case_dir: str) -> None:
    lock = case_lock(case_dir).acquire()
    RuntimeServer(case_dir, _Engine(), lock).serve_forever()


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
        ]
        assert client.request(
            {"type": "command", "command_id": "c1", "operation": "stop"}
        ) == ["c1", "stop", {}]
        client.claim_control()
        other = RuntimeClient(case)
        with pytest.raises(RuntimeError, match="already has a Runtime owner"):
            other.claim_control()
        with pytest.raises(RuntimeError, match="Another TUI currently controls"):
            other.request({"type": "command", "command_id": "c2", "operation": "stop"})
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
            "policy_body": "# Objective\n\nDetermine whether approved maintenance occurred.",
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
    from forensia.core.control import InvestigationStopped
    from forensia.runtime.engine import RuntimeEngine

    case = Case.init(tmp_path / "case")
    with CaseDB(case):
        pass
    engine = RuntimeEngine(case.path)
    engine.prepare()
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
            first_investigation.set()
            try:
                assert engine.stop_requested.wait(3)
                raise InvestigationStopped
            finally:
                engine._active = False
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
