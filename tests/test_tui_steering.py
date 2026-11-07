"""The live client displays and submits directions through the Runtime contract."""

from __future__ import annotations

import asyncio

from forensia.config import Settings
from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.investigation import intervention
from forensia.runtime.engine import RuntimeEngine
from forensia.tui import CaseApp, _format_activity


def test_live_direction_is_recorded_applied_and_investigation_continues(
    tmp_path, monkeypatch
):
    case = Case.init(tmp_path / "case")
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO trace.investigation_sessions (session_id, status, started_at) VALUES ('investigation', 'running', now())"
        )
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status) VALUES ('H-current', 'Check the deletion flag', 'active')"
        )
        record_progress_event(
            db,
            progress_event(
                "hypothesis.investigation_started",
                "running",
                session_id="investigation",
                refs={"hypothesis_id": "H-current"},
                summary="Checking the deletion flag",
                stage="investigate",
            ),
        )
    engine = RuntimeEngine(case.path)
    engine.prepare()
    settings = Settings(llm_base_url="http://llm.invalid", llm_model="offline-test")
    engine._settings = settings
    engine._active = True
    engine._investigating = True
    resumed = []
    monkeypatch.setattr(engine, "_resume_settings", lambda: settings)
    monkeypatch.setattr(engine, "_investigate", lambda *a, **kw: resumed.append(kw))
    monkeypatch.setattr(
        intervention,
        "request_llm_json",
        lambda *a, **kw: {
            "action": "update_policy",
            "policy_updates": {"objective": "Prioritize the deletion timeline"},
        },
    )

    class Bridge:
        """Use real Runtime operations with an in-process transport for the UI test."""

        _controller = "test-controller"

        def claim_control(self):
            pass

        def release_control(self):
            pass

        def request(self, request):
            match request["type"]:
                case "snapshot":
                    return engine.snapshot()
                case "events":
                    return engine.events(
                        after_index=request["after_index"], limit=request["limit"]
                    )
                case "detail":
                    return engine.detail(
                        request["kind"], request["id"], limit=request["limit"]
                    )
                case "command":
                    return engine.command(
                        request["command_id"], request["operation"], request["payload"]
                    )
            raise AssertionError(request)

    bridge = Bridge()
    monkeypatch.setattr("forensia.tui.probe_runtime", lambda _: True)
    monkeypatch.setattr("forensia.tui.RuntimeClient", lambda _: bridge)
    instruction = (
        "Prioritize the deletion timeline [bold]without assuming intent[/bold]."
    )

    async def exercise():
        app = CaseApp(case)
        async with app.run_test(size=(120, 40)) as pilot:
            assert "Check the deletion flag" in app._current.content.plain
            assert "Autonomous investigation" in app._current.content.plain
            assert not app._prompt.disabled
            app._prompt.value = instruction
            await pilot.press("enter")
            (command_id,) = app._pending_commands
            receipt = engine.detail("command_receipt", command_id)
            assert receipt["status"] == "accepted"
            assert receipt["payload"]["text"] == instruction
            assert "waiting for a safe boundary" in app._current.content.plain
            accepted_event = next(
                e
                for e in app._events
                if (e.get("payload") or {}).get("command_status") == "accepted"
            )
            accepted_text = _format_activity(accepted_event).plain
            assert "You" in accepted_text and instruction in accepted_text
            assert "FORENSIA" in accepted_text

            # The investigation reaches its existing safe boundary; then the
            # real intervention owner applies the deterministic parsed policy.
            engine._active = False
            engine._investigating = False
            await asyncio.to_thread(engine._apply_command, command_id)
            await app._refresh()
            assert not app._pending_commands
            assert not app._prompt.disabled
            assert len(resumed) == 1 and resumed[0]["manual_resume"] is True
            receipt = engine.detail("command_receipt", command_id)
            assert receipt["status"] == "applied"
            rendered = "\n".join(_format_activity(e).plain for e in app._events)
            assert "Continuing autonomous investigation" in rendered
            assert any(
                (e.get("payload") or {}).get("command_status") == "applied"
                for e in app._events
            )
            await pilot.resize_terminal(64, 32)
            assert app._current.region.y < app._log.region.y
            assert app._prompt.region.bottom <= 32

    try:
        asyncio.run(exercise())
        with CaseDB(case, read_only=True) as db:
            assert (
                db.execute(
                    "SELECT objective FROM investigation_state WHERE state_id = 'case'"
                ).fetchone()[0]
                == "Prioritize the deletion timeline"
            )
    finally:
        engine.close()
