"""No-LLM smoke test for the investigate() entry point wiring.

Runs one full report_only cycle against an empty case. This exercises session
init (rule seeding, case profile, memory), the cycle body, termination, and
session bookkeeping WITHOUT any LLM call. The periodic report refresh is
skipped and the mandatory final refresh is mocked. A missing or renamed
argument in the investigate() wiring fails this test.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from unittest import mock

from forensia.core.case import Case
from forensia.db.database import CaseDB


class InvestigateWiringTests(unittest.TestCase):
    def tearDown(self) -> None:
        # investigate() sets the module-global case profile; reset it so later
        # tests cannot accidentally depend on this test's profile (order bugs).
        from forensia.ai.case_profile import set_case_profile

        set_case_profile(None, None)

    def test_report_only_cycle_completes_without_llm(self) -> None:
        from forensia.ai.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with mock.patch.object(
                    investigator_module,
                    "async_refresh_report_sections",
                    new=mock.AsyncMock(return_value={}),
                ) as refresh_sections:
                    result = asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://127.0.0.1:9",
                            model="dummy-model",
                            max_iter=1,
                            report_only=True,
                            report_every_n_cycles=2,
                        )
                    )
                refresh_sections.assert_awaited_once()
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["iteration"], 1)
                row = db.execute(
                    "SELECT status FROM investigation_sessions WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "completed")


class ReportRefreshFailureTests(unittest.TestCase):
    """R6-02: a dead report pipeline must be loud (Rule 12).

    Background: a TypeError inside the refresh path was collapsed into a
    one-line summary for 15 cycles across two sessions while the sessions
    finished 'completed'."""

    def test_run_report_phase_returns_failed_status_with_traceback(self) -> None:
        import io
        from contextlib import redirect_stdout
        from pathlib import Path
        from unittest import mock

        from forensia.ai.investigation import investigator as investigator_module
        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState

        async def _boom(**kwargs):
            raise TypeError("tuple indices must be integers or slices, not str")

        events: list[dict] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-1", iteration=1)
                buffer = io.StringIO()
                with mock.patch.object(
                    investigator_module, "async_refresh_report_sections", _boom
                ):
                    with redirect_stdout(buffer):
                        report_after, progress, refresh_status = asyncio.run(
                            investigator_module._run_report_phase(
                                case=case,
                                db=db,
                                session_id="S-1",
                                plan_cycle=1,
                                report_every_n_cycles=1,
                                template_root=Path(tmpdir),
                                base_url="http://127.0.0.1:1",
                                model="none",
                                llm_logger=None,
                                progress_callback=events.append,
                                focus_sections=[],
                                report_max_queries_per_section=1,
                                state=state,
                                report_before={"total_gaps": 0},
                                memory=MemoryManager(case),
                            )
                        )
        self.assertTrue(refresh_status.startswith("failed: TypeError"), refresh_status)
        self.assertFalse(progress)
        output = buffer.getvalue()
        self.assertIn(
            "Traceback", output, "full traceback must be printed, not just str(exc)"
        )
        self.assertTrue(
            any("TypeError" in str(e.get("summary")) for e in events),
            "progress event must carry the exception type",
        )

    def test_run_report_phase_skipped_off_cycle(self) -> None:
        from pathlib import Path

        from forensia.ai.investigation import investigator as investigator_module
        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-1", iteration=1)
                _, _, refresh_status = asyncio.run(
                    investigator_module._run_report_phase(
                        case=case,
                        db=db,
                        session_id="S-1",
                        plan_cycle=1,
                        report_every_n_cycles=3,
                        template_root=Path(tmpdir),
                        base_url="http://127.0.0.1:1",
                        model="none",
                        llm_logger=None,
                        progress_callback=None,
                        focus_sections=[],
                        report_max_queries_per_section=1,
                        state=state,
                        report_before={},
                        memory=MemoryManager(case),
                    )
                )
        self.assertEqual("skipped", refresh_status)

    def test_run_report_phase_propagates_exhausted_llm_outage(self) -> None:
        """An LLM-server outage is not a per-cycle failure: the phase waits for
        recovery (same policy as the investigation loop) and only an exhausted
        outage budget propagates and stops the session."""
        from pathlib import Path
        from unittest import mock

        from forensia.ai.investigation import investigation_session
        from forensia.ai.investigation import investigator as investigator_module
        from forensia.ai.llm.llm_client import LLMServerUnavailableError
        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState

        async def _outage(**kwargs):
            raise LLMServerUnavailableError("server gone")

        async def _instant_recovery_probe(base_url, model):
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-1", iteration=1)
                with (
                    mock.patch.object(
                        investigator_module, "async_refresh_report_sections", _outage
                    ),
                    mock.patch.object(
                        investigation_session,
                        "outage_wait_until_recovered",
                        _instant_recovery_probe,
                    ),
                ):
                    with self.assertRaises(LLMServerUnavailableError):
                        asyncio.run(
                            investigator_module._run_report_phase(
                                case=case,
                                db=db,
                                session_id="S-1",
                                plan_cycle=1,
                                report_every_n_cycles=1,
                                template_root=Path(tmpdir),
                                base_url="http://127.0.0.1:1",
                                model="none",
                                llm_logger=None,
                                progress_callback=None,
                                focus_sections=[],
                                report_max_queries_per_section=1,
                                state=state,
                                report_before={},
                                memory=MemoryManager(case),
                            )
                        )


if __name__ == "__main__":
    unittest.main()
