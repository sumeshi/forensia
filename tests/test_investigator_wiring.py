"""No-LLM smoke test for the investigate() entry point wiring.

Runs one full report_only cycle against an empty case. This exercises session
init (finding snapshot, case evidence summary, memory), the cycle body, termination, and
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
    def test_report_only_cycle_completes_without_llm(self) -> None:
        from forensia.investigation import investigation_session
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # R07 boundary: report-only must not claim Case completion for
                # an unresolved Case — durable gaps/tasks stay open and the
                # stop state keeps the value of the last real stop.
                from forensia.db.investigation_state import (
                    ensure_investigation_state,
                    save_stop_reason,
                )

                db.execute(
                    "INSERT INTO report_gaps (gap_id, description, status, origin) "
                    "VALUES ('GAP-SEL-1', 'unresolved gap', 'open', 'termination')"
                )
                db.execute(
                    "INSERT INTO investigation_tasks (task_id, description, status, "
                    "kind, retry_condition) VALUES ('TASK-SEL-1', 'unresolved task', "
                    "'open', 'blocked', 'required_capability_available')"
                )
                ensure_investigation_state(db, objective="preserve this objective")
                save_stop_reason(
                    db,
                    status="stopped",
                    stop_reason_code="no_progress_limit",
                    stop_reason="seeded prior stop",
                    stop_summary={"active": 1},
                )
                db.execute(
                    "INSERT INTO investigation_sessions "
                    "(session_id, started_at, finished_at, iterations, status, heartbeat_at) "
                    "VALUES ('old-running', '2020-01-02 03:04:05', NULL, 0, 'running', "
                    "'2020-01-02 03:04:05')"
                )
                with (
                    mock.patch.object(
                        investigator_module,
                        "async_refresh_report_sections",
                        new=mock.AsyncMock(return_value={}),
                    ) as refresh_sections,
                    mock.patch.object(
                        investigation_session, "_seed_rule_hypotheses"
                    ) as seed_rule_hypotheses,
                ):
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
                seed_rule_hypotheses.assert_not_called()
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["iteration"], 1)
                row = db.execute(
                    "SELECT status, finished_at, owner_id, heartbeat_at, phase, "
                    "status_reason FROM investigation_sessions WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "completed")
                self.assertIsNotNone(row[1])
                self.assertTrue(str(row[2]).startswith("worker-"))
                self.assertIsNotNone(row[3])
                self.assertEqual(row[4], "terminal")
                self.assertTrue(row[5])
                self.assertEqual(
                    ("abandoned", "2020-01-02 03:04:05"),
                    tuple(
                        map(
                            str,
                            db.execute(
                                "SELECT status, finished_at FROM investigation_sessions "
                                "WHERE session_id = 'old-running'"
                            ).fetchone(),
                        )
                    ),
                )
                # The Case stop state is not the report job's business: the
                # last real stop value is kept, open work is not reopened and
                # not classified.
                state_row = db.execute(
                    "SELECT status, stop_reason_code, objective FROM investigation_state "
                    "WHERE state_id = 'case'"
                ).fetchone()
                self.assertEqual(
                    ("stopped", "no_progress_limit", "preserve this objective"),
                    tuple(state_row),
                )
                self.assertEqual(
                    0,
                    db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0],
                )
                self.assertEqual(
                    1,
                    db.execute("SELECT COUNT(*) FROM report_gaps").fetchone()[0],
                )
                self.assertEqual(
                    ("open", "open"),
                    tuple(
                        db.execute(
                            "SELECT (SELECT status FROM report_gaps WHERE gap_id = "
                            "'GAP-SEL-1'), (SELECT status FROM investigation_tasks "
                            "WHERE task_id = 'TASK-SEL-1')"
                        ).fetchone()
                    ),
                )

    def test_planner_only_session_gets_explicit_terminal_reason(self) -> None:
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-1', 'session-planner', 'H-1', 1,
                              'plan-hypothesis', '{}', '{}', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase,
                        body, created_at
                    ) VALUES ('R-1', 'H-1', 'session-planner', 1, 'plan',
                              '[planner-validation] invalid_action: bad SQL', now())
                    """
                )
                self.assertEqual(
                    "planner_validation_failure",
                    investigator_module._planner_only_terminal_reason(
                        db, "session-planner"
                    ),
                )

    def test_terminal_reason_ignores_unrelated_or_executed_steps(self) -> None:
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-unrelated', 'session-unrelated', NULL, 1,
                              'plan-broad', '{}', '{}', now())
                    """
                )
                self.assertIsNone(
                    investigator_module._planner_only_terminal_reason(
                        db, "session-unrelated"
                    )
                )
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-executed', 'session-executed', 'H-1', 1,
                              'plan-hypothesis', '{}', '{}', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-do', 'session-executed', 'H-1', 1,
                              'do', '{}', '{}', now())
                    """
                )
                self.assertIsNone(
                    investigator_module._planner_only_terminal_reason(
                        db, "session-executed"
                    )
                )

    def test_cycle_executes_only_durably_eligible_hypotheses(self) -> None:
        """The cycle uses durable eligibility before calling the deep-dive runner."""

        from forensia.core.memory import MemoryManager
        from forensia.core.session import Hypothesis, SessionState
        from forensia.investigation import investigation_cycle
        from forensia.investigation.investigation_session import Ctx

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            hypothesis = Hypothesis(
                id="H-WIRING", description="exercise deep-dive wiring", status="active"
            )
            state = SessionState(session_id="S-WIRING", active_hypotheses=[hypothesis])
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "blocked_reason, verification_spec) VALUES "
                    "(?, ?, 'active', '', '{\"spec_version\": \"1\"}'), "
                    "('H-BLOCKED', 'Wait for prerequisite', 'active', "
                    "'prerequisite', '{\"spec_version\": \"1\"}')",
                    (hypothesis.id, hypothesis.description),
                )
                state.active_hypotheses.append(
                    Hypothesis(
                        id="H-BLOCKED",
                        description="Wait for prerequisite",
                        status="active",
                    )
                )
                runner = mock.create_autospec(
                    investigation_cycle._investigate_one_hypothesis,
                    return_value=(False, state, {}),
                )
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_call_with_outage_recovery",
                        new=mock.AsyncMock(return_value=False),
                    ),
                    mock.patch.object(
                        investigation_cycle, "ctx_refresh_caches", return_value=None
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "_investigate_one_hypothesis",
                        new=runner,
                    ),
                ):
                    asyncio.run(
                        investigation_cycle._run_cycle_body(
                            state=state,
                            ctx=Ctx(),
                            db=db,
                            case=case,
                            session_id="S-WIRING",
                            base_url="http://127.0.0.1:9",
                            model="none",
                            memory=MemoryManager(case),
                            progress_callback=None,
                            max_queries_per_hypothesis=1,
                            plan_cycle=1,
                            max_iter=1,
                            report_only=False,
                        )
                    )
                runner.assert_awaited_once()
                self.assertEqual(
                    hypothesis.id, runner.await_args.kwargs["hypothesis"].id
                )
                self.assertEqual(
                    [("H-BLOCKED", 0), ("H-WIRING", 1)],
                    db.execute(
                        "SELECT hypothesis_id, selection_count FROM hypotheses ORDER BY hypothesis_id"
                    ).fetchall(),
                )

    def test_selection_failure_persists_failed_session_without_execution(self) -> None:
        from forensia.investigation import investigation_cycle
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec) "
                    "VALUES ('H-1', 'Wait for prerequisite', 'active', "
                    '\'{"spec_version": "1"}\')'
                )
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_run_broad_plan_step",
                        new=mock.AsyncMock(return_value=False),
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "select_focus_hypotheses",
                        side_effect=RuntimeError("selection failed"),
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "_investigate_one_hypothesis",
                        new=mock.AsyncMock(),
                    ) as runner,
                    self.assertRaisesRegex(RuntimeError, "selection failed"),
                ):
                    asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://127.0.0.1:9",
                            model="none",
                            max_iter=1,
                            report_every_n_cycles=2,
                        )
                    )
                runner.assert_not_awaited()
                session = db.execute(
                    "SELECT status, phase, finished_at FROM investigation_sessions"
                ).fetchone()
                self.assertEqual(session[:2], ("failed", "terminal"))
                self.assertIsNotNone(session[2])
                self.assertEqual(
                    ("failed", "exception"),
                    db.execute(
                        "SELECT status, stop_reason_code FROM investigation_state WHERE state_id = 'case'"
                    ).fetchone(),
                )

                # Corruption encountered during initialization also closes the
                # acquired lease, before any model or execution work starts.
                db.execute(
                    "UPDATE hypotheses SET required_entities = ? WHERE hypothesis_id = 'H-1'",
                    ('"corrupt-list"',),
                )
                with self.assertRaisesRegex(ValueError, "required_entities"):
                    asyncio.run(
                        investigator_module.investigate(
                            case, db, base_url="http://127.0.0.1:9", model="none"
                        )
                    )
                self.assertEqual(
                    [("failed", "terminal", True), ("failed", "terminal", True)],
                    db.execute(
                        "SELECT status, phase, finished_at IS NOT NULL "
                        "FROM investigation_sessions ORDER BY started_at"
                    ).fetchall(),
                )

    def test_stopped_cycle_persists_state_before_final_refresh(self) -> None:
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                states_seen_by_refresh: list[str] = []

                async def _refresh(**kwargs):
                    row = (
                        kwargs["db"]
                        .execute(
                            "SELECT status FROM investigation_state WHERE state_id = 'case'"
                        )
                        .fetchone()
                    )
                    states_seen_by_refresh.append(str(row[0]))
                    return {}

                with (
                    mock.patch.object(
                        investigator_module,
                        "_run_investigation_loop",
                        new=mock.AsyncMock(
                            return_value=("stopped", 0, "no_progress_limit")
                        ),
                    ),
                    mock.patch.object(
                        investigator_module,
                        "async_refresh_report_sections",
                        side_effect=_refresh,
                    ) as refresh_sections,
                ):
                    result = asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://127.0.0.1:9",
                            model="dummy-model",
                            max_iter=1,
                            # The loop is mocked; report_only stays off so the
                            # under-test contract here is the state-before-
                            # refresh ordering of a real (non-report-only) stop.
                            report_only=False,
                            report_every_n_cycles=2,
                        )
                    )

                refresh_sections.assert_awaited_once()
                self.assertEqual(result["status"], "stopped")
                self.assertEqual(states_seen_by_refresh, ["stopped"])

    def test_stop_classification_projects_terminal_tasks_to_memory(self) -> None:
        from forensia.core.memory import MemoryManager
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses "
                    "(hypothesis_id, description, status, created_at, updated_at, "
                    "verification_spec) VALUES ('H-001', "
                    "'Acquire missing telemetry', 'untestable', now(), now(), "
                    '\'{"spec_version": "1"}\')'
                )
                investigator_module._classify_active_hypotheses_on_stop(
                    db,
                    [],
                    "no_progress_limit",
                    MemoryManager(case),
                )

            projected = (case.memory_dir / "tasks.md").read_text(encoding="utf-8")
            self.assertIn("[untestable] Acquire missing telemetry", projected)
            self.assertIn("TASK-STOP-", projected)


class ReportRefreshFailureTests(unittest.TestCase):
    """R6-02: a dead report pipeline must be loud (Rule 12).

    Background: a TypeError inside the refresh path was collapsed into a
    one-line summary for 15 cycles across two sessions while the sessions
    finished 'completed'."""

    def test_run_report_phase_returns_failed_status_with_traceback(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState
        from forensia.investigation import investigator as investigator_module

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
                        report_after, refresh_status = asyncio.run(
                            investigator_module._run_report_phase(
                                case=case,
                                db=db,
                                session_id="S-1",
                                plan_cycle=1,
                                report_every_n_cycles=1,
                                report_sections=[],
                                base_url="http://127.0.0.1:1",
                                model="none",
                                progress_callback=events.append,
                                focus_sections=[],
                                report_max_queries_per_section=1,
                                state=state,
                                memory=MemoryManager(case),
                            )
                        )
        self.assertTrue(refresh_status.startswith("failed: TypeError"), refresh_status)
        self.assertIsNotNone(report_after)
        output = buffer.getvalue()
        self.assertIn(
            "Traceback", output, "full traceback must be printed, not just str(exc)"
        )
        self.assertTrue(
            any("TypeError" in str(e.get("summary")) for e in events),
            "progress event must carry the exception type",
        )

    def test_run_report_phase_skipped_off_cycle(self) -> None:
        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-1", iteration=1)
                _, refresh_status = asyncio.run(
                    investigator_module._run_report_phase(
                        case=case,
                        db=db,
                        session_id="S-1",
                        plan_cycle=1,
                        report_every_n_cycles=3,
                        report_sections=[],
                        base_url="http://127.0.0.1:1",
                        model="none",
                        progress_callback=None,
                        focus_sections=[],
                        report_max_queries_per_section=1,
                        state=state,
                        memory=MemoryManager(case),
                    )
                )
        self.assertEqual("skipped", refresh_status)

    def test_live_session_lease_blocks_startup_reconciliation(self) -> None:
        from forensia.investigation.investigation_session import (
            reconcile_stale_sessions,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO investigation_sessions "
                    "(session_id, started_at, status, owner_id, heartbeat_at) "
                    "VALUES ('live', now(), 'running', 'worker-a', now())"
                )
                with self.assertRaisesRegex(RuntimeError, "already owns"):
                    reconcile_stale_sessions(db)
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM investigation_sessions "
                        "WHERE session_id = 'live'"
                    ).fetchone()[0],
                    "running",
                )

    def test_stale_session_reconcile_keeps_historical_terminal_reasons(self) -> None:
        """Crash recovery abandons only expired running leases; past terminal
        rows keep whatever reason they were written with (R07)."""
        from forensia.investigation.investigation_session import (
            reconcile_stale_sessions,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO investigation_sessions "
                    "(session_id, started_at, finished_at, status, terminal_reason) "
                    "VALUES ('old-done', '2020-01-02 03:04:05', '2020-01-02 03:05:05', "
                    "'completed', 'historical reason')"
                )
                self.assertEqual(reconcile_stale_sessions(db), 0)
                self.assertEqual(
                    db.execute(
                        "SELECT status, terminal_reason FROM investigation_sessions "
                        "WHERE session_id = 'old-done'"
                    ).fetchone(),
                    ("completed", "historical reason"),
                )

    def test_run_report_phase_propagates_exhausted_llm_outage(self) -> None:
        """An LLM-server outage is not a per-cycle failure: the phase waits for
        recovery (same policy as the investigation loop) and only an exhausted
        outage budget propagates and stops the session."""
        from unittest import mock

        from forensia.core.memory import MemoryManager
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_session
        from forensia.investigation import investigator as investigator_module
        from forensia.llm.llm_client import LLMServerUnavailableError

        async def _outage(**kwargs):
            raise LLMServerUnavailableError("server gone")

        async def _instant_recovery_probe(base_url, model, progress_callback=None):
            if progress_callback:
                progress_callback(
                    {
                        "stage": "waiting_for_llm",
                        "status": "running",
                        "summary": "LLM server unavailable",
                    }
                )
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-1", iteration=1)
                progress_events: list[dict] = []
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
                                report_sections=[],
                                base_url="http://127.0.0.1:1",
                                model="none",
                                progress_callback=progress_events.append,
                                focus_sections=[],
                                report_max_queries_per_section=1,
                                state=state,
                                memory=MemoryManager(case),
                            )
                        )
                    self.assertTrue(
                        any(
                            event.get("stage") == "waiting_for_llm"
                            for event in progress_events
                        )
                    )


class TerminationDurableWorkTests(unittest.TestCase):
    """T05: the completion gate reads durable Gap/Task rows, not report prose."""

    def test_open_durable_gap_blocks_completion(self) -> None:
        from forensia.investigation.investigator import _check_termination

        # B0 repro: prose total_gaps == 0 but one open termination-origin gap.
        status, no_progress_count, reason = _check_termination(
            report_only=False,
            broad_plan_stop=True,
            active_hypotheses=[],
            durable_open_gaps=1,
            durable_open_tasks=0,
            no_progress_count=0,
            no_progress_limit=3,
            cycle_progress=False,
        )
        self.assertIsNone(status)
        self.assertEqual(no_progress_count, 1)
        self.assertEqual(reason, "")

    def test_empty_durable_work_completes_with_no_gaps_no_hypotheses(self) -> None:
        from forensia.investigation.investigator import _check_termination

        status, no_progress_count, reason = _check_termination(
            report_only=False,
            broad_plan_stop=True,
            active_hypotheses=[],
            durable_open_gaps=0,
            durable_open_tasks=0,
            no_progress_count=0,
            no_progress_limit=3,
            cycle_progress=False,
        )
        self.assertEqual(
            (status, no_progress_count, reason),
            ("completed", 0, "no_gaps_no_hypotheses"),
        )

    def test_open_durable_task_blocks_completion(self) -> None:
        from forensia.investigation.investigator import _check_termination

        status, _, _ = _check_termination(
            report_only=False,
            broad_plan_stop=True,
            active_hypotheses=[],
            durable_open_gaps=0,
            durable_open_tasks=2,
            no_progress_count=0,
            no_progress_limit=3,
            cycle_progress=False,
        )
        self.assertIsNone(status)

    def test_durable_open_work_counts_read_authoritative_rows(self) -> None:
        from forensia.investigation.investigator import _durable_open_work_counts

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self.assertEqual(_durable_open_work_counts(db), (0, 0))
                db.execute(
                    "INSERT INTO report_gaps (gap_id, description, status, origin) "
                    "VALUES ('GAP-STOP-1', 't', 'open', 'termination')"
                )
                db.execute(
                    "INSERT INTO investigation_tasks (task_id, description, status) "
                    "VALUES ('TASK-STOP-1', 't', 'open')"
                )
                db.execute(
                    "INSERT INTO report_gaps (gap_id, description, status, origin) "
                    "VALUES ('GAP-old', 't', 'resolved', 'section')"
                )
                self.assertEqual(_durable_open_work_counts(db), (1, 1))

    def test_llm_budget_exhaustion_is_resumable_terminal_stop(self) -> None:
        from forensia.core.session import LLMBudgetExceededError
        from forensia.investigation import investigator as investigator_module

        async def exhausted(env):
            raise LLMBudgetExceededError(1, 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                mock.patch.object(
                    investigator_module, "_run_investigation_loop", exhausted
                ),
            ):
                result = asyncio.run(
                    investigator_module.investigate(
                        case=case,
                        db=db,
                        base_url="http://127.0.0.1:9",
                        model="none",
                        max_iter=1,
                        report_only=False,
                    )
                )
                assert result["status"] == "stopped"
                state_row = db.execute(
                    "SELECT status, stop_reason_code FROM investigation_state "
                    "WHERE state_id = 'case'"
                ).fetchone()
                assert state_row == ("stopped", "budget_exhausted")
                row = db.execute(
                    "SELECT status, status_reason, finished_at FROM investigation_sessions "
                    "WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                assert row[0] == "stopped"
                assert "budget_exhausted" in row[1].lower()
                assert row[2] is not None


class ProgressBudgetTests(unittest.TestCase):
    """R06: the no-progress budget is compared from evaluation snapshots at
    the loop's state-commit point — prose edits cannot extend it, source
    replacements still trigger re-evaluation."""

    @staticmethod
    def _run_loop(case, db, *, no_progress_limit, hook):
        from forensia.investigation import investigator as investigator_module
        from forensia.knowledge.coverage import refresh_evidence_coverage

        # The pipeline refreshes coverage during analysis before investigation
        # starts; direct investigator tests model that completed boundary.
        refresh_evidence_coverage(db)

        async def _refresh(**kwargs):
            db = kwargs["db"]
            db.execute(
                "INSERT INTO report_sections (section_key, title, body, gaps, "
                "confidence, status) VALUES ('1_overview', 'Overview', ?, '[]', "
                "0.0, 'draft') ON CONFLICT (section_key) DO UPDATE SET "
                "body = EXCLUDED.body",
                ["x" * hook(db)],
            )
            return {"report_status": {"current_section": None}, "gaps": []}

        with (
            mock.patch.object(
                investigator_module, "async_refresh_report_sections", _refresh
            ),
            mock.patch(
                "forensia.investigation.investigation_cycle._run_broad_plan_step",
                new=mock.AsyncMock(return_value=False),
            ),
            mock.patch(
                "forensia.investigation.investigation_cycle.select_focus_hypotheses",
                return_value=[],
            ),
        ):
            return asyncio.run(
                investigator_module.investigate(
                    case=case,
                    db=db,
                    base_url="http://127.0.0.1:9",
                    model="none",
                    max_iter=10,
                    no_progress_limit=no_progress_limit,
                    report_every_n_cycles=1,
                )
            )

    def test_report_prose_growth_does_not_refresh_no_progress_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            length = [10]

            def grow(db) -> int:
                length[0] *= 2
                return length[0]

            with CaseDB(case) as db:
                result = self._run_loop(case, db, no_progress_limit=2, hook=grow)
                self.assertEqual(result["status"], "stopped")
                # Body growth gave no extra cycles: the budget expired on plan.
                self.assertEqual(result["iteration"], 2)
                row = db.execute(
                    "SELECT stop_reason_code FROM investigation_state "
                    "WHERE state_id = 'case'"
                ).fetchone()
                self.assertEqual(row[0], "no_progress_limit")

    def test_same_count_source_replacement_triggers_re_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            calls = [0]

            def replace_source(db) -> int:
                calls[0] += 1
                if calls[0] == 2:
                    # Same source row count, different identity: the evaluation
                    # comparison must trigger re-evaluation, not miss it.
                    db.execute("DELETE FROM evidence_sources")
                    db.execute(
                        "INSERT INTO evidence_sources (source_id, artifact_family, "
                        "display_path, ingest_status, parser_name, row_count, "
                        "created_at, updated_at) VALUES ('src-replacement', "
                        "'evtx', '/evtx/backup.evtx', 'normalized', 'evtx', 5, "
                        "now(), now())"
                    )
                return 10

            with CaseDB(case) as db:
                result = self._run_loop(
                    case, db, no_progress_limit=2, hook=replace_source
                )
                # Without the replacement the budget would expire in cycle 2;
                # the identity change resets it and the loop runs two more.
                self.assertEqual(result["status"], "stopped")
                self.assertEqual(result["iteration"], 4)
                # 4 in-loop report phases + the closing full refresh.
                self.assertEqual(calls[0], 5)


if __name__ == "__main__":
    unittest.main()
