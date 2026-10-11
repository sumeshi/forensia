"""No-LLM smoke test for the investigate() entry point wiring.

Runs one full report_only cycle against an empty case. This exercises session
init (finding snapshot, case evidence summary, memory), the cycle body, termination, and
session bookkeeping WITHOUT any LLM call. The periodic report refresh is
skipped and the mandatory final refresh is mocked. A missing or renamed
argument in the investigate() wiring fails this test.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from unittest import mock

from forensia.core.case import Case
from forensia.db.database import CaseDB


class InvestigateWiringTests(unittest.TestCase):
    def test_settlement_receipt_failure_rolls_back_case_and_trace_together(
        self,
    ) -> None:
        from types import SimpleNamespace

        from forensia.db.investigation_state import ensure_investigation_state
        from forensia.investigation.hypotheses import hypothesis_runner
        from forensia.investigation.verification.settlement import SettlementDecision

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ensure_investigation_state(db, objective="preserve objective")
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, verdict, "
                    "verification_spec, updated_at) VALUES ('H-1', 'test', 'confirmed', "
                    "'confirmed', '{\"spec_version\":\"1\"}', now())"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file) "
                    "VALUES ('E-1', 'source')"
                )
                db.execute(
                    "INSERT INTO hypothesis_evidence "
                    "(link_id, hypothesis_id, evidence_id, role) "
                    "VALUES ('L-1', 'H-1', 'E-1', 'supporting')"
                )
                case_state_before = db.execute(
                    "SELECT status, objective FROM investigation_state WHERE state_id = 'case'"
                ).fetchone()

                original_save_step = hypothesis_runner._save_step

                def fail_act_receipt(**kwargs):
                    original_save_step(**kwargs)
                    if kwargs["phase"] == "act":
                        raise RuntimeError("simulate act receipt failure")

                rs = SimpleNamespace(
                    check_result=SimpleNamespace(
                        verdict="confirmed",
                        report_text="checked",
                        new_hypotheses=[],
                    ),
                    state=SimpleNamespace(
                        history=[], active_hypotheses=[], resolved_hypotheses=[]
                    ),
                    db=db,
                    session_id="S-1",
                    hypothesis=SimpleNamespace(
                        id="H-1",
                        verification_spec=SimpleNamespace(evidence_requirements=[]),
                    ),
                    planned_query=SimpleNamespace(query_id="Q-1"),
                    rows=[],
                    ctx=SimpleNamespace(progress_callback=None),
                    plan_cycle=1,
                    query_index=1,
                    emit_fn=None,
                )
                with (
                    mock.patch.object(hypothesis_runner, "_apply_sufficiency_guard"),
                    mock.patch.object(hypothesis_runner, "_build_settlement_input"),
                    mock.patch.object(
                        hypothesis_runner,
                        "settle_hypothesis",
                        return_value=SettlementDecision(
                            verdict="inconclusive",
                            reason="settlement blocked",
                            allowed=False,
                            gates_failed=["supporting evidence required"],
                        ),
                    ),
                    mock.patch.object(
                        hypothesis_runner, "_save_step", side_effect=fail_act_receipt
                    ),
                    self.assertRaisesRegex(RuntimeError, "act receipt failure"),
                ):
                    with db.transaction():
                        hypothesis_runner._phase_apply_verdict(rs)

            with CaseDB(case) as reopened:
                self.assertEqual(
                    ("confirmed", "confirmed"),
                    reopened.execute(
                        "SELECT status, verdict FROM hypotheses WHERE hypothesis_id = 'H-1'"
                    ).fetchone(),
                )
                self.assertEqual(
                    [("E-1",)],
                    reopened.execute(
                        "SELECT evidence_id FROM hypothesis_evidence WHERE link_id = 'L-1'"
                    ).fetchall(),
                )
                self.assertEqual(
                    case_state_before,
                    reopened.execute(
                        "SELECT status, objective FROM investigation_state WHERE state_id = 'case'"
                    ).fetchone(),
                )
                self.assertEqual(
                    (0, 0),
                    reopened.execute(
                        "SELECT "
                        "(SELECT COUNT(*) FROM trace.hypothesis_reasoning WHERE phase = 'settlement'), "
                        "(SELECT COUNT(*) FROM trace.investigation_steps WHERE phase = 'act')"
                    ).fetchone(),
                )

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
                    "INSERT INTO trace.investigation_sessions "
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
                    "status_reason FROM trace.investigation_sessions WHERE session_id = ?",
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
                                "SELECT status, finished_at FROM trace.investigation_sessions "
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

    def test_broad_plan_adopts_canonical_id_and_skips_unchanged_candidate_on_resume(
        self,
    ) -> None:
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_cycle

        draft = {
            "hypothesis": {
                "description": "Event 999 activity on the observed host requires investigation",
                "required_entities": ["computer"],
                "source_rule_ids": ["candidate-rule"],
                "confirm_when": {"co_observed_event_ids": [999]},
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, computer, "
                    "timestamp, target_user, event_id) VALUES "
                    "('evtx-candidate', 'source-a', 'host-a', '2026-01-01T00:00:00', "
                    "'user-a', 999)"
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, summary, "
                    "severity, confidence, status, evidence) VALUES "
                    "('F-candidate', 'candidate-rule', 'Observed event', 'Lead', "
                    "'high', 0.8, 'accepted', '[{\"evidence_id\":\"evtx-candidate\"}]')"
                )
                state = SessionState(session_id="S-candidate")
                request = mock.AsyncMock(return_value=draft)
                with mock.patch.object(
                    investigation_cycle.json_response, "request_llm_json", request
                ):
                    asyncio.run(
                        investigation_cycle._run_broad_plan_step(
                            state,
                            db,
                            "S-candidate",
                            "http://unused",
                            "dummy",
                            1,
                            [],
                            None,
                            lambda _message: None,
                        )
                    )
                    self.assertEqual(
                        [item.id for item in state.active_hypotheses], ["H-001"]
                    )
                    attempt = db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad-candidate'"
                    ).fetchone()[0]
                    self.assertEqual(
                        json.loads(attempt)["admitted_hypothesis_id"], "H-001"
                    )

                    calls_before_resume = request.await_count
                    asyncio.run(
                        investigation_cycle._run_broad_plan_step(
                            state,
                            db,
                            "S-candidate",
                            "http://unused",
                            "dummy",
                            2,
                            [],
                            None,
                            lambda _message: None,
                        )
                    )
                    self.assertEqual(request.await_count, calls_before_resume)
                    latest = db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad' ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()[0]
                    self.assertEqual(
                        json.loads(latest)["candidate_summary"]["already_linked_count"],
                        1,
                    )

    def test_broad_plan_bounds_invalid_drafts_and_does_not_complete_with_unresolved_candidate(
        self,
    ) -> None:
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_cycle

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, computer, "
                    "timestamp, target_user, event_id) VALUES "
                    "('evtx-bad', 'source-a', 'host-a', '2026-01-01T00:00:00', 'user-a', 999)"
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('F-bad', 'bad-rule', 'Observed event', 'accepted', "
                    '\'[{"evidence_id":"evtx-bad"}]\')'
                )
                state = SessionState(session_id="S-bad-candidate")
                request = mock.AsyncMock(
                    return_value={"hypothesis": {"description": ""}}
                )
                with mock.patch.object(
                    investigation_cycle.json_response, "request_llm_json", request
                ):
                    for iteration in (1, 2, 3):
                        stop = asyncio.run(
                            investigation_cycle._run_broad_plan_step(
                                state,
                                db,
                                "S-bad-candidate",
                                "http://unused",
                                "dummy",
                                iteration,
                                [],
                                None,
                                lambda _message: None,
                            )
                        )
                        self.assertFalse(stop)
                    self.assertEqual(request.await_count, 2)
                    outputs = [
                        json.loads(row[0])
                        for row in db.execute(
                            "SELECT output_json FROM trace.investigation_steps "
                            "WHERE phase = 'plan-broad' ORDER BY iteration"
                        ).fetchall()
                    ]
                    self.assertEqual(outputs[-1]["status"], "completed")
                    self.assertEqual(
                        outputs[-1]["candidate_summary"]["attempt_exhausted_count"], 1
                    )
                    self.assertEqual(
                        outputs[-1]["candidate_summary"]["candidate_count"], 1
                    )

    def test_no_finding_path_uses_and_replays_completed_gap_selection(self) -> None:
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_cycle
        from forensia.report.answers.keypoint_catalog import REPORT_KEYPOINTS

        keypoint = next(iter(REPORT_KEYPOINTS))
        calls: list[str] = []

        async def llm(**kwargs):
            phase = kwargs["telemetry_phase"]
            calls.append(phase)
            if phase == "plan-broad-gap":
                return {
                    "gap_areas": [
                        {"keypoint_id": keypoint, "why_uncovered": "observed"}
                    ]
                }
            return {"hypothesis": {"description": ""}}

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="S-gap-replay")
                observed = [{"keypoint": keypoint, "row_count": 1}]
                with mock.patch.object(
                    investigation_cycle.json_response, "request_llm_json", llm
                ):
                    for iteration in (1, 2):
                        stop = asyncio.run(
                            investigation_cycle._run_broad_plan_step(
                                state,
                                db,
                                "S-gap-replay",
                                "http://unused",
                                "dummy",
                                iteration,
                                observed,
                                None,
                                lambda _message: None,
                            )
                        )
                        self.assertFalse(stop)

                self.assertEqual(calls.count("plan-broad-gap"), 1)
                self.assertEqual(calls.count("plan-broad-draft"), 2)
                gap_attempts = db.execute(
                    "SELECT output_json FROM trace.investigation_steps "
                    "WHERE phase = 'plan-broad-gap-selection'"
                ).fetchall()
                self.assertEqual(len(gap_attempts), 1)
                self.assertEqual(json.loads(gap_attempts[0][0])["status"], "completed")

    def test_broad_plan_respects_last_active_slot_and_call_allowance(self) -> None:
        from types import SimpleNamespace

        from forensia.core.session import Hypothesis, SessionState
        from forensia.investigation import investigation_cycle

        draft = {
            "hypothesis": {
                "description": "Event 999 activity on the observed host requires investigation",
                "required_entities": ["computer"],
                "source_rule_ids": ["candidate-rule"],
                "confirm_when": {"co_observed_event_ids": [999]},
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index, username in enumerate(("user-a", "user-b")):
                    evidence_id = f"evtx-slot-{index}"
                    finding_id = f"F-slot-{index}"
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, source_file, computer, "
                        "timestamp, target_user, event_id) VALUES (?, 'source-a', "
                        "'host-a', '2026-01-01T00:00:00', ?, 999)",
                        [evidence_id, username],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                        "VALUES (?, 'candidate-rule', 'Observed event', 'accepted', ?)",
                        [finding_id, json.dumps([{"evidence_id": evidence_id}])],
                    )
                state = SessionState(
                    session_id="S-slot",
                    active_hypotheses=[
                        Hypothesis(
                            id=f"H-{index:03d}", description=f"Existing claim {index}"
                        )
                        for index in range(1, 8)
                    ],
                )
                request = mock.AsyncMock(return_value=draft)
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "get_active_telemetry",
                        return_value=SimpleNamespace(max_logical_calls=1),
                    ),
                    mock.patch.object(
                        investigation_cycle.json_response, "request_llm_json", request
                    ),
                ):
                    asyncio.run(
                        investigation_cycle._run_broad_plan_step(
                            state,
                            db,
                            "S-slot",
                            "http://unused",
                            "dummy",
                            1,
                            [],
                            None,
                            lambda _message: None,
                        )
                    )

                self.assertEqual(request.await_count, 1)
                self.assertEqual(len(state.active_hypotheses), 8)
                plan = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps WHERE phase = 'plan-broad'"
                    ).fetchone()[0]
                )
                self.assertEqual(
                    plan["candidate_summary"]["available_hypothesis_slots"], 1
                )
                self.assertEqual(
                    plan["candidate_summary"]["remaining_call_allowance"], 1
                )
                self.assertEqual(plan["candidate_summary"]["draft_selected_count"], 1)

    def test_candidate_retry_fingerprint_tracks_spec_and_observation_not_status(
        self,
    ) -> None:
        from forensia.core.session import Hypothesis, SessionState
        from forensia.investigation import investigation_cycle

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                hypothesis = Hypothesis(
                    id="H-001",
                    description="Linked work",
                    confirm_when={"co_observed_event_ids": [999]},
                )
                state = SessionState(
                    session_id="S-fingerprint", active_hypotheses=[hypothesis]
                )
                ctx = investigation_cycle._BroadPlanContext(
                    state=state,
                    db=db,
                    session_id="S-fingerprint",
                    base_url="http://unused",
                    model="dummy",
                    plan_cycle=1,
                    observed_keypoints=[],
                    observed_keypoint_labels=[],
                    emit_fn=None,
                    llm_status_fn=lambda _message: None,
                    progress_callback=None,
                    case_profile=None,
                )
                candidate = {
                    "candidate_ref": "cand-current",
                    "candidate_fingerprint": "cf-current",
                }
                prior = {
                    "cand-current": [
                        {
                            "status": "admitted",
                            "admitted_hypothesis_id": "H-001",
                        }
                    ]
                }
                original = investigation_cycle._candidate_input_fingerprint(
                    candidate, ctx, prior
                )
                state.active_hypotheses = []
                state.resolved_hypotheses = [
                    hypothesis.model_copy(
                        update={"status": "confirmed", "verdict": "confirmed"}
                    )
                ]
                status_only = investigation_cycle._candidate_input_fingerprint(
                    candidate, ctx, prior
                )
                self.assertEqual(original, status_only)
                state.active_hypotheses = [
                    Hypothesis(id="H-unrelated", description="Unrelated active work")
                ]
                unrelated = investigation_cycle._candidate_input_fingerprint(
                    candidate, ctx, prior
                )
                self.assertEqual(original, unrelated)

                changed = state.resolved_hypotheses[0].model_copy(
                    update={
                        "verification_spec": hypothesis.verification_spec.model_copy(
                            update={"refute_conditions": {"zero_rows": True}}
                        )
                    }
                )
                state.resolved_hypotheses = [changed]
                spec_changed = investigation_cycle._candidate_input_fingerprint(
                    candidate, ctx, prior
                )
                self.assertNotEqual(original, spec_changed)
                source_changed_candidate = {
                    **candidate,
                    "candidate_ref": "cand-revision-b",
                    "candidate_fingerprint": "cf-revision-b",
                }
                source_changed = investigation_cycle._candidate_input_fingerprint(
                    source_changed_candidate, ctx, prior
                )
                self.assertNotEqual(original, source_changed)

    def test_broad_plan_failure_replaces_running_receipt_with_terminal_failure(
        self,
    ) -> None:
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_cycle

        draft = {
            "hypothesis": {
                "description": "Event 999 activity on the observed host requires investigation",
                "required_entities": ["computer"],
                "source_rule_ids": ["fail-rule"],
                "confirm_when": {"co_observed_event_ids": [999]},
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, computer, "
                    "timestamp, target_user, event_id) VALUES "
                    "('evtx-fail', 'source-a', 'host-a', '2026-01-01T00:00:00', 'user-a', 999)"
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('F-fail', 'fail-rule', 'Observed event', 'accepted', "
                    '\'[{"evidence_id":"evtx-fail"}]\')'
                )
                with (
                    mock.patch.object(
                        investigation_cycle.json_response,
                        "request_llm_json",
                        new=mock.AsyncMock(return_value=draft),
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "qualify_event_contexts",
                        side_effect=RuntimeError("mock qualification failure"),
                    ),
                ):
                    stop = asyncio.run(
                        investigation_cycle._run_broad_plan_step(
                            SessionState(session_id="S-terminal-receipt"),
                            db,
                            "S-terminal-receipt",
                            "http://unused",
                            "dummy",
                            1,
                            [],
                            None,
                            lambda _message: None,
                        )
                    )
                self.assertFalse(stop)
                plan = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad'"
                    ).fetchone()[0]
                )
                self.assertEqual(plan["status"], "failed")
                self.assertNotEqual(plan["status"], "running")
                self.assertEqual(plan["terminal_error"]["error_type"], "RuntimeError")
                self.assertEqual(
                    plan["terminal_error"]["reason"], "mock qualification failure"
                )
                candidate_attempt = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad-candidate'"
                    ).fetchone()[0]
                )
                self.assertEqual(candidate_attempt["status"], "failed")
                self.assertEqual(
                    candidate_attempt["reason"], "mock qualification failure"
                )

    def test_planner_only_session_gets_explicit_terminal_reason(self) -> None:
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO trace.investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-1', 'session-planner', 'H-1', 1,
                              'plan-hypothesis', '{}', '{}', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO trace.hypothesis_reasoning (
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
                    INSERT INTO trace.investigation_steps (
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
                    INSERT INTO trace.investigation_steps (
                        step_id, session_id, hypothesis_id, iteration, phase,
                        input_json, output_json, created_at
                    ) VALUES ('S-executed', 'session-executed', 'H-1', 1,
                              'plan-hypothesis', '{}', '{}', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO trace.investigation_steps (
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
                    return_value=(state, {}),
                )
                broad_call = mock.AsyncMock(return_value=False)
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_call_with_outage_recovery",
                        new=broad_call,
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
                            progress_callback=None,
                            max_queries_per_hypothesis=1,
                            plan_cycle=1,
                            max_iter=1,
                            report_only=False,
                        )
                    )
                runner.assert_awaited_once()
                broad_call.assert_not_awaited()
                self.assertEqual(
                    hypothesis.id, runner.await_args.kwargs["hypothesis"].id
                )
                self.assertEqual(
                    [("H-BLOCKED", 0), ("H-WIRING", 1)],
                    db.execute(
                        "SELECT hypothesis_id, selection_count FROM hypotheses ORDER BY hypothesis_id"
                    ).fetchall(),
                )
                skipped_plan = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad'"
                    ).fetchone()[0]
                )
                self.assertEqual(skipped_plan["status"], "skipped")
                self.assertEqual(skipped_plan["reason"], "existing_runnable_work")

    def test_blocked_active_work_does_not_suppress_broad_planning(self) -> None:
        from forensia.core.session import Hypothesis, SessionState
        from forensia.investigation import investigation_cycle
        from forensia.investigation.investigation_session import Ctx

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            hypothesis = Hypothesis(
                id="H-BLOCKED-ONLY",
                description="Waiting for an unavailable prerequisite",
                status="active",
            )
            state = SessionState(
                session_id="S-BLOCKED-ONLY", active_hypotheses=[hypothesis]
            )
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "blocked_reason, verification_spec) VALUES (?, ?, 'active', "
                    "'prerequisite', '{\"spec_version\":\"1\"}')",
                    (hypothesis.id, hypothesis.description),
                )
                broad_call = mock.AsyncMock(return_value=False)
                runner = mock.create_autospec(
                    investigation_cycle._investigate_one_hypothesis,
                    return_value=(state, {}),
                )
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_call_with_outage_recovery",
                        new=broad_call,
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
                            session_id="S-BLOCKED-ONLY",
                            base_url="http://127.0.0.1:9",
                            model="none",
                            progress_callback=None,
                            max_queries_per_hypothesis=1,
                            plan_cycle=1,
                            max_iter=1,
                            report_only=False,
                        )
                    )

                broad_call.assert_awaited_once()
                runner.assert_not_awaited()

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
                    "SELECT status, phase, finished_at FROM trace.investigation_sessions"
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
                        "FROM trace.investigation_sessions ORDER BY started_at"
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

    def test_stop_classification_persists_terminal_tasks_in_case_db(self) -> None:
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
                investigator_module.classify_active_hypotheses_on_stop(
                    db,
                    [],
                    "no_progress_limit",
                )
                row = db.execute(
                    "SELECT kind, status, description FROM investigation_tasks"
                ).fetchone()

            self.assertEqual("untestable", row[0])
            self.assertEqual("open", row[1])
            self.assertIn("Acquire missing telemetry", row[2])


class ReportRefreshFailureTests(unittest.TestCase):
    """R6-02: a dead report pipeline must be loud (Rule 12).

    Background: a TypeError inside the refresh path was collapsed into a
    one-line summary for 15 cycles across two sessions while the sessions
    finished 'completed'."""

    def test_run_report_phase_returns_failed_status_with_traceback(self) -> None:
        import io
        from contextlib import redirect_stdout
        from unittest import mock

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
                                state=state,
                            )
                        )
        self.assertTrue(refresh_status.startswith("failed: TypeError"), refresh_status)
        self.assertIsNotNone(report_after)
        output = buffer.getvalue()
        self.assertIn(
            "Traceback", output, "full traceback must be printed, not just str(exc)"
        )
        self.assertTrue(
            any(
                event.get("kind") == "report.cycle"
                and event.get("reason") == "exception:TypeError"
                for event in events
            ),
            "progress event must carry a typed failure reason",
        )

    def test_run_report_phase_skipped_off_cycle(self) -> None:
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
                        state=state,
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
                    "INSERT INTO trace.investigation_sessions "
                    "(session_id, started_at, status, owner_id, heartbeat_at) "
                    "VALUES ('live', now(), 'running', 'worker-a', now())"
                )
                with self.assertRaisesRegex(RuntimeError, "already owns"):
                    reconcile_stale_sessions(db)
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM trace.investigation_sessions "
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
                    "INSERT INTO trace.investigation_sessions "
                    "(session_id, started_at, finished_at, status, terminal_reason) "
                    "VALUES ('old-done', '2020-01-02 03:04:05', '2020-01-02 03:05:05', "
                    "'completed', 'historical reason')"
                )
                self.assertEqual(reconcile_stale_sessions(db), 0)
                self.assertEqual(
                    db.execute(
                        "SELECT status, terminal_reason FROM trace.investigation_sessions "
                        "WHERE session_id = 'old-done'"
                    ).fetchone(),
                    ("completed", "historical reason"),
                )

    def test_run_report_phase_propagates_exhausted_llm_outage(self) -> None:
        """An LLM-server outage is not a per-cycle failure: the phase waits for
        recovery (same policy as the investigation loop) and only an exhausted
        outage budget propagates and stops the session."""
        from unittest import mock

        from forensia.core.session import SessionState
        from forensia.investigation import investigation_session
        from forensia.investigation import investigator as investigator_module
        from forensia.llm.llm_client import LLMServerUnavailableError

        async def _outage(**kwargs):
            raise LLMServerUnavailableError("server gone")

        async def _instant_recovery_probe(base_url, progress_callback=None):
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
                                state=state,
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
            evaluation_changed=False,
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
            evaluation_changed=False,
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
            evaluation_changed=False,
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
                    "SELECT status, status_reason, finished_at FROM trace.investigation_sessions "
                    "WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                assert row[0] == "stopped"
                assert "budget_exhausted" in row[1].lower()
                assert row[2] is not None


def test_report_gap_and_terminal_events_are_persisted_with_durable_refs() -> None:
    from forensia.investigation import investigation_cycle, investigator

    async def refresh(**_kwargs):
        return {
            "report_status": {},
            "gaps": ["Use external threat intel to assess indicator ownership"],
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            with (
                mock.patch.object(
                    investigation_cycle,
                    "_run_broad_plan_step",
                    new=mock.AsyncMock(return_value=False),
                ),
                mock.patch.object(
                    investigator,
                    "async_refresh_report_sections",
                    new=mock.AsyncMock(side_effect=refresh),
                ),
                mock.patch.object(investigator, "render_written_report"),
            ):
                result = asyncio.run(
                    investigator.investigate(
                        case=case,
                        db=db,
                        base_url="http://unused",
                        model="unused",
                        max_iter=1,
                        report_every_n_cycles=1,
                    )
                )

            rows = db.execute(
                "SELECT kind, status, reason, refs FROM trace.progress_events "
                "WHERE session_id = ? ORDER BY event_index",
                [result["session_id"]],
            ).fetchall()
            events = [
                (
                    kind,
                    status,
                    reason,
                    json.loads(refs) if isinstance(refs, str) else refs,
                )
                for kind, status, reason, refs in rows
            ]
            task_event = next(
                event for event in events if event[0] == "investigation.task_admitted"
            )
            gap_event = next(
                event for event in events if event[0] == "report_gap.admitted"
            )
            terminal_event = next(
                event for event in events if event[0] == "investigation.terminal"
            )
            gap_id = task_event[3]["gap_id"]
            task_id = task_event[3]["task_id"]
            assert gap_event[3]["gap_id"] == gap_id
            assert db.execute(
                "SELECT 1 FROM report_gaps WHERE gap_id = ?", [gap_id]
            ).fetchone()
            assert db.execute(
                "SELECT 1 FROM investigation_tasks WHERE task_id = ?", [task_id]
            ).fetchone()
            assert terminal_event[3]["session_id"] == result["session_id"]
            assert terminal_event[1] == result["status"]
            assert terminal_event[2]


def test_invalid_hypothesis_planner_emits_retry_event_and_retries_once() -> None:
    from types import SimpleNamespace

    from forensia.core.session import Hypothesis, SessionState
    from forensia.db.progress import record_progress_event
    from forensia.investigation import investigation_cycle, planner
    from forensia.investigation.investigation_session import Ctx

    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        hypothesis = Hypothesis(
            id="H-RETRY", description="inspect the observed event", status="active"
        )
        state = SessionState(
            session_id="S-PLANNER-RETRY", active_hypotheses=[hypothesis]
        )
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO hypotheses (hypothesis_id, description, status, "
                "blocked_reason, verification_spec) VALUES (?, ?, 'active', '', ?)",
                (hypothesis.id, hypothesis.description, '{"spec_version":"1"}'),
            )
            calls = 0

            def invalid_plan(*_args, **_kwargs):
                nonlocal calls
                calls += 1
                return planner._QueryIntentResult(
                    action=None,
                    raw_response={"action": {"type": "unsupported.action"}},
                    error="unsupported action type",
                )

            with (
                mock.patch(
                    "forensia.investigation.planner.request_query_intent",
                    side_effect=invalid_plan,
                ),
                mock.patch.object(
                    investigation_cycle,
                    "judge_work",
                    return_value={hypothesis.id: SimpleNamespace(runnable=True)},
                ),
                mock.patch.object(
                    investigation_cycle,
                    "_run_broad_plan_step",
                    new=mock.AsyncMock(return_value=False),
                ),
            ):
                asyncio.run(
                    investigation_cycle._run_cycle_body(
                        state=state,
                        ctx=Ctx(),
                        db=db,
                        case=case,
                        session_id=state.session_id,
                        base_url="http://unused",
                        model="offline",
                        progress_callback=lambda event: record_progress_event(
                            db, event
                        ),
                        max_queries_per_hypothesis=1,
                        plan_cycle=1,
                        max_iter=1,
                        report_only=False,
                    )
                )

            events = db.execute(
                "SELECT kind, status, reason, refs FROM trace.progress_events "
                "WHERE kind IN ('hypothesis.plan_rejected', 'hypothesis.plan_retry') "
                "ORDER BY event_index"
            ).fetchall()
            assert calls == 2, (
                f"one invalid response plus one bounded retry expected, got {calls}"
            )
            assert len(events) == 3, events
            rejected = [
                event for event in events if event[0] == "hypothesis.plan_rejected"
            ]
            retries = [event for event in events if event[0] == "hypothesis.plan_retry"]
            assert len(rejected) == 2, rejected
            assert len(retries) == 1, retries
            for event in events:
                refs = json.loads(event[3]) if isinstance(event[3], str) else event[3]
                assert refs["hypothesis_id"] == hypothesis.id
                assert db.execute(
                    "SELECT 1 FROM trace.investigation_steps WHERE step_id = ?",
                    [refs["step_id"]],
                ).fetchone()
            assert all(
                (event[1], event[2]) == ("failed", "planner_validation_failed")
                for event in rejected
            )
            assert all(
                (event[1], event[2]) == ("running", "planner_retry_granted")
                for event in retries
            )


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
