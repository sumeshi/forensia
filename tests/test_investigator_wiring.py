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

import pytest

from forensia.core.case import Case
from forensia.db.database import CaseDB


class InvestigateWiringTests(unittest.TestCase):
    def test_gap_discovery_retries_invalid_sql_once_then_stops_at_budget(self) -> None:
        from forensia.core.session import SessionState
        from forensia.investigation import investigation_cycle

        with tempfile.TemporaryDirectory() as tmpdir, CaseDB(Case.init(tmpdir)) as db:
            db.execute(
                "INSERT INTO prefetch_executions "
                "(evidence_id, executable_name, last_exec_time) VALUES "
                "('prefetch-gap-retry', 'VEGA.EXE', '2032-08-17 10:00:00')"
            )
            session_id = "S-gap-retry"
            ctx = investigation_cycle._BroadPlanContext(
                state=SessionState(session_id=session_id),
                db=db,
                session_id=session_id,
                base_url="unused",
                model="unused",
                plan_cycle=1,
                observed_keypoints=[],
                observed_keypoint_labels=[],
                emit_fn=None,
                llm_status_fn=lambda _: None,
                progress_callback=None,
                case_profile=None,
            )
            candidate = {
                "candidate_ref": "gap-candidate",
                "candidate_fingerprint": "candidate-fingerprint",
                "title": "Find requested records",
                "scope": {},
            }
            selected = {
                "candidate": candidate,
                "gap": {
                    "gap_id": "gap-retry",
                    "block_heading": "Question",
                    "description": "Find requested records",
                },
                "input_fingerprint": "input-fingerprint",
                "attempt_number": 1,
                "prior_attempts": {},
            }
            invalid_sql = (
                "SELECT evidence_id, last_exec_time FROM prefetch_executions "
                "WHERE last_exec_time BETWEEN '09:00:00' AND '18:00:00'"
            )
            corrected_sql = (
                "SELECT evidence_id, last_exec_time FROM prefetch_executions "
                "WHERE CAST(last_exec_time AS TIME) BETWEEN "
                "TIME '09:00:00' AND TIME '18:00:00'"
            )

            with (
                mock.patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=[
                        {
                            "request_contract": {
                                "status": "resolved",
                                "scope_filters": [],
                                "requirements": [
                                    {
                                        "family": "prefetch",
                                        "field": "last_exec_time",
                                        "kind": "observed_value",
                                    }
                                ],
                            },
                            "action": {
                                "intent": "Find records",
                                "target_table": "prefetch_executions",
                                "sql": invalid_sql,
                            },
                        },
                        {
                            "action": {
                                "intent": "Find records",
                                "target_table": "prefetch_executions",
                                "sql": corrected_sql,
                            },
                        },
                    ],
                ) as request,
                mock.patch.object(
                    investigation_cycle,
                    "_call_broad_drafter",
                    new=mock.AsyncMock(return_value=(None, "invalid draft")),
                ),
            ):
                asyncio.run(
                    investigation_cycle._draft_and_admit_candidate(ctx, selected, 1)
                )

            self.assertEqual(2, request.call_count)
            self.assertIn(
                "Conversion", str(request.call_args_list[1].kwargs["messages"])
            )
            receipts = db.execute(
                "SELECT phase, output_json FROM trace.investigation_steps "
                "ORDER BY created_at, step_id"
            ).fetchall()
            receipts = [row[1] for row in receipts if row[0] == "plan-gap-discovery"]
            discovery = [json.loads(row) for row in receipts]
            by_status = {item["status"]: item for item in discovery}
            self.assertEqual({"invalid", "completed"}, set(by_status), receipts)
            self.assertIn("09:00:00", by_status["invalid"]["sql"])
            self.assertIn("09:00:00", by_status["completed"]["sql"])

            exhausted = {
                **selected,
                "candidate": {**candidate, "candidate_ref": "gap-exhausted"},
                "gap": {**selected["gap"], "gap_id": "gap-exhausted"},
                "prior_attempts": {
                    "gap-exhausted": [
                        {
                            "candidate_fingerprint": "candidate-fingerprint",
                            "input_fingerprint": "input-fingerprint",
                            "correction_calls_used": 1,
                            "draft_calls_used": 0,
                        }
                    ]
                },
            }
            with (
                mock.patch(
                    "forensia.llm.json_response.request_llm_json",
                    return_value={
                        "action": {
                            "intent": "Find records",
                            "target_table": "prefetch_executions",
                            "sql": invalid_sql,
                        }
                    },
                ) as request,
                mock.patch.object(
                    investigation_cycle,
                    "_call_broad_drafter",
                    new=mock.AsyncMock(),
                ) as draft,
            ):
                asyncio.run(
                    investigation_cycle._draft_and_admit_candidate(ctx, exhausted, 2)
                )
            request.assert_called_once()
            draft.assert_not_awaited()

    def test_explicit_questions_exist_before_first_investigation_cycle(self) -> None:
        from pathlib import Path

        from forensia.investigation import investigator

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            spec = Path(tmpdir) / "questions.md"
            spec.write_text(
                "# Inventory\n\nKeep every source reference.\n\n"
                "## Label\n<!-- question: What label is configured? -->\n"
                "<!-- answer_id: configured-label -->\n"
            )
            with CaseDB(case) as db:

                async def first_cycle(env):
                    rows = db.execute(
                        "SELECT description, status, coverage_reason, hypothesis_id FROM report_gaps WHERE block_heading = 'Label'"
                    ).fetchall()
                    self.assertEqual(1, len(rows))
                    self.assertIn("What label is configured?", rows[0][0])
                    self.assertIn("Keep every source reference.", rows[0][0])
                    self.assertEqual(("open", "discovery_pending", None), rows[0][1:])
                    return "stopped", 0, "max_iterations"

                with (
                    mock.patch.object(
                        investigator, "_run_investigation_loop", side_effect=first_cycle
                    ),
                    mock.patch(
                        "forensia.llm.json_response.request_llm_json",
                        side_effect=AssertionError("No model needed"),
                    ),
                ):
                    asyncio.run(
                        investigator.investigate(
                            case=case,
                            db=db,
                            base_url="unused",
                            model="unused",
                            max_iter=1,
                            report_spec=spec,
                        )
                    )
                answer = json.loads(
                    (case.reports_dir / "structured/configured-label.json").read_text()
                )
                self.assertEqual("insufficient_evidence", answer["status"])
                self.assertEqual(["discovery_pending"], answer["missing_reason"])

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

                async def fail_final_refresh(**kwargs):
                    self.assertIsNone(kwargs["iteration"])
                    receipt = db.execute(
                        "SELECT status, finished_at, terminal_reason "
                        "FROM trace.investigation_sessions WHERE session_id = ?",
                        (kwargs["session_id"],),
                    ).fetchone()
                    self.assertEqual(receipt[0], "completed")
                    self.assertIsNotNone(receipt[1])
                    self.assertTrue(receipt[2])
                    raise RuntimeError("simulated final report failure")

                with (
                    mock.patch.object(
                        investigator_module,
                        "async_refresh_report_sections",
                        new=mock.AsyncMock(side_effect=fail_final_refresh),
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
                self.assertEqual(result["report_refresh_failures"], 1)
                self.assertEqual(result["iteration"], 1)
                row = db.execute(
                    "SELECT status, finished_at, owner_id, heartbeat_at, phase, "
                    "status_reason, terminal_reason FROM trace.investigation_sessions "
                    "WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "completed")
                self.assertIsNotNone(row[1])
                self.assertTrue(str(row[2]).startswith("worker-"))
                self.assertIsNotNone(row[3])
                self.assertEqual(row[4], "terminal")
                self.assertTrue(row[5])
                self.assertTrue(row[6])
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
                        return_value=SimpleNamespace(
                            max_logical_calls=1,
                            begin_logical_call=lambda **_kwargs: "logical-slot",
                            close_logical_call=lambda **_kwargs: None,
                        ),
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
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, verification_spec) VALUES (?, ?, 'active', ?)",
                    [
                        hypothesis.id,
                        hypothesis.description,
                        hypothesis.verification_spec.model_dump_json(),
                    ],
                )

                def fingerprint(candidate):
                    linked_work = investigation_cycle._candidate_linked_work(
                        candidate, db, prior
                    )
                    return investigation_cycle._candidate_input_fingerprint(
                        candidate, ctx, linked_work
                    )

                original = fingerprint(candidate)
                state.active_hypotheses = []
                state.resolved_hypotheses = [
                    hypothesis.model_copy(
                        update={"status": "confirmed", "verdict": "confirmed"}
                    )
                ]
                status_only = fingerprint(candidate)
                self.assertEqual(original, status_only)
                state.active_hypotheses = [
                    Hypothesis(id="H-unrelated", description="Unrelated active work")
                ]
                unrelated = fingerprint(candidate)
                self.assertEqual(original, unrelated)
                state.resolved_hypotheses = []
                self.assertEqual(
                    original,
                    fingerprint(candidate),
                )

                changed = hypothesis.model_copy(
                    update={
                        "verification_spec": hypothesis.verification_spec.model_copy(
                            update={"refute_conditions": {"zero_rows": True}}
                        )
                    }
                )
                state.resolved_hypotheses = [changed]
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ? WHERE hypothesis_id = ?",
                    [changed.verification_spec.model_dump_json(), hypothesis.id],
                )
                spec_changed = fingerprint(candidate)
                self.assertNotEqual(original, spec_changed)
                source_changed_candidate = {
                    **candidate,
                    "candidate_ref": "cand-revision-b",
                    "candidate_fingerprint": "cf-revision-b",
                }
                source_changed = fingerprint(source_changed_candidate)
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

    def test_generated_output_failure_stays_local_to_broad_gap_identification(
        self,
    ) -> None:
        from forensia.investigation import investigation_cycle
        from forensia.investigation import investigator as investigator_module
        from forensia.llm.llm_client import LLMStructuredOutputError

        error = LLMStructuredOutputError(
            status_code=500,
            error_code="generated_output_parse_failed",
            body="Failed to parse input: generated markdown analysis",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_identify_broad_plan_gaps",
                        new=mock.AsyncMock(side_effect=error),
                    ),
                    mock.patch.object(
                        investigator_module,
                        "async_refresh_report_sections",
                        new=mock.AsyncMock(
                            return_value={
                                "report_status": {},
                                "gaps": [],
                                "question_requests": [],
                            }
                        ),
                    ),
                ):
                    asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://unused",
                            model="dummy",
                            max_iter=1,
                        )
                    )

                plan = json.loads(
                    db.execute(
                        "SELECT output_json FROM trace.investigation_steps "
                        "WHERE phase = 'plan-broad'"
                    ).fetchone()[0]
                )
                self.assertEqual("completed", plan["status"])
                self.assertIn(
                    "generated_output_parse_failed",
                    plan["candidate_summary"]["gap_identification_error"],
                )
                session = db.execute(
                    "SELECT status, terminal_reason, finished_at "
                    "FROM trace.investigation_sessions"
                ).fetchone()
                self.assertNotEqual("failed", session[0])
                self.assertIsNotNone(session[2])

    def test_generated_output_failure_pauses_one_hypothesis_and_runs_the_next(
        self,
    ) -> None:
        from forensia.llm.llm_client import LLMStructuredOutputError

        self._assert_provider_failure_pauses_one_hypothesis_and_runs_the_next(
            LLMStructuredOutputError(
                status_code=500,
                error_code="generated_output_parse_failed",
                body="Failed to parse input: generated prose before JSON",
            )
        )

    def test_response_timeout_pauses_one_hypothesis_and_runs_the_next(self) -> None:
        from forensia.llm.llm_client import LLMRequestTimeoutError

        self._assert_provider_failure_pauses_one_hypothesis_and_runs_the_next(
            LLMRequestTimeoutError("Repeated response deadline")
        )

    def _assert_provider_failure_pauses_one_hypothesis_and_runs_the_next(self, error):
        from forensia.db.investigation_state import ensure_investigation_state
        from forensia.investigation import investigator as investigator_module
        from forensia.investigation.hypotheses import hypothesis_runner
        from forensia.investigation.planner import HypothesisPlanResult

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ensure_investigation_state(db, objective="keep independent work moving")
                for hypothesis_id in ("H-FAIL", "H-NEXT"):
                    db.execute(
                        "INSERT INTO hypotheses "
                        "(hypothesis_id, description, status, verification_spec) "
                        "VALUES (?, ?, 'active', ?)",
                        [
                            hypothesis_id,
                            f"Independent investigation {hypothesis_id}",
                            '{"spec_version":"1"}',
                        ],
                    )
                planned: list[str] = []

                def plan(**kwargs):
                    hypothesis_id = kwargs["hypothesis"].id
                    planned.append(hypothesis_id)
                    if hypothesis_id == "H-FAIL":
                        raise error
                    return HypothesisPlanResult(
                        query=None,
                        stop_reason="independent proposal ended",
                        raw_response={},
                    )

                with (
                    mock.patch.object(
                        hypothesis_runner, "plan_hypothesis_query", side_effect=plan
                    ),
                    mock.patch.object(
                        investigator_module,
                        "async_refresh_report_sections",
                        new=mock.AsyncMock(
                            return_value={
                                "report_status": {},
                                "gaps": [],
                                "question_requests": [],
                            }
                        ),
                    ),
                ):
                    asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://unused",
                            model="dummy",
                            max_iter=1,
                            max_queries_per_hypothesis=1,
                        )
                    )

                self.assertEqual({"H-FAIL", "H-NEXT"}, set(planned))
                blocked_reason = db.execute(
                    "SELECT blocked_reason FROM hypotheses "
                    "WHERE hypothesis_id = 'H-FAIL'"
                ).fetchone()[0]
                self.assertEqual(error.error_code, blocked_reason)
                error_trace = db.execute(
                    "SELECT body FROM trace.hypothesis_reasoning "
                    "WHERE hypothesis_id = 'H-FAIL' AND phase = 'error'"
                ).fetchone()[0]
                self.assertIn(str(error), error_trace)
                from forensia.investigation.working_state import (
                    build_working_state,
                    render_working_state,
                )

                prompt_context = render_working_state(
                    build_working_state(db, hypothesis_id="H-FAIL")
                )
                self.assertNotIn("Failed to parse input:", prompt_context)
                self.assertNotIn("generated prose before JSON", prompt_context)
                self.assertTrue(
                    db.execute(
                        "SELECT COUNT(*) FROM trace.hypothesis_reasoning "
                        "WHERE hypothesis_id = 'H-FAIL' "
                        "AND body LIKE ?",
                        [f"%{error.error_code}%"],
                    ).fetchone()[0]
                )
                session = db.execute(
                    "SELECT status, terminal_reason, finished_at "
                    "FROM trace.investigation_sessions"
                ).fetchone()
                self.assertNotEqual("failed", session[0])
                self.assertIsNotNone(session[2])

    def test_schema_rejection_remains_fatal_to_investigation(self) -> None:
        from forensia.investigation import investigation_cycle
        from forensia.investigation import investigator as investigator_module
        from forensia.llm.llm_client import LLMStructuredOutputError

        error = LLMStructuredOutputError(
            status_code=500,
            error_code="response_schema_rejected",
            body="JSON schema conversion failed",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_identify_broad_plan_gaps",
                        new=mock.AsyncMock(side_effect=error),
                    ),
                    self.assertRaises(LLMStructuredOutputError),
                ):
                    asyncio.run(
                        investigator_module.investigate(
                            case=case,
                            db=db,
                            base_url="http://unused",
                            model="dummy",
                            max_iter=1,
                        )
                    )
                session = db.execute(
                    "SELECT status, terminal_reason, finished_at "
                    "FROM trace.investigation_sessions"
                ).fetchone()
                self.assertEqual("failed", session[0])
                self.assertIn("response_schema_rejected", session[1])
                self.assertIsNotNone(session[2])

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
                              'session-settings', '{}', '{}', now())
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

    def test_broad_only_candidate_stops_get_explicit_planner_reasons(self) -> None:
        from forensia.investigation import investigator as investigator_module

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                    "VALUES ('S-candidate-open', 'candidate-open', 1, 'plan-broad', "
                    "'{}', '{\"candidate_summary\":{\"unexamined_candidate_count\":1}}', now())"
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                    "VALUES ('S-candidate-repair', 'candidate-open', 1, 'plan-broad-candidate', "
                    '\'{"candidate_ref":"C-1"}\', '
                    '\'{"status":"feasibility_rejected","correction_calls_used":1}\', now())'
                )
                self.assertEqual(
                    "proposal_repair_pending",
                    investigator_module._planner_only_terminal_reason(
                        db, "candidate-open"
                    ),
                )

                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                    "VALUES ('S-candidate-rejected', 'candidate-rejected', 1, 'plan-broad', "
                    "'{}', '{\"candidate_summary\":{\"unexamined_candidate_count\":0}}', now())"
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                    "VALUES ('S-candidate-failure', 'candidate-rejected', 1, 'plan-broad-candidate', "
                    '\'{"candidate_ref":"C-2"}\', '
                    '\'{"status":"admission_rejected","correction_calls_used":0}\', now())'
                )
                self.assertEqual(
                    "planner_no_executable_action",
                    investigator_module._planner_only_terminal_reason(
                        db, "candidate-rejected"
                    ),
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

    def test_stalled_hypothesis_yields_to_new_work_within_cycle_budget(self) -> None:
        from forensia.core.session import Hypothesis, SessionState
        from forensia.investigation import investigation_cycle
        from forensia.investigation.investigation_session import Ctx

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            stalled = Hypothesis(
                id="H-STALL", description="repeat the same query", status="active"
            )
            state = SessionState(session_id="S-SWITCH", active_hypotheses=[stalled])
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec) VALUES ('H-STALL', ?, 'active', ?)",
                    [stalled.description, '{"spec_version":"1"}'],
                )
                broad_calls: list[int] = []

                async def broad_plan(**kwargs):
                    broad_calls.append(kwargs["plan_cycle"])
                    next_hypothesis = Hypothesis(
                        id="H-NEW", description="new candidate", status="active"
                    )
                    db.execute(
                        "INSERT INTO hypotheses (hypothesis_id, description, status, "
                        "verification_spec) VALUES ('H-NEW', ?, 'active', ?)",
                        [next_hypothesis.description, '{"spec_version":"1"}'],
                    )
                    state.active_hypotheses.append(next_hypothesis)
                    return False

                async def runner(**kwargs):
                    hypothesis = kwargs["hypothesis"]
                    if hypothesis.id == "H-NEW":
                        db.execute(
                            "INSERT INTO hypothesis_evidence "
                            "(link_id, hypothesis_id, evidence_id, assessment_id, role) "
                            "VALUES ('L-NEW', 'H-NEW', 'E-NEW', 'A-NEW', 'supporting')"
                        )
                    return kwargs["state"], {}

                async def passthrough(call_fn, **kwargs):
                    return await call_fn(**kwargs)

                with (
                    mock.patch.object(
                        investigation_cycle,
                        "_run_broad_plan_step",
                        new=mock.AsyncMock(side_effect=broad_plan),
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "_call_with_outage_recovery",
                        new=passthrough,
                    ),
                    mock.patch.object(
                        investigation_cycle,
                        "_investigate_one_hypothesis",
                        new=mock.AsyncMock(side_effect=runner),
                    ) as run_hypothesis,
                ):
                    for plan_cycle in (1, 2):
                        if plan_cycle == 2:
                            for index in range(7):
                                blocked = Hypothesis(
                                    id=f"H-NOCATALOG-{index}",
                                    description="Unmapped capability requires review",
                                )
                                db.execute(
                                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                                    "verification_spec) VALUES (?, ?, 'active', ?)",
                                    [
                                        blocked.id,
                                        blocked.description,
                                        '{"spec_version":"1","required_capabilities":["unmapped"]}',
                                    ],
                                )
                                state.active_hypotheses.append(blocked)
                            self.assertEqual(8, len(state.active_hypotheses))
                        asyncio.run(
                            investigation_cycle._run_cycle_body(
                                state=state,
                                ctx=Ctx(),
                                db=db,
                                case=case,
                                session_id="S-SWITCH",
                                base_url="http://127.0.0.1:9",
                                model="none",
                                progress_callback=None,
                                max_queries_per_hypothesis=1,
                                plan_cycle=plan_cycle,
                                max_iter=2,
                                report_only=False,
                            )
                        )

                self.assertEqual([2], broad_calls)
                self.assertEqual(
                    8,
                    db.execute(
                        "SELECT COUNT(*) FROM investigation_tasks WHERE status = 'open'"
                    ).fetchone()[0],
                )
                self.assertNotIn(stalled, state.active_hypotheses)
                self.assertEqual(
                    ["H-STALL", "H-NEW"],
                    [
                        call.kwargs["hypothesis"].id
                        for call in run_hypothesis.await_args_list
                    ],
                )
                self.assertEqual(
                    [
                        ("H-NEW", "true"),
                        ("H-STALL", "false"),
                    ],
                    db.execute(
                        "SELECT hypothesis_id, json_extract(output_json, '$.progressed') "
                        "FROM trace.investigation_steps WHERE phase = 'work-progress' "
                        "ORDER BY hypothesis_id"
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

    def test_interrupted_and_budget_stops_classify_active_work(self) -> None:
        from forensia.investigation import investigator as investigator_module

        for reason in ("interrupted", "budget_exhausted"):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as tmpdir:
                case = Case.init(tmpdir)
                with CaseDB(case) as db:
                    db.execute(
                        "INSERT INTO hypotheses (hypothesis_id, description, status, "
                        "verification_spec) VALUES ('H-INTERRUPTED', "
                        "'Inspect the unreviewed evidence', 'active', "
                        '\'{"spec_version":"1"}\')'
                    )
                    states_seen_by_refresh: list[tuple] = []

                    async def _refresh(**kwargs):
                        refresh_db = kwargs["db"]
                        state_status = refresh_db.execute(
                            "SELECT status FROM investigation_state WHERE state_id = 'case'"
                        ).fetchone()[0]
                        hypothesis_status = refresh_db.execute(
                            "SELECT status FROM hypotheses "
                            "WHERE hypothesis_id = 'H-INTERRUPTED'"
                        ).fetchone()[0]
                        task = refresh_db.execute(
                            "SELECT status, retry_condition FROM investigation_tasks "
                            "WHERE hypothesis_id = 'H-INTERRUPTED'"
                        ).fetchone()
                        receipt = refresh_db.execute(
                            "SELECT status, phase, finished_at IS NOT NULL "
                            "FROM trace.investigation_sessions"
                        ).fetchone()
                        states_seen_by_refresh.append(
                            (
                                state_status,
                                hypothesis_status,
                                task,
                                receipt,
                                kwargs["allow_narration"],
                            )
                        )
                        return {}

                    async def _stop_after_execution(_env):
                        session_id = db.execute(
                            "SELECT session_id FROM trace.investigation_sessions "
                            "ORDER BY started_at DESC LIMIT 1"
                        ).fetchone()[0]
                        db.execute(
                            "INSERT INTO trace.investigation_steps "
                            "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                            "VALUES ('plan-old', ?, 1, 'plan-broad', '{}', ?, now()), "
                            "('plan-last', ?, 2, 'plan-broad', '{}', ?, now()), "
                            "('draft-old', ?, 1, 'plan-broad-candidate', ?, '{}', now()), "
                            "('draft-a', ?, 2, 'plan-broad-candidate', ?, '{}', now()), "
                            "('draft-a-retry', ?, 2, 'plan-broad-candidate', ?, '{}', now()), "
                            "('draft-b', ?, 2, 'plan-broad-candidate', ?, '{}', now()), "
                            "('executed', ?, 2, 'do', '{}', '{}', now())",
                            [
                                session_id,
                                json.dumps(
                                    {
                                        "status": "completed",
                                        "candidate_summary": {"candidate_count": 3},
                                    }
                                ),
                                session_id,
                                json.dumps(
                                    {
                                        "status": "completed",
                                        "candidate_summary": {
                                            "candidate_count": 2,
                                            "unexamined_candidate_count": 0,
                                        },
                                    }
                                ),
                                session_id,
                                json.dumps({"candidate_ref": "C-old"}),
                                session_id,
                                json.dumps({"candidate_ref": "C-a"}),
                                session_id,
                                json.dumps({"candidate_ref": "C-a"}),
                                session_id,
                                json.dumps({"candidate_ref": "C-b"}),
                                session_id,
                            ],
                        )
                        return "stopped", 0, reason

                    with (
                        mock.patch.object(
                            investigator_module,
                            "_run_investigation_loop",
                            new=mock.AsyncMock(side_effect=_stop_after_execution),
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
                                # The loop is mocked; verify terminal work
                                # classification and receipt ordering.
                                report_only=False,
                                report_every_n_cycles=2,
                            )
                        )

                    self.assertEqual(result["status"], "stopped")
                    stopped_summary = db.execute(
                        "SELECT stop_summary FROM investigation_state WHERE state_id = 'case'"
                    ).fetchone()[0]
                    stopped_summary = (
                        json.loads(stopped_summary)
                        if isinstance(stopped_summary, str)
                        else stopped_summary
                    )
                    self.assertEqual(stopped_summary["candidate_count"], 2)
                    self.assertEqual(stopped_summary["drafted_work_count"], 2)
                    self.assertEqual(
                        stopped_summary["drafted_work_scope"],
                        "finding_and_gap_candidates",
                    )
                    self.assertEqual(stopped_summary["planner_status"], "completed")
                    self.assertEqual(stopped_summary["planner_iteration"], 2)
                    self.assertEqual(stopped_summary["planner_step_id"], "plan-last")
                    receipt = db.execute(
                        "SELECT status, phase, finished_at IS NOT NULL, terminal_reason "
                        "FROM trace.investigation_sessions"
                    ).fetchone()
                    self.assertEqual(receipt[:3], ("stopped", "terminal", True))
                    self.assertIn(reason, receipt[3])
                    self.assertEqual(
                        db.execute(
                            "SELECT status FROM hypotheses "
                            "WHERE hypothesis_id = 'H-INTERRUPTED'"
                        ).fetchone()[0],
                        "deferred",
                    )
                    self.assertEqual(
                        db.execute(
                            "SELECT status, retry_condition FROM investigation_tasks "
                            "WHERE hypothesis_id = 'H-INTERRUPTED'"
                        ).fetchone(),
                        ("open", "new_evidence_or_manual_resume"),
                    )
                    refresh_sections.assert_awaited_once()
                    self.assertEqual(
                        states_seen_by_refresh,
                        [
                            (
                                "stopped",
                                "deferred",
                                ("open", "new_evidence_or_manual_resume"),
                                ("stopped", "terminal", True),
                                False,
                            )
                        ],
                    )

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

    def test_stale_session_closes_open_llm_receipts_with_unknown_outcome(self) -> None:
        from forensia.investigation.investigation_session import (
            reconcile_stale_sessions,
        )
        from forensia.llm.telemetry import LLMTelemetry

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO trace.investigation_sessions "
                    "(session_id, started_at, status, heartbeat_at, phase) "
                    "VALUES ('stale-llm', '2020-01-02', 'running', '2020-01-02', 'waiting_for_llm')"
                )
                telemetry = LLMTelemetry(db, "stale-llm")
                call_id = telemetry.begin_logical_call(phase="plan-broad-draft")
                attempt_id = telemetry.begin_attempt(
                    logical_call_id=call_id,
                    endpoint="http://provider/v1/chat/completions",
                    provider="openai-compatible",
                    model="test",
                    schema_mode="none",
                    request_fingerprint="fp",
                    configured_output_limit=100,
                    reasoning_reserve_tokens=0,
                    known_context_limit=None,
                    effective_output_limit=100,
                    requested_output_limit=100,
                    input_chars=20,
                    retry_ordinal=0,
                    phase="plan-broad-draft",
                )

                self.assertEqual(reconcile_stale_sessions(db), 1)
                session = db.execute(
                    "SELECT status, terminal_reason FROM trace.investigation_sessions "
                    "WHERE session_id = 'stale-llm'"
                ).fetchone()
                call = db.execute(
                    "SELECT status FROM trace.llm_logical_calls WHERE logical_call_id = ?",
                    (call_id,),
                ).fetchone()
                attempt = db.execute(
                    "SELECT status, error_type, end_time, input_tokens, output_tokens, "
                    "input_tokens_source, output_tokens_source "
                    "FROM trace.llm_provider_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                usage = telemetry.session_aggregates()

                self.assertEqual(session[0], "abandoned")
                self.assertEqual(call[0], "discarded")
                self.assertEqual(
                    attempt,
                    (
                        "application_discard",
                        "process_interrupted",
                        None,
                        None,
                        None,
                        "unknown",
                        "unknown",
                    ),
                )
                self.assertEqual(usage["interrupted_attempts"], 1)
                self.assertEqual(usage["unknown_input_usage_attempts"], 1)
                self.assertIsNone(usage["actual_input_tokens"])

    def test_run_report_phase_propagates_exhausted_llm_outage(self) -> None:
        """An LLM-server outage is not a per-cycle failure: the phase waits for
        recovery (same policy as the investigation loop) and only an exhausted
        outage budget propagates and stops the session."""
        from types import SimpleNamespace
        from unittest import mock

        from forensia.core.session import SessionState
        from forensia.investigation import investigation_session
        from forensia.investigation import investigator as investigator_module
        from forensia.llm.llm_client import LLMServerUnavailableError

        async def _outage(**kwargs):
            raise LLMServerUnavailableError("server gone")

        async def _instant_recovery_probe(
            base_url, progress_callback=None, budget_s=None
        ):
            if progress_callback:
                progress_callback(
                    {
                        "stage": "waiting_for_llm",
                        "status": "running",
                        "summary": "LLM server unavailable",
                    }
                )
            raise LLMServerUnavailableError("outage budget exceeded")

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
                    mock.patch.object(
                        investigation_session,
                        "get_settings",
                        return_value=SimpleNamespace(
                            llm_outage_wall_clock_budget_s=10,
                            llm_outage_probe_interval_s=0,
                        ),
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
                assert "operator" not in row[1].lower()
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


@pytest.mark.parametrize("correction_raises", [False, True])
def test_invalid_hypothesis_planner_emits_retry_event_and_retries_once(
    correction_raises,
) -> None:
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
                if correction_raises and calls == 2:
                    raise RuntimeError("correction could not be parsed")
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
                        max_queries_per_hypothesis=5,
                        plan_cycle=1,
                        max_iter=1,
                        report_only=False,
                    )
                )

            assert db.execute(
                "SELECT status FROM hypotheses WHERE hypothesis_id = ?", [hypothesis.id]
            ).fetchone() == ("needs_review" if correction_raises else "deferred",)
            assert db.execute(
                "SELECT COUNT(*) FROM trace.investigation_steps WHERE phase = 'do'"
            ).fetchone() == (0,)
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
            assert [(event[1], event[2]) for event in rejected] == [
                ("failed", "planner_validation_failed"),
                (
                    "failed",
                    "planner_failed"
                    if correction_raises
                    else "planner_validation_failed",
                ),
            ]
            plans = db.execute(
                "SELECT output_json FROM trace.investigation_steps WHERE phase = 'plan-hypothesis' ORDER BY created_at"
            ).fetchall()
            assert len(plans) == 2
            latest = json.loads(plans[-1][0])["_plan_status"]
            assert latest["retry_available"] is False
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
