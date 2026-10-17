"""Tests for M1/M3: investigation state, report gaps, and investigation tasks."""

from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock

from forensia.core.case import Case
from forensia.core.identifiers import report_gap_id
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import (
    ensure_investigation_state,
    load_investigation_state,
    mark_investigation_started,
    save_stop_reason,
)
from forensia.investigation.report_gap import (
    inject_gap_hypotheses,
)


class InvestigationStateTests(unittest.TestCase):
    """Test investigation_state singleton table."""

    def test_question_discovery_rejects_bad_query_and_huge_count_without_repeating(
        self,
    ) -> None:
        import asyncio

        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _draft_and_admit_candidate,
            _persisted_gap_drafts,
            _select_gap_drafts,
        )
        from forensia.report.answers.answer_registry import build_structured_answer

        with tempfile.TemporaryDirectory() as tmpdir, CaseDB(Case.init(tmpdir)) as db:
            db.execute(
                "INSERT INTO registry_artifacts (artifact_id, plugin, value_name) VALUES ('registry-target', 'LabelPlugin', 'Aster')"
            )
            question = "Which value names were returned by LabelPlugin?"
            ctx = _BroadPlanContext(
                state=SessionState(session_id="discovery-bounds"),
                db=db,
                session_id="discovery-bounds",
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
            inject_gap_hypotheses(
                db,
                ctx.state,
                [],
                ctx.session_id,
                question_requests=[
                    {
                        "section_key": "identity",
                        "block_heading": "Stored label",
                        "question_text": question,
                    }
                ],
            )
            selected, _ = _select_gap_drafts(ctx, _persisted_gap_drafts(ctx), 1)
            responses = [
                {
                    "request_contract": {
                        "status": "resolved",
                        "scope_filters": [
                            {
                                "family": "registry",
                                "field": "plugin",
                                "operator": "equals",
                                "value": "LabelPlugin",
                            }
                        ],
                        "requirements": [
                            {
                                "family": "registry",
                                "field": "value_name",
                                "kind": "observed_value",
                            }
                        ],
                    },
                    "action": {
                        "intent": "Read labels",
                        "target_table": "registry_artifacts",
                        "template_id": None,
                        "sql": "DELETE FROM registry_artifacts",
                    },
                },
                {
                    "action": {
                        "intent": "Read labels",
                        "target_table": "registry_artifacts",
                        "template_id": None,
                        "sql": "SELECT artifact_id, 'fabricated' AS value_name FROM registry_artifacts WHERE plugin = 'LabelPlugin'",
                    },
                },
                {
                    "hypothesis": {
                        "required_entities": [],
                        "confirm_when": {
                            "min_count": 1000000000000000,
                            "observation": {
                                "family": "registry",
                                "capability": "registry_observation",
                                "field": "value_name",
                                "operator": "equals",
                                "value": "Aster",
                            },
                        },
                    }
                },
            ]
            with mock.patch(
                "forensia.llm.json_response.request_llm_json", side_effect=responses
            ) as model:
                _, outcome = asyncio.run(
                    _draft_and_admit_candidate(ctx, selected[0], 1)
                )
            self.assertEqual(3, model.call_count)
            self.assertEqual("question_contract_rejected", outcome["status"])
            self.assertTrue(
                outcome["reason"].startswith("question_contract_observation_mismatch")
            )
            self.assertEqual(
                ("Aster",),
                db.execute("SELECT value_name FROM registry_artifacts").fetchone(),
            )
            self.assertIn("Aster", str(model.call_args_list[-1].kwargs["messages"]))
            remaining, exhausted = _select_gap_drafts(
                ctx, _persisted_gap_drafts(ctx), 1
            )
            self.assertEqual([], remaining)
            self.assertEqual(1, exhausted)
            db.execute(
                "UPDATE trace.investigation_steps SET output_json = ? "
                "WHERE session_id = ? AND phase = 'plan-broad-candidate' "
                "AND json_extract_string(input_json, '$.candidate_ref') = ?",
                [
                    json.dumps(
                        {"status": "unresolved_observation", "draft_calls_used": 0}
                    ),
                    ctx.session_id,
                    selected[0]["candidate"]["candidate_ref"],
                ],
            )
            unresolved_remaining, unresolved_exhausted = _select_gap_drafts(
                ctx, _persisted_gap_drafts(ctx), 1
            )
            self.assertEqual([], unresolved_remaining)
            self.assertEqual(1, unresolved_exhausted)
            answer = build_structured_answer(
                db.case,
                db,
                answer_spec="",
                answer_id="label",
                section_key="identity",
                block_heading="Stored label",
                question_text=question,
            )
            self.assertEqual([], answer["answer"])
            self.assertEqual([outcome["reason"]], answer["missing_reason"])
            self.assertEqual([], answer["queries_run"])

    def test_empty_question_discovery_retries_once_with_compact_same_contract(
        self,
    ) -> None:
        import asyncio

        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _draft_and_admit_candidate,
            _persisted_gap_drafts,
            _select_gap_drafts,
        )

        with tempfile.TemporaryDirectory() as tmpdir, CaseDB(Case.init(tmpdir)) as db:
            db.execute(
                "INSERT INTO registry_artifacts (artifact_id, plugin, value_name) "
                "VALUES ('registry-target', 'LabelPlugin', 'Aster')"
            )
            question = "Which value names were returned by LabelPlugin?"
            state = SessionState(session_id="empty-discovery-retry")
            ctx = _BroadPlanContext(
                state=state,
                db=db,
                session_id=state.session_id,
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
            inject_gap_hypotheses(
                db,
                state,
                [],
                ctx.session_id,
                question_requests=[
                    {
                        "section_key": "identity",
                        "block_heading": "Stored label",
                        "question_text": question,
                    }
                ],
            )
            selected, _ = _select_gap_drafts(ctx, _persisted_gap_drafts(ctx), 1)
            contract = {
                "status": "resolved",
                "scope_filters": [
                    {
                        "family": "registry",
                        "field": "plugin",
                        "operator": "equals",
                        "value": "LabelPlugin",
                    }
                ],
                "requirements": [
                    {
                        "family": "registry",
                        "field": "value_name",
                        "kind": "observed_value",
                    }
                ],
            }

            def action(sql: str) -> dict[str, object]:
                return {
                    "request_contract": contract,
                    "action": {
                        "intent": "Read label values",
                        "target_table": "registry_artifacts",
                        "template_id": None,
                        "sql": sql,
                    },
                }

            responses = [
                action(
                    "SELECT artifact_id, value_name FROM registry_artifacts "
                    "WHERE plugin = 'LabelPlugin' AND false"
                ),
                {
                    "action": action(
                        "SELECT artifact_id, value_name FROM registry_artifacts "
                        "WHERE plugin = 'LabelPlugin'"
                    )["action"]
                },
                {
                    "hypothesis": {
                        "required_entities": [],
                        "confirm_when": {
                            "min_count": 1,
                            "observation": {
                                "family": "registry",
                                "capability": "registry_observation",
                                "field": "value_name",
                                "operator": "equals",
                                "value": "Aster",
                                "evidence_ids": ["registry-target"],
                            },
                        },
                    }
                },
            ]
            with mock.patch(
                "forensia.llm.json_response.request_llm_json", side_effect=responses
            ) as model:
                hypothesis, outcome = asyncio.run(
                    _draft_and_admit_candidate(ctx, selected[0], 1)
                )

            self.assertEqual("admitted", outcome["status"])
            self.assertIsNotNone(hypothesis)
            self.assertEqual(3, model.call_count)
            retry_prompt = str(model.call_args_list[1].kwargs["messages"])
            self.assertIn("request_contract", retry_prompt)
            self.assertIn("registry", retry_prompt)
            self.assertNotIn("canonical_scope_evidence_ids", retry_prompt)
            rejected = db.execute(
                "SELECT output_json FROM trace.investigation_steps "
                "WHERE session_id = ? AND phase = 'plan-gap-discovery' "
                "AND step_id LIKE '%-rejected'",
                [ctx.session_id],
            ).fetchone()
            rejected_receipt = json.loads(rejected[0])
            self.assertEqual("empty", rejected_receipt["status"])
            self.assertTrue(rejected_receipt["contract_validated"])
            self.assertEqual(0, rejected_receipt["row_count"])
            remaining, exhausted = _select_gap_drafts(
                ctx, _persisted_gap_drafts(ctx), 1
            )
            self.assertEqual([], remaining)
            self.assertEqual(0, exhausted)
            final_attempt = db.execute(
                "SELECT output_json FROM trace.investigation_steps "
                "WHERE session_id = ? AND phase = 'plan-broad-candidate' "
                "ORDER BY created_at DESC LIMIT 1",
                [ctx.session_id],
            ).fetchone()
            self.assertEqual(1, json.loads(final_attempt[0])["correction_calls_used"])

            candidate = selected[0]["candidate"]
            exhausted_retry = {
                **selected[0],
                "attempt_number": 2,
                "prior_attempts": {
                    candidate["candidate_ref"]: [
                        {
                            "candidate_fingerprint": candidate["candidate_fingerprint"],
                            "input_fingerprint": selected[0]["input_fingerprint"],
                            "correction_calls_used": 1,
                            "draft_calls_used": 0,
                        }
                    ]
                },
            }
            with mock.patch(
                "forensia.llm.json_response.request_llm_json",
                return_value=action(
                    "SELECT artifact_id, value_name FROM registry_artifacts "
                    "WHERE plugin = 'LabelPlugin' AND false"
                ),
            ) as exhausted_model:
                _, exhausted_outcome = asyncio.run(
                    _draft_and_admit_candidate(ctx, exhausted_retry, 2)
                )
            self.assertEqual("discovery_failed", exhausted_outcome["status"])
            self.assertEqual(1, exhausted_model.call_count)
            final_attempt = db.execute(
                "SELECT output_json FROM trace.investigation_steps "
                "WHERE session_id = ? AND phase = 'plan-broad-candidate' "
                "ORDER BY created_at DESC LIMIT 1",
                [ctx.session_id],
            ).fetchone()
            self.assertEqual(2, json.loads(final_attempt[0])["correction_calls_used"])

    def test_observed_draft_keeps_target_and_rejects_transposed_timestamp(self) -> None:
        import asyncio

        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _call_broad_drafter,
        )
        from forensia.investigation.planner import plan_hypothesis_query
        from forensia.investigation.verification.assessment import assess_evidence_group

        candidate = {
            "scope": {"source_family": "mft"},
            "evidence": [
                {
                    "evidence_id": "mft-target",
                    "_source": "mft_entries",
                    "file_path": "Users/alice/client/cache.db",
                    "si_modified": "2026-01-02 03:04:05",
                    "fn_modified": "2026-01-01 03:04:05",
                    "is_deleted": True,
                }
            ],
        }
        support = {
            "observation": {
                "family": "mft",
                "capability": "file_activity",
                "field": "is_deleted",
                "operator": "equals",
                "value": True,
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir, CaseDB(Case.init(tmpdir)) as db:
            db.execute(
                "INSERT INTO mft_entries (evidence_id, file_path, is_deleted) VALUES "
                "('mft-target', 'Users/alice/client/cache.db', true), "
                "('mft-unrelated', 'Other/deleted.txt', true)"
            )
            state = SessionState(session_id="target-binding")
            ctx = _BroadPlanContext(
                state=state,
                db=db,
                session_id=state.session_id,
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
            with mock.patch(
                "forensia.llm.json_response.request_llm_json",
                return_value={"hypothesis": {"confirm_when": support}},
            ):
                hypothesis, error = asyncio.run(
                    _call_broad_drafter(
                        ctx,
                        {"summary": "Investigate this deleted file"},
                        candidate=candidate,
                        draft_index=1,
                        correction_budget=[0],
                        logical_call_id=None,
                        attempt_ordinal=[0],
                    )
                )
            self.assertIsNone(error)
            self.assertIn('"mft-target"', hypothesis.description)
            with mock.patch(
                "forensia.llm.json_response.request_llm_json",
                side_effect=AssertionError("typed primary needs no inference"),
            ):
                plan = plan_hypothesis_query(
                    state, hypothesis, "unused", "unused", db=db
                )
            self.assertEqual(db.execute(plan.query.sql).fetchall(), [("mft-target",)])
            unrelated = {
                "evidence_id": "mft-unrelated",
                "source_family": "mft",
                "is_deleted": True,
            }
            assessment = assess_evidence_group(
                hypothesis=hypothesis,
                rows=[unrelated],
                evidence_ids=["mft-unrelated"],
            )
            self.assertEqual(assessment.role, "contextual")
            assessment = assess_evidence_group(
                hypothesis=hypothesis,
                rows=[unrelated, {**unrelated, "evidence_id": "mft-target"}],
                evidence_ids=["mft-unrelated", "mft-target"],
            )
            self.assertEqual(assessment.role, "supporting")
            self.assertEqual(assessment.evidence_ids, ("mft-target",))

            support["observation"].update(
                field="fn_modified", value="2026-01-02 03:04:05"
            )
            with mock.patch(
                "forensia.llm.json_response.request_llm_json",
                return_value={"hypothesis": {"confirm_when": support}},
            ):
                hypothesis, error = asyncio.run(
                    _call_broad_drafter(
                        ctx,
                        {},
                        candidate=candidate,
                        draft_index=2,
                        correction_budget=[0],
                        logical_call_id=None,
                        attempt_ordinal=[0],
                    )
                )
            self.assertIsNone(hypothesis)
            self.assertIn("observation-field-value-mismatch", error)
            self.assertIn("si_modified", error)

    def test_exhausted_early_gap_drafts_do_not_starve_later_persisted_gaps(
        self,
    ) -> None:
        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _persisted_gap_drafts,
            _select_gap_drafts,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index in range(5):
                    db.execute(
                        "INSERT INTO report_gaps (gap_id, description, kind, status, origin) "
                        "VALUES (?, ?, 'needs_review', 'open', 'test')",
                        [f"GAP-{index}", f"Persisted gap {index}"],
                    )
                ctx = _BroadPlanContext(
                    state=SessionState(session_id="gap-starvation"),
                    db=db,
                    session_id="gap-starvation",
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

                selected, _ = _select_gap_drafts(
                    ctx, _persisted_gap_drafts(ctx), limit=4
                )
                self.assertEqual(len(selected), 4)
                for index, item in enumerate(selected):
                    candidate = item["candidate"]
                    db.execute(
                        "INSERT INTO trace.investigation_steps "
                        "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                        "VALUES (?, 'gap-starvation', 1, 'plan-broad-candidate', ?, ?, now())",
                        [
                            f"gap-attempt-{index}",
                            json.dumps(
                                {
                                    "candidate_ref": candidate["candidate_ref"],
                                    "candidate_fingerprint": candidate[
                                        "candidate_fingerprint"
                                    ],
                                    "input_fingerprint": item["input_fingerprint"],
                                }
                            ),
                            json.dumps(
                                {
                                    "status": "question_contract_rejected",
                                    "draft_calls_used": 1,
                                }
                            ),
                        ],
                    )

                remaining, exhausted = _select_gap_drafts(
                    ctx, _persisted_gap_drafts(ctx), limit=1
                )

                ctx.case_policy = mock.Mock(content_sha256="policy-revision-2")
                revised, revised_exhausted = _select_gap_drafts(
                    ctx, _persisted_gap_drafts(ctx), limit=1
                )

        self.assertEqual(exhausted, 4)
        self.assertEqual(remaining[0]["candidate"]["candidate_ref"], "gap-GAP-4")
        self.assertEqual(revised_exhausted, 0)
        self.assertEqual(revised[0]["candidate"]["candidate_ref"], "gap-GAP-0")

    def test_family_rule_fairness_and_gap_draft_survive_finding_flood(self) -> None:
        from forensia.context.investigation_candidates import (
            build_investigation_candidates,
        )
        from forensia.core.session import Hypothesis
        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _candidate_input_fingerprint,
            _candidate_linked_work,
            _select_candidate_drafts,
            _select_gap_drafts,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                for index in range(12):
                    evidence_id = f"flood-{index:02d}"
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, event_id) "
                        "VALUES (?, ?, 'host-a', '2026-01-02 03:04:05', 4624)",
                        [evidence_id, f"source-{index:02d}"],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                        "VALUES (?, 'flood-rule', 'Repeated login', 'accepted', ?)",
                        [
                            f"flood-finding-{index:02d}",
                            json.dumps([{"evidence_id": evidence_id}]),
                        ],
                    )
                for index in range(2):
                    evidence_id = f"rare-{index}"
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, event_id) "
                        "VALUES (?, ?, 'host-b', '2026-01-02 03:04:05', 1102)",
                        [evidence_id, f"rare-source-{index}"],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                        "VALUES (?, ?, 'Rare event', 'accepted', ?)",
                        [
                            f"rare-finding-{index}",
                            f"rare-rule-{index}",
                            json.dumps([{"evidence_id": evidence_id}]),
                        ],
                    )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, source_file, record_number, file_path) "
                    "VALUES ('mft-1', 'mft-source', 1, 'C:/Temp/payload.exe')"
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('mft-finding', 'mft-rule', 'File activity', 'accepted', '[{\"evidence_id\":\"mft-1\"}]')"
                )
                ctx = _BroadPlanContext(
                    state=SessionState(session_id="fairness"),
                    db=db,
                    session_id="fairness",
                    base_url="unused",
                    model="unused",
                    plan_cycle=1,
                    observed_keypoints=[],
                    observed_keypoint_labels=["host_execution_activity (rows=3)"],
                    emit_fn=None,
                    llm_status_fn=lambda _: None,
                    progress_callback=None,
                    case_profile=None,
                )

                projection = build_investigation_candidates(db, limit=5)
                selected, _counts = _select_candidate_drafts(ctx, limit=3)
                gap_selected, _exhausted = _select_gap_drafts(
                    ctx,
                    [{"keypoint_id": "host_execution_activity"}],
                    limit=1,
                )
                for index, item in enumerate(selected):
                    hypothesis = Hypothesis(
                        id=f"H-{index}",
                        description="Observed activity",
                        confirm_when={"co_observed_event_ids": [4624]},
                    )
                    db.execute(
                        "INSERT INTO hypotheses (hypothesis_id, verification_spec) VALUES (?, ?)",
                        [hypothesis.id, hypothesis.verification_spec.model_dump_json()],
                    )
                    candidate = item["candidate"]
                    settled_fingerprint = _candidate_input_fingerprint(
                        candidate,
                        ctx,
                        _candidate_linked_work(
                            candidate, db, {}, additional_ids={hypothesis.id}
                        ),
                    )
                    db.execute(
                        "INSERT INTO trace.investigation_steps "
                        "(step_id, phase, input_json, output_json, created_at) "
                        "VALUES (?, 'plan-broad-candidate', ?, ?, now())",
                        [
                            f"admitted-{index}",
                            json.dumps(
                                {
                                    "candidate_ref": candidate["candidate_ref"],
                                    "candidate_fingerprint": candidate[
                                        "candidate_fingerprint"
                                    ],
                                    "input_fingerprint": item["input_fingerprint"],
                                }
                            ),
                            json.dumps(
                                {
                                    "status": "admitted",
                                    "admitted_hypothesis_id": hypothesis.id,
                                    "settled_input_fingerprint": settled_fingerprint,
                                }
                            ),
                        ],
                    )
                next_selected, next_counts = _select_candidate_drafts(ctx, limit=3)

                self.assertEqual(len(next_selected), 3)
                self.assertEqual(next_counts["already_linked_count"], 3)
                self.assertEqual(next_counts["eligibility_evaluated_count"], 6)
                self.assertFalse(next_counts["eligibility_complete"])
                self.assertTrue(
                    {
                        item["candidate"]["candidate_ref"] for item in selected
                    }.isdisjoint(
                        item["candidate"]["candidate_ref"] for item in next_selected
                    )
                )

        self.assertEqual(
            [item["scope"]["source_family"] for item in projection["candidates"][:2]],
            ["evtx", "mft"],
        )
        selected_rules = {
            rule_id for item in selected for rule_id in item["candidate"]["rule_ids"]
        }
        self.assertIn("flood-rule", selected_rules)
        self.assertIn("mft-rule", selected_rules)
        self.assertTrue(selected_rules.intersection({"rare-rule-0", "rare-rule-1"}))
        self.assertEqual(len(gap_selected), 1)

    def test_terminal_candidate_attempts_do_not_repeat_on_resume(
        self,
    ) -> None:
        from forensia.context.investigation_candidates import (
            build_investigation_candidates,
        )
        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _select_candidate_drafts,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                evidence_id = "evtx-interrupted"
                row = {
                    "evidence_id": evidence_id,
                    "source_file": "source-interrupted",
                    "computer": "host-a",
                    "timestamp": "2026-01-02T03:04:05",
                    "event_id": 4624,
                }
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, event_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        evidence_id,
                        row["source_file"],
                        row["computer"],
                        row["timestamp"],
                        row["event_id"],
                    ],
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('finding-interrupted', 'rule-interrupted', 'Observed', 'accepted', ?)",
                    [json.dumps([row])],
                )
                ctx = _BroadPlanContext(
                    state=SessionState(session_id="resume"),
                    db=db,
                    session_id="resume",
                    base_url="unused",
                    model="unused",
                    plan_cycle=2,
                    observed_keypoints=[],
                    observed_keypoint_labels=[],
                    emit_fn=None,
                    llm_status_fn=lambda _: None,
                    progress_callback=None,
                    case_profile=None,
                )
                candidate = build_investigation_candidates(db, limit=1)["candidates"][0]
                from forensia.investigation.investigation_cycle import (
                    _candidate_input_fingerprint,
                )

                fingerprint = _candidate_input_fingerprint(candidate, ctx, [])
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
                    "VALUES ('prior-attempt', 'prior-session', 1, 'plan-broad-candidate', ?, ?, now())",
                    [
                        json.dumps(
                            {
                                "candidate_ref": candidate["candidate_ref"],
                                "candidate_fingerprint": candidate[
                                    "candidate_fingerprint"
                                ],
                                "input_fingerprint": fingerprint,
                            }
                        ),
                        json.dumps(
                            {"status": "unresolved_observation", "draft_calls_used": 0}
                        ),
                    ],
                )

                selected, counts = _select_candidate_drafts(ctx, limit=1)
                db.execute(
                    "UPDATE trace.investigation_steps SET output_json = ? WHERE step_id = ?",
                    [
                        json.dumps({"status": "interrupted", "draft_calls_used": 1}),
                        "prior-attempt",
                    ],
                )
                interrupted_selected, interrupted_counts = _select_candidate_drafts(
                    ctx, limit=1
                )

        self.assertEqual(selected, [])
        self.assertEqual(counts["attempt_exhausted_count"], 1)
        self.assertEqual(interrupted_selected, [])
        self.assertEqual(interrupted_counts["attempt_exhausted_count"], 1)

    def test_resume_preserves_objective_and_json_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ensure_investigation_state(
                    db,
                    objective="human objective",
                    termination_policy={"max_iterations": 4},
                )
                save_stop_reason(
                    db, status="stopped", stop_reason_code="max_iterations"
                )
                ensure_investigation_state(db, objective="later policy objective")
                mark_investigation_started(db)
                state = load_investigation_state(db)
                self.assertEqual(state["objective"], "human objective")
                self.assertEqual(state["termination_policy"], {"max_iterations": 4})
                self.assertEqual(state["status"], "active")
                self.assertEqual(state["stop_reason_code"], "")

    def test_session_persists_neutral_default_objective_in_case_db(
        self,
    ) -> None:
        from forensia.investigation import investigation_session

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                mock.patch.object(investigation_session, "_seed_rule_hypotheses"),
                mock.patch.object(
                    investigation_session, "build_report_status", return_value={}
                ),
            ):
                _state, _ctx, _session_id = investigation_session._init_session(
                    case,
                    db,
                    case.report_template_dir,
                    report_input_record={"source_path": None},
                )
                state = load_investigation_state(db)

            objective = state["objective"]
            self.assertTrue(objective)

    def test_candidate_projection_aggregates_before_limit_and_keeps_provenance(
        self,
    ) -> None:
        from forensia.context.investigation_candidates import (
            build_investigation_candidates,
            expand_investigation_candidate,
            expand_investigation_candidate_rules,
        )
        from forensia.investigation.investigation_cycle import (
            _BroadPlanContext,
            _emit_broad_plan_result,
            _select_candidate_drafts,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index in range(26):
                    evidence_id = f"evtx-flood-{index:03d}"
                    row = {
                        "evidence_id": evidence_id,
                        "source_file": "source-revision-a",
                        "computer": "host-a",
                        "timestamp": "2026-01-02T03:04:05",
                        "target_user": "service-account",
                        "event_id": 4624,
                    }
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, target_user, event_id) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            evidence_id,
                            row["source_file"],
                            row["computer"],
                            row["timestamp"],
                            row["target_user"],
                            row["event_id"],
                        ],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, summary, severity, confidence, status, evidence) "
                        "VALUES (?, 'common-rule', 'Repeated login', 'Repeated observation', 'high', 0.5, 'accepted', ?)",
                        [f"common-{index:03d}", json.dumps([row])],
                    )
                rare = {
                    "evidence_id": "evtx-rare-001",
                    "source_file": "source-revision-b",
                    "computer": "host-b",
                    "timestamp": "2026-01-02T03:04:05",
                    "src_ip": "203.0.113.9",
                    "event_id": 1102,
                }
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, src_ip, event_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        rare["evidence_id"],
                        rare["source_file"],
                        rare["computer"],
                        rare["timestamp"],
                        rare["src_ip"],
                        rare["event_id"],
                    ],
                )
                for rule_id in ("rare-rule", "corroborating-rule"):
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, summary, severity, confidence, status, evidence) "
                        "VALUES (?, ?, 'Rare event', 'Distinct lead', 'medium', 0.5, 'accepted', ?)",
                        [rule_id, rule_id, json.dumps([rare])],
                    )
                for index in range(2):
                    unknown = {
                        "evidence_id": f"evtx-unknown-{index}",
                        "source_file": "source-revision-a",
                        "computer": "host-a",
                        "timestamp": "2026-01-02T03:04:05",
                        "event_id": 999,
                    }
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, source_file, computer, timestamp, event_id) "
                        "VALUES (?, ?, ?, ?, ?)",
                        [
                            unknown["evidence_id"],
                            unknown["source_file"],
                            unknown["computer"],
                            unknown["timestamp"],
                            unknown["event_id"],
                        ],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, summary, severity, confidence, status, evidence) "
                        "VALUES (?, 'unknown-rule', 'Unknown target', 'Unknown entity', 'low', 0.5, 'accepted', ?)",
                        [f"unknown-{index}", json.dumps([unknown])],
                    )
                for index in range(2):
                    evidence_id = f"mft-source-revision-{index:03d}"
                    db.execute(
                        "INSERT INTO mft_entries (evidence_id, source_file, record_number, file_path, si_modified) "
                        "VALUES (?, 'mft-source-revision', ?, 'C:/Temp/payload.exe', '2026-01-02 03:04:05')",
                        [evidence_id, index],
                    )
                    db.execute(
                        "INSERT INTO findings (finding_id, rule_id, title, summary, severity, confidence, status, evidence) "
                        "VALUES (?, 'mft-rule', 'File observation', 'Repeated file observation', 'low', 0.5, 'accepted', ?)",
                        [
                            f"mft-finding-{index}",
                            json.dumps([{"evidence_id": evidence_id}]),
                        ],
                    )
                # A removed source row and a suppressed match are ineligible.
                stale = {**rare, "evidence_id": "evtx-stale-001"}
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('stale', 'stale-rule', 'Stale', 'accepted', ?)",
                    [json.dumps([stale])],
                )
                db.execute(
                    "INSERT INTO findings (finding_id, rule_id, title, status, evidence) "
                    "VALUES ('suppressed', 'suppressed-rule', 'Suppressed', 'suppressed', ?)",
                    [json.dumps([rare])],
                )
                projection = build_investigation_candidates(db, limit=5)
                repeated = build_investigation_candidates(db, limit=5)
                severity_diverse = build_investigation_candidates(db, limit=2)
                emit = mock.Mock()
                ctx = _BroadPlanContext(
                    state=SessionState(session_id="test"),
                    db=db,
                    session_id="test",
                    base_url="unused",
                    model="unused",
                    plan_cycle=1,
                    observed_keypoints=[],
                    observed_keypoint_labels=[],
                    emit_fn=emit,
                    llm_status_fn=lambda _: None,
                    progress_callback=None,
                    case_profile=None,
                )
                selected, plan_counts = _select_candidate_drafts(ctx, limit=1)
                self.assertEqual(len(selected), 1)
                self.assertIsNone(plan_counts["eligible_candidate_count"])
                self.assertIsNone(plan_counts["draft_cap_omitted_count"])
                _emit_broad_plan_result(ctx, [], False, plan_counts)
                self.assertIn("unassessed=unknown", emit.call_args.args[1])
                eligible_only = build_investigation_candidates(
                    db,
                    limit=1,
                    eligible=lambda candidate: "rare-rule" in candidate["rule_ids"],
                )
                excluded_projection = build_investigation_candidates(
                    db,
                    limit=1,
                    excluded_fingerprints=[
                        projection["candidates"][0]["candidate_ref"]
                    ],
                )
                flood = next(
                    item
                    for item in projection["candidates"]
                    if item["evidence_count"] == 26
                )
                first_page = expand_investigation_candidate(db, flood, limit=20)
                second_page = expand_investigation_candidate(
                    db, flood, offset=20, limit=20
                )
                rare_candidate = next(
                    item
                    for item in projection["candidates"]
                    if item["evidence_count"] == 1 and item["match_count"] == 2
                )
                rare_rules = expand_investigation_candidate_rules(db, rare_candidate)
                db.execute(
                    "UPDATE evtx_events SET event_id = 4625 WHERE evidence_id = 'evtx-flood-000'"
                )
                changed = build_investigation_candidates(db, limit=5)

            self.assertEqual(
                projection["counts"],
                {
                    "match_count": 32,
                    "distinct_evidence_count": 31,
                    "candidate_count": 5,
                    "eligible_candidate_count": 5,
                    "eligibility_evaluated_count": 5,
                    "eligibility_complete": True,
                    "excluded_count": 0,
                    "presented_count": 5,
                    "unpresented_count": 0,
                },
            )
            self.assertEqual(
                [item["candidate_ref"] for item in projection["candidates"]],
                [item["candidate_ref"] for item in repeated["candidates"]],
            )
            self.assertEqual(severity_diverse["counts"]["presented_count"], 2)
            self.assertEqual(
                severity_diverse["counts"]["eligibility_evaluated_count"], 2
            )
            self.assertFalse(severity_diverse["counts"]["eligibility_complete"])
            self.assertIsNone(severity_diverse["counts"]["eligible_candidate_count"])
            self.assertEqual(len(severity_diverse["candidates"]), 2)
            self.assertEqual(severity_diverse["candidates"][1]["match_count"], 2)
            self.assertEqual(eligible_only["counts"]["candidate_count"], 5)
            self.assertIsNone(eligible_only["counts"]["eligible_candidate_count"])
            self.assertEqual(eligible_only["counts"]["eligibility_evaluated_count"], 3)
            self.assertFalse(eligible_only["counts"]["eligibility_complete"])
            self.assertEqual(eligible_only["counts"]["excluded_count"], 2)
            self.assertIn("rare-rule", eligible_only["candidates"][0]["rule_ids"])
            changed_flood = next(
                item for item in changed["candidates"] if item["evidence_count"] == 26
            )
            self.assertEqual(changed_flood["candidate_ref"], flood["candidate_ref"])
            self.assertNotEqual(
                changed_flood["candidate_fingerprint"], flood["candidate_fingerprint"]
            )
            self.assertEqual(excluded_projection["counts"]["candidate_count"], 5)
            self.assertIsNone(excluded_projection["counts"]["eligible_candidate_count"])
            self.assertEqual(
                excluded_projection["counts"]["eligibility_evaluated_count"], 2
            )
            self.assertFalse(excluded_projection["counts"]["eligibility_complete"])
            self.assertEqual(excluded_projection["counts"]["excluded_count"], 1)
            self.assertEqual(excluded_projection["counts"]["presented_count"], 1)
            self.assertNotEqual(
                excluded_projection["candidates"][0]["candidate_ref"],
                projection["candidates"][0]["candidate_ref"],
            )
            self.assertEqual(rare_candidate["match_count"], 2)
            self.assertEqual(
                set(rare_candidate["rule_ids"]), {"rare-rule", "corroborating-rule"}
            )
            self.assertEqual(set(rare_rules), {"rare-rule", "corroborating-rule"})
            self.assertEqual(
                rare_candidate["evidence"][0]["evidence_id"], "evtx-rare-001"
            )
            self.assertEqual(rare_candidate["omitted_count"], 0)
            self.assertEqual(
                len(
                    [
                        item
                        for item in projection["candidates"]
                        if item["evidence_count"] == 1
                    ]
                ),
                3,
            )
            mft_candidate = next(
                item for item in projection["candidates"] if item["evidence_count"] == 2
            )
            self.assertEqual(mft_candidate["scope"]["source_family"], "mft")
            self.assertIsNone(mft_candidate["scope"]["host"])
            self.assertEqual(len(first_page), 20)
            self.assertEqual(len(second_page), 6)
            self.assertEqual(
                {row["evidence_id"] for row in first_page + second_page},
                {f"evtx-flood-{index:03d}" for index in range(26)},
            )


class ReportGapsTests(unittest.TestCase):
    """Test report_gaps table."""

    def test_broad_gap_draft_keeps_exact_request_as_source_context(self) -> None:
        import asyncio

        from forensia.context.case_profile import CaseEvidenceProfile
        from forensia.core.session import Hypothesis
        from forensia.investigation.investigation_cycle import (
            _attach_explicit_gap_source,
            _BroadPlanContext,
            _draft_and_admit_candidate,
            _persisted_gap_drafts,
            _select_gap_drafts,
        )
        from forensia.investigation.planner import plan_hypothesis_query
        from forensia.investigation.working_state import (
            build_working_state,
            render_working_state,
        )

        question = (
            "Find the metadata for the specified file. "
            "Preserve the distinction between the file timestamps and access activity; "
            "a file record alone does not prove which person opened it. "
            "Keep the source evidence available for the report. "
            "What file name is recorded for Users/Nori/quarterly_budget.xlsx?"
        )
        gap_id = report_gap_id(
            question, section_key="activity", block_heading="File access"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name) VALUES "
                    "('mft-target', 'Users/Nori/quarterly_budget.xlsx', 'quarterly_budget.xlsx'), "
                    "('mft-other-user', 'Users/Sora/quarterly_budget.xlsx', 'quarterly_budget.xlsx'), "
                    "('mft-other-file', 'Users/Nori/notes.txt', 'notes.txt')"
                )
                db.execute(
                    "UPDATE mft_entries SET source_file = 'synthetic-mft-source'"
                )
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, block_heading, "
                    "description, kind, status, origin) "
                    "VALUES (?, 'activity', 'File access', ?, 'internal_db_check', "
                    "'open', 'section')",
                    [gap_id, question],
                )
                draft = Hypothesis(
                    id="draft-1",
                    description="User Alice opened the file",
                    summary="unchanged result summary",
                )
                ctx = _BroadPlanContext(
                    state=SessionState(session_id="draft-context"),
                    db=db,
                    session_id="draft-context",
                    base_url="unused",
                    model="unused",
                    plan_cycle=1,
                    observed_keypoints=[],
                    observed_keypoint_labels=[],
                    emit_fn=None,
                    llm_status_fn=lambda _: None,
                    progress_callback=None,
                    case_profile=CaseEvidenceProfile(event_ids=frozenset()),
                )
                selected, _ = _select_gap_drafts(
                    ctx, _persisted_gap_drafts(ctx), limit=1
                )
                self.assertEqual(selected[0]["gap"]["description"], question)
                _attach_explicit_gap_source(draft, selected[0]["gap"], db)
                self.assertEqual(draft.source_gap_id, gap_id)
                self.assertEqual(draft.description, "User Alice opened the file")
                self.assertEqual(draft.summary, "unchanged result summary")
                self.assertIsNone(selected[0]["prompt_candidate"])

                def model_response(**kwargs):
                    prompt = "\n".join(m["content"] for m in kwargs["messages"])
                    if "action" in kwargs["json_schema"]["properties"]:
                        self.assertEqual(
                            question,
                            json.loads(kwargs["messages"][-1]["content"])["question"],
                        )
                        return {
                            "request_contract": {
                                "status": "resolved",
                                "scope_filters": [
                                    {
                                        "family": "mft",
                                        "field": "file_path",
                                        "operator": "equals",
                                        "value": "Users/Nori/quarterly_budget.xlsx",
                                    }
                                ],
                                "requirements": [
                                    {
                                        "family": "mft",
                                        "field": "file_name",
                                        "kind": "observed_value",
                                    }
                                ],
                            },
                            "action": {
                                "intent": "Find the requested file's canonical record",
                                "target_table": "mft_entries",
                                "template_id": None,
                                "sql": "SELECT evidence_id, file_name FROM mft_entries WHERE file_path = 'Users/Nori/quarterly_budget.xlsx'",
                            },
                        }
                    self.assertIn(question, prompt)
                    self.assertIn("<OBSERVED_CANDIDATE>", prompt)
                    conditions = kwargs["json_schema"]["properties"]["hypothesis"][
                        "properties"
                    ]["confirm_when"]["properties"]
                    variants = conditions["observation"]["anyOf"]
                    self.assertEqual(
                        {"mft"},
                        {v["properties"]["family"]["enum"][0] for v in variants},
                    )
                    self.assertEqual(
                        ["file_name"], variants[0]["properties"]["field"]["enum"]
                    )
                    self.assertEqual(1, conditions["min_count"]["maximum"])
                    return {
                        "hypothesis": {
                            "required_entities": [],
                            "source_rule_ids": [],
                            "confirm_when": {
                                "observation": {
                                    "family": "mft",
                                    "capability": "file_activity",
                                    "field": "file_name",
                                    "operator": "equals",
                                    "value": "quarterly_budget.xlsx",
                                }
                            },
                            "refute_when": {"zero_rows": True},
                        }
                    }

                with mock.patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=model_response,
                ):
                    hypothesis, outcome = asyncio.run(
                        _draft_and_admit_candidate(ctx, selected[0], 1)
                    )
                self.assertEqual("admitted", outcome["status"], outcome)
                self.assertEqual(gap_id, hypothesis.source_gap_id)
                hypothesis = next(
                    item
                    for item in ctx.state.active_hypotheses
                    if item.id == outcome["admitted_hypothesis_id"]
                )
                with mock.patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=AssertionError("typed primary needs no inference"),
                ):
                    plan = plan_hypothesis_query(
                        ctx.state, hypothesis, "unused", "unused", db=db
                    )
                self.assertEqual(
                    [("mft-target",)], db.execute(plan.query.sql).fetchall()
                )
                neighboring_question = (
                    "Other context. " * 20 + "Unrelated final detail."
                )
                db.execute(
                    "INSERT INTO report_gaps (gap_id, description, status, hypothesis_id) "
                    "VALUES ('neighboring-gap', ?, 'open', ?)",
                    [neighboring_question, hypothesis.id],
                )
                context = render_working_state(
                    build_working_state(db, hypothesis_id=hypothesis.id)
                )
                self.assertIn(question, context)
                self.assertIn(neighboring_question[:200], context)
                self.assertNotIn("Unrelated final detail.", context)
                from forensia.investigation.hypotheses.hypothesis_manager import (
                    resolve_hypothesis,
                )
                from forensia.investigation.hypotheses.hypothesis_runner import (
                    _canonical_evidence_rows,
                )
                from forensia.investigation.verification.assessment import (
                    assess_evidence_group,
                )
                from forensia.investigation.verification.sufficiency import (
                    assess_and_persist_sufficiency,
                    create_evidence_links_for_query,
                )
                from forensia.report.answers.answer_registry import (
                    build_structured_answer,
                )

                rows, ids, fingerprints = _canonical_evidence_rows(
                    db, [{"evidence_id": "mft-target"}]
                )
                assessment = assess_evidence_group(
                    hypothesis=hypothesis,
                    rows=rows,
                    evidence_ids=ids,
                    content_fingerprints=fingerprints,
                )
                self.assertEqual("supporting", assessment.role)
                create_evidence_links_for_query(
                    db,
                    hypothesis_id=hypothesis.id,
                    evidence_ids=ids,
                    query_id=plan.query.query_id,
                    role=assessment.role,
                    assessment_id=assessment.assessment_id,
                    matched_conditions=assessment.matched_conditions,
                )
                sufficiency, _, _ = assess_and_persist_sufficiency(
                    db,
                    hypothesis_id=hypothesis.id,
                    evidence_requirements={},
                    verification_spec=hypothesis.verification_spec,
                    session_id=ctx.session_id,
                )
                self.assertEqual("sufficient", sufficiency.status, sufficiency)
                resolve_hypothesis(
                    db,
                    ctx.state,
                    hypothesis.id,
                    "confirmed",
                    hypothesis.description,
                    ctx.session_id,
                    sample_rows=rows,
                )
                answer = build_structured_answer(
                    db.case,
                    db,
                    answer_spec="",
                    answer_id="discovered-file",
                    section_key="activity",
                    block_heading="File access",
                    question_text=question,
                )
                self.assertEqual("answered", answer["status"])
                self.assertEqual(
                    ["quarterly_budget.xlsx"],
                    [row["file_name"] for row in answer["answer"]],
                )
                self.assertEqual(["mft-target"], list(answer["evidence"]))
                self.assertEqual([], answer["missing_reason"])
                exported = json.loads(
                    (
                        db.case.reports_dir / "structured/discovered-file.json"
                    ).read_text()
                )
                self.assertEqual(question, exported["question_text"])
                self.assertEqual(
                    ["quarterly_budget.xlsx"],
                    [row["file_name"] for row in exported["answer"]],
                )
                self.assertEqual([], exported["missing_reason"])
                csv_text = (db.case.reports_dir / exported["csv_path"]).read_text()
                self.assertIn("quarterly_budget.xlsx", csv_text)
                self.assertNotIn("mft-other-user", exported["evidence"])
                from forensia.report.answers.answer_store import (
                    _render_structured_answer_markdown,
                )

                markdown = _render_structured_answer_markdown(exported, "File access")
                self.assertIn("quarterly_budget.xlsx", markdown)
                from forensia.report.render.html import render_markdown_fragment

                html = str(render_markdown_fragment(markdown))
                self.assertIn("quarterly_budget.xlsx", html)

    def test_block_questions_revalidate_status_only_resolved_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            state = SessionState(session_id="S-1")
            first = "Check event 4624 for user alice"
            second = "Check event 4624 for user alicia"
            requests = [
                {
                    "section_key": "activity",
                    "block_heading": "Logons",
                    "question_text": first,
                },
                {
                    "section_key": "activity",
                    "block_heading": "Logons",
                    "question_text": second,
                },
            ]
            with CaseDB(case) as db:
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=[],
                    session_id="S-1",
                    question_requests=requests,
                    llm_output={
                        "required_entities": [],
                        "confirm_when": {
                            "co_observed_event_ids": [4624],
                            "event_contexts": [
                                {
                                    "event_id": 4624,
                                    "channel": "Security",
                                    "provider": "Microsoft-Windows-Security-Auditing",
                                }
                            ],
                        },
                    },
                )
                rows = db.execute(
                    "SELECT gap_id, block_heading, description FROM report_gaps "
                    "ORDER BY description"
                ).fetchall()
                self.assertEqual(
                    rows,
                    [
                        (
                            report_gap_id(
                                first, section_key="activity", block_heading="Logons"
                            ),
                            "Logons",
                            first,
                        ),
                        (
                            report_gap_id(
                                second, section_key="activity", block_heading="Logons"
                            ),
                            "Logons",
                            second,
                        ),
                    ],
                )
                links = db.execute(
                    "SELECT hypothesis_id FROM report_gaps ORDER BY description"
                ).fetchall()
                self.assertEqual([(None,), (None,)], links)
                self.assertEqual([], state.active_hypotheses)
                first_id = report_gap_id(
                    first, section_key="activity", block_heading="Logons"
                )
                second_id = report_gap_id(
                    second, section_key="activity", block_heading="Logons"
                )
                db.execute(
                    "UPDATE report_gaps SET status = 'resolved' WHERE gap_id = ?",
                    [first_id],
                )
                db.execute(
                    "UPDATE report_gaps SET status = 'needs_review', "
                    "coverage_reason = 'admission_unresolved-test' WHERE gap_id = ?",
                    [second_id],
                )
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=[],
                    session_id="S-1",
                    question_requests=requests,
                )
                status = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                    [first_id],
                ).fetchone()
                self.assertEqual(status, ("open", "question_relevance_unverified"))
                review_state = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                    [second_id],
                ).fetchone()
                self.assertEqual(
                    review_state, ("needs_review", "admission_unresolved-test")
                )

    def test_confirmed_child_does_not_resolve_explicit_question(self) -> None:
        from forensia.core.session import Hypothesis

        question = "Check event 4624 for user alice"
        section_key = "activity"
        block_heading = "Logons"
        gap_id = report_gap_id(
            question, section_key=section_key, block_heading=block_heading
        )
        child = Hypothesis(
            id="child-observation",
            description="An event 4624 exists for user alice",
            status="confirmed",
            source_gap_id=gap_id,
            confirm_when={"co_observed_event_ids": [4624]},
        )
        state = SessionState(
            session_id="S-child",
            resolved_hypotheses=[child],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=[],
                    session_id="S-child",
                    question_requests=[
                        {
                            "section_key": section_key,
                            "block_heading": block_heading,
                            "question_text": question,
                        }
                    ],
                    llm_output={
                        "required_entities": [],
                        "confirm_when": {
                            "co_observed_event_ids": [4624],
                            "event_contexts": [
                                {
                                    "event_id": 4624,
                                    "channel": "Security",
                                    "provider": "Microsoft-Windows-Security-Auditing",
                                }
                            ],
                        },
                    },
                )
                row = db.execute(
                    "SELECT status, hypothesis_id FROM report_gaps WHERE gap_id = ?",
                    [gap_id],
                ).fetchone()
                self.assertEqual(row[0], "open")
                self.assertNotEqual(row[1], child.id)

    def test_prose_absence_keeps_gap_and_task_open_in_case_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            state = SessionState(session_id="S-1")
            with CaseDB(case) as db:
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=["External reputation lookup for 203.0.113.5"],
                    session_id="S-1",
                )
                self.assertEqual(
                    db.execute("SELECT status FROM investigation_tasks").fetchone()[0],
                    "open",
                )
                # The request prose vanishing is a report-side edit, not a
                # resolution: the Gap and its Task stay open in Case State.
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=[],
                    session_id="S-1",
                )
                gap_row = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps"
                ).fetchone()
                self.assertEqual(gap_row, ("open", "report_request_absent"))
                self.assertEqual(
                    db.execute("SELECT status FROM investigation_tasks").fetchone()[0],
                    "open",
                )
                self.assertEqual(
                    db.execute("SELECT reason FROM investigation_tasks").fetchone()[0],
                    "report_request_absent",
                )
                # A real conclusion owner can close the Task.
                db.execute(
                    "UPDATE investigation_tasks SET status = 'resolved', "
                    "updated_at = now()"
                )
