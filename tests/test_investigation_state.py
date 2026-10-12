"""Tests for M1/M3: investigation state, report gaps, and investigation tasks."""

from __future__ import annotations

import json
import tempfile
import unittest
from unittest import mock

from forensia.core.case import Case
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
                                {"status": "admission_rejected", "draft_calls_used": 1}
                            ),
                        ],
                    )

                remaining, exhausted = _select_gap_drafts(
                    ctx, _persisted_gap_drafts(ctx), limit=1
                )

        self.assertEqual(exhausted, 4)
        self.assertEqual(remaining[0]["candidate"]["candidate_ref"], "gap-GAP-4")

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

    def test_interrupted_candidate_attempt_consumes_draft_budget_on_resume(
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
                        json.dumps({"status": "interrupted", "draft_calls_used": 1}),
                    ],
                )

                selected, counts = _select_candidate_drafts(ctx, limit=1)

        self.assertEqual(selected, [])
        self.assertEqual(counts["attempt_exhausted_count"], 1)

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
