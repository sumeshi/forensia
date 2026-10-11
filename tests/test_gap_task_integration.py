"""Integration tests for the R8-04 Gap/Task/termination state machine."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest

from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.investigation.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.investigation.investigator import _durable_open_work_counts
from forensia.investigation.report_gap import (
    evaluation_snapshot,
    inject_gap_hypotheses,
    report_cycle_progress,
)
from forensia.investigation.verification.sufficiency import (
    create_hypothesis_evidence_link,
)
from forensia.investigation.work_judgment import (
    judge_work,
    open_work_refs,
    work_context_snapshot,
)
from forensia.investigation.work_state import (
    classify_active_hypotheses_on_stop,
    ensure_objective_gap,
    format_stop_reason,
    reopen_retryable_work,
    resolve_linked_work,
    stop_summary,
)
from forensia.report.answers.gap_tables import _build_gaps_unresolved_table
from forensia.report.report_validation import check_work_state_consistency


def _insert_hypothesis(
    db: CaseDB,
    hypothesis_id: str,
    *,
    sufficiency: str = "",
    blocked_reason: str = "",
) -> Hypothesis:
    db.execute(
        "INSERT INTO hypotheses (hypothesis_id, description, status, "
        "sufficiency_status, blocked_reason, created_at, updated_at, "
        "verification_spec) "
        "VALUES (?, ?, 'active', ?, ?, now(), now(), '{\"spec_version\": \"1\"}')",
        [hypothesis_id, f"Description {hypothesis_id}", sufficiency, blocked_reason],
    )
    return Hypothesis(id=hypothesis_id, description=f"Description {hypothesis_id}")


class WorkContextSnapshotTests(unittest.TestCase):
    """V2-07: the per-attempt context is selected deterministically from Case/Trace."""

    _SPEC = {
        "spec_version": "1",
        "support_conditions": {
            "co_observed_event_ids": [4624, 4104],
            "same_entities": ["src_ip"],
        },
        "required_capabilities": ["logon"],
    }

    def _seed(self, db: CaseDB) -> None:
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
            "VALUES ('evtx-w1', 'sha-w1', 4624)"
        )
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
            "VALUES ('evtx-w2', 'sha-w2', 4104)"
        )
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
            "VALUES ('evtx-w3', 'sha-w3', 4624)"
        )
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
            "VALUES ('evtx-w4', 'sha-w4', 4624)"
        )
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status, "
            "created_at, updated_at, verification_spec) VALUES "
            "('H-WC', 'co-observed logon', 'active', now(), now(), ?)",
            [json.dumps(self._SPEC)],
        )
        db.execute(
            "INSERT INTO evidence_coverage (capability, source_family, state) "
            "VALUES ('logon', 'evtx', 'available')"
        )
        create_hypothesis_evidence_link(
            db,
            hypothesis_id="H-WC",
            evidence_id="evtx-w1",
            role="supporting",
            query_id="Q-1",
            assessment_id="EA-1",
            matched_conditions=("co_observed_event_ids",),
        )
        create_hypothesis_evidence_link(
            db,
            hypothesis_id="H-WC",
            evidence_id="evtx-w2",
            role="contradictory",
            query_id="Q-2",
            assessment_id="EA-2",
            matched_conditions=("co_observed_event_ids",),
        )
        create_hypothesis_evidence_link(
            db,
            hypothesis_id="H-WC",
            evidence_id="evtx-w3",
            role="supporting",
            query_id="Q-3",
            assessment_id="EA-3",
            matched_conditions=("co_observed_event_ids",),
        )
        create_hypothesis_evidence_link(
            db,
            hypothesis_id="H-WC",
            evidence_id="evtx-w4",
            role="supporting",
        )
        # The third link's backing row disappears: the recorded judgment is
        # kept as history but is no longer current support.
        db.execute("DELETE FROM evtx_events WHERE evidence_id = 'evtx-w3'")

    def test_same_originals_and_work_resolve_the_same_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._seed(db)
                db.execute(
                    "INSERT INTO investigation_tasks (task_id, kind, status, "
                    "hypothesis_id, created_at, updated_at) "
                    "VALUES ('TASK-WC', 'human_decision', 'open', 'H-WC', now(), now())"
                )
                snapshot = work_context_snapshot(db, "H-WC")
                self.assertIsNotNone(snapshot)
                # Same originals + work → same context (deterministic).
                self.assertEqual(snapshot, work_context_snapshot(db, "H-WC"))
                self.assertEqual(snapshot.status, "active")
                self.assertEqual(snapshot.capabilities, ("logon",))
                self.assertEqual(snapshot.unready_capabilities, ())
                # Consumption checks currentness first: matched conditions only
                # count on currently-current assessed links.
                self.assertEqual(
                    snapshot.unmet_conditions,
                    ('same_entities=["src_ip"]',),
                )
                self.assertEqual(
                    snapshot.support_roots[0],
                    "evidence=evtx-w1 assessment=EA-1 query=Q-1",
                )
                self.assertEqual(
                    snapshot.contradiction_roots,
                    ("evidence=evtx-w2 assessment=EA-2 query=Q-2",),
                )
                # Stale material is named with its currentness reason and is
                # never presented as current support.
                self.assertEqual(
                    snapshot.reevaluation_required,
                    ("evidence=evtx-w3 reason=evidence_row_missing",),
                )
                self.assertEqual(
                    snapshot.requirements,
                    (
                        "blocked: waiting for external investigation task",
                        "external task=TASK-WC",
                        "task=TASK-WC",
                    ),
                )


class StopClassificationTests(unittest.TestCase):
    def test_typed_observation_infeasibility_blocks_selection_and_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-OBS")
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ?, required_entities = ? "
                    "WHERE hypothesis_id = ?",
                    [
                        json.dumps(
                            {
                                "spec_version": "1",
                                "support_conditions": {
                                    "observation": {
                                        "family": "prefetch",
                                        "capability": "process_execution",
                                        "field": "executable_name",
                                        "operator": "equals",
                                        "value": "cmd.exe",
                                    },
                                    "min_count": 2,
                                },
                            }
                        ),
                        "[]",
                        hypothesis.id,
                    ],
                )
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) "
                    "VALUES ('prefetch-one', 'cmd.exe'), ('prefetch-one', 'cmd.exe')"
                )
                db.execute(
                    "INSERT INTO evidence_coverage (capability, source_family, state) "
                    "VALUES ('process_execution', 'prefetch', 'available')"
                )

                judgment = judge_work(db, [hypothesis.id], selection_gate=True)[
                    hypothesis.id
                ]
                self.assertFalse(judgment.runnable)
                self.assertEqual(judgment.retry_condition, "new_evidence_or_coverage")
                counts = classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                self.assertEqual(counts["blocked"], 1)
                task = db.execute(
                    "SELECT kind, retry_condition, reason FROM investigation_tasks "
                    "WHERE hypothesis_id = ?",
                    [hypothesis.id],
                ).fetchone()
                self.assertEqual(task[0], "blocked")
                self.assertEqual(task[1], "new_evidence_or_coverage")
                self.assertIn("current-family-count:1", task[2])
                self.assertEqual(reopen_retryable_work(db, manual_resume=True), [])

                db.execute(
                    "UPDATE investigation_tasks SET updated_at = now() - INTERVAL '1 day' "
                    "WHERE hypothesis_id = ?",
                    [hypothesis.id],
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, updated_at) "
                    "VALUES ('prefetch-source-1', 'prefetch', 'normalized', now())"
                )
                self.assertEqual(reopen_retryable_work(db), [])
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) "
                    "VALUES ('prefetch-two', 'cmd.exe')"
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, updated_at) "
                    "VALUES ('prefetch-source-2', 'prefetch', 'normalized', now())"
                )
                self.assertEqual(reopen_retryable_work(db), [hypothesis.id])

    def test_unobservable_typed_entity_is_a_reviewable_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-OBS-ENTITY")
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ?, required_entities = ? "
                    "WHERE hypothesis_id = ?",
                    [
                        json.dumps(
                            {
                                "spec_version": "1",
                                "support_conditions": {
                                    "observation": {
                                        "family": "prefetch",
                                        "capability": "process_execution",
                                        "field": "executable_name",
                                        "operator": "equals",
                                        "value": "cmd.exe",
                                    }
                                },
                            }
                        ),
                        '["computer"]',
                        hypothesis.id,
                    ],
                )
                judgment = judge_work(db, [hypothesis.id])[hypothesis.id]
                self.assertFalse(judgment.runnable)
                self.assertTrue(
                    any(
                        blocker.code == "observation_required_entity_unobservable"
                        and blocker.owner
                        == "required entity columns absent from canonical schema: computer"
                        for blocker in judgment.blockers
                    )
                )
                self.assertEqual(judgment.retry_condition, "human_or_external_result")
                counts = classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                self.assertEqual(counts["blocked"], 1)
                self.assertEqual(
                    db.execute(
                        "SELECT retry_condition FROM investigation_tasks "
                        "WHERE hypothesis_id = ?",
                        [hypothesis.id],
                    ).fetchone()[0],
                    "human_or_external_result",
                )
                self.assertEqual(reopen_retryable_work(db, manual_resume=True), [])
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, updated_at) "
                    "VALUES ('prefetch-new', 'prefetch', 'normalized', now())"
                )
                self.assertEqual(reopen_retryable_work(db), [])

    def test_stop_classifies_and_persists_linked_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                deferred = _insert_hypothesis(db, "H-001")
                blocked = _insert_hypothesis(
                    db, "H-002", blocked_reason="waiting for acquired source"
                )
                review = _insert_hypothesis(db, "H-003", sufficiency="partial")
                db.execute(
                    "INSERT INTO trace.hypothesis_reasoning "
                    "(entry_id, hypothesis_id, phase, body) VALUES "
                    "('R-3', 'H-003', 'check', 'partial result')"
                )
                counts = classify_active_hypotheses_on_stop(
                    db, [deferred, blocked, review], "no_progress_limit"
                )

                self.assertEqual(counts["deferred"], 1)
                self.assertEqual(counts["blocked"], 1)
                self.assertEqual(counts["needs_review"], 1)
                statuses = dict(
                    db.execute(
                        "SELECT hypothesis_id, status FROM hypotheses"
                    ).fetchall()
                )
                self.assertEqual(
                    statuses,
                    {"H-001": "deferred", "H-002": "blocked", "H-003": "needs_review"},
                )
                self.assertNotIn("active", statuses.values())

                task = db.execute(
                    "SELECT task_id, gap_id, owner_phase, retry_condition, "
                    "blocked_reason FROM investigation_tasks WHERE hypothesis_id = 'H-002'"
                ).fetchone()
                self.assertTrue(task[0].startswith("TASK-STOP-"))
                self.assertTrue(task[1].startswith("GAP-STOP-"))
                self.assertEqual(task[2], "termination")
                self.assertTrue(task[3])
                self.assertTrue(task[4])
                gap = db.execute(
                    "SELECT task_id, hypothesis_id, origin FROM report_gaps "
                    "WHERE gap_id = ?",
                    [task[1]],
                ).fetchone()
                self.assertEqual(gap, (task[0], "H-002", "termination"))

    def test_unobservable_is_really_untestable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001", sufficiency="unobservable")
                counts = classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                self.assertEqual(counts["untestable"], 1)
                self.assertEqual(hypothesis.status, "untestable")

    def test_preclassified_untestable_gets_linked_work_on_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                _insert_hypothesis(db, "H-001")
                db.execute(
                    "UPDATE hypotheses SET status = 'untestable', "
                    "blocked_reason = 'Required telemetry is unavailable' "
                    "WHERE hypothesis_id = 'H-001'"
                )

                classify_active_hypotheses_on_stop(db, [], "no_progress_limit")

                task = db.execute(
                    "SELECT kind, status, gap_id FROM investigation_tasks "
                    "WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(task[0:2], ("untestable", "open"))
                self.assertEqual(
                    db.execute(
                        "SELECT status, task_id FROM report_gaps WHERE gap_id = ?",
                        [task[2]],
                    ).fetchone(),
                    (
                        "open",
                        db.execute(
                            "SELECT task_id FROM investigation_tasks "
                            "WHERE hypothesis_id = 'H-001'"
                        ).fetchone()[0],
                    ),
                )
                self.assertFalse(check_work_state_consistency(db))

    def test_second_stop_updates_existing_task_without_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(db, [hypothesis], "first_stop")
                db.execute(
                    "UPDATE hypotheses SET status = 'active', blocked_reason = 'blocked now' "
                    "WHERE hypothesis_id = 'H-001'"
                )
                hypothesis.status = "active"
                classify_active_hypotheses_on_stop(db, [hypothesis], "second_stop")
                row = db.execute(
                    "SELECT COUNT(*), MAX(kind), MAX(reason) FROM investigation_tasks "
                    "WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], 1)
                self.assertEqual(row[1], "blocked")
                self.assertIn("second_stop", row[2])


class ObjectiveAndGapStoreTests(unittest.TestCase):
    def test_objective_gap_opens_and_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                gap_id = ensure_objective_gap(db, "")
                self.assertEqual(
                    db.execute(
                        "SELECT status, origin FROM report_gaps WHERE gap_id = ?",
                        [gap_id],
                    ).fetchone(),
                    ("open", "configuration"),
                )
                ensure_objective_gap(db, "Determine whether an intrusion occurred")
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM report_gaps WHERE gap_id = ?", [gap_id]
                    ).fetchone()[0],
                    "resolved",
                )

    def test_three_section_gaps_reach_persisted_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                gaps = [
                    "Acquire cloud audit export",
                    "Acquire mailbox audit export",
                    "Acquire perimeter network telemetry",
                ]
                inject_gap_hypotheses(db, state, gaps, "S-1")
                rows = db.execute(
                    "SELECT origin FROM report_gaps WHERE status = 'needs_review'"
                ).fetchall()
                self.assertEqual(len(rows), 3)
                self.assertEqual({row[0] for row in rows}, {"section"})

    def test_section_refresh_does_not_resolve_termination_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                inject_gap_hypotheses(db, SessionState(session_id="S-1"), [], "S-1")
                row = db.execute(
                    "SELECT status FROM report_gaps WHERE origin = 'termination'"
                ).fetchone()
                self.assertEqual(row[0], "open")


class ProseChangeResolutionTests(unittest.TestCase):
    """T05: report wording changes are not resolutions of admitted work."""

    @staticmethod
    def _gap_id(gap: str) -> str:
        return "GAP-" + hashlib.sha256(gap.encode()).hexdigest()[:16]

    def test_reworded_gap_keeps_admitted_work_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                old_gap = "External reputation lookup for 203.0.113.5"
                db.execute(
                    "INSERT INTO report_sections (section_key, title, gaps) "
                    "VALUES ('summary', 'Summary', ?)",
                    [json.dumps([old_gap])],
                )
                inject_gap_hypotheses(db, state, [old_gap], "S-1")
                old_id = self._gap_id(old_gap)
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM report_gaps WHERE gap_id = ?", [old_id]
                    ).fetchone()[0],
                    "open",
                )
                new_gap = "External reputation lookup for the IP 203.0.113.5"
                db.execute(
                    "UPDATE report_sections SET gaps = ? WHERE section_key = 'summary'",
                    [json.dumps([new_gap])],
                )
                inject_gap_hypotheses(db, state, [new_gap], "S-1")
                old_row = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                    [old_id],
                ).fetchone()
                self.assertEqual(old_row[0], "open")
                self.assertEqual(old_row[1], "report_request_absent")
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM investigation_tasks WHERE gap_id = ?",
                        [old_id],
                    ).fetchone()[0],
                    "open",
                )
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM report_gaps WHERE gap_id = ?",
                        [self._gap_id(new_gap)],
                    ).fetchone()[0],
                    "open",
                )

    def test_prose_absent_without_successor_keeps_gap_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                gap = "Confirm successful logon event 4624 for host WS-1"
                gap_id = self._gap_id(gap)
                db.execute(
                    "INSERT INTO report_gaps (gap_id, description, kind, status, "
                    "origin) VALUES (?, ?, 'internal_db_check', 'open', 'section')",
                    [gap_id, gap],
                )
                # Request withdrawn from the prose with no reworded successor:
                # the Gap stays open with the absence recorded.
                inject_gap_hypotheses(db, state, [], "S-1")
                row = db.execute(
                    "SELECT status, coverage_reason FROM report_gaps WHERE gap_id = ?",
                    [gap_id],
                ).fetchone()
                self.assertEqual(row, ("open", "report_request_absent"))

    def test_human_origin_survives_section_refresh_and_orphaning(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                gap = "Confirm successful logon event 4624 for host WS-1"
                gap_id = self._gap_id(gap)
                db.execute(
                    "INSERT INTO report_sections (section_key, title, gaps) "
                    "VALUES ('summary', 'Summary', ?)",
                    [json.dumps([gap])],
                )
                inject_gap_hypotheses(db, state, [gap], "S-1")
                inject_gap_hypotheses(db, state, [gap], "S-1", origin="human")
                inject_gap_hypotheses(db, state, [gap], "S-1")

                # The section later drops the request. It remains human-owned,
                # so a section refresh cannot mark it as an orphaned request.
                db.execute(
                    "UPDATE report_sections SET gaps = '[]' WHERE section_key = 'summary'"
                )
                inject_gap_hypotheses(db, state, [], "S-1")
                row = db.execute(
                    "SELECT status, origin, coverage_reason FROM report_gaps "
                    "WHERE gap_id = ?",
                    [gap_id],
                ).fetchone()
                self.assertEqual(row[1], "human")
                self.assertEqual(row[2], "admission_non-testable-verification-spec")

    def test_unrelated_question_in_same_section_cannot_complete_old_work(self) -> None:
        from forensia.investigation.investigator import (
            _check_termination,
            _durable_open_work_counts,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                old = "External reputation lookup for 203.0.113.5"
                new = "Manager approval for incident response action"
                db.execute(
                    "INSERT INTO report_sections (section_key, title, gaps) "
                    "VALUES ('4_gaps', 'Gaps', ?)",
                    [json.dumps([old])],
                )
                inject_gap_hypotheses(db, state, [old], "S-1")
                db.execute("UPDATE report_sections SET gaps = ?", [json.dumps([new])])
                inject_gap_hypotheses(db, state, [new], "S-1")
                # Only the new human work was completed; the original external
                # lookup has no conclusion or explicit withdrawal.
                db.execute(
                    "UPDATE investigation_tasks SET status = 'resolved' WHERE gap_id = ?",
                    [self._gap_id(new)],
                )
                db.execute(
                    "UPDATE report_gaps SET status = 'resolved' WHERE gap_id = ?",
                    [self._gap_id(new)],
                )
                self.assertEqual(_durable_open_work_counts(db), (1, 1))
                status, _, _ = _check_termination(
                    report_only=False,
                    broad_plan_stop=True,
                    active_hypotheses=[],
                    durable_open_gaps=1,
                    durable_open_tasks=1,
                    no_progress_count=0,
                    no_progress_limit=3,
                    evaluation_changed=False,
                )
                self.assertIsNone(status)

    def test_untestable_linked_hypothesis_keeps_gap_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                gap = "Confirm successful logon event 4624 for host WS-1"
                state = SessionState(
                    session_id="S-1",
                    resolved_hypotheses=[
                        Hypothesis(id="H-1", description=gap, status="untestable")
                    ],
                )
                added = inject_gap_hypotheses(db, state, [gap], "S-1")
                self.assertEqual(added, 0)
                row = db.execute(
                    "SELECT status, coverage_reason, hypothesis_id FROM report_gaps"
                ).fetchone()
                self.assertEqual(row[0], "open")
                self.assertEqual(row[1], "linked_hypothesis_untestable")
                self.assertEqual(row[2], "H-1")

    def test_confirmed_or_refuted_linked_hypothesis_resolves_gap(self) -> None:
        for status in ("confirmed", "refuted"):
            with tempfile.TemporaryDirectory() as tmpdir:
                with CaseDB(Case.init(tmpdir)) as db:
                    gap = "Confirm successful logon event 4624 for host WS-1"
                    state = SessionState(
                        session_id="S-1",
                        resolved_hypotheses=[
                            Hypothesis(id="H-1", description=gap, status=status)
                        ],
                    )
                    inject_gap_hypotheses(db, state, [gap], "S-1")
                    row = db.execute("SELECT status FROM report_gaps").fetchone()
                    self.assertEqual(row[0], "resolved")


class RetryAndProjectionTests(unittest.TestCase):
    def test_linked_stop_work_is_one_ref_not_two(self) -> None:
        """A terminal hypothesis's Gap+Task pair is one unresolved work item.

        The completion gate and blocker counts read per work ref (V2-03), so
        a linked pair cannot inflate open-item counts by describing the same
        work twice.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                unlinked = open_work_refs(db)
                self.assertEqual(len(unlinked), 1)
                self.assertEqual(unlinked[0].hypothesis_ids, ("H-001",))
                self.assertEqual(unlinked[0].gap_ids, ())
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                refs = open_work_refs(db)
                self.assertEqual(len(refs), 1)
                ref = refs[0]
                self.assertEqual(ref.ref_id, "H-001")
                self.assertEqual(len(ref.gap_ids), 1)
                self.assertEqual(len(ref.task_ids), 1)
                self.assertEqual(_durable_open_work_counts(db), (1, 1))
                before = evaluation_snapshot(db)
                _insert_hypothesis(db, "H-002")
                db.execute(
                    "UPDATE hypotheses SET source_gap_id = ? WHERE hypothesis_id = 'H-002'",
                    [ref.gap_ids[0]],
                )
                self.assertEqual(len(open_work_refs(db)), 1)
                self.assertTrue(report_cycle_progress(before, evaluation_snapshot(db)))

    def test_stop_persists_external_blocker_with_owner_and_retry(self) -> None:
        """Blocked work with no runnable action stops with persisted blocker,
        owner, and reopen condition — never recorded as completed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                inject_gap_hypotheses(
                    db,
                    state,
                    ["Manager approval for incident response action"],
                    "S-1",
                )
                classify_active_hypotheses_on_stop(db, [], "no_progress_limit")
                task = db.execute(
                    "SELECT kind, status, reason, retry_condition, owner_phase "
                    "FROM investigation_tasks WHERE kind = 'human_decision'"
                ).fetchone()
                self.assertEqual(task[1], "open")
                self.assertIn("human decision required", task[2])
                self.assertEqual(task[3], "human_or_external_result")
                self.assertEqual(task[4], "report_admission")
                # Externally-owned work never auto-reopens.
                self.assertEqual(reopen_retryable_work(db), [])

    def test_external_blocker_stays_owned_after_coverage_becomes_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-EXT")
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ? WHERE hypothesis_id = ?",
                    [json.dumps({"required_capabilities": ["logon"]}), hypothesis.id],
                )
                db.execute(
                    "INSERT INTO investigation_tasks "
                    "(task_id, kind, status, hypothesis_id, created_at, updated_at) "
                    "VALUES ('TASK-EXT', 'human_decision', 'open', 'H-EXT', now(), now())"
                )
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                condition = db.execute(
                    "SELECT retry_condition FROM investigation_tasks "
                    "WHERE hypothesis_id = 'H-EXT' AND owner_phase = 'termination'"
                ).fetchone()[0]
                self.assertEqual(condition, "human_or_external_result")
                db.execute(
                    "INSERT INTO evidence_coverage (capability, source_family, state) "
                    "VALUES ('logon', 'evtx', 'available')"
                )
                self.assertEqual(reopen_retryable_work(db), [])

    def test_gap_linked_external_task_blocks_its_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                _insert_hypothesis(db, "H-GAP")
                db.execute(
                    "INSERT INTO report_gaps "
                    "(gap_id, description, kind, status, hypothesis_id, task_id) "
                    "VALUES ('G-EXT', 'approval', 'human_decision', 'open', "
                    "'H-GAP', 'T-EXT')"
                )
                db.execute(
                    "INSERT INTO investigation_tasks "
                    "(task_id, kind, status, gap_id) "
                    "VALUES ('T-EXT', 'human_decision', 'open', 'G-EXT')"
                )
                judgment = judge_work(db, ["H-GAP"], selection_gate=True)["H-GAP"]
                self.assertFalse(judgment.runnable)
                self.assertEqual(judgment.external_task_ids, ("T-EXT",))
                self.assertEqual(judgment.retry_condition, "human_or_external_result")

    def test_reopen_checks_the_saved_retry_condition_not_kind(self) -> None:
        """The persisted retry_condition is the reopen contract (V2-03)."""
        for condition, should_reopen, manual_resume_reopens in (
            ("required_capability_available", True, False),
            ("new_evidence_or_human_review", False, False),
            ("new_evidence_or_manual_resume", False, True),
            ("human_or_external_result", False, False),
            (None, False, False),
        ):
            with self.subTest(condition=condition):
                with tempfile.TemporaryDirectory() as tmpdir:
                    with CaseDB(Case.init(tmpdir)) as db:
                        db.execute(
                            "INSERT INTO hypotheses (hypothesis_id, description, "
                            "status, created_at, updated_at, verification_spec) "
                            "VALUES ('H-CAP', 'needs telemetry', 'blocked', "
                            'now(), now(), \'{"spec_version": "1"}\')'
                        )
                        db.execute(
                            "INSERT INTO investigation_tasks "
                            "(task_id, kind, status, hypothesis_id, "
                            "required_capability, retry_condition, created_at, "
                            "updated_at) VALUES ('TASK-1', 'needs_review', 'open', "
                            "'H-CAP', 'logon', ?, now(), now())",
                            [condition],
                        )
                        db.execute(
                            "INSERT INTO evidence_coverage "
                            "(capability, source_family, state) "
                            "VALUES ('logon', 'evtx', 'available')"
                        )
                        reopened = reopen_retryable_work(db)
                        self.assertEqual(reopened, ["H-CAP"] if should_reopen else [])
                        if manual_resume_reopens:
                            self.assertEqual(
                                reopen_retryable_work(db, manual_resume=True),
                                ["H-CAP"],
                            )

    def test_new_evidence_retry_uses_latest_stop_as_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                _insert_hypothesis(db, "H-RETRY")
                db.execute(
                    "UPDATE hypotheses SET status = 'needs_review' "
                    "WHERE hypothesis_id = 'H-RETRY'"
                )
                db.execute(
                    "INSERT INTO investigation_tasks "
                    "(task_id, kind, status, hypothesis_id, retry_condition, "
                    "created_at, updated_at) VALUES "
                    "('TASK-RETRY', 'needs_review', 'open', 'H-RETRY', "
                    "'new_evidence_or_human_review', '2024-01-01', '2024-03-01')"
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, updated_at) VALUES "
                    "('SRC-1', 'evtx', 'normalized', '2024-02-01')"
                )
                self.assertEqual(reopen_retryable_work(db), [])
                db.execute(
                    "UPDATE evidence_sources SET updated_at = '2024-04-01' "
                    "WHERE source_id = 'SRC-1'"
                )
                self.assertEqual(reopen_retryable_work(db), ["H-RETRY"])

    def test_partial_coverage_reopens_blocked_work(self) -> None:
        """Selection, stop, and reopen share the ready rule: an
        available/partial Coverage row makes the capability retrievable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "created_at, updated_at, verification_spec) "
                    "VALUES ('H-SSO', 'suspicious logon series', 'blocked', "
                    "now(), now(), "
                    '\'{"spec_version": "1", '
                    '"required_capabilities": ["logon"]}\')'
                )
                db.execute(
                    "INSERT INTO investigation_tasks "
                    "(task_id, kind, status, hypothesis_id, required_capability, "
                    "owner_phase, retry_condition, created_at, updated_at) "
                    "VALUES ('TASK-SSO', 'blocked', 'open', 'H-SSO', 'logon', "
                    "'termination', 'required_capability_available', now(), now())"
                )
                db.execute(
                    "INSERT INTO evidence_coverage "
                    "(capability, source_family, state) "
                    "VALUES ('logon', 'evtx', 'partial')"
                )
                self.assertEqual(reopen_retryable_work(db), ["H-SSO"])

    def test_only_task_with_satisfied_capability_reopens(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                for hypothesis_id, capability in (
                    ("H-LOGON", "logon"),
                    ("H-POWERSHELL", "powershell"),
                ):
                    db.execute(
                        "INSERT INTO hypotheses (hypothesis_id, description, status, "
                        "created_at, updated_at, verification_spec) "
                        "VALUES (?, ?, 'blocked', now(), now(), "
                        '\'{"spec_version": "1"}\')',
                        [hypothesis_id, hypothesis_id],
                    )
                    db.execute(
                        "INSERT INTO investigation_tasks "
                        "(task_id, kind, status, hypothesis_id, required_capability, "
                        "owner_phase, retry_condition, created_at, updated_at) "
                        "VALUES (?, 'blocked', 'open', ?, ?, 'termination', "
                        "'required_capability_available', now(), now())",
                        [f"TASK-{hypothesis_id}", hypothesis_id, capability],
                    )
                db.execute(
                    "INSERT INTO evidence_coverage "
                    "(capability, source_family, state, source_ids, derived_at) "
                    "VALUES ('logon', 'evtx', 'available', ['src-1'], now())"
                )
                reopened = reopen_retryable_work(db)
                self.assertEqual(reopened, ["H-LOGON"])
                statuses = dict(
                    db.execute(
                        "SELECT hypothesis_id, status FROM hypotheses"
                    ).fetchall()
                )
                self.assertEqual(statuses["H-LOGON"], "active")
                self.assertEqual(statuses["H-POWERSHELL"], "blocked")

    def test_spec_declared_capabilities_preferred_for_stop_task(self) -> None:
        """T02: work state reads declared caps from the canonical spec."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec, created_at, updated_at) "
                    "VALUES (?, ?, 'active', ?, now(), now())",
                    [
                        "H-SPEC-CAPS",
                        "registry persistence hypothesis",
                        json.dumps(
                            {
                                "spec_version": "1",
                                "required_capabilities": ["registry_observation"],
                            }
                        ),
                    ],
                )
                hypothesis = Hypothesis(
                    id="H-SPEC-CAPS", description="registry persistence hypothesis"
                )
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                row = db.execute(
                    "SELECT required_capability FROM investigation_tasks "
                    "WHERE hypothesis_id = 'H-SPEC-CAPS'"
                ).fetchone()
                self.assertEqual(row[0], "registry_observation")

    def test_terminal_needs_review_is_not_loaded_until_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001", sufficiency="partial")
                db.execute(
                    "INSERT INTO trace.hypothesis_reasoning "
                    "(entry_id, hypothesis_id, phase, body) "
                    "VALUES ('R-1', 'H-001', 'check', 'partial')"
                )
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                active, resolved = load_persisted_hypotheses(db)
                self.assertEqual(active, [])
                self.assertEqual([item.id for item in resolved], ["H-001"])

    def test_conclusive_resolution_closes_linked_task_and_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                resolve_linked_work(db, "H-001")
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM investigation_tasks "
                        "WHERE hypothesis_id = 'H-001'"
                    ).fetchone()[0],
                    "resolved",
                )
                self.assertEqual(
                    db.execute(
                        "SELECT status FROM report_gaps WHERE hypothesis_id = 'H-001'"
                    ).fetchone()[0],
                    "resolved",
                )

    def test_report_and_persisted_rows_share_task_gap_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                report_row = _build_gaps_unresolved_table(db)[0]
                task_row = db.execute(
                    "SELECT task_id, gap_id, hypothesis_id FROM investigation_tasks "
                    "WHERE status = 'open'"
                ).fetchone()
                gap_row = db.execute(
                    "SELECT gap_id, hypothesis_id FROM report_gaps WHERE status = 'open'"
                ).fetchone()
                self.assertEqual(report_row["task_id"], task_row[0])
                self.assertEqual(report_row["gap_id"], gap_row[0])
                self.assertEqual(task_row[1], gap_row[0])
                self.assertEqual(task_row[2], report_row["hypothesis_id"])


class StopSummaryTests(unittest.TestCase):
    def test_summary_is_machine_readable_and_code_stays_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                for index, status in enumerate(
                    (
                        "blocked",
                        "blocked",
                        "blocked",
                        "blocked",
                        "needs_review",
                        "untestable",
                        "confirmed",
                        "refuted",
                    ),
                    start=2,
                ):
                    _insert_hypothesis(db, f"H-{index:03}")
                    db.execute(
                        "UPDATE hypotheses SET status = ? WHERE hypothesis_id = ?",
                        [status, f"H-{index:03}"],
                    )
                summary = stop_summary(db)
                reason = format_stop_reason("stopped", "no_progress_limit", summary)
                self.assertEqual(summary["deferred"], 1)
                self.assertEqual(summary["blocked"], 4)
                self.assertEqual(summary["needs_review"], 1)
                self.assertEqual(summary["untestable"], 1)
                self.assertEqual(summary["resolved"], 2)
                self.assertEqual(summary["active"], 0)
                self.assertIn("deferred=1", reason)
                self.assertNotIn("active=1", reason)

    def test_validation_rejects_stopped_case_with_active_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                _insert_hypothesis(db, "H-001")
                db.execute(
                    "INSERT INTO investigation_state "
                    "(state_id, objective, status, created_at, updated_at) "
                    "VALUES ('case', 'test', 'stopped', now(), now())"
                )
                findings = check_work_state_consistency(db)
                self.assertTrue(
                    any(
                        "retains active hypothesis" in item.message for item in findings
                    )
                )


if __name__ == "__main__":
    unittest.main()
