"""Integration tests for the R8-04 Gap/Task/termination state machine."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest

from forensia.ai.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.ai.investigation.work_state import (
    classify_active_hypotheses_on_stop,
    ensure_objective_gap,
    format_stop_reason,
    reopen_retryable_work,
    resolve_linked_work,
    stop_summary,
)
from forensia.ai.report_gap import inject_gap_hypotheses
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
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


class StopClassificationTests(unittest.TestCase):
    def test_stop_classifies_and_persists_linked_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                deferred = _insert_hypothesis(db, "H-001")
                blocked = _insert_hypothesis(
                    db, "H-002", blocked_reason="waiting for acquired source"
                )
                review = _insert_hypothesis(db, "H-003", sufficiency="partial")
                db.execute(
                    "INSERT INTO hypothesis_reasoning "
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

    def test_unrelated_question_in_same_section_cannot_complete_old_work(self) -> None:
        from forensia.ai.investigation.investigator import (
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
                    cycle_progress=False,
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
                    "INSERT INTO hypothesis_reasoning "
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
                summary = stop_summary(db)
                reason = format_stop_reason("stopped", "no_progress_limit", summary)
                self.assertEqual(summary["deferred"], 1)
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
