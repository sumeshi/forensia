"""Integration tests for the R8-04 Gap/Task/termination state machine."""

from __future__ import annotations

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
from forensia.api.service_investigation import (
    list_investigation_tasks_dto,
    list_report_gaps_dto,
)
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
        "sufficiency_status, blocked_reason, created_at, updated_at) "
        "VALUES (?, ?, 'active', ?, ?, now(), now())",
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

    def test_three_section_gaps_reach_store_and_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                state = SessionState(session_id="S-1")
                gaps = [
                    "Acquire cloud audit export",
                    "Acquire mailbox audit export",
                    "Acquire perimeter network telemetry",
                ]
                inject_gap_hypotheses(db, state, gaps, "S-1")
                api_gaps = list_report_gaps_dto(db, status="open")
                self.assertEqual(len(api_gaps), 3)
                self.assertEqual({gap.origin for gap in api_gaps}, {"section"})

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
                        "created_at, updated_at) VALUES (?, ?, 'blocked', now(), now())",
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

    def test_report_and_api_share_task_gap_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                hypothesis = _insert_hypothesis(db, "H-001")
                classify_active_hypotheses_on_stop(
                    db, [hypothesis], "no_progress_limit"
                )
                report_row = _build_gaps_unresolved_table(db)[0]
                api_task = list_investigation_tasks_dto(db, status="open")[0]
                api_gap = list_report_gaps_dto(db, status="open")[0]
                self.assertEqual(report_row["task_id"], api_task.task_id)
                self.assertEqual(report_row["gap_id"], api_gap.gap_id)
                self.assertEqual(api_task.gap_id, api_gap.gap_id)
                self.assertEqual(api_task.hypothesis_id, report_row["hypothesis_id"])


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
