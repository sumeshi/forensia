"""Tests for M1/M3: investigation state, report gaps, and investigation tasks."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.report_gap import inject_gap_hypotheses, project_investigation_tasks
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import (
    ensure_investigation_state,
    load_investigation_state,
    mark_investigation_started,
    save_stop_reason,
)


class InvestigationStateTests(unittest.TestCase):
    """Test investigation_state singleton table."""

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
                ensure_investigation_state(db, objective="profile objective")
                mark_investigation_started(db)
                state = load_investigation_state(db)
                self.assertEqual(state["objective"], "human objective")
                self.assertEqual(state["termination_policy"], {"max_iterations": 4})
                self.assertEqual(state["status"], "active")
                self.assertEqual(state["stop_reason_code"], "")


class ReportGapsTests(unittest.TestCase):
    """Test report_gaps table."""

    def test_prose_absence_keeps_gap_task_open_and_projected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            state = SessionState(session_id="S-1")
            with CaseDB(case) as db:
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=["External reputation lookup for 203.0.113.5"],
                    session_id="S-1",
                    memory=memory,
                )
                self.assertEqual(
                    db.execute("SELECT status FROM investigation_tasks").fetchone()[0],
                    "open",
                )
                self.assertIn(
                    "External reputation lookup",
                    memory.tasks_memory_path.read_text(encoding="utf-8"),
                )
                # The request prose vanishing is a report-side edit, not a
                # resolution: the Gap and its Task stay open and the Memory
                # projection keeps listing the work (T05, GOAL 9.4).
                inject_gap_hypotheses(
                    db=db,
                    state=state,
                    gaps=[],
                    session_id="S-1",
                    memory=memory,
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
                self.assertIn(
                    "External reputation lookup",
                    memory.tasks_memory_path.read_text(encoding="utf-8"),
                )
                # A real conclusion owner closing the Task removes it from the
                # Memory projection.
                db.execute(
                    "UPDATE investigation_tasks SET status = 'resolved', "
                    "updated_at = now()"
                )
                project_investigation_tasks(db, memory)
                self.assertIn(
                    "## Investigation Tasks\n- none",
                    memory.tasks_memory_path.read_text(encoding="utf-8"),
                )
