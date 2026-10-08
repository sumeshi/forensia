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

    def test_insert_and_read_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO investigation_state (state_id, objective, status) "
                    "VALUES ('case', 'Find the attacker', 'active')"
                )
                row = db.execute(
                    "SELECT objective, status FROM investigation_state WHERE state_id = 'case'"
                ).fetchone()
                self.assertEqual(row[0], "Find the attacker")
                self.assertEqual(row[1], "active")

    def test_update_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO investigation_state (state_id, status) VALUES ('case', 'active')"
                )
                db.execute(
                    "UPDATE investigation_state SET status = 'completed', stop_reason_code = 'no_gaps' "
                    "WHERE state_id = 'case'"
                )
                row = db.execute(
                    "SELECT status, stop_reason_code FROM investigation_state WHERE state_id = 'case'"
                ).fetchone()
                self.assertEqual(row[0], "completed")
                self.assertEqual(row[1], "no_gaps")

    def test_hypothesis_new_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, selection_count, "
                    "sufficiency_status, human_review_required) "
                    "VALUES ('H-001', 'test hypothesis', 'active', 3, 'sufficient', FALSE)"
                )
                row = db.execute(
                    "SELECT selection_count, sufficiency_status, human_review_required "
                    "FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], 3)
                self.assertEqual(row[1], "sufficient")
                self.assertFalse(row[2])

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

    def test_insert_and_query_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, description, kind, status) "
                    "VALUES ('GAP-001', '3_technical', 'Missing 4688 data', 'internal_db_check', 'open')"
                )
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, description, kind, status) "
                    "VALUES ('GAP-002', '4_gaps', 'Need external lookup', 'external_lookup', 'open')"
                )
                rows = db.execute(
                    "SELECT gap_id, kind FROM report_gaps WHERE status = 'open'"
                ).fetchall()
                self.assertEqual(len(rows), 2)
                kinds = {r[0]: r[1] for r in rows}
                self.assertEqual(kinds["GAP-001"], "internal_db_check")
                self.assertEqual(kinds["GAP-002"], "external_lookup")

    def test_gap_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, description, kind, status) "
                    "VALUES ('GAP-001', '3_technical', 'test', 'internal_db_check', 'open')"
                )
                db.execute(
                    "UPDATE report_gaps SET status = 'resolved' WHERE gap_id = 'GAP-001'"
                )
                row = db.execute(
                    "SELECT status FROM report_gaps WHERE gap_id = 'GAP-001'"
                ).fetchone()
                self.assertEqual(row[0], "resolved")

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


class InvestigationTasksTests(unittest.TestCase):
    """Test investigation_tasks table."""

    def test_insert_and_query_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO investigation_tasks (task_id, kind, description, status, "
                    "required_capability) VALUES ('TASK-001', 'collect_evidence', "
                    "'Obtain Security log for host X', 'open', 'process_execution')"
                )
                row = db.execute(
                    "SELECT kind, status, required_capability FROM investigation_tasks WHERE task_id = 'TASK-001'"
                ).fetchone()
                self.assertEqual(row[0], "collect_evidence")
                self.assertEqual(row[1], "open")
                self.assertEqual(row[2], "process_execution")

    def test_task_linked_to_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_gaps (gap_id, section_key, description, kind, status) "
                    "VALUES ('GAP-001', '3_technical', 'test', 'evidence_acquisition', 'open')"
                )
                db.execute(
                    "INSERT INTO investigation_tasks (task_id, kind, description, status, gap_id) "
                    "VALUES ('TASK-001', 'collect_evidence', 'Get Security log', 'open', 'GAP-001')"
                )
                row = db.execute(
                    "SELECT t.description FROM investigation_tasks t "
                    "JOIN report_gaps g ON t.gap_id = g.gap_id "
                    "WHERE g.gap_id = 'GAP-001'"
                ).fetchone()
                self.assertIsNotNone(row)
