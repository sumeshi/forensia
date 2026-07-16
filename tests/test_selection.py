"""Tests for M4: deterministic next-best hypothesis selection."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.investigation.selection import (
    SelectionContext,
    check_eligibility,
    compute_priority_score,
    select_focus_hypotheses,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


class EligibilityTests(unittest.TestCase):
    """Test eligibility filtering."""

    def test_active_hypothesis_eligible(self) -> None:
        hyp = {"status": "active", "blocked_reason": "", "next_eligible_at": None}
        eligible, reason = check_eligibility(hyp)
        self.assertTrue(eligible)
        self.assertEqual(reason, "")

    def test_resolved_hypothesis_not_eligible(self) -> None:
        hyp = {"status": "resolved", "blocked_reason": "", "next_eligible_at": None}
        eligible, reason = check_eligibility(hyp)
        self.assertFalse(eligible)
        self.assertIn("resolved", reason)

    def test_blocked_hypothesis_not_eligible(self) -> None:
        hyp = {
            "status": "active",
            "blocked_reason": "waiting for prerequisite",
            "next_eligible_at": None,
        }
        eligible, reason = check_eligibility(hyp)
        self.assertFalse(eligible)
        self.assertIn("blocked", reason)


class PriorityScoreTests(unittest.TestCase):
    """Test priority score computation."""

    def test_score_has_all_components(self) -> None:
        hyp = {
            "hypothesis_id": "H-001",
            "description": "test",
            "status": "active",
            "source_rule_ids": ["rule-1"],
            "selection_count": 0,
            "last_selected_at": None,
            "origin": "rule",
        }
        ctx = SelectionContext(
            active_hypotheses=[hyp],
            relations={},
            coverage={},
            report_sections={},
            open_gaps=[],
            objective="",
        )
        total, components = compute_priority_score(hyp, ctx)
        component_names = {c.name for c in components}
        self.assertIn("severity", component_names)
        self.assertIn("report_relevance", component_names)
        self.assertIn("aging", component_names)
        self.assertIn("retry_penalty", component_names)

    def test_never_selected_has_high_aging(self) -> None:
        hyp = {
            "hypothesis_id": "H-001",
            "description": "test",
            "status": "active",
            "source_rule_ids": [],
            "selection_count": 0,
            "last_selected_at": None,
            "origin": "rule",
        }
        ctx = SelectionContext(
            active_hypotheses=[hyp],
            relations={},
            coverage={},
            report_sections={},
            open_gaps=[],
            objective="",
        )
        _, components = compute_priority_score(hyp, ctx)
        aging = next(c for c in components if c.name == "aging")
        self.assertEqual(aging.raw_value, 8.0)

    def test_higher_selection_count_increases_penalty(self) -> None:
        hyp_new = {
            "hypothesis_id": "H-001",
            "description": "test",
            "status": "active",
            "source_rule_ids": [],
            "selection_count": 0,
            "last_selected_at": None,
            "origin": "rule",
        }
        hyp_old = {
            "hypothesis_id": "H-002",
            "description": "test",
            "status": "active",
            "source_rule_ids": [],
            "selection_count": 5,
            "last_selected_at": None,
            "origin": "rule",
        }
        ctx = SelectionContext(
            active_hypotheses=[hyp_new, hyp_old],
            relations={},
            coverage={},
            report_sections={},
            open_gaps=[],
            objective="",
        )
        _, comp_new = compute_priority_score(hyp_new, ctx)
        _, comp_old = compute_priority_score(hyp_old, ctx)
        penalty_new = next(c for c in comp_new if c.name == "retry_penalty").weighted
        penalty_old = next(c for c in comp_old if c.name == "retry_penalty").weighted
        self.assertLess(penalty_old, penalty_new)


class SelectionIntegrationTests(unittest.TestCase):
    """Test end-to-end hypothesis selection."""

    def test_select_from_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                results = select_focus_hypotheses(db, limit=2)
                self.assertEqual(len(results), 0)

    def test_selects_active_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status) "
                    "VALUES ('H-001', 'suspicious logon', 'active')"
                )
                results = select_focus_hypotheses(db, limit=2)
                self.assertEqual(len(results), 1)
                self.assertTrue(results[0].eligible)
                self.assertEqual(results[0].hypothesis_id, "H-001")

    def test_skips_blocked_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, blocked_reason) "
                    "VALUES ('H-001', 'blocked hypothesis', 'active', 'waiting for data')"
                )
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status) "
                    "VALUES ('H-002', 'active hypothesis', 'active')"
                )
                results = select_focus_hypotheses(db, limit=2)
                eligible = [r for r in results if r.eligible]
                self.assertEqual(len(eligible), 1)
                self.assertEqual(eligible[0].hypothesis_id, "H-002")

    def test_selection_updates_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, selection_count) "
                    "VALUES ('H-001', 'test', 'active', 0)"
                )
                select_focus_hypotheses(db, limit=1)
                row = db.execute(
                    "SELECT selection_count FROM hypotheses WHERE hypothesis_id = 'H-001'"
                ).fetchone()
                self.assertEqual(row[0], 1)

    def test_selects_two_distinct_never_selected_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status) "
                    "VALUES ('H-001', 'one', 'active'), ('H-002', 'two', 'active')"
                )
                results = [
                    result
                    for result in select_focus_hypotheses(db, limit=2)
                    if result.eligible
                ]
                self.assertEqual(len(results), 2)
                self.assertEqual(len({result.hypothesis_id for result in results}), 2)
