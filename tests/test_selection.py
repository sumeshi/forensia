"""Tests for M4: deterministic next-best hypothesis selection."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.investigation.selection import (
    SelectionContext,
    _capabilities_for_hypothesis,
    check_eligibility,
    compute_priority_score,
    select_focus_hypotheses,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


class EligibilityTests(unittest.TestCase):
    """Test eligibility filtering."""

    def test_resolved_hypothesis_not_eligible(self) -> None:
        hyp = {"status": "resolved", "blocked_reason": "", "next_eligible_at": None}
        eligible, reason = check_eligibility(hyp)
        self.assertFalse(eligible)
        self.assertIn("resolved", reason)


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
            "verification_spec": {"spec_version": "1"},
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
            "verification_spec": {"spec_version": "1"},
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
            "verification_spec": {"spec_version": "1"},
        }
        hyp_old = {
            "hypothesis_id": "H-002",
            "description": "test",
            "status": "active",
            "source_rule_ids": [],
            "selection_count": 5,
            "last_selected_at": None,
            "origin": "rule",
            "verification_spec": {"spec_version": "1"},
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


class RequiredCapabilityTests(unittest.TestCase):
    """T02: capabilities derive from the canonical spec, not re-inference."""

    def test_declared_spec_capabilities_short_circuit_inference(self) -> None:
        hyp = {
            "verification_spec": {
                "spec_version": "1",
                "required_capabilities": ["declared_cap"],
                "support_conditions": {},
            },
        }
        self.assertEqual(_capabilities_for_hypothesis(hyp), {"declared_cap"})

    def test_spec_support_conditions_infer_when_no_declared_list(self) -> None:
        hyp = {
            "verification_spec": {
                "spec_version": "1",
                "support_conditions": {"keywords": ["evtx_events 4624"]},
            },
        }
        self.assertEqual(
            _capabilities_for_hypothesis(hyp), {"lateral_movement", "logon"}
        )

    def test_unavailable_inferred_capability_blocks_until_spec_declares(self) -> None:
        ctx = SelectionContext(
            active_hypotheses=[],
            relations={},
            coverage={
                "evtx:logon": {
                    "state": "unavailable",
                    "reason": "artifact_not_collected",
                    "family": "evtx",
                }
            },
            report_sections={},
            open_gaps=[],
            objective="",
        )
        spec = {
            "hypothesis_id": "H-SPEC",
            "status": "active",
            "blocked_reason": "",
            "next_eligible_at": None,
            "verification_spec": {
                "spec_version": "1",
                "support_conditions": {"keywords": ["evtx_events 4624"]},
            },
        }
        eligible, reason = check_eligibility(spec, ctx=ctx)
        self.assertFalse(eligible)
        self.assertIn("capability unavailable", reason)
        declared = {
            **spec,
            "verification_spec": {
                "spec_version": "1",
                "required_capabilities": ["declared_cap"],
                "support_conditions": {},
            },
        }
        eligible, reason = check_eligibility(declared, ctx=ctx)
        self.assertTrue(eligible)
        self.assertEqual(reason, "")


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
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec) VALUES "
                    "('H-001', 'suspicious logon', 'active', '{\"spec_version\": \"1\"}')"
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
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "blocked_reason, verification_spec) VALUES "
                    "('H-001', 'blocked hypothesis', 'active', 'waiting for data', "
                    '\'{"spec_version": "1"}\')'
                )
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec) VALUES "
                    "('H-002', 'active hypothesis', 'active', '{\"spec_version\": \"1\"}')"
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
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "selection_count, verification_spec) VALUES "
                    "('H-001', 'test', 'active', 0, '{\"spec_version\": \"1\"}')"
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
                    "INSERT INTO hypotheses (hypothesis_id, description, status, "
                    "verification_spec) VALUES "
                    "('H-001', 'one', 'active', '{\"spec_version\": \"1\"}'), "
                    "('H-002', 'two', 'active', '{\"spec_version\": \"1\"}')"
                )
                results = [
                    result
                    for result in select_focus_hypotheses(db, limit=2)
                    if result.eligible
                ]
                self.assertEqual(len(results), 2)
                self.assertEqual(len({result.hypothesis_id for result in results}), 2)
