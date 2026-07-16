"""Tests for M3: hypothesis relationship validation, cycle detection, and propagation."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.hypotheses.relations import (
    VALID_RELATION_TYPES,
    check_cycle,
    get_adjacent_hypotheses,
    get_relations_for_hypothesis,
    propagate_verdict,
    validate_relation,
)
from forensia.ai.hypotheses.relations import (
    insert_relation as _insert_relation,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


def insert_relation(db: CaseDB, **kwargs):
    """Seed valid endpoints so relation tests exercise relation semantics."""
    for hypothesis_id in (kwargs["from_id"], kwargs["to_id"]):
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status) "
            "VALUES (?, ?, 'active') ON CONFLICT (hypothesis_id) DO NOTHING",
            [hypothesis_id, hypothesis_id],
        )
    return _insert_relation(db, **kwargs)


class RelationValidationTests(unittest.TestCase):
    """Test relation validation logic."""

    def test_valid_relation_types(self) -> None:
        self.assertIn("parent_of", VALID_RELATION_TYPES)
        self.assertIn("prerequisite_for", VALID_RELATION_TYPES)
        self.assertIn("derived_from", VALID_RELATION_TYPES)
        self.assertIn("contradicts", VALID_RELATION_TYPES)
        self.assertIn("alternative_to", VALID_RELATION_TYPES)
        self.assertIn("supersedes", VALID_RELATION_TYPES)

    def test_self_edge_rejected(self) -> None:
        error = validate_relation(
            from_id="H-001", to_id="H-001",
            relation_type="parent_of", existing_relations=[],
        )
        self.assertIsNotNone(error)
        self.assertIn("Self-edge", error)

    def test_invalid_type_rejected(self) -> None:
        error = validate_relation(
            from_id="H-001", to_id="H-002",
            relation_type="supports", existing_relations=[],
        )
        self.assertIsNotNone(error)
        self.assertIn("Invalid", error)

    def test_duplicate_rejected(self) -> None:
        existing = [("H-001", "H-002", "parent_of")]
        error = validate_relation(
            from_id="H-001", to_id="H-002",
            relation_type="parent_of", existing_relations=existing,
        )
        self.assertIsNotNone(error)
        self.assertIn("Duplicate", error)

    def test_symmetric_duplicate_rejected(self) -> None:
        existing = [("H-002", "H-001", "contradicts")]
        error = validate_relation(
            from_id="H-001", to_id="H-002",
            relation_type="contradicts", existing_relations=existing,
        )
        self.assertIsNotNone(error)
        self.assertIn("Duplicate", error)

    def test_empty_id_rejected(self) -> None:
        error = validate_relation(
            from_id="", to_id="H-002",
            relation_type="parent_of", existing_relations=[],
        )
        self.assertIsNotNone(error)


class CycleDetectionTests(unittest.TestCase):
    """Test cycle detection in hypothesis relations."""

    def test_no_cycle_when_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                has_cycle = check_cycle(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                self.assertFalse(has_cycle)

    def test_detects_direct_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypothesis_relations (from_hypothesis_id, to_hypothesis_id, "
                    "relation_type, origin, confidence) VALUES ('H-001', 'H-002', 'parent_of', 'code', 1.0)"
                )
                has_cycle = check_cycle(
                    db, from_id="H-002", to_id="H-001",
                    relation_type="parent_of",
                )
                self.assertTrue(has_cycle)

    def test_no_cycle_for_symmetric(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypothesis_relations (from_hypothesis_id, to_hypothesis_id, "
                    "relation_type, origin, confidence) VALUES ('H-001', 'H-002', 'contradicts', 'code', 1.0)"
                )
                has_cycle = check_cycle(
                    db, from_id="H-002", to_id="H-001",
                    relation_type="contradicts",
                )
                self.assertFalse(has_cycle)

    def test_detects_cycle_longer_than_previous_depth_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index in range(1, 6):
                    insert_relation(
                        db,
                        from_id=f"H-{index:03d}",
                        to_id=f"H-{index + 1:03d}",
                        relation_type="parent_of",
                    )
                self.assertTrue(
                    check_cycle(
                        db,
                        from_id="H-006",
                        to_id="H-001",
                        relation_type="parent_of",
                    )
                )


class InsertRelationTests(unittest.TestCase):
    """Test relation insertion with validation."""

    def test_insert_valid_relation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                result = insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                self.assertTrue(result)
                rows = db.execute(
                    "SELECT from_hypothesis_id, to_hypothesis_id FROM hypothesis_relations"
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "H-001")
                self.assertEqual(rows[0][1], "H-002")

    def test_unknown_reference_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self.assertFalse(
                    _insert_relation(
                        db,
                        from_id="H-missing-1",
                        to_id="H-missing-2",
                        relation_type="parent_of",
                    )
                )

    def test_insert_symmetric_uses_canonical_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-002", to_id="H-001",
                    relation_type="contradicts",
                )
                row = db.execute(
                    "SELECT from_hypothesis_id, to_hypothesis_id FROM hypothesis_relations"
                ).fetchone()
                self.assertEqual(row[0], "H-001")
                self.assertEqual(row[1], "H-002")

    def test_insert_cycle_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                result = insert_relation(
                    db, from_id="H-002", to_id="H-001",
                    relation_type="parent_of",
                )
                self.assertFalse(result)


class RelationQueryTests(unittest.TestCase):
    """Test relation querying functions."""

    def test_get_relations_for_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                insert_relation(
                    db, from_id="H-001", to_id="H-003",
                    relation_type="derived_from",
                )
                rels = get_relations_for_hypothesis(db, "H-001")
                self.assertEqual(len(rels), 2)

    def test_get_adjacent_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                insert_relation(
                    db, from_id="H-003", to_id="H-001",
                    relation_type="prerequisite_for",
                )
                adj = get_adjacent_hypotheses(db, "H-001")
                self.assertIn("H-002", adj)
                self.assertIn("H-003", adj)

    def test_get_adjacent_with_type_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                insert_relation(
                    db, from_id="H-001", to_id="H-003",
                    relation_type="derived_from",
                )
                adj = get_adjacent_hypotheses(db, "H-001", "parent_of")
                self.assertEqual(adj, ["H-002"])


class VerdictPropagationTests(unittest.TestCase):
    """Test verdict propagation through relations."""

    def test_prerequisite_confirmed_unblocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, description, status, blocked_reason) "
                    "VALUES ('H-002', 'dependent', 'active', 'waiting for H-001')"
                )
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="prerequisite_for",
                )
                actions = propagate_verdict(
                    db, hypothesis_id="H-001",
                    verdict="confirmed", created_session="S1",
                )
                self.assertTrue(any(a["action"] == "unblock" for a in actions))
                row = db.execute(
                    "SELECT blocked_reason FROM hypotheses WHERE hypothesis_id = 'H-002'"
                ).fetchone()
                self.assertIsNone(row[0])

    def test_parent_refuted_flags_reevaluation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="parent_of",
                )
                actions = propagate_verdict(
                    db, hypothesis_id="H-001",
                    verdict="refuted", created_session="S1",
                )
                self.assertTrue(any(a["action"] == "re_evaluate" for a in actions))

    def test_contradicts_confirmed_flags_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                insert_relation(
                    db, from_id="H-001", to_id="H-002",
                    relation_type="contradicts",
                )
                actions = propagate_verdict(
                    db, hypothesis_id="H-001",
                    verdict="confirmed", created_session="S1",
                )
                self.assertTrue(any(a["action"] == "flag_contradiction" for a in actions))
