"""Tests for M2: evidence sufficiency evaluation."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.checking.assessment import assess_evidence_group
from forensia.ai.checking.sufficiency import (
    EvidenceLink,
    SufficiencyResult,
    create_hypothesis_evidence_link,
    evaluate_sufficiency,
    load_evidence_links,
    reconcile_verdicts,
    update_claim_support_for_hypothesis,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB


class SufficiencyEvaluationTests(unittest.TestCase):
    """Test evidence sufficiency evaluation logic."""

    def test_no_evidence_returns_insufficient(self) -> None:
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            [],
            {},
        )
        self.assertEqual(result.status, "insufficient")
        self.assertEqual(result.score, 0.0)
        self.assertEqual(result.independent_groups, 0)

    def test_single_supporting_returns_sufficient(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="evtx-1",
                finding_id="",
                query_id="Q1",
                assessment_id="",
                role="supporting",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="evtx-1",
                strength="moderate",
            ),
        ]
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            {},
        )
        self.assertIn(result.status, ("sufficient", "partial"))

    def test_weak_single_source_is_not_sufficient(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="mft-1",
                finding_id="",
                query_id="Q1",
                assessment_id="",
                role="supporting",
                source_family="mft",
                source_file="$MFT",
                derivation_group="mft-1",
                strength="weak",
            )
        ]
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            {},
        )
        self.assertNotEqual(result.status, "sufficient")

    def test_multi_family_bonus(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="evtx-1",
                finding_id="",
                query_id="Q1",
                assessment_id="",
                role="supporting",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="evtx-1",
                strength="moderate",
            ),
            EvidenceLink(
                link_id="L2",
                hypothesis_id="H-001",
                evidence_id="prefetch-1",
                finding_id="",
                query_id="Q2",
                assessment_id="",
                role="supporting",
                source_family="prefetch",
                source_file="test.pf",
                derivation_group="prefetch-1",
                strength="moderate",
            ),
        ]
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            {},
        )
        self.assertGreaterEqual(result.score, 0.5)
        self.assertIn("evtx", result.families)
        self.assertIn("prefetch", result.families)

    def test_contradictory_evidence_flags_review(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="evtx-1",
                finding_id="",
                query_id="Q1",
                assessment_id="",
                role="supporting",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="evtx-1",
                strength="moderate",
            ),
            EvidenceLink(
                link_id="L2",
                hypothesis_id="H-001",
                evidence_id="evtx-2",
                finding_id="",
                query_id="Q2",
                assessment_id="",
                role="contradictory",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="evtx-2",
                strength="strong",
            ),
        ]
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            {},
        )
        self.assertTrue(result.human_review_required)
        self.assertGreater(result.contradictory_groups, 0)

    def test_same_derivation_group_not_independent(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="evtx-1",
                finding_id="F1",
                query_id="",
                assessment_id="",
                role="supporting",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="group-A",
                strength="moderate",
            ),
            EvidenceLink(
                link_id="L2",
                hypothesis_id="H-001",
                evidence_id="evtx-2",
                finding_id="",
                query_id="Q1",
                assessment_id="",
                role="supporting",
                source_family="evtx",
                source_file="Security.evtx",
                derivation_group="group-A",
                strength="moderate",
            ),
        ]
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            {},
        )
        self.assertEqual(result.independent_groups, 1)

    def test_unavailable_coverage_with_no_evidence_is_unobservable(self) -> None:
        links: list[EvidenceLink] = []
        coverage = {
            "evtx:process_execution": {
                "state": "unavailable",
                "reason": "artifact_not_collected",
                "family": "evtx",
            },
        }
        result = evaluate_sufficiency(
            {"hypothesis_id": "H-001"},
            links,
            coverage,
        )
        self.assertEqual(result.status, "unobservable")

    def test_assessment_uses_spec_and_tracks_condition_version(self) -> None:
        rows = [{"evidence_id": "evtx-1", "event_id": 4624}]
        first = assess_evidence_group(
            hypothesis=Hypothesis(
                id="H-HASH",
                description="same",
                confirm_when={"co_observed_event_ids": [4624]},
            ),
            rows=rows,
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(first.role, "supporting")
        self.assertTrue(first.assessment_id.startswith("EA-v1-"))
        second = assess_evidence_group(
            hypothesis=Hypothesis(
                id="H-HASH",
                description="same",
                confirm_when={"co_observed_event_ids": [4625]},
            ),
            rows=rows,
            evidence_ids=["evtx-1"],
        )
        self.assertNotEqual(first.assessment_id, second.assessment_id)

    def test_assessment_fails_closed_for_unproven_observations(self) -> None:
        cases = [
            (
                Hypothesis(
                    id="H-ABSENCE",
                    description="missing event",
                    refute_when={"zero_rows": True},
                ),
                [],
                [],
                "adequate",
            ),
            (
                Hypothesis(
                    id="H-UNKNOWN",
                    description="unknown condition",
                    confirm_when={"keywords": ["sc.exe"]},
                ),
                [{"evidence_id": "evtx-1", "event_id": 7045}],
                ["evtx-1"],
                "adequate",
            ),
            (
                Hypothesis(
                    id="H-WINDOW",
                    description="time window",
                    confirm_when={
                        "co_observed_event_ids": [4624, 4697],
                        "within_minutes": 5,
                    },
                ),
                [
                    {"evidence_id": "evtx-1", "event_id": 4624, "timestamp": 1000},
                    {"evidence_id": "evtx-2", "event_id": 4697, "timestamp": 4600},
                ],
                ["evtx-1", "evtx-2"],
                "adequate",
            ),
            (
                Hypothesis(
                    id="H-PARTIAL",
                    description="partial retrieval",
                    confirm_when={"co_observed_event_ids": [4624]},
                ),
                [{"evidence_id": "evtx-1", "event_id": 4624}],
                ["evtx-1"],
                "partial",
            ),
        ]
        for hypothesis, rows, evidence_ids, outcome in cases:
            with self.subTest(hypothesis=hypothesis.id):
                assessment = assess_evidence_group(
                    hypothesis=hypothesis,
                    rows=rows,
                    evidence_ids=evidence_ids,
                    retrieval_outcome=outcome,
                )
                self.assertNotIn(assessment.role, {"supporting", "contradictory"})


class VerdictReconciliationTests(unittest.TestCase):
    """Test LLM/machine verdict reconciliation."""

    def test_llm_confirmed_machine_sufficient(self) -> None:
        machine = SufficiencyResult(
            status="sufficient",
            score=0.8,
            reasons=[],
            independent_groups=2,
            families=["evtx", "prefetch"],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        verdict, reason = reconcile_verdicts(machine, "confirmed")
        self.assertEqual(verdict, "confirmed")
        self.assertIn("agree", reason)

    def test_llm_confirmed_machine_insufficient(self) -> None:
        machine = SufficiencyResult(
            status="insufficient",
            score=0.2,
            reasons=[],
            independent_groups=0,
            families=[],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        verdict, reason = reconcile_verdicts(machine, "confirmed")
        self.assertEqual(verdict, "inconclusive")
        self.assertIn("insufficient", reason)

    def test_llm_refuted_machine_unobservable(self) -> None:
        machine = SufficiencyResult(
            status="unobservable",
            score=0.0,
            reasons=[],
            independent_groups=0,
            families=[],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        verdict, reason = reconcile_verdicts(machine, "refuted")
        self.assertEqual(verdict, "untestable")

    def test_machine_sufficient_llm_inconclusive(self) -> None:
        machine = SufficiencyResult(
            status="sufficient",
            score=0.7,
            reasons=[],
            independent_groups=2,
            families=["evtx"],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        verdict, reason = reconcile_verdicts(machine, "inconclusive")
        self.assertEqual(verdict, "needs_review")

    def test_default_uses_llm_verdict(self) -> None:
        machine = SufficiencyResult(
            status="partial",
            score=0.4,
            reasons=[],
            independent_groups=1,
            families=["evtx"],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )
        verdict, _ = reconcile_verdicts(machine, "newlead")
        self.assertEqual(verdict, "newlead")


class EvidenceLinkPersistenceTests(unittest.TestCase):
    """Test hypothesis_evidence table operations."""

    def test_insert_and_load_evidence_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypothesis_evidence (link_id, hypothesis_id, evidence_id, "
                    "role, source_family, derivation_group) "
                    "VALUES ('L-001', 'H-001', 'evtx-001', 'supporting', 'evtx', 'evtx-001')"
                )
                links = load_evidence_links(db, "H-001")
                self.assertEqual(len(links), 1)
                self.assertEqual(links[0].evidence_id, "evtx-001")
                self.assertEqual(links[0].role, "supporting")

    def test_multiple_links_for_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO hypothesis_evidence (link_id, hypothesis_id, evidence_id, "
                    "role, source_family, derivation_group) VALUES "
                    "('L-001', 'H-001', 'evtx-001', 'supporting', 'evtx', 'evtx-001'), "
                    "('L-002', 'H-001', 'prefetch-001', 'corroborating', 'prefetch', 'prefetch-001')"
                )
                links = load_evidence_links(db, "H-001")
                self.assertEqual(len(links), 2)
                families = {l.source_family for l in links}
                self.assertEqual(families, {"evtx", "prefetch"})

    def test_evidence_link_creation_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                first = create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-001",
                    evidence_id="evtx-001",
                    query_id="Q-1",
                )
                second = create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-001",
                    evidence_id="evtx-001",
                    query_id="Q-1",
                    assessment_id="EA-v1-deterministic-test",
                )
                self.assertEqual(first, second)
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM hypothesis_evidence").fetchone()[
                        0
                    ],
                    1,
                )
                self.assertEqual(
                    db.execute(
                        "SELECT assessment_id FROM hypothesis_evidence"
                    ).fetchone()[0],
                    "EA-v1-deterministic-test",
                )

    def test_unobservable_sufficiency_updates_linked_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO claims (claim_id, claim_text, hypothesis_ids, "
                    "support_status) VALUES ('C-1', 'claim', '[\"H-001\"]', 'supported')"
                )
                result = SufficiencyResult(
                    status="unobservable",
                    score=0.0,
                    reasons=[],
                    independent_groups=0,
                    families=[],
                    contradictory_groups=0,
                    missing_requirements=[],
                    human_review_required=False,
                )
                update_claim_support_for_hypothesis(
                    db,
                    hypothesis_id="H-001",
                    result=result,
                    final_verdict="untestable",
                )
                self.assertEqual(
                    db.execute(
                        "SELECT support_status FROM claims WHERE claim_id = 'C-1'"
                    ).fetchone()[0],
                    "unobservable",
                )
