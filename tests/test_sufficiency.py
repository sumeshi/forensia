"""Tests for M2: evidence sufficiency evaluation."""

from __future__ import annotations

import json
import tempfile
import unittest
from typing import Any

from forensia.ai.checking.assessment import assess_evidence_group
from forensia.ai.checking.settlement import (
    build_settlement_input_from_confirm_when,
    decide_settlement,
)
from forensia.ai.checking.sufficiency import (
    EvidenceLink,
    SufficiencyResult,
    assess_and_persist_sufficiency,
    create_evidence_links_for_query,
    create_hypothesis_evidence_link,
    evaluate_sufficiency,
    evidence_link_currentness,
    load_evidence_links,
    load_unlinkable_observations_for_session,
    reconcile_verdicts,
    record_unlinkable_observation,
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
        explicit_no_capabilities = evaluate_sufficiency(
            {"hypothesis_id": "H-001", "required_capabilities": []},
            [],
            {"evtx:logon": {"state": "unavailable"}},
        )
        self.assertEqual(explicit_no_capabilities.status, "insufficient")

    def test_single_supporting_returns_sufficient(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="evtx-1",
                finding_id="",
                query_id="Q1",
                assessment_id="EA-test-1",
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

    def test_legacy_unassessed_link_is_not_evidence(self) -> None:
        link = EvidenceLink(
            link_id="legacy",
            hypothesis_id="H-001",
            evidence_id="evtx-legacy",
            finding_id="",
            query_id="Q1",
            assessment_id="",
            role="supporting",
            source_family="evtx",
            source_file="Security.evtx",
            derivation_group="evtx-legacy",
            strength="strong",
        )
        result = evaluate_sufficiency({"hypothesis_id": "H-001"}, [link], {})
        self.assertEqual(result.independent_groups, 0)
        self.assertEqual(result.families, [])
        self.assertEqual(result.status, "insufficient")

    def test_weak_single_source_is_not_sufficient(self) -> None:
        links = [
            EvidenceLink(
                link_id="L1",
                hypothesis_id="H-001",
                evidence_id="mft-1",
                finding_id="",
                query_id="Q1",
                assessment_id="EA-test-2",
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
                assessment_id="EA-test-3",
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
                assessment_id="EA-test-4",
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
                assessment_id="EA-test-5",
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
                assessment_id="EA-test-6",
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
                assessment_id="EA-test-7",
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
                assessment_id="EA-test-8",
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

    def test_qualified_event_contexts_reach_supporting(self) -> None:
        """A persisted spec with qualified event_contexts is evaluable.

        Admission (via qualify_event_contexts / the planner contract) injects
        qualified event_contexts into support_conditions; those conditions used
        to fail closed at Assessment, so the hypothesis could never reach
        supporting. The eligible row matches the catalog-qualified
        channel/provider; the provider-reused ineligible row must not satisfy
        the condition (mirrors
        test_hypothesis_manager.test_co_observation_ignores_ineligible_provider_rows).
        """

        hypothesis = Hypothesis(
            id="H-CTX",
            description="PowerShell script block execution was observed",
            confirm_when={
                "co_observed_event_ids": [4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": "Microsoft-Windows-PowerShell/Operational",
                        "provider": "Microsoft-Windows-PowerShell",
                    }
                ],
            },
        )
        eligible_rows = [
            {
                "evidence_id": "evtx-1",
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-PowerShell"}}
                },
            }
        ]
        assessment = assess_evidence_group(
            hypothesis=hypothesis,
            rows=eligible_rows,
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(assessment.role, "supporting")
        self.assertEqual(
            set(assessment.matched_conditions),
            {"co_observed_event_ids", "event_contexts"},
        )

        ineligible_rows = [
            {
                "evidence_id": "evtx-2",
                "event_id": 4104,
                "channel": "Application",
                "raw_json": {
                    "winlog": {"provider": {"name": "Microsoft-Windows-Winlogon"}}
                },
            }
        ]
        rejected = assess_evidence_group(
            hypothesis=hypothesis,
            rows=ineligible_rows,
            evidence_ids=["evtx-2"],
        )
        self.assertEqual(rejected.role, "contextual")
        self.assertEqual(rejected.reason, "observed but conditions were not satisfied")

    def test_unsupported_condition_key_records_explicit_reason(self) -> None:
        """Unknown condition keys stay contextual with an explicit reason."""

        hypothesis = Hypothesis(
            id="H-KEYWORDS",
            description="unknown condition key",
            confirm_when={"keywords": ["sc.exe"]},
        )
        assessment = assess_evidence_group(
            hypothesis=hypothesis,
            rows=[{"evidence_id": "evtx-1", "event_id": 7045}],
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(assessment.role, "contextual")
        self.assertEqual(assessment.reason, "unsupported condition keys: ['keywords']")

    def test_event_constraints_share_host_entity_and_time_witnesses(self) -> None:
        from forensia.ai.checking.settlement import (
            build_settlement_input_from_confirm_when,
            decide_settlement,
        )

        hypothesis = Hypothesis(
            id="H-RDP-WINDOW",
            description="RDP session",
            confirm_when={
                "co_observed_event_ids": [21, 4624],
                "same_host": True,
                "same_entities": ["target_user"],
                "within_minutes": 5,
                "event_constraints": {4624: {"logon_type": ["10"]}},
            },
        )
        rows = [
            {
                "evidence_id": "evtx-21",
                "event_id": 21,
                "computer": "WS-A",
                "target_user": "alice",
                "timestamp": "2026-10-07T00:00:00",
                "channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "raw_json": {
                    "winlog": {
                        "provider": {
                            "name": "Microsoft-Windows-TerminalServices-LocalSessionManager"
                        }
                    }
                },
            },
            {
                "evidence_id": "evtx-4624-a",
                "event_id": 4624,
                "computer": "WS-A",
                "target_user": "alice",
                "timestamp": "2026-10-07T00:01:00",
                "logon_type": 5,
                "channel": "Security",
                "raw_json": {
                    "winlog": {
                        "provider": {"name": "Microsoft-Windows-Security-Auditing"}
                    }
                },
            },
        ]
        extra = {**rows[-1], "evidence_id": "evtx-4624-b", "logon_type": 10}
        variants = [
            ({"timestamp": "2026-10-07T01:00:00"}, False),
            ({"computer": "WS-B"}, False),
            ({"target_user": "bob"}, False),
            ({}, True),
        ]
        for change, expected in variants:
            with self.subTest(change=change):
                observations = [*rows, {**extra, **change}]
                assessment = assess_evidence_group(
                    hypothesis=hypothesis,
                    rows=observations,
                    evidence_ids=[row["evidence_id"] for row in observations],
                )
                self.assertEqual(assessment.role == "supporting", expected)
                si = build_settlement_input_from_confirm_when(
                    hypothesis=hypothesis,
                    checker_verdict="confirmed",
                    check_summary="proposed confirmation",
                    sample_rows=observations,
                )
                decision = decide_settlement(si, links=[], coverage={})
                correlation_failed = any(
                    gate.startswith("correlation:") for gate in decision.gates_failed
                )
                self.assertEqual(correlation_failed, not expected)

    def test_event_constraints_fail_closed_on_unknown_sub_key(self) -> None:
        """An unknown constraint field fails closed with an explicit reason."""

        rows = [
            {"evidence_id": "evtx-4624", "event_id": 4624, "logon_type": 10},
        ]
        hypothesis = Hypothesis(
            id="H-RDP-UNKNOWN",
            description="RDP session established from a remote host",
            confirm_when={
                "co_observed_event_ids": [21, 4624],
                "event_constraints": {4624: {"boot_type": ["10"]}},
            },
        )
        assessment = assess_evidence_group(
            hypothesis=hypothesis,
            rows=rows,
            evidence_ids=["evtx-4624"],
        )
        self.assertEqual(assessment.role, "contextual")


class RequiredCapabilityDerivationTests(unittest.TestCase):
    """T02: declared spec capabilities win; legacy fallback stays text-based."""

    def _insert_hypothesis(
        self, db: CaseDB, hypothesis_id: str, *, spec: dict | None = None
    ) -> None:
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status, "
            "verification_spec, created_at, updated_at) "
            "VALUES (?, ?, 'active', ?, now(), now())",
            [
                hypothesis_id,
                f"Description {hypothesis_id}",
                json.dumps(spec or {"spec_version": "1"}),
            ],
        )

    def test_declared_spec_capabilities_short_circuit_text_inference(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._insert_hypothesis(
                    db,
                    "H-SPEC-CAPS",
                    spec={
                        "spec_version": "1",
                        "required_capabilities": ["declared_cap"],
                        "support_conditions": {},
                    },
                )
                _result, _verdict, _reason, caps = assess_and_persist_sufficiency(
                    db,
                    hypothesis_id="H-SPEC-CAPS",
                    evidence_requirements={},
                    llm_verdict="confirmed",
                    verification_spec={
                        "spec_version": "1",
                        "required_capabilities": ["declared_cap"],
                        "support_conditions": {},
                    },
                )
                self.assertEqual(caps, ["declared_cap"])

    def test_support_conditions_derive_capabilities_without_declared_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._insert_hypothesis(db, "H-SUPPORT-CAPS")
                _result, _verdict, _reason, caps = assess_and_persist_sufficiency(
                    db,
                    hypothesis_id="H-SUPPORT-CAPS",
                    evidence_requirements={},
                    llm_verdict="confirmed",
                    verification_spec={
                        "spec_version": "1",
                        "support_conditions": {"keywords": ["evtx_events 4624"]},
                    },
                )
                self.assertEqual(caps, ["lateral_movement", "logon"])


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

    @staticmethod
    def _insert_hypothesis(db: CaseDB) -> None:
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, description, status, "
            "verification_spec, created_at, updated_at) VALUES "
            "('H-001', 'test hypothesis', 'active', '{\"spec_version\":\"1\"}', now(), now())"
        )

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
                self._insert_hypothesis(db)
                first = create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-001",
                    evidence_id="evtx-001",
                    query_id="Q-1",
                    assessment_id="EA-v1-deterministic-test",
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

    def test_query_links_share_assessment_derivation_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._insert_hypothesis(db)
                create_evidence_links_for_query(
                    db,
                    hypothesis_id="H-001",
                    evidence_ids=["evtx-1", "evtx-2"],
                    query_id="Q-1",
                    assessment_id="EA-query-1",
                    derivation_group="Q-1",
                    finding_ids_by_evidence={"evtx-1": "finding-1"},
                )
                groups = db.execute(
                    "SELECT DISTINCT derivation_group FROM hypothesis_evidence"
                ).fetchall()
                self.assertEqual(groups, [("Q-1",)])
                self.assertEqual(
                    db.execute(
                        "SELECT finding_id FROM hypothesis_evidence WHERE evidence_id = 'evtx-1'"
                    ).fetchone()[0],
                    "finding-1",
                )

    def test_unlinkable_observations_are_session_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                record_unlinkable_observation(
                    db,
                    hypothesis_id="H-SCOPE",
                    reason="old",
                    observed_rows=1,
                    created_session="session-old",
                )
                record_unlinkable_observation(
                    db,
                    hypothesis_id="H-SCOPE",
                    reason="new",
                    observed_rows=2,
                    created_session="session-new",
                )
                self.assertEqual(
                    load_unlinkable_observations_for_session(
                        db, "H-SCOPE", "session-new"
                    ),
                    [("new", 2)],
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


class CurrentLinkTests(unittest.TestCase):
    """T04: historical links must not count as currently-usable support."""

    def _seed(
        self,
        db: CaseDB,
        *,
        source_file: str = "sha-a",
        verification_spec: dict[str, Any] | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
            "VALUES ('evtx-1', ?, 4624)",
            [source_file],
        )
        spec = verification_spec or {"spec_version": "1"}
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, status, created_at, updated_at, "
            "verification_spec) VALUES ('H-CUR', 'active', now(), now(), ?) ",
            [json.dumps(spec)],
        )
        if verification_spec is None:
            create_evidence_links_for_query(
                db,
                hypothesis_id="H-CUR",
                evidence_ids=["evtx-1"],
                query_id="Q-current",
                role="supporting",
                assessment_id="EA-cur",
                derivation_group="evtx-1",
            )
        else:
            from forensia.core.verification import VerificationSpec

            hypothesis = Hypothesis(
                id="H-CUR",
                description="currentness fixture",
                status="active",
                verification_spec=VerificationSpec.model_validate(verification_spec),
            )
            assessment = assess_evidence_group(
                hypothesis=hypothesis,
                rows=[{"event_id": 4624}],
                evidence_ids=["evtx-1"],
                derivation_group="evtx-1",
            )
            create_hypothesis_evidence_link(
                db,
                hypothesis_id="H-CUR",
                evidence_id="evtx-1",
                query_id="Q-current",
                role=assessment.role,
                assessment_id=assessment.assessment_id,
                derivation_group=assessment.derivation_group,
            )

    def _assess(
        self,
        db: CaseDB,
        *,
        verification_spec: dict[str, Any] | None = None,
    ) -> SufficiencyResult:
        result, _verdict, _reason, _caps = assess_and_persist_sufficiency(
            db,
            hypothesis_id="H-CUR",
            evidence_requirements={},
            llm_verdict="confirmed",
            verification_spec=verification_spec or {"spec_version": "1"},
        )
        return result

    def _link_count(self, db: CaseDB) -> int:
        return int(
            db.execute(
                "SELECT COUNT(*) FROM hypothesis_evidence WHERE hypothesis_id = 'H-CUR'"
            ).fetchone()[0]
        )

    def test_deleted_evidence_row_stops_support_but_keeps_link_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._seed(db)
                self.assertEqual(self._assess(db).status, "sufficient")

                db.execute("DELETE FROM evtx_events WHERE evidence_id = 'evtx-1'")
                result = self._assess(db)
                self.assertEqual(result.status, "insufficient")
                # The stale link stays as a historical record.
                self.assertEqual(self._link_count(db), 1)

    def test_same_id_new_source_is_excluded_and_same_source_is_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._seed(db)
                self.assertEqual(self._assess(db).status, "sufficient")

                # Same evidence_id re-created under a different source: the
                # recorded identity no longer matches, so the link is
                # conservatively excluded from current support.
                db.execute("DELETE FROM evtx_events WHERE evidence_id = 'evtx-1'")
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
                    "VALUES ('evtx-1', 'sha-new', 4624)"
                )
                self.assertEqual(self._assess(db).status, "insufficient")

                # Re-created under the originally linked source again with
                # identical content, the judged material is present as-is and
                # the link counts as current without re-assessment.
                db.execute("DELETE FROM evtx_events WHERE evidence_id = 'evtx-1'")
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
                    "VALUES ('evtx-1', 'sha-a', 4624)"
                )
                self.assertEqual(self._assess(db).status, "sufficient")
                self.assertEqual(self._link_count(db), 1)

    def test_same_id_same_source_content_change_requires_reevaluation(self) -> None:
        """R03: a content change under the same evidence_id+source is detected.

        The link keeps recording the judged material; the changed row is not
        silently refilled as current support.  A re-evaluation creates a NEW
        link whose fingerprint matches the live row, while the historical
        link stays excluded and undeleted.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self._seed(db)
                self.assertEqual(self._assess(db).status, "sufficient")

                db.execute(
                    "UPDATE evtx_events SET message = 'rewritten content' "
                    "WHERE evidence_id = 'evtx-1'"
                )
                result = self._assess(db)
                self.assertEqual(result.status, "insufficient")
                self.assertTrue(
                    any("content_changed" in reason for reason in result.reasons)
                )
                self.assertEqual(self._link_count(db), 1)

                # Re-observing through the same query produces the same
                # deterministic assessment ID. The changed content must
                # still create a new link and preserve the old fingerprint.
                create_evidence_links_for_query(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_ids=["evtx-1"],
                    query_id="Q-current",
                    role="supporting",
                    assessment_id="EA-cur",
                )
                current = load_evidence_links(db, "H-CUR", current_only=True)
                historical = load_evidence_links(db, "H-CUR")
                self.assertEqual(self._link_count(db), 2)
                self.assertEqual(len(current), 1)
                self.assertEqual(current[0].assessment_id, "EA-cur")
                self.assertEqual(
                    {link.assessment_id for link in historical}, {"EA-cur"}
                )
                self.assertEqual(
                    len({link.content_fingerprint for link in historical}), 2
                )
                self.assertEqual(self._assess(db).status, "sufficient")
                create_evidence_links_for_query(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_ids=["evtx-1"],
                    query_id="Q-current",
                    role="supporting",
                    assessment_id="EA-cur",
                )
                self.assertEqual(self._link_count(db), 2)

                # A timestamp inside raw evidence is material even though
                # top-level ingestion timestamps are administrative metadata.
                db.execute(
                    "UPDATE evtx_events SET raw_json = ? WHERE evidence_id = 'evtx-1'",
                    ['{"created_at":"2020-01-01"}'],
                )
                create_evidence_links_for_query(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_ids=["evtx-1"],
                    query_id="Q-current",
                    role="supporting",
                    assessment_id="EA-cur",
                )
                self.assertEqual(self._assess(db).status, "sufficient")
                db.execute(
                    "UPDATE evtx_events SET raw_json = ? WHERE evidence_id = 'evtx-1'",
                    ['{"created_at":"2026-01-01"}'],
                )
                self.assertEqual(self._assess(db).status, "insufficient")

    def test_unresolvable_currentness_requires_reassessment(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Empty source_file on both link and row: the check cannot be
                # resolved, so it stays historical without current support.
                self._seed(db, source_file="")
                result = self._assess(db)
                self.assertEqual(result.status, "insufficient")
                self.assertEqual(self._link_count(db), 1)
                self.assertTrue(
                    any(
                        "source_identity_unverifiable" in reason
                        for reason in result.reasons
                    )
                )

    def test_spec_change_makes_old_assessment_historical(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                original_spec = {
                    "spec_version": "1",
                    "support_conditions": {"co_observed_event_ids": [4624]},
                }
                self._seed(db, verification_spec=original_spec)
                before = load_evidence_links(db, "H-CUR", current_only=True)
                self.assertEqual(len(before), 1)

                changed_spec = {
                    "spec_version": "1",
                    "support_conditions": {"co_observed_event_ids": [4624]},
                    "refute_conditions": {"zero_rows": True},
                }
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ? "
                    "WHERE hypothesis_id = 'H-CUR'",
                    [json.dumps(changed_spec)],
                )

                self.assertEqual(
                    load_evidence_links(db, "H-CUR", current_only=True), []
                )
                historical = load_evidence_links(db, "H-CUR")
                self.assertEqual(len(historical), 1)
                self.assertEqual(
                    evidence_link_currentness(db, historical[0])[1],
                    "verification_spec_changed",
                )

                # Reassess the same row under the new Spec with the same query.
                from forensia.core.verification import VerificationSpec

                hypothesis = Hypothesis(
                    id="H-CUR",
                    description="currentness fixture",
                    status="active",
                    verification_spec=VerificationSpec.model_validate(changed_spec),
                )
                assessment = assess_evidence_group(
                    hypothesis=hypothesis,
                    rows=[{"event_id": 4624}],
                    evidence_ids=["evtx-1"],
                    derivation_group="evtx-1",
                )
                self.assertEqual(assessment.role, "supporting")
                create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_id="evtx-1",
                    query_id="Q-current",
                    role=assessment.role,
                    assessment_id=assessment.assessment_id,
                    derivation_group=assessment.derivation_group,
                )
                history_after = load_evidence_links(db, "H-CUR")
                current_after = load_evidence_links(db, "H-CUR", current_only=True)
                self.assertEqual(len(history_after), 2)
                self.assertEqual(len(current_after), 1)
                self.assertNotEqual(history_after[0].link_id, history_after[1].link_id)
                self.assertEqual(
                    self._assess(db, verification_spec=changed_spec).status,
                    "sufficient",
                )

    def test_new_assessment_captures_source_without_rewriting_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._seed(db)
                self.assertEqual(
                    load_evidence_links(db, "H-CUR")[0].source_file, "sha-a"
                )
                db.execute("UPDATE evtx_events SET source_file = 'sha-new'")
                self.assertEqual(self._assess(db).status, "insufficient")
                create_evidence_links_for_query(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_ids=["evtx-1"],
                    query_id="Q-current",
                    role="supporting",
                    assessment_id="EA-reassessed",
                    derivation_group="evtx-1",
                )
                self.assertEqual(self._link_count(db), 2)
                self.assertEqual(
                    load_evidence_links(db, "H-CUR", current_only=True)[0].source_file,
                    "sha-new",
                )
                self.assertEqual(self._assess(db).status, "sufficient")

    def test_legacy_link_source_is_not_backfilled_from_today(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._seed(db)
                db.execute("UPDATE hypothesis_evidence SET source_file = ''")
                self.assertEqual(self._assess(db).status, "insufficient")
                self.assertEqual(load_evidence_links(db, "H-CUR")[0].source_file, "")


class CrossQueryIndependenceTests(unittest.TestCase):
    """R02: attempt identity is acquisition history; the evidence row is the root.

    Reproduction boundary (previously observed with a temporary database): the
    same evidence fetched via two query IDs became two derivation groups, so
    independent support counted 1 -> 2.  Suppression is deterministic from the
    existing evidence references: the same evidence_id under the same source
    identity is one derivation root regardless of which query observed it.
    """

    def _seed(self, db: CaseDB) -> None:
        db.execute(
            "INSERT INTO hypotheses (hypothesis_id, status, created_at, "
            "updated_at, verification_spec) VALUES ('H-XQ', 'active', now(), "
            'now(), \'{"spec_version": "1", "support_conditions": '
            '{"co_observed_event_ids": [4624]}}\')'
        )

    def _observed_rows(self, source: str, evidence_id: str) -> list[dict]:
        return [
            {
                "evidence_id": evidence_id,
                "event_id": 4624,
                "channel": "Security",
                "source_file": source,
            }
        ]

    def _link_observation(
        self,
        db: CaseDB,
        *,
        query_id: str,
        rows: list[dict],
        evidence_id: str,
    ) -> None:
        hypothesis = Hypothesis(
            id="H-XQ",
            description="logon was observed",
            confirm_when={"co_observed_event_ids": [4624]},
        )
        for row in rows:
            db.execute(
                "DELETE FROM evtx_events WHERE evidence_id = ?",
                [row["evidence_id"]],
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, source_file, "
                "channel, event_id) VALUES (?, ?, ?, ?)",
                [
                    row["evidence_id"],
                    row["source_file"],
                    row["channel"],
                    row["event_id"],
                ],
            )
        assessment = assess_evidence_group(
            hypothesis=hypothesis,
            rows=rows,
            evidence_ids=[evidence_id],
        )
        create_evidence_links_for_query(
            db,
            hypothesis_id="H-XQ",
            evidence_ids=[evidence_id],
            query_id=query_id,
            role=assessment.role,
            assessment_id=assessment.assessment_id,
        )

    def _assess(
        self,
        db: CaseDB,
        *,
        evidence_requirements: dict | None = None,
    ) -> SufficiencyResult:
        result, _verdict, _reason, _caps = assess_and_persist_sufficiency(
            db,
            hypothesis_id="H-XQ",
            evidence_requirements=evidence_requirements or {},
            llm_verdict="confirmed",
            verification_spec={
                "spec_version": "1",
                "support_conditions": {"co_observed_event_ids": [4624]},
            },
        )
        return result

    def _settle(self, db: CaseDB, rows: list[dict], result: SufficiencyResult) -> str:
        hypothesis = Hypothesis(
            id="H-XQ",
            description="logon was observed",
            confirm_when={"co_observed_event_ids": [4624]},
        )
        si = build_settlement_input_from_confirm_when(
            hypothesis=hypothesis,
            checker_verdict="confirmed",
            check_summary="proposed confirmation",
            sample_rows=rows,
            sufficiency_result=result,
        )
        return decide_settlement(
            si, links=load_evidence_links(db, "H-XQ", current_only=True), coverage={}
        )

    def test_refetch_via_different_query_is_one_group_for_both_gates(self) -> None:
        """Same evidence via two query IDs: one independent group end to end.

        A two-group requirement fails while only the duplicated attempt
        exists (LLM 'confirmed' is reconciled down), settlement is blocked,
        and a genuinely independent row (different source identity)
        restores two independent groups and confirms settlement.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                self._seed(db)
                requirements = {"min_independent_groups": 2}
                rows = self._observed_rows("sha-a", "evtx-1")
                self._link_observation(
                    db, query_id="Q-one", rows=rows, evidence_id="evtx-1"
                )
                self._link_observation(
                    db, query_id="Q-two", rows=rows, evidence_id="evtx-1"
                )
                self.assertEqual(len(load_evidence_links(db, "H-XQ")), 2)

                result = self._assess(db, evidence_requirements=requirements)
                self.assertEqual(result.independent_groups, 1)
                self.assertNotEqual(result.status, "sufficient")

                decision = self._settle(db, rows, result)
                self.assertFalse(decision.allowed)
                self.assertIn("machine_sufficiency=", "; ".join(decision.gates_failed))

                # A genuinely independent derivation root is not lost.
                independent_rows = self._observed_rows("sha-b", "evtx-2")
                self._link_observation(
                    db, query_id="Q-three", rows=independent_rows, evidence_id="evtx-2"
                )
                result = self._assess(db, evidence_requirements=requirements)
                self.assertEqual(result.independent_groups, 2)
                self.assertEqual(result.status, "sufficient")
                decision = self._settle(db, [*rows, *independent_rows], result)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.verdict, "confirmed")
