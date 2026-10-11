"""Tests for M2: evidence sufficiency evaluation."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from forensia.core.case import Case
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.evidence.links import (
    EvidenceLink,
    evidence_link_currentness,
    load_evidence_links,
)
from forensia.investigation.verification.assessment import (
    _observation_value_matches,
    assess_evidence_group,
)
from forensia.investigation.verification.settlement import (
    build_settlement_input_from_confirm_when,
    decide_settlement,
)
from forensia.investigation.verification.sufficiency import (
    SufficiencyResult,
    assess_and_persist_sufficiency,
    create_evidence_links_for_query,
    create_hypothesis_evidence_link,
    evaluate_sufficiency,
    load_unlinkable_observations_for_session,
    reconcile_verdicts,
    record_unlinkable_observation,
)
from forensia.knowledge.coverage import canonical_observation_claim

_LOGON_EVENT_CONTEXT = {
    "event_id": 4624,
    "channel": "Security",
    "provider": "Microsoft-Windows-Security-Auditing",
}
_LOGON_RAW_JSON = json.dumps(
    {"winlog": {"provider": {"name": _LOGON_EVENT_CONTEXT["provider"]}}}
)


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
        rows = [
            {
                "evidence_id": "evtx-1",
                "event_id": 4624,
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
            }
        ]
        first = assess_evidence_group(
            hypothesis=Hypothesis(
                id="H-HASH",
                description="same",
                confirm_when={
                    "co_observed_event_ids": [4624],
                    "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                },
            ),
            rows=rows,
            evidence_ids=["evtx-1"],
        )
        self.assertEqual(first.role, "supporting")
        self.assertTrue(first.assessment_id.startswith("EA-v2-"))
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

    def test_assessment_identity_tracks_canonical_content_changes(self) -> None:
        hypothesis = Hypothesis(
            id="H-CONTENT-HASH",
            description="same",
            confirm_when={"co_observed_event_ids": [4624]},
        )
        kwargs = {
            "hypothesis": hypothesis,
            "rows": [{"evidence_id": "evtx-1", "event_id": 4624}],
            "evidence_ids": ["evtx-1"],
        }
        first = assess_evidence_group(
            **kwargs, content_fingerprints={"evtx-1": "cf-content-a"}
        )
        changed = assess_evidence_group(
            **kwargs, content_fingerprints={"evtx-1": "cf-content-b"}
        )

        self.assertNotEqual(first.assessment_id, changed.assessment_id)
        self.assertEqual(first.content_fingerprints, (("evtx-1", "cf-content-a"),))

    def test_assessment_links_only_condition_witness_rows(self) -> None:
        hypothesis = Hypothesis(
            id="H-WITNESS",
            description="A successful logon was observed",
            confirm_when={
                "co_observed_event_ids": [4624],
                "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
            },
        )
        rows = [
            {"evidence_id": f"evtx-{index:02d}", "event_id": 4625}
            for index in range(10)
        ] + [
            {
                "evidence_id": "evtx-witness",
                "event_id": 4624,
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
            }
        ]
        first = assess_evidence_group(
            hypothesis=hypothesis,
            rows=rows,
            evidence_ids=[row["evidence_id"] for row in rows],
        )
        reordered = assess_evidence_group(
            hypothesis=hypothesis,
            rows=list(reversed(rows)),
            evidence_ids=[row["evidence_id"] for row in reversed(rows)],
        )

        self.assertEqual(first.role, "supporting")
        self.assertEqual(first.witness_groups, (("evtx-witness",),))
        self.assertEqual(
            set(first.contextual_evidence_ids),
            {f"evtx-{index:02d}" for index in range(10)},
        )
        self.assertEqual(first.assessment_id, reordered.assessment_id)
        self.assertEqual(first.witness_groups, reordered.witness_groups)

    def test_correlated_witness_selection_is_stable_across_row_order(self) -> None:
        base = datetime(2025, 1, 1, tzinfo=UTC)
        context = {
            "event_id": 4104,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
        }
        rows = [
            {
                **context,
                "evidence_id": "evtx-host-z-1",
                "computer": "host-z",
                "timestamp": base.isoformat(),
            },
            {
                **context,
                "evidence_id": "evtx-host-z-2",
                "computer": "host-z",
                "timestamp": (base + timedelta(minutes=1)).isoformat(),
            },
            {
                **context,
                "evidence_id": "evtx-host-a-first-1",
                "computer": "host-a",
                "timestamp": (base + timedelta(hours=2)).isoformat(),
            },
            {
                **context,
                "evidence_id": "evtx-host-a-first-2",
                "computer": "host-a",
                "timestamp": (base + timedelta(hours=2, minutes=1)).isoformat(),
            },
            {
                **context,
                "evidence_id": "evtx-host-a-later-1",
                "computer": "host-a",
                "timestamp": (base + timedelta(hours=3)).isoformat(),
            },
            {
                **context,
                "evidence_id": "evtx-host-a-later-2",
                "computer": "host-a",
                "timestamp": (base + timedelta(hours=3, minutes=1)).isoformat(),
            },
        ]
        hypothesis = Hypothesis(
            id="H-CORRELATED",
            description="Repeated PowerShell script block activity was observed",
            confirm_when={
                "co_observed_event_ids": [4104],
                "event_contexts": [
                    {
                        "event_id": 4104,
                        "channel": context["channel"],
                        "provider": context["provider"],
                    }
                ],
                "same_host": True,
                "within_minutes": 5,
                "min_count": 2,
            },
        )
        first = assess_evidence_group(
            hypothesis=hypothesis,
            rows=rows,
            evidence_ids=[row["evidence_id"] for row in rows],
        )
        reversed_rows = list(reversed(rows))
        reordered = assess_evidence_group(
            hypothesis=hypothesis,
            rows=reversed_rows,
            evidence_ids=[row["evidence_id"] for row in reversed_rows],
        )

        expected = ("evtx-host-a-first-1", "evtx-host-a-first-2")
        self.assertEqual(first.role, "supporting")
        self.assertEqual(first.witness_groups, (expected,))
        self.assertEqual(reordered.witness_groups, first.witness_groups)
        self.assertEqual(reordered.assessment_id, first.assessment_id)
        self.assertEqual(
            set(first.contextual_evidence_ids),
            {row["evidence_id"] for row in rows} - set(expected),
        )

    def test_non_evtx_observation_condition_is_typed_and_family_scoped(self) -> None:
        hypothesis = Hypothesis(
            id="H-PREFETCH",
            description="PowerShell execution appears in Prefetch",
            confirm_when={
                "observation": {
                    "family": "prefetch",
                    "capability": "process_execution",
                    "field": "executable_name",
                    "operator": "equals",
                    "value": "POWERSHELL.EXE",
                }
            },
        )
        rows = [
            {
                "evidence_id": "prefetch-match",
                "source_family": "prefetch",
                "executable_name": "powershell.exe",
            },
            {
                "evidence_id": "mft-other",
                "source_family": "mft",
                "executable_name": "powershell.exe",
            },
        ]
        assessment = assess_evidence_group(
            hypothesis=hypothesis,
            rows=rows,
            evidence_ids=[row["evidence_id"] for row in rows],
        )

        self.assertEqual(assessment.role, "supporting")
        self.assertEqual(assessment.witness_groups, (("prefetch-match",),))
        self.assertEqual(assessment.contextual_evidence_ids, ("mft-other",))

        typed_cases = (
            (
                "mft",
                "file_activity",
                "size",
                "greater_than",
                100,
                {"size": 101},
            ),
            (
                "mft",
                "file_activity",
                "is_deleted",
                "equals",
                True,
                {"is_deleted": True},
            ),
            (
                "registry",
                "registry_observation",
                "key_path",
                "contains",
                "Run",
                {"key_path": r"HKLM\Software\Run"},
            ),
            (
                "prefetch",
                "process_execution",
                "exec_times",
                "contains",
                "2015-03-25 14:00:00",
                {"exec_times": ["2015-03-25 14:00:00", "2015-03-25 14:30:00"]},
            ),
        )
        for index, (family, capability, field, operator, value, observed) in enumerate(
            typed_cases, start=1
        ):
            with self.subTest(family=family):
                scoped = assess_evidence_group(
                    hypothesis=Hypothesis(
                        id=f"H-{family.upper()}-OBSERVATION",
                        description=f"{family} {field} observation",
                        confirm_when={
                            "observation": {
                                "family": family,
                                "capability": capability,
                                "field": field,
                                "operator": operator,
                                "value": value,
                            }
                        },
                    ),
                    rows=[
                        {
                            "evidence_id": f"{family}-{index}",
                            "source_family": family,
                            **observed,
                        }
                    ],
                    evidence_ids=[f"{family}-{index}"],
                )
                self.assertEqual("supporting", scoped.role)

        two_matches = Hypothesis(
            id="H-PREFETCH-MIN-COUNT",
            description="two Prefetch observations match the executable name",
            confirm_when={
                **hypothesis.verification_spec.support_conditions,
                "min_count": 2,
            },
        )
        duplicate_rows = [rows[0], {**rows[0]}]
        duplicate_assessment = assess_evidence_group(
            hypothesis=two_matches,
            rows=duplicate_rows,
            evidence_ids=["prefetch-match", "prefetch-match"],
        )
        self.assertEqual("contextual", duplicate_assessment.role)
        self.assertIn("distinct canonical evidence IDs", duplicate_assessment.reason)
        distinct_rows = [rows[0], {**rows[0], "evidence_id": "prefetch-match-2"}]
        distinct_assessment = assess_evidence_group(
            hypothesis=two_matches,
            rows=distinct_rows,
            evidence_ids=[row["evidence_id"] for row in distinct_rows],
        )
        self.assertEqual("supporting", distinct_assessment.role)
        self.assertEqual(
            {"prefetch-match", "prefetch-match-2"},
            set(distinct_assessment.evidence_ids),
        )

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

    def test_assessment_rejects_invalid_typed_observation_conditions(self) -> None:
        observation = {
            "family": "registry",
            "capability": "registry_observation",
            "field": "key_path",
            "operator": "contains",
            "value": "RunKey",
        }
        cases = (
            (
                {"observation": {**observation, "family": "evtx"}},
                "observation-family-unsupported",
            ),
            (
                {"observation": observation, "co_observed_event_ids": [4624]},
                "mixed-verification-condition-kinds",
            ),
            (
                {"observation": {**observation, "value": "  "}},
                "observation-value-invalid",
            ),
        )
        for conditions, reason in cases:
            with self.subTest(conditions=conditions):
                assessment = assess_evidence_group(
                    hypothesis=Hypothesis(
                        id="H-INVALID-OBSERVATION",
                        description="Registry observation",
                        confirm_when=conditions,
                    ),
                    rows=[
                        {
                            "evidence_id": "registry-1",
                            "source_family": "registry",
                            "key_path": r"HKLM\Software\Run",
                        }
                    ],
                    evidence_ids=["registry-1"],
                )
                self.assertNotEqual(assessment.role, "supporting")
                self.assertIn(reason, assessment.reason)

    def test_greater_than_observations_fail_closed_on_uncomparable_values(self) -> None:
        observation = {
            "family": "registry",
            "capability": "registry_observation",
            "field": "key_path",
            "operator": "greater_than",
            "value": "2025-01-01T00:00:00+00:00",
        }
        for index, value in enumerate(
            (10**1000, True, float("inf"), "2025-01-02T00:00:00"), start=1
        ):
            with self.subTest(value_type=type(value).__name__):
                assessment = assess_evidence_group(
                    hypothesis=Hypothesis(
                        id=f"H-GREATER-THAN-{index}",
                        description="Registry observation",
                        confirm_when={"observation": observation},
                    ),
                    rows=[
                        {
                            "evidence_id": "registry-1",
                            "source_family": "registry",
                            "key_path": value,
                        }
                    ],
                    evidence_ids=["registry-1"],
                )
                self.assertEqual("contextual", assessment.role)

    def test_numeric_observations_preserve_precision_and_reject_nonfinite(self) -> None:
        cases = (
            ("equals", 2**53, 2**53 + 1, "contextual"),
            ("greater_than", 2**53 + 1, 2**53, "supporting"),
            ("greater_than", 10**400, 10**399, "supporting"),
            ("greater_than", float("inf"), 1, "contextual"),
            ("greater_than", float("nan"), 1, "contextual"),
            ("greater_than", True, 0, "contextual"),
            ("equals", True, "true", "contextual"),
            ("equals", float("inf"), "Infinity", "contextual"),
        )
        for index, (operator, actual, expected, role) in enumerate(cases, start=1):
            with self.subTest(operator=operator, actual=actual, expected=expected):
                assessment = assess_evidence_group(
                    hypothesis=Hypothesis(
                        id=f"H-NUMERIC-OBSERVATION-{index}",
                        description="Numeric observation",
                        confirm_when={
                            "observation": {
                                "family": "mft",
                                "capability": "file_activity",
                                "field": "size",
                                "operator": operator,
                                "value": expected,
                            }
                        },
                    ),
                    rows=[
                        {
                            "evidence_id": "mft-numeric",
                            "source_family": "mft",
                            "size": actual,
                        }
                    ],
                    evidence_ids=["mft-numeric"],
                )
                self.assertEqual(role, assessment.role)
        self.assertFalse(_observation_value_matches(True, "equals", "true"))
        self.assertTrue(_observation_value_matches(True, "equals", True))
        self.assertTrue(_observation_value_matches(False, "equals", False))
        self.assertFalse(_observation_value_matches(True, "equals", 1))
        self.assertFalse(_observation_value_matches(1, "equals", True))
        self.assertFalse(_observation_value_matches(True, "contains", True))
        self.assertFalse(_observation_value_matches("Infinity", "equals", "Infinity"))
        self.assertFalse(_observation_value_matches(float("inf"), "equals", "Infinity"))

        datetime_cases = (
            (datetime(2026, 1, 2), "greater_than", "2026-01-01T00:00:00Z", True),
            (
                datetime(2026, 1, 1),
                "greater_than",
                "2026-01-01T01:00:00+01:00",
                False,
            ),
            (
                datetime(2026, 1, 2),
                "equals",
                "2026-01-02T01:00:00+01:00",
                True,
            ),
            (
                datetime.fromisoformat("2026-01-02T01:00:00+01:00"),
                "equals",
                datetime(2026, 1, 2),
                True,
            ),
            (datetime(2026, 1, 2), "greater_than", "not-a-timestamp", False),
            (
                "2026-01-02T00:00:00Z",
                "greater_than",
                "2026-01-01T01:00:00+01:00",
                True,
            ),
            (
                "2026-01-02T00:00:00Z",
                "greater_than",
                "2026-01-03T00:00:00Z",
                False,
            ),
        )
        for actual, operator, expected, matches in datetime_cases:
            with self.subTest(actual=actual, operator=operator, expected=expected):
                self.assertEqual(
                    matches, _observation_value_matches(actual, operator, expected)
                )

    def test_typed_observation_claim_scope_gates_settlement(self) -> None:
        condition = {
            "observation": {
                "family": "prefetch",
                "capability": "process_execution",
                "field": "executable_name",
                "operator": "equals",
                "value": "ERASER.EXE",
            }
        }
        canonical_hypothesis = Hypothesis(
            id="H-OBSERVATION-SCOPE",
            description="placeholder",
            confirm_when=condition,
        )
        canonical_claim = canonical_observation_claim(
            canonical_hypothesis.verification_spec
        )
        self.assertIsNotNone(canonical_claim)
        self.assertEqual(
            'At least 2 prefetch observations have executable_name equals "ERASER.EXE".',
            canonical_observation_claim(
                {
                    "support_conditions": {**condition, "min_count": 2},
                }
            ),
        )
        boolean_condition = {
            "support_conditions": {
                "observation": {
                    "family": "mft",
                    "capability": "file_activity",
                    "field": "is_deleted",
                    "operator": "equals",
                    "value": True,
                }
            }
        }
        self.assertEqual(
            "At least 1 mft observation has is_deleted equals true.",
            canonical_observation_claim(boolean_condition),
        )
        self.assertIsNone(
            canonical_observation_claim(
                {
                    "support_conditions": {
                        "observation": {
                            **boolean_condition["support_conditions"]["observation"],
                            "value": "true",
                        }
                    }
                }
            )
        )

        rows = [
            {
                "evidence_id": "prefetch-eraser",
                "source_family": "prefetch",
                "executable_name": "ERASER.EXE",
            }
        ]
        sufficiency = SufficiencyResult(
            status="sufficient",
            score=1.0,
            reasons=[],
            independent_groups=1,
            families=["prefetch"],
            contradictory_groups=0,
            missing_requirements=[],
            human_review_required=False,
        )

        def settle(description: str, verdict: str, role: str = "supporting"):
            hypothesis = Hypothesis(
                id="H-OBSERVATION-SCOPE",
                description=description,
                confirm_when=condition,
            )
            return decide_settlement(
                build_settlement_input_from_confirm_when(
                    hypothesis=hypothesis,
                    checker_verdict=verdict,
                    check_summary="typed observation",
                    sample_rows=rows,
                    sufficiency_result=sufficiency,
                ),
                links=[
                    EvidenceLink(
                        link_id="L-OBSERVATION-SCOPE",
                        hypothesis_id=hypothesis.id,
                        evidence_id="prefetch-eraser",
                        finding_id="",
                        query_id="Q-OBSERVATION-SCOPE",
                        assessment_id="EA-OBSERVATION-SCOPE",
                        role=role,
                        source_family="prefetch",
                        source_file="eraser.pf",
                        derivation_group="prefetch-eraser",
                        strength="strong",
                    )
                ],
                coverage={},
            )

        broad_confirmation = settle(
            "ERASER.EXE destroyed confidential files", "confirmed"
        )
        self.assertEqual("inconclusive", broad_confirmation.verdict)
        self.assertIn("scope unproven", broad_confirmation.reason)

        exact_confirmation = settle(canonical_claim or "", "confirmed")
        self.assertEqual("confirmed", exact_confirmation.verdict)
        self.assertTrue(exact_confirmation.allowed)

        refutation = settle(canonical_claim or "", "refuted", role="contradictory")
        self.assertEqual("inconclusive", refutation.verdict)
        self.assertIn("does not establish", refutation.reason)

    def test_observation_without_canonical_row_id_cannot_become_a_witness(self) -> None:
        assessment = assess_evidence_group(
            hypothesis=Hypothesis(
                id="H-UNLINKABLE-WITNESS",
                description="A successful logon was observed",
                confirm_when={
                    "co_observed_event_ids": [4624],
                    "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                },
            ),
            rows=[
                {
                    "event_id": 4624,
                    "channel": "Security",
                    "provider": "Microsoft-Windows-Security-Auditing",
                }
            ],
            evidence_ids=["evtx-unlinked"],
        )

        self.assertEqual("contextual", assessment.role)
        self.assertEqual((), assessment.evidence_ids)
        self.assertEqual(("evtx-unlinked",), assessment.contextual_evidence_ids)
        self.assertIn("no linkable witness ID", assessment.reason)

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
        from forensia.investigation.verification.settlement import (
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
            "INSERT INTO evtx_events (evidence_id, source_file, channel, event_id, raw_json) "
            "VALUES ('evtx-1', ?, 'Security', 4624, ?)",
            [source_file, _LOGON_RAW_JSON],
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
                rows=[
                    {
                        "evidence_id": "evtx-1",
                        "event_id": 4624,
                        "channel": "Security",
                        "provider": _LOGON_EVENT_CONTEXT["provider"],
                    }
                ],
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
                assessment_reason=assessment.reason,
                matched_conditions=assessment.matched_conditions,
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
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, event_id, raw_json) "
                    "VALUES ('evtx-1', 'sha-new', 'Security', 4624, ?)",
                    [_LOGON_RAW_JSON],
                )
                self.assertEqual(self._assess(db).status, "insufficient")

                # Re-created under the originally linked source again with
                # identical content, the judged material is present as-is and
                # the link counts as current without re-assessment.
                db.execute("DELETE FROM evtx_events WHERE evidence_id = 'evtx-1'")
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, event_id, raw_json) "
                    "VALUES ('evtx-1', 'sha-a', 'Security', 4624, ?)",
                    [_LOGON_RAW_JSON],
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
                    "support_conditions": {
                        "co_observed_event_ids": [4624],
                        "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                    },
                }
                self._seed(db, verification_spec=original_spec)
                before = load_evidence_links(db, "H-CUR", current_only=True)
                self.assertEqual(len(before), 1)

                changed_spec = {
                    "spec_version": "1",
                    "support_conditions": {
                        "co_observed_event_ids": [4624],
                        "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                    },
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
                    rows=[
                        {
                            "evidence_id": "evtx-1",
                            "event_id": 4624,
                            "channel": "Security",
                            "provider": _LOGON_EVENT_CONTEXT["provider"],
                        }
                    ],
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

    def test_re_evaluation_keeps_old_assessment_grounds_per_link(self) -> None:
        """R08: the judgment grounds ride on the existing link payload.

        Each link carries the ``reason``/``matched_conditions`` of exactly one
        deterministic Assessment; a re-evaluation under a changed Spec adds a
        new link with new grounds instead of overwriting the old judgment.
        """
        from forensia.core.verification import VerificationSpec

        first_spec = {
            "spec_version": "1",
            "support_conditions": {
                "co_observed_event_ids": [4624],
                "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
            },
        }
        changed_spec = {
            "spec_version": "1",
            "support_conditions": {
                "co_observed_event_ids": [4624],
                "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                "same_host": True,
            },
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, event_id, raw_json) "
                    "VALUES ('evtx-1', 'sha-a', 'Security', 4624, ?)",
                    [_LOGON_RAW_JSON],
                )
                db.execute(
                    "INSERT INTO hypotheses (hypothesis_id, status, created_at, "
                    "updated_at, verification_spec) VALUES ('H-CUR', 'active', "
                    "now(), now(), ?)",
                    [json.dumps(first_spec)],
                )

                def _assess_under(spec: dict, rows: list[dict]):
                    hypothesis = Hypothesis(
                        id="H-CUR",
                        description="currentness fixture",
                        status="active",
                        verification_spec=VerificationSpec.model_validate(spec),
                    )
                    return assess_evidence_group(
                        hypothesis=hypothesis,
                        rows=rows,
                        evidence_ids=["evtx-1"],
                        derivation_group="evtx-1",
                    )

                assessment = _assess_under(
                    first_spec,
                    [
                        {
                            "evidence_id": "evtx-1",
                            "event_id": 4624,
                            "channel": "Security",
                            "provider": _LOGON_EVENT_CONTEXT["provider"],
                        }
                    ],
                )
                self.assertEqual(assessment.role, "supporting")
                create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_id="evtx-1",
                    query_id="Q-20",
                    role=assessment.role,
                    assessment_id=assessment.assessment_id,
                    assessment_reason=assessment.reason,
                    matched_conditions=assessment.matched_conditions,
                    derivation_group=assessment.derivation_group,
                )
                grounds = db.execute(
                    "SELECT assessment_reason, matched_conditions, assessment_id "
                    "FROM hypothesis_evidence WHERE hypothesis_id = 'H-CUR'"
                ).fetchall()
                self.assertEqual(len(grounds), 1)
                self.assertEqual(grounds[0][0], "matched support conditions")
                self.assertEqual(
                    json.loads(grounds[0][1]),
                    ["co_observed_event_ids", "event_contexts"],
                )

                # Re-evaluation under a narrowed Spec: new assessment id,
                # new link, new grounds; the old link is untouched.
                db.execute(
                    "UPDATE hypotheses SET verification_spec = ? "
                    "WHERE hypothesis_id = 'H-CUR'",
                    [json.dumps(changed_spec)],
                )
                re_assessment = _assess_under(
                    changed_spec,
                    [
                        {
                            "evidence_id": "evtx-1",
                            "event_id": 4624,
                            "channel": "Security",
                            "provider": _LOGON_EVENT_CONTEXT["provider"],
                            "computer": "host-a",
                        }
                    ],
                )
                self.assertEqual(re_assessment.role, "supporting")
                self.assertNotEqual(re_assessment.assessment_id, grounds[0][2])
                create_hypothesis_evidence_link(
                    db,
                    hypothesis_id="H-CUR",
                    evidence_id="evtx-1",
                    query_id="Q-21",
                    role=re_assessment.role,
                    assessment_id=re_assessment.assessment_id,
                    assessment_reason=re_assessment.reason,
                    matched_conditions=re_assessment.matched_conditions,
                    derivation_group=re_assessment.derivation_group,
                )
                rows = db.execute(
                    "SELECT assessment_id, role, assessment_reason, "
                    "matched_conditions FROM hypothesis_evidence "
                    "WHERE hypothesis_id = 'H-CUR' ORDER BY query_id, link_id"
                ).fetchall()
                self.assertEqual(len(rows), 2)
                self.assertEqual(
                    [row[2] for row in rows],
                    ["matched support conditions", "matched support conditions"],
                )
                self.assertEqual(
                    json.loads(rows[0][3]),
                    ["co_observed_event_ids", "event_contexts"],
                )
                self.assertEqual(
                    json.loads(rows[1][3]),
                    ["co_observed_event_ids", "event_contexts", "same_host"],
                )
                self.assertNotEqual(rows[0][0], rows[1][0])


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
            '{"co_observed_event_ids": [4624], "event_contexts": '
            + json.dumps([_LOGON_EVENT_CONTEXT])
            + "}}')"
        )

    def _observed_rows(self, source: str, evidence_id: str) -> list[dict]:
        return [
            {
                "evidence_id": evidence_id,
                "event_id": 4624,
                "channel": "Security",
                "provider": _LOGON_EVENT_CONTEXT["provider"],
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
            confirm_when={
                "co_observed_event_ids": [4624],
                "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
            },
        )
        for row in rows:
            db.execute(
                "DELETE FROM evtx_events WHERE evidence_id = ?",
                [row["evidence_id"]],
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, source_file, "
                "channel, event_id, raw_json) VALUES (?, ?, ?, ?, ?)",
                [
                    row["evidence_id"],
                    row["source_file"],
                    row["channel"],
                    row["event_id"],
                    _LOGON_RAW_JSON,
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
                "support_conditions": {
                    "co_observed_event_ids": [4624],
                    "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
                },
            },
        )
        return result

    def _settle(self, db: CaseDB, rows: list[dict], result: SufficiencyResult) -> str:
        hypothesis = Hypothesis(
            id="H-XQ",
            description="logon was observed",
            confirm_when={
                "co_observed_event_ids": [4624],
                "event_contexts": [dict(_LOGON_EVENT_CONTEXT)],
            },
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
