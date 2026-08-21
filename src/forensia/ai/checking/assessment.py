"""Evidence Assessment between retrieval and cumulative sufficiency."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from forensia.ai.checking.check_guardrails import _co_observation_satisfied

AssessmentRole = Literal[
    "supporting",
    "corroborating",
    "contradictory",
    "contextual",
    "unrelated",
    "duplicate",
]


@dataclass(frozen=True)
class EvidenceAssessment:
    """Deterministic relationship between one observation group and a hypothesis."""

    assessment_id: str
    hypothesis_id: str
    role: AssessmentRole
    evidence_ids: tuple[str, ...]
    derivation_group: str
    origin: str
    spec_version: str
    reason: str
    matched_conditions: tuple[str, ...] = ()


def _condition_matches(
    condition: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[bool, list[str]]:
    """Evaluate only the condition vocabulary already enforced by guardrails."""

    supported = {
        "co_observed_event_ids",
        "same_host",
        "within_minutes",
        "same_entities",
        "min_count",
    }
    if not isinstance(condition, dict) or set(condition) - supported:
        return False, []
    raw_ids = condition.get("co_observed_event_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        return False, []
    try:
        for value in raw_ids:
            int(value)
    except TypeError, ValueError:
        # Finding IDs and other condition types require a different observation
        # adapter; do not silently treat them as satisfied event conditions.
        return False, []
    satisfied, _reason = _co_observation_satisfied(condition, rows)
    matched = [key for key in supported if key in condition]
    return satisfied, matched if satisfied else []


def assess_evidence_group(
    *,
    hypothesis: Any,
    rows: list[dict[str, Any]],
    evidence_ids: list[str],
    query_id: str = "",
    derivation_group: str = "",
    retrieval_outcome: str = "adequate",
) -> EvidenceAssessment:
    """Classify observations without reading a checker or final verdict.

    Unsupported VerificationSpec conditions remain contextual. Empty or
    non-adequate retrievals cannot create supporting/contradictory relations.
    """

    normalized_ids = tuple(
        dict.fromkeys(str(item).strip() for item in evidence_ids if str(item).strip())
    )
    spec = getattr(hypothesis, "verification_spec", None)
    support = (
        getattr(spec, "support_conditions", None)
        or getattr(hypothesis, "confirm_when", None)
        or {}
    )
    refute = (
        getattr(spec, "refute_conditions", None)
        or getattr(hypothesis, "refute_when", None)
        or {}
    )
    version = str(getattr(spec, "spec_version", "legacy") or "legacy")
    group = (
        derivation_group
        or query_id
        or (normalized_ids[0] if normalized_ids else "empty")
    )

    role: AssessmentRole = "unrelated"
    reason = "observation has no matching VerificationSpec condition"
    matched: list[str] = []
    if retrieval_outcome != "adequate":
        role, reason = "contextual", f"retrieval outcome is {retrieval_outcome}"
    elif normalized_ids and rows:
        refute_match, refute_fields = _condition_matches(refute, rows)
        support_match, support_fields = _condition_matches(support, rows)
        if refute_match:
            role, reason, matched = (
                "contradictory",
                "matched refute conditions",
                refute_fields,
            )
        elif support_match:
            role, reason, matched = (
                "supporting",
                "matched support conditions",
                support_fields,
            )
        else:
            role, reason = "contextual", "observed but conditions were not satisfied"

    # Sole authority: roles are derived only from VerificationSpec conditions,
    # coverage, support/refute/diversity — never from a checker verdict or any
    # prose.  A supporting/contradictory role without matched conditions is a
    # programming error and is downgraded to contextual so no claim is
    # manufactured from narrative text.
    if role in ("supporting", "contradictory") and not matched:
        role, reason = "contextual", "role requires matched conditions"

    canonical_conditions = json.dumps(
        {"support": support, "refute": refute},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    payload = "|".join(
        (
            str(hypothesis.id),
            version,
            canonical_conditions,
            group,
            *normalized_ids,
            role,
        )
    )
    assessment_id = (
        "EA-v1-deterministic-"
        + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    )
    return EvidenceAssessment(
        assessment_id=assessment_id,
        hypothesis_id=str(hypothesis.id),
        role=role,
        evidence_ids=normalized_ids,
        derivation_group=group,
        origin="verification_spec:deterministic",
        spec_version=version,
        reason=reason,
        matched_conditions=tuple(matched),
    )
