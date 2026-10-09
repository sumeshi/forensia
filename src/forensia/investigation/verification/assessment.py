"""Evidence Assessment between retrieval and cumulative sufficiency."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from forensia.core.verification import EVALUABLE_CONDITION_KEYS
from forensia.investigation.verification.check_guardrails import (
    _co_observation_satisfied,
)

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
) -> tuple[bool, list[str], str]:
    """Evaluate one VerificationSpec condition against observation rows.

    Returns ``(satisfied, matched_fields, rejection_reason)``.  The condition
    keys come from the shared vocabulary in ``core/verification.py``
    (``EVALUABLE_CONDITION_KEYS``).  Keys outside it fail closed with an
    explicit unsupported-key reason and are never treated as satisfied.
    ``event_contexts`` needs no separate handling here: the co-observation
    adapter itself reads it from the condition payload and filters rows to
    catalog-qualified channel/provider contexts. Field constraints filter the
    observations before the shared host/entity/time-window correlation search.
    """

    if not isinstance(condition, dict):
        return False, [], "conditions not satisfied"
    unsupported = sorted(set(condition) - EVALUABLE_CONDITION_KEYS)
    if unsupported:
        return False, [], f"unsupported condition keys: {unsupported}"
    raw_ids = condition.get("co_observed_event_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        # A condition without event IDs (for example bare event_contexts)
        # would be trivially satisfied by the co-observation adapter; keep it
        # unmatched.  Admission rejects such support specs as non-testable.
        return False, [], "conditions not satisfied"
    try:
        for value in raw_ids:
            int(value)
    except TypeError, ValueError:
        # Finding IDs and other condition types require a different observation
        # adapter; do not silently treat them as satisfied event conditions.
        return False, [], "conditions not satisfied"
    satisfied, _reason = _co_observation_satisfied(condition, rows)
    if not satisfied:
        return False, [], "conditions not satisfied"
    matched = [key for key in sorted(EVALUABLE_CONDITION_KEYS) if key in condition]
    return True, matched, ""


def assess_evidence_group(
    *,
    hypothesis: Any,
    rows: list[dict[str, Any]],
    evidence_ids: list[str],
    derivation_group: str = "",
    retrieval_outcome: str = "adequate",
) -> EvidenceAssessment:
    """Classify observations without reading a checker or final verdict.

    Condition keys outside the shared verification vocabulary remain
    contextual with an explicit unsupported-key reason; known conditions that
    the observations do not satisfy stay contextual too. ``event_contexts`` is
    evaluated through the co-observation adapter, which filters rows to
    catalog-qualified channel/provider contexts. Empty or non-adequate
    retrievals cannot create supporting/contradictory relations.

    ``derivation_group`` is the declared derivation root of the observation
    (same declared root stays one independence group at sufficiency/settlement).
    It defaults to the first evidence id: the derivation root is a property of
    the observed content, never of the acquisition attempt.  The query id is
    acquisition history and is deliberately absent from the assessment
    identity, so re-observing the same evidence is the same assessment.
    """

    normalized_ids = tuple(
        dict.fromkeys(str(item).strip() for item in evidence_ids if str(item).strip())
    )
    spec = getattr(hypothesis, "verification_spec", None)
    support = getattr(spec, "support_conditions", None) or {}
    refute = getattr(spec, "refute_conditions", None) or {}
    version = str(getattr(spec, "spec_version", "legacy") or "legacy")
    group = derivation_group or (normalized_ids[0] if normalized_ids else "empty")

    role: AssessmentRole = "unrelated"
    reason = "observation has no matching VerificationSpec condition"
    matched: list[str] = []
    if retrieval_outcome != "adequate":
        role, reason = "contextual", f"retrieval outcome is {retrieval_outcome}"
    elif normalized_ids and rows:
        refute_match, refute_fields, refute_reason = _condition_matches(refute, rows)
        support_match, support_fields, support_reason = _condition_matches(
            support, rows
        )
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
        elif support_reason != "conditions not satisfied":
            # An unsupported condition key must be distinguishable from a
            # known condition that the observations simply did not satisfy.
            role, reason = "contextual", support_reason
        elif refute_reason != "conditions not satisfied":
            role, reason = "contextual", refute_reason
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
