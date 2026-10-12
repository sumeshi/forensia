"""Evidence Assessment between retrieval and cumulative sufficiency."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from forensia.core.verification import EVALUABLE_CONDITION_KEYS
from forensia.db.query import normalize_value
from forensia.investigation.verification.check_guardrails import (
    _co_observation_evaluation,
)
from forensia.knowledge.coverage import observation_condition_error

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
    """Deterministic witness and context classification for observed evidence."""

    assessment_id: str
    hypothesis_id: str
    role: AssessmentRole
    evidence_ids: tuple[str, ...]
    derivation_group: str
    origin: str
    spec_version: str
    reason: str
    matched_conditions: tuple[str, ...] = ()
    witness_groups: tuple[tuple[str, ...], ...] = ()
    contextual_evidence_ids: tuple[str, ...] = ()
    content_fingerprints: tuple[tuple[str, str], ...] = ()


def _condition_matches(
    condition: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[bool, list[str], str, list[list[int]]]:
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
        return False, [], "conditions not satisfied", []
    unsupported = sorted(set(condition) - EVALUABLE_CONDITION_KEYS)
    if unsupported:
        return False, [], f"unsupported condition keys: {unsupported}", []
    if "observation" in condition:
        validation_error = observation_condition_error(condition)
        if validation_error:
            return False, [], validation_error, []

    witness_groups: list[list[int]] = []
    if "co_observed_event_ids" in condition:
        raw_ids = condition.get("co_observed_event_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            return False, [], "conditions not satisfied", []
        try:
            for value in raw_ids:
                int(value)
        except TypeError, ValueError:
            return False, [], "conditions not satisfied", []
        satisfied, reason, witness_groups = _co_observation_evaluation(condition, rows)
        if not satisfied:
            return False, [], reason, []

    if "observation" in condition:
        observation = condition.get("observation")
        family = str(observation.get("family") or "").strip().lower()
        field = str(observation.get("field") or "").strip()
        operator = str(observation.get("operator") or "").strip()
        expected = observation.get("value")

        matching_rows: list[int] = []
        matching_family_rows = 0
        available_field_rows = 0
        for index, row in enumerate(rows):
            row_family = (
                str(row.get("source_family") or row.get("artifact_family") or "")
                .strip()
                .lower()
            )
            if row_family != family:
                continue
            matching_family_rows += 1
            if field not in row:
                continue
            available_field_rows += 1
            if _observation_value_matches(row.get(field), operator, expected):
                matching_rows.append(index)
        if not matching_rows:
            if not matching_family_rows:
                return False, [], f"observation family {family} not present in rows", []
            if not available_field_rows:
                return False, [], f"observation field {field} unavailable in rows", []
            return False, [], "observation condition not satisfied", []
        witness_groups.extend([[index] for index in matching_rows])

    if not witness_groups:
        return False, [], "conditions not satisfied", []
    matched = [key for key in sorted(EVALUABLE_CONDITION_KEYS) if key in condition]
    return True, matched, "", witness_groups


def _observation_value_matches(value: Any, operator: str, expected: Any) -> bool:
    """Apply the small typed observation operator set to a normalized field."""
    if isinstance(value, str):
        value = normalize_value(value)
    if value is None:
        return False
    if isinstance(value, bool) or isinstance(expected, bool):
        return (
            operator == "equals"
            and isinstance(value, bool)
            and isinstance(expected, bool)
            and value is expected
        )
    if operator == "equals":
        if isinstance(expected, str):
            try:
                expected_number = Decimal(expected)
            except InvalidOperation:
                expected_number = None
            if expected_number is not None and not expected_number.is_finite():
                return False
        if isinstance(value, (int, float, Decimal)):
            actual_number = _finite_decimal(value)
            expected_number = _finite_decimal(expected)
            return (
                actual_number is not None
                and expected_number is not None
                and actual_number == expected_number
            )
        if isinstance(value, datetime):
            actual_time = _observation_utc_datetime(value)
            expected_time = _observation_utc_datetime(expected)
            return (
                actual_time is not None
                and expected_time is not None
                and actual_time == expected_time
            )
        return str(value).strip().casefold() == str(expected).strip().casefold()
    if operator == "contains":
        wanted = str(expected).strip().casefold()
        values = value if isinstance(value, (list, tuple, set)) else [value]
        return any(
            wanted in str(item).casefold() for item in values if item is not None
        )
    if operator == "greater_than":
        actual_number = _finite_decimal(value)
        expected_number = _finite_decimal(expected)
        if actual_number is not None and expected_number is not None:
            return actual_number > expected_number
        if isinstance(value, datetime):
            actual_time = _observation_utc_datetime(value)
            expected_time = _observation_utc_datetime(expected)
            return (
                actual_time is not None
                and expected_time is not None
                and actual_time > expected_time
            )
        try:
            actual_time = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            expected_time = (
                expected
                if isinstance(expected, datetime)
                else datetime.fromisoformat(str(expected).replace("Z", "+00:00"))
            )
            return actual_time > expected_time
        except TypeError, ValueError, OverflowError:
            return False
    return False


def _observation_utc_datetime(value: Any) -> datetime | None:
    """Interpret naive database timestamps as UTC and normalize ISO inputs."""
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except TypeError, ValueError, OverflowError:
        return None
    if parsed.utcoffset() is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _finite_decimal(value: Any) -> Decimal | None:
    """Parse a finite numeric comparison operand without losing precision."""
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        return None
    return number if number.is_finite() else None


def assess_evidence_group(
    *,
    hypothesis: Any,
    rows: list[dict[str, Any]],
    evidence_ids: list[str],
    derivation_group: str = "",
    retrieval_outcome: str = "adequate",
    content_fingerprints: dict[str, str] | None = None,
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
    identity, so re-observing unchanged evidence is the same assessment.
    Canonical content fingerprints are part of that identity, so an in-place
    evidence change creates a new assessment.
    """

    provided_ids = [str(item).strip() for item in evidence_ids if str(item).strip()]
    normalized_ids = tuple(sorted(set(provided_ids)))
    spec = getattr(hypothesis, "verification_spec", None)
    support = getattr(spec, "support_conditions", None) or {}
    refute = getattr(spec, "refute_conditions", None) or {}
    version = str(getattr(spec, "spec_version", "legacy") or "legacy")
    group = derivation_group or (normalized_ids[0] if normalized_ids else "empty")

    role: AssessmentRole = "unrelated"
    reason = "observation has no matching VerificationSpec condition"
    matched: list[str] = []
    witness_groups: list[list[int]] = []
    if retrieval_outcome != "adequate":
        role, reason = "contextual", f"retrieval outcome is {retrieval_outcome}"
    elif normalized_ids and rows:
        refute_match, refute_fields, refute_reason, refute_groups = _condition_matches(
            refute, rows
        )
        support_match, support_fields, support_reason, support_groups = (
            _condition_matches(support, rows)
        )
        if refute_match:
            role, reason, matched = (
                "contradictory",
                "matched refute conditions",
                refute_fields,
            )
            witness_groups = refute_groups
        elif support_match:
            role, reason, matched = (
                "supporting",
                "matched support conditions",
                support_fields,
            )
            witness_groups = support_groups
        elif (
            support_reason.startswith(("unsupported condition keys", "observation-"))
            or support_reason == "mixed-verification-condition-kinds"
        ):
            role, reason = "contextual", support_reason
        elif (
            refute_reason.startswith(("unsupported condition keys", "observation-"))
            or refute_reason == "mixed-verification-condition-kinds"
        ):
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

    row_ids = [
        str(row.get("evidence_id") or row.get("artifact_id") or "").strip()
        for row in rows
    ]
    linked_ids = set(normalized_ids)
    normalized_witness_groups = [
        tuple(
            sorted(
                {
                    row_ids[index]
                    for index in indices
                    if 0 <= index < len(row_ids) and row_ids[index] in linked_ids
                }
            )
        )
        for indices in witness_groups
    ]
    normalized_witness_groups = [
        group_ids for group_ids in normalized_witness_groups if group_ids
    ]
    normalized_witness_groups.sort()
    witness_ids = tuple(
        dict.fromkeys(
            item for group_ids in normalized_witness_groups for item in group_ids
        )
    )
    if role == "supporting" and "observation" in support:
        min_count = support.get("min_count", 1)
    elif role == "contradictory" and "observation" in refute:
        min_count = refute.get("min_count", 1)
    else:
        min_count = 1
    if (
        min_count > 1
        and role in ("supporting", "contradictory")
        and len(witness_ids) < min_count
    ):
        role, reason = (
            "contextual",
            f"observation requires {min_count} distinct canonical evidence IDs",
        )
    if role in ("supporting", "contradictory") and not witness_ids:
        role, reason = "contextual", "matched observation has no linkable witness ID"
    contextual_ids = tuple(
        item for item in normalized_ids if item not in set(witness_ids)
    )

    canonical_conditions = json.dumps(
        {"support": support, "refute": refute},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    normalized_fingerprints = tuple(
        sorted(
            (str(evidence_id).strip(), str(fingerprint).strip())
            for evidence_id, fingerprint in (content_fingerprints or {}).items()
            if str(evidence_id).strip() in linked_ids and str(fingerprint).strip()
        )
    )
    canonical_fingerprints = json.dumps(
        dict(normalized_fingerprints),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    payload = "|".join(
        (
            str(hypothesis.id),
            version,
            canonical_conditions,
            canonical_fingerprints,
            group,
            *normalized_ids,
            *(
                "witness:" + ",".join(group_ids)
                for group_ids in normalized_witness_groups
            ),
            role,
        )
    )
    assessment_id = (
        "EA-v2-deterministic-"
        + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    )
    return EvidenceAssessment(
        assessment_id=assessment_id,
        hypothesis_id=str(hypothesis.id),
        role=role,
        evidence_ids=witness_ids,
        derivation_group=group,
        origin="verification_spec:deterministic",
        spec_version=version,
        reason=reason,
        matched_conditions=tuple(matched),
        witness_groups=tuple(normalized_witness_groups),
        contextual_evidence_ids=contextual_ids,
        content_fingerprints=normalized_fingerprints,
    )
