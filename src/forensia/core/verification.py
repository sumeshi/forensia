"""Canonical verification semantics for admitted hypotheses.

The case database historically stored the three pieces of a hypothesis' test
policy independently (``confirm_when``, ``refute_when`` and
``evidence_requirements``).  ``VerificationSpec`` is the single normalized
representation.  The legacy fields remain projections for compatibility with
the existing planner/checker code and are deliberately kept lossless.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

# Shared support-condition vocabulary ("confirm_when" / VerificationSpec
# support_conditions).  This is the single owner of the condition-key set that
# admission and Assessment agree on, so a spec admitted with a key is always
# evaluable at Assessment.  Each key and where it is evaluated:
#
# - ``co_observed_event_ids``: integer event IDs that must all be observed in
#   the evidence group.  Required by the admission pre-screen
#   (``_claim_spec_conformance_error``); evaluated through the co-observation
#   adapter (``ai/checking/check_guardrails._co_observation_satisfied``).
# - ``event_contexts``: catalog-qualified channel/provider declarations for
#   provider-reused event IDs.  Admission validates each declaration against
#   the event catalog; the co-observation adapter filters rows through
#   ``_context_qualified_rows`` before checking ID presence.
# - ``same_host`` / ``within_minutes`` / ``same_entities`` / ``min_count``:
#   correlation constraints evaluated by the co-observation adapter at
#   Assessment; admission additionally cross-checks them against the claim
#   wording.
# - ``event_constraints``: per-event field constraints of the shape
#   ``{event_id: {field: [values]}}`` (for example requiring
#   ``logon_type=10`` on the 4624 rows of an RDP hypothesis).  Evaluated
#   before host/entity/time correlation by the shared co-observation adapter
#   at Assessment and Settlement, so the gates use the same witnesses. A
#   declared event absent from the rows, or a constraint field no row
#   carries, fails closed with an explicit reason.
#
# Condition keys outside this set are never treated as satisfied: Assessment
# keeps the observation contextual and records an explicit unsupported-key
# reason.  In particular ``keywords`` (declared by some rulepacks next to
# ``co_observed_event_ids``) is NOT an observation condition: nothing in the
# pipeline evaluates it over rows, so it stays outside the vocabulary and a
# spec that carries it fails closed at Assessment with an explicit reason.
# Keywords used by the planner/checker live in ``fallback_search[].keywords``
# and ``event_ids.yaml`` (``keywords_for_string_search``), a separate
# planner-facing vocabulary.  Refute conditions use a separate vocabulary
# (for example ``zero_rows``) owned by the settlement gates.
EVALUABLE_CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "co_observed_event_ids",
        "event_contexts",
        "same_host",
        "within_minutes",
        "same_entities",
        "min_count",
        "event_constraints",
    }
)


class VerificationSpec(BaseModel):
    """Versioned, serializable verification policy for one hypothesis.

    The condition and policy payloads intentionally remain structured JSON:
    rulepacks and future artifact families may add condition keys without a
    schema migration.  The surrounding fields provide the stable contract
    consumed by later planner, assessment, sufficiency, and settlement work.
    """

    model_config = ConfigDict(extra="forbid")

    CURRENT_VERSION: ClassVar[str] = "1"

    spec_version: Literal["1"] = CURRENT_VERSION
    support_conditions: dict[str, Any] = Field(default_factory=dict)
    refute_conditions: dict[str, Any] = Field(default_factory=dict)
    required_capabilities: list[str] = Field(default_factory=list)
    required_source_families: list[str] = Field(default_factory=list)
    required_entities: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    correlation: dict[str, Any] = Field(default_factory=dict)
    evidence_requirements: dict[str, Any] = Field(default_factory=dict)
    derivation_dedup_policy: dict[str, Any] = Field(default_factory=dict)
    allowed_settlement_states: list[str] = Field(default_factory=list)
    untestable_conditions: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_legacy(
        cls,
        *,
        confirm_when: Any = None,
        refute_when: Any = None,
        evidence_requirements: Any = None,
        required_entities: Any = None,
        verification_spec: Any = None,
    ) -> VerificationSpec:
        """Normalize either canonical or legacy fields without dropping data."""

        if verification_spec is not None:
            if isinstance(verification_spec, cls):
                return verification_spec.model_copy(deep=True)
            if not isinstance(verification_spec, dict):
                raise ValueError("verification_spec must be a JSON object")
            return cls.model_validate(deepcopy(verification_spec))

        def object_or_empty(value: Any, name: str) -> dict[str, Any]:
            if value is None:
                return {}
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be a JSON object")
            return deepcopy(value)

        entities: list[str] = []
        if required_entities is not None:
            if not isinstance(required_entities, list):
                raise ValueError("required_entities must be a JSON array")
            entities = [str(item) for item in deepcopy(required_entities) if item]

        return cls(
            support_conditions=object_or_empty(confirm_when, "confirm_when"),
            refute_conditions=object_or_empty(refute_when, "refute_when"),
            required_entities=entities,
            evidence_requirements=object_or_empty(
                evidence_requirements, "evidence_requirements"
            ),
        )

    def legacy_fields(self) -> dict[str, Any]:
        """Return lossless compatibility projections for existing callers."""

        return {
            "confirm_when": deepcopy(self.support_conditions) or None,
            "refute_when": deepcopy(self.refute_conditions) or None,
            "evidence_requirements": deepcopy(self.evidence_requirements) or None,
            "required_entities": deepcopy(self.required_entities),
        }


def normalize_verification_spec(
    *,
    confirm_when: Any = None,
    refute_when: Any = None,
    evidence_requirements: Any = None,
    required_entities: Any = None,
    verification_spec: Any = None,
) -> VerificationSpec:
    """Small public normalization seam shared by creation and persistence paths."""

    return VerificationSpec.from_legacy(
        confirm_when=confirm_when,
        refute_when=refute_when,
        evidence_requirements=evidence_requirements,
        required_entities=required_entities,
        verification_spec=verification_spec,
    )
