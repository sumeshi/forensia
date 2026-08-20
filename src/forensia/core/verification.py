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
