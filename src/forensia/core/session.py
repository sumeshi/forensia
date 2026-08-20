from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from forensia.core.verdicts import assert_valid_verdict
from forensia.core.verification import VerificationSpec, normalize_verification_spec

ENTITY_TYPE_ALIASES = {
    "host": "host",
    "hostname": "host",
    "computer": "host",
    "user": "user",
    "username": "user",
    "account": "user",
    "machine_account": "machine_account",
    "computer_account": "machine_account",
    "group": "group",
    "security_group": "group",
    "ip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "source_ip": "ip",
    "destination_ip": "ip",
    "ip_address": "ip",
    "process": "process",
    "new_process": "process",
    "service": "service",
    "service_name": "service",
    "file": "file",
    "path": "file",
    "registry": "registry",
    "unknown": "unknown",
}

ENTITY_ROLES = {
    "actor_user",
    "target_user",
    "target_group",
    "source_ip",
    "source_host",
    "source_account",
    "destination_host",
    "service_name",
    "service_path",
    "process_name",
    "file_path",
    "registry_key",
    "unknown",
}


class Hypothesis(BaseModel):
    id: str
    description: str
    status: Literal[
        "active",
        "confirmed",
        "refuted",
        "untestable",
        "needs_review",
        "deferred",
        "blocked",
    ] = "active"
    verdict: Literal["confirmed", "refuted", "untestable"] | None = None
    summary: str = ""
    source_rule_ids: list[str] = Field(default_factory=list)
    required_entities: list[str] = Field(default_factory=list)
    target_keypoint_id: str | None = None
    source_decl_id: str | None = None
    source_gap_id: str | None = None
    confirm_when: dict[str, Any] | None = None
    refute_when: dict[str, Any] | None = None
    evidence_requirements: dict[str, Any] | None = None
    # Canonical source of verification semantics.  The three legacy fields
    # above remain compatibility projections for existing callers.
    verification_spec: VerificationSpec | None = None
    fallback_phase: str | None = None
    fallback_source_rule_id: str | None = None

    @field_validator("verdict")
    @classmethod
    def _validate_verdict(cls, v: str | None) -> str | None:
        if v is not None:
            assert_valid_verdict(v, "hypothesis_verdict")
        return v

    @model_validator(mode="after")
    def _normalize_verification_spec(self) -> Hypothesis:
        spec = normalize_verification_spec(
            confirm_when=self.confirm_when,
            refute_when=self.refute_when,
            evidence_requirements=self.evidence_requirements,
            required_entities=self.required_entities,
            verification_spec=self.verification_spec,
        )
        projections = spec.legacy_fields()
        self.verification_spec = spec
        self.confirm_when = projections["confirm_when"]
        self.refute_when = projections["refute_when"]
        self.evidence_requirements = projections["evidence_requirements"]
        # Keep the existing entity field as a compatibility projection too;
        # canonical specs loaded from a case must not lose it.
        self.required_entities = projections["required_entities"]
        return self


class PlannedQuery(BaseModel):
    query_id: str
    hypothesis_id: str
    purpose: str
    sql: str = ""
    template_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("params", mode="before")
    @classmethod
    def coerce_params(cls, v: Any) -> dict[str, Any]:
        if v is None or not isinstance(v, dict):
            return {}
        return v


class HistoryEntry(BaseModel):
    iteration: int
    query_id: str
    hypothesis_id: str | None = None
    verdict: str | None = None
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    template_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""

    @field_validator("verdict")
    @classmethod
    def _validate_verdict(cls, v: str | None) -> str | None:
        if v is not None:
            assert_valid_verdict(v, "hypothesis_verdict")
        return v


class SessionState(BaseModel):
    session_id: str
    iteration: int = 0
    focus_hypothesis_id: str | None = None
    focus_depth: int = 0
    active_hypotheses: list[Hypothesis] = Field(default_factory=list)
    resolved_hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    history: list[HistoryEntry] = Field(default_factory=list)
    last_execution_error: dict[str, Any] | None = None
    proposed_keypoints: dict[str, int] = Field(default_factory=dict)
