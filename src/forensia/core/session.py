from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from forensia.core.verdicts import assert_valid_verdict
from forensia.core.verification import VerificationSpec

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
    status: str = "active"
    verdict: str | None = None
    summary: str = ""
    source_rule_ids: list[str] = Field(default_factory=list)
    required_entities: list[str] = Field(default_factory=list)
    target_keypoint_id: str | None = None
    source_decl_id: str | None = None
    source_gap_id: str | None = None
    # Canonical source of verification semantics.  Rule/LLM declarations
    # (``confirm_when``/``refute_when``/``evidence_requirements``) are
    # converted into it once, here; it is the only condition state the model
    # carries and the only condition representation that is stored.
    verification_spec: VerificationSpec = Field(default_factory=VerificationSpec)
    fallback_phase: str | None = None
    fallback_source_rule_id: str | None = None

    @field_validator("verdict")
    @classmethod
    def _validate_verdict(cls, v: str | None) -> str | None:
        if v is not None:
            assert_valid_verdict(v, "hypothesis_verdict")
        return v

    @field_validator("status")
    @classmethod
    def _validate_status(cls, v: str) -> str:
        assert_valid_verdict(v, "hypothesis_status")
        return v

    @model_validator(mode="before")
    @classmethod
    def _convert_declarations(cls, data: Any) -> Any:
        """Convert declaration-vocabulary conditions into the canonical spec.

        Rulepack and drafter declarations arrive as ``confirm_when`` /
        ``refute_when`` / ``evidence_requirements``; they are normalized into
        ``verification_spec`` exactly once here.  When a canonical spec is
        supplied it wins and any declaration kwargs are ignored, so storage
        can never overwrite canonical conditions from declaration-shaped
        copies.
        """
        if not isinstance(data, dict):
            return data
        if data.get("verification_spec") is None:
            declarations = {
                key: data.pop(key)
                for key in ("confirm_when", "refute_when", "evidence_requirements")
                if data.get(key) is not None
            }
            if declarations:
                data["verification_spec"] = VerificationSpec.from_legacy(
                    **declarations
                )
            else:
                # An explicit None means "no declared conditions"; the default
                # empty spec applies.
                data.pop("verification_spec", None)
        for key in ("confirm_when", "refute_when", "evidence_requirements"):
            data.pop(key, None)
        return data

    # Derived projections over the canonical spec.  They return the live
    # condition dicts (or None when empty) so read-mutate callers keep the
    # same aliasing the former fields had.
    @property
    def confirm_when(self) -> dict[str, Any] | None:
        return self.verification_spec.support_conditions or None

    @property
    def refute_when(self) -> dict[str, Any] | None:
        return self.verification_spec.refute_conditions or None

    @property
    def evidence_requirements(self) -> dict[str, Any] | None:
        return self.verification_spec.evidence_requirements or None


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
    # Host-side planner validation feedback is consumed by the next
    # query-intent call.  Keep it separate from SQL execution failures so the
    # planner never mistakes a materialization error for a failed query.
    last_planner_error: dict[str, Any] | None = None
    proposed_keypoints: dict[str, int] = Field(default_factory=dict)
