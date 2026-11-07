"""Versioned task acceptance and host result references.

Verification semantics remain in VerificationSpec and Settlement. These types
describe the work handed off and the existing result needed to finish it.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TaskContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    task_id: str = Field(min_length=1)
    task_kind: str
    purpose: str = Field(min_length=1)
    gap_id: str = ""
    gap_fingerprint: str = ""
    hypothesis_id: str = ""
    hypothesis_fingerprint: str = ""
    input_identity: str = Field(min_length=1)
    verification_spec_fingerprint: str = ""
    required_capabilities: tuple[str, ...] = ()
    required_sources: tuple[str, ...] = ()
    expected_output: Literal["hypothesis_settlement", "external_result"]
    completion_condition: Literal["current_settlement", "external_owner_result"]


class TaskCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    task_id: str = Field(min_length=1)
    contract_ref: str = ""
    settlement_ref: str = ""
    status: Literal["completed", "blocked", "stale"]
    reason: str
    output_refs: tuple[str, ...] = ()


class TaskSettlementReceipt(BaseModel):
    """The host's existing settlement decision, bound to its actual inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["1"] = "1"
    origin: Literal["host:settlement"] = "host:settlement"
    hypothesis_id: str = Field(min_length=1)
    attempt_ref: str
    input_identity: str = Field(min_length=1)
    verification_spec_fingerprint: str = Field(min_length=1)
    assessed_links_fingerprint: str = Field(min_length=1)
    task_contract_refs: dict[str, str]
    verdict: str
    allowed: bool
    reason: str = ""
    gates_passed: tuple[str, ...] = ()
    gates_failed: tuple[str, ...] = ()
    assessment_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
