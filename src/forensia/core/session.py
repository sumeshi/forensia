from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

ENTITY_TYPE_ALIASES = {
    "host": "host",
    "hostname": "host",
    "computer": "host",
    "user": "user",
    "username": "user",
    "account": "user",
    "ip": "ip",
    "src_ip": "ip",
    "dst_ip": "ip",
    "source_ip": "ip",
    "destination_ip": "ip",
    "ip_address": "ip",
}


class Hypothesis(BaseModel):
    id: str
    description: str
    status: Literal["active", "confirmed", "refuted"] = "active"
    verdict: Literal["confirmed", "refuted"] | None = None
    summary: str = ""


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


class SessionState(BaseModel):
    session_id: str
    iteration: int = 0
    focus_hypothesis_id: str | None = None
    focus_depth: int = 0
    active_hypotheses: list[Hypothesis] = Field(default_factory=list)
    resolved_hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    history: list[HistoryEntry] = Field(default_factory=list)
