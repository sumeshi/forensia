from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FindingTemplate(BaseModel):
    title: str
    summary: str


class Rule(BaseModel):
    id: str
    title: str
    severity: str = "medium"
    confidence: float = 0.5
    query: str
    finding: FindingTemplate
    tags: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    summary: str
    severity: str
    confidence: float
    status: str = "new"
    tags: list[str] = Field(default_factory=list)
    attack: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    ai_summary: str | None = None
    missing_checks: list[str] = Field(default_factory=list)
