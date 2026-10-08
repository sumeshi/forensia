from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingTemplate(BaseModel):
    title: str
    summary: str


class HypothesisDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    segment: str
    description: str
    required_entities: list[str] = Field(default_factory=list)
    confirm_when: dict[str, Any] | None = None
    refute_when: dict[str, Any] | None = None
    evidence_requirements: dict[str, Any] | None = None
    follow_up_questions: list[str] = Field(default_factory=list)
    report_sections: list[str] = Field(default_factory=list)


class AttackEntry(BaseModel):
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""


class CorrelateEvent(BaseModel):
    event_ids: list[int]
    rationale: str


class RulePackMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    applies_when: dict = Field(default_factory=dict)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    severity: str = "medium"
    confidence: float = 0.5
    required_fields: list[str] = Field(default_factory=list)
    query: str
    finding: FindingTemplate
    tags: list[str] = Field(default_factory=list)
    attack: list[AttackEntry] = Field(default_factory=list)
    hypotheses: list[HypothesisDeclaration] = Field(default_factory=list)
    correlate_with: list[CorrelateEvent] = Field(default_factory=list)
    fallback_search: list[dict[str, Any]] = Field(default_factory=list)
    applies_when: dict | None = None



class Finding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    summary: str
    severity: str
    confidence: float
    status: str = "new"
    tags: list[str] = Field(default_factory=list)
    attack: list[AttackEntry] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    ai_summary: str | None = None
    missing_checks: list[str] = Field(default_factory=list)
