from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class DTOModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CaseDTO(DTOModel):
    case_name: str
    paths: dict[str, str]
    manifest: dict[str, Any]


class CaseStatsDTO(DTOModel):
    evtx_rows: int
    mft_entries: int
    channel_count: int
    findings_accepted: int
    findings_suppressed: int
    active_hypotheses: int
    resolved_hypotheses: int
    open_gaps: int
    sessions: int
    total_iterations: int
    report_human_reviewed: int = 0
    report_ai_exhausted: int = 0


class FindingDTO(DTOModel):
    finding_id: str
    rule_id: str | None = None
    title: str
    summary: str
    severity: str
    confidence: float | None = None
    status: str | None = None
    tags: list[Any] | dict[str, Any] | None = None
    attack: list[Any] | None = None
    evidence: list[Any] | None = None
    evidence_ids: list[str] = []
    evidence_count: int = 0
    ai_summary: str | None = None
    missing_checks: list[Any] | None = None
    created_at: str | None = None


class HypothesisDTO(DTOModel):
    hypothesis_id: str
    description: str
    status: str
    verdict: str | None = None
    summary: str | None = None
    origin: str | None = None
    created_session: str | None = None
    resolved_session: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    reasoning_count: int = 0
    latest_iteration: int | None = None
    latest_reasoning_at: str | None = None
    latest_reasoning: list["HypothesisReasoningEntryDTO"] = []


class HypothesesResponseDTO(DTOModel):
    active: list[HypothesisDTO]
    resolved: list[HypothesisDTO]


class HypothesisReasoningEntryDTO(DTOModel):
    entry_id: str
    hypothesis_id: str
    session_id: str | None = None
    iteration: int
    phase: str
    verdict: str | None = None
    query_id: str | None = None
    body: str
    created_at: str | None = None


class SessionDTO(DTOModel):
    session_id: str
    started_at: str | None = None
    finished_at: str | None = None
    iterations: int | None = None
    status: str | None = None


class InvestigationStepDTO(DTOModel):
    step_id: str
    session_id: str
    hypothesis_id: str | None = None
    iteration: int
    phase: str
    input_json: Any = None
    output_json: Any = None
    created_at: str | None = None


class ReportSectionDTO(DTOModel):
    section_key: str
    title: str
    body: str
    confidence: float | None = None
    status: str = "draft"
    update_count: int = 0
    gaps: list[str]
    gap_hypothesis_ids: list[str] = []
    gap_count: int
    evidence_ids: list[str] = []
    evidence_count: int = 0
    last_filled_session: str | None = None
    last_filled_at: str | None = None
    is_writing: bool = False
    is_highlighted: bool = False


class SectionQuestionDTO(DTOModel):
    question_id: str
    section_key: str
    block_heading: str | None = None
    question_text: str | None = None
    question_type: str | None = None
    answer_spec: str | None = None
    intent: str | None = None
    confidence: float | None = None
    matched_rule: str | None = None
    required_evidence: Any = None
    status: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class ClaimDTO(DTOModel):
    claim_id: str
    section_key: str
    claim_text: str
    finding_ids: list[str]
    hypothesis_ids: list[str]
    evidence_ids: list[str]
    support_status: str
    created_at: str | None = None
    updated_at: str | None = None


class MftTimelineDTO(DTOModel):
    timeline_id: str | None = None
    evidence_id: str | None = None
    record_number: int | None = None
    file_path: str | None = None
    timestamp: str | None = None
    timestamp_type: str | None = None
    description: str | None = None
    is_deleted: bool | None = None
    tags: list[Any] | dict[str, Any] | None = None


class AIReviewDTO(DTOModel):
    review_id: str | None = None
    finding_id: str
    verdict: str | None = None
    report_text: str | None = None
    missing_checks: list[Any] | None = None
    confidence_adjustment: float | None = None
    notes: str | None = None
    raw_response: dict[str, Any] | list[Any] | None = None
    created_at: str | None = None


class ProgressEventDTO(DTOModel):
    event_index: int
    stage: str | None = None
    status: str | None = None
    iteration: int | None = None
    current_query: str | None = None
    summary: str | None = None
    payload: dict[str, Any]
    created_at: str | None = None


class EntityCardDTO(DTOModel):
    kind: str
    name: str
    mention_count: int | None = None
    summary: str | None = None


class AttackCoverageRowDTO(DTOModel):
    tactic: str
    technique_id: str
    technique_name: str | None = None
    count: int = 0
    accepted: int = 0
    suppressed: int = 0


class EventVolumePointDTO(DTOModel):
    bucket: str
    series: str
    count: int


HypothesisDTO.model_rebuild()
