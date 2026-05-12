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
    session_count: int


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


class HypothesesResponseDTO(DTOModel):
    active: list[HypothesisDTO]
    resolved: list[HypothesisDTO]


class SessionDTO(DTOModel):
    session_id: str
    started_at: str | None = None
    finished_at: str | None = None
    iterations: int | None = None
    status: str | None = None


class InvestigationStepDTO(DTOModel):
    step_id: str
    session_id: str
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
    last_filled_session: str | None = None
    last_filled_at: str | None = None
    is_writing: bool = False
    is_highlighted: bool = False


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


class EventVolumePointDTO(DTOModel):
    bucket: str
    series: str
    count: int
