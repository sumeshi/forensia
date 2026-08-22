from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DTOModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CaseDTO(DTOModel):
    case_name: str
    paths: dict[str, str]
    manifest: dict[str, Any]


class RuntimeConfigDTO(DTOModel):
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_max_tokens: int
    llm_temperature: float
    llm_output_language: str
    llm_report_max_queries_per_section: int
    llm_outage_wall_clock_budget_s: int
    llm_outage_probe_interval_s: int


class HostInfoDTO(DTOModel):
    """A distinct host (computer name) seen in EVTX, with its activity window.

    Multiple entries for one physical machine indicate a rename over time."""

    name: str
    first_seen: str | None = None
    last_seen: str | None = None
    event_count: int = 0


class CaseStatsDTO(DTOModel):
    evtx_rows: int
    mft_entries: int
    channel_count: int
    host_count: int = 0
    prefetch_rows: int = 0
    hosts: list[HostInfoDTO] = []
    findings_accepted: int
    findings_suppressed: int
    active_hypotheses: int
    resolved_hypotheses: int
    confirmed_hypotheses: int = 0
    refuted_hypotheses: int = 0
    untestable_hypotheses: int = 0
    needs_review_hypotheses: int = 0
    deferred_hypotheses: int = 0
    blocked_hypotheses: int = 0
    open_gaps: int
    sessions: int
    total_iterations: int
    report_human_reviewed: int = 0
    report_ai_exhausted: int = 0
    report_draft_count: int = 0
    report_human_review_pct: float = 0.0
    needs_review_finding_total: int = 0


class AttackMappingDTO(DTOModel):
    tactic: str = ""
    technique_id: str = ""
    technique_name: str = ""


class FindingDTO(DTOModel):
    finding_id: str
    rule_id: str | None = None
    title: str
    summary: str
    severity: str
    confidence: float | None = None
    status: str | None = None
    tags: list[Any] | dict[str, Any] | None = None
    attack: list[AttackMappingDTO | str] | None = None
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
    latest_reasoning: list[HypothesisReasoningEntryDTO] = []
    selection_count: int = 0
    blocked_reason: str | None = None
    sufficiency_status: str | None = None
    sufficiency_score: float | None = None
    sufficiency_reason: str | None = None
    human_review_required: bool = False


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
    terminal_reason: str | None = None
    owner_id: str | None = None
    heartbeat_at: str | None = None
    phase: str | None = None
    status_reason: str | None = None


class FindingAggregatesDTO(DTOModel):
    """Authoritative server-side finding aggregates (not a 200-row sample)."""

    total: int = 0
    accepted: int = 0
    suppressed: int = 0
    severity_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    top_rules: list[dict[str, object]] = []
    top_families: list[dict[str, object]] = []


class FindingPageDTO(DTOModel):
    """Bounded, paged finding response with authoritative aggregates."""

    items: list[FindingDTO] = []
    total: int = 0
    limit: int = 100
    offset: int = 0
    is_sample: bool = False
    aggregates: FindingAggregatesDTO | None = None


class LogicalCallDTO(DTOModel):
    logical_call_id: str
    session_id: str | None = None
    parent_logical_call_id: str | None = None
    phase: str | None = None
    iteration: int | None = None
    hypothesis_id: str | None = None
    section_id: str | None = None
    action_id: str | None = None
    request_fingerprint: str | None = None
    status: str | None = None
    created_at: str | None = None
    attempt_count: int = 0
    provider_attempt_failures: int = 0
    provider_attempt_retries: int = 0
    duplicate_attempts: int = 0


class ProviderAttemptDTO(DTOModel):
    attempt_id: str
    logical_call_id: str | None = None
    parent_attempt_id: str | None = None
    session_id: str | None = None
    phase: str | None = None
    retry_ordinal: int = 0
    endpoint: str | None = None
    provider: str | None = None
    model: str | None = None
    schema_mode: str | None = None
    request_fingerprint: str | None = None
    configured_output_limit: int | None = None
    reasoning_reserve_tokens: int | None = None
    known_context_limit: int | None = None
    requested_output_limit: int | None = None
    effective_output_limit: int | None = None
    input_chars: int | None = None
    output_chars: int | None = None
    connect_timeout_ms: int | None = None
    read_timeout_ms: int | None = None
    logical_deadline_ms: int | None = None
    retry_class: str | None = None
    retry_reason: str | None = None
    policy_decision: str | None = None
    request_changed_fields: dict[str, object] | None = None
    prompt_metadata: dict[str, object] | None = None
    request_body: dict[str, object] | None = None
    response_body: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    duration_ms: int | None = None
    http_status: int | None = None
    error_type: str | None = None
    error_code: str | None = None
    error_body_summary: str | None = None
    exception_class: str | None = None
    finish_reason: str | None = None
    parse_status: str | None = None
    truncated: bool | None = None
    accepted: bool | None = None
    discarded_reason: str | None = None
    response_fingerprint: str | None = None
    action_fingerprint: str | None = None
    duplicate_of: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    input_tokens_source: str | None = None
    output_tokens_source: str | None = None
    status: str | None = None


class DeterministicOpDTO(DTOModel):
    op_id: str
    session_id: str | None = None
    phase: str | None = None
    hypothesis_id: str | None = None
    section_id: str | None = None
    op_type: str | None = None
    target: str | None = None
    duration_ms: int | None = None
    note: str | None = None
    created_at: str | None = None


class LogicalCallPageDTO(DTOModel):
    session_id: str | None = None
    items: list[LogicalCallDTO] = []
    total: int = 0
    limit: int = 50
    offset: int = 0
    is_sample: bool = False
    filters: dict[str, object] = {}


class AttemptPageDTO(DTOModel):
    logical_call_id: str | None = None
    session_id: str | None = None
    items: list[ProviderAttemptDTO] = []
    total: int = 0
    limit: int = 50
    offset: int = 0
    is_sample: bool = False
    filters: dict[str, object] = {}


class SessionTrajectoryDTO(DTOModel):
    session_id: str
    started_at: str | None = None
    finished_at: str | None = None
    status: str | None = None
    terminal_reason: str | None = None
    timezone: str = "UTC"
    wall_time_ms: int | None = None
    explained_time_ms: int = 0
    unexplained_wall_time_ms: int | None = None
    latency_by_phase: dict[str, int] = {}
    aggregates: dict[str, object] = {}
    deterministic_operations: list[DeterministicOpDTO] = []
    retrieval_events: list[dict[str, object]] = []
    snapshot_revision: str | None = None
    generated_at: str | None = None
    authoritative_updated_at: str | None = None
    state: str | None = None


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
    body_html: str = ""
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


class EvidenceRecordDTO(DTOModel):
    evidence_id: str
    source: str
    record: dict[str, Any]


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


class EvidenceSourceDTO(DTOModel):
    source_id: str
    artifact_family: str
    display_path: str
    ingest_status: str
    parser_name: str
    row_count: int
    channel: str
    hosts: list[str]
    min_time: str | None
    max_time: str | None
    error_code: str
    error_summary: str


class EvidenceCoverageDTO(DTOModel):
    capability: str
    host: str
    channel: str
    source_family: str
    state: str
    reason_code: str
    source_ids: list[str]
    start_time: str | None
    end_time: str | None
    excluded_timestamps: dict[str, int]
    confidence: float


class InvestigationStateDTO(DTOModel):
    state_id: str
    objective: str
    status: str
    termination_policy: dict | None
    stop_reason_code: str
    stop_reason: str
    stop_summary: dict[str, int] = Field(default_factory=dict)
    updated_at: str | None


class ReportGapDTO(DTOModel):
    gap_id: str
    section_key: str
    block_heading: str
    description: str
    kind: str
    status: str
    source_claim_id: str
    hypothesis_id: str
    task_id: str
    coverage_reason: str
    origin: str = "section"
    created_at: str | None
    updated_at: str | None


class InvestigationTaskDTO(DTOModel):
    task_id: str
    kind: str
    description: str
    status: str
    gap_id: str
    hypothesis_id: str
    required_capability: str
    required_source: str = ""
    owner_phase: str = ""
    retry_condition: str = ""
    blocked_reason: str = ""
    reason: str
    created_at: str | None
    updated_at: str | None


class HypothesisRelationDTO(DTOModel):
    from_hypothesis_id: str
    to_hypothesis_id: str
    relation_type: str
    origin: str
    confidence: float
    rationale: str


class HypothesisEvidenceLinkDTO(DTOModel):
    link_id: str
    hypothesis_id: str
    evidence_id: str
    finding_id: str
    query_id: str
    assessment_id: str
    role: str
    source_family: str
    derivation_group: str
    strength: str


HypothesisDTO.model_rebuild()
