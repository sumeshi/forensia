export type CaseDTO = {
  case_name: string;
  paths: Record<string, string>;
  manifest: Record<string, unknown>;
};

export type RuntimeConfigDTO = {
  llm_base_url?: string | null;
  llm_model?: string | null;
  llm_max_tokens: number;
  llm_temperature: number;
  llm_output_language: string;
  llm_report_max_queries_per_section: number;
  llm_outage_wall_clock_budget_s: number;
  llm_outage_probe_interval_s: number;
};

export type HostInfoDTO = {
  name: string;
  first_seen?: string | null;
  last_seen?: string | null;
  event_count: number;
};

export type CaseStatsDTO = {
  evtx_rows: number;
  mft_entries: number;
  channel_count: number;
  host_count: number;
  prefetch_rows: number;
  hosts: HostInfoDTO[];
  findings_accepted: number;
  findings_suppressed: number;
  active_hypotheses: number;
  resolved_hypotheses: number;
  open_gaps: number;
  sessions: number;
  total_iterations: number;
  report_human_reviewed: number;
  report_ai_exhausted: number;
  confirmed_hypotheses?: number;
  refuted_hypotheses?: number;
  untestable_hypotheses?: number;
  needs_review_hypotheses?: number;
  deferred_hypotheses?: number;
  blocked_hypotheses?: number;
  report_draft_count?: number;
  report_human_review_pct?: number;
  needs_review_finding_total?: number;
};

export type AttackMappingDTO = {
  tactic?: string;
  technique_id?: string;
  technique_name?: string;
};

export type FindingDTO = {
  finding_id: string;
  rule_id?: string | null;
  title: string;
  summary: string;
  severity: string;
  confidence?: number | null;
  status?: string | null;
  tags?: Array<unknown> | Record<string, unknown> | null;
  attack?: Array<AttackMappingDTO | string> | null;
  evidence?: Array<Record<string, unknown>> | null;
  evidence_ids?: string[];
  evidence_count?: number;
  ai_summary?: string | null;
  missing_checks?: Array<unknown> | null;
  created_at?: string | null;
};

export type HypothesisDTO = {
  hypothesis_id: string;
  description: string;
  status: string;
  verdict?: string | null;
  summary?: string | null;
  origin?: string | null;
  reasoning_count: number;
  latest_iteration?: number | null;
  latest_reasoning_at?: string | null;
  latest_reasoning: HypothesisReasoningEntryDTO[];
  selection_count?: number;
  blocked_reason?: string | null;
  sufficiency_status?: string | null;
  sufficiency_score?: number | null;
  sufficiency_reason?: string | null;
  human_review_required?: boolean;
};

export type HypothesisReasoningEntryDTO = {
  entry_id: string;
  hypothesis_id: string;
  session_id?: string | null;
  iteration: number;
  phase: string;
  verdict?: string | null;
  query_id?: string | null;
  body: string;
  created_at?: string | null;
};

export type HypothesesResponseDTO = {
  active: HypothesisDTO[];
  resolved: HypothesisDTO[];
};

export type SessionDTO = {
  session_id: string;
  started_at?: string | null;
  finished_at?: string | null;
  iterations?: number | null;
  status?: string | null;
  terminal_reason?: string | null;
};

export type InvestigationStepDTO = {
  step_id: string;
  session_id: string;
  hypothesis_id?: string | null;
  iteration: number;
  phase: string;
  input_json?: unknown;
  output_json?: unknown;
  created_at?: string | null;
};

export type ReportSectionDTO = {
  section_key: string;
  title: string;
  body: string;
  body_html?: string;
  confidence?: number | null;
  status: string;
  update_count: number;
  gaps: string[];
  gap_hypothesis_ids?: string[];
  gap_count: number;
  last_filled_session?: string | null;
  last_filled_at?: string | null;
  is_writing: boolean;
  is_highlighted: boolean;
};

export type ClaimDTO = {
  claim_id: string;
  section_key: string;
  claim_text: string;
  finding_ids: string[];
  hypothesis_ids: string[];
  evidence_ids: string[];
  support_status: string;
  created_at?: string | null;
  updated_at?: string | null;
};

export type MftTimelineDTO = {
  timeline_id?: string | null;
  record_number?: number | null;
  file_path?: string | null;
  timestamp?: string | null;
  timestamp_type?: string | null;
  description?: string | null;
  is_deleted?: boolean | null;
};

export type AIReviewDTO = {
  review_id?: string | null;
  finding_id: string;
  verdict?: string | null;
  report_text?: string | null;
  created_at?: string | null;
};

export type ProgressEventDTO = {
  event_index: number;
  stage?: string | null;
  status?: string | null;
  iteration?: number | null;
  current_query?: string | null;
  summary?: string | null;
  created_at?: string | null;
  payload: Record<string, unknown>;
};

export type EntityCardDTO = {
  kind: string;
  name: string;
  mention_count: number | null;
  summary?: string | null;
};

export type AttackCoverageRowDTO = {
  tactic: string;
  technique_id: string;
  technique_name: string | null;
  count: number;
  accepted: number;
  suppressed: number;
};

export type EventVolumePointDTO = {
  bucket: string;
  series: string;
  count: number;
};

export type FindingAggregatesDTO = {
  total: number;
  accepted: number;
  suppressed: number;
  severity_counts: Record<string, number>;
  status_counts: Record<string, number>;
  top_rules: Array<Record<string, unknown>>;
  top_families: Array<Record<string, unknown>>;
};

export type FindingPageDTO = {
  items: FindingDTO[];
  total: number;
  limit: number;
  offset: number;
  is_sample: boolean;
  aggregates?: FindingAggregatesDTO | null;
};

export type LogicalCallDTO = {
  logical_call_id: string;
  session_id?: string | null;
  parent_logical_call_id?: string | null;
  phase?: string | null;
  iteration?: number | null;
  hypothesis_id?: string | null;
  section_id?: string | null;
  action_id?: string | null;
  request_fingerprint?: string | null;
  status?: string | null;
  created_at?: string | null;
  attempt_count: number;
  provider_attempt_failures: number;
  provider_attempt_retries: number;
  duplicate_attempts: number;
};

export type LogicalCallPageDTO = {
  session_id?: string | null;
  items: LogicalCallDTO[];
  total: number;
  limit: number;
  offset: number;
  is_sample: boolean;
  filters: Record<string, unknown>;
};

export type ProviderAttemptDTO = {
  attempt_id: string;
  logical_call_id?: string | null;
  parent_attempt_id?: string | null;
  session_id?: string | null;
  phase?: string | null;
  retry_ordinal: number;
  request_fingerprint?: string | null;
  prompt_metadata?: Record<string, unknown> | null;
  request_body?: Record<string, unknown> | null;
  response_body?: string | null;
  configured_output_limit?: number | null;
  reasoning_reserve_tokens?: number | null;
  known_context_limit?: number | null;
  requested_output_limit?: number | null;
  effective_output_limit?: number | null;
  input_chars?: number | null;
  output_chars?: number | null;
  retry_class?: string | null;
  retry_reason?: string | null;
  start_time?: string | null;
  end_time?: string | null;
  duration_ms?: number | null;
  http_status?: number | null;
  error_type?: string | null;
  error_code?: string | null;
  finish_reason?: string | null;
  parse_status?: string | null;
  truncated?: boolean | null;
  accepted?: boolean | null;
  discarded_reason?: string | null;
  duplicate_of?: string | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  input_tokens_source?: string | null;
  output_tokens_source?: string | null;
  status?: string | null;
};

export type AttemptPageDTO = {
  logical_call_id?: string | null;
  session_id?: string | null;
  items: ProviderAttemptDTO[];
  total: number;
  limit: number;
  offset: number;
  is_sample: boolean;
  filters: Record<string, unknown>;
};

export type DeterministicOpDTO = {
  op_id: string;
  session_id?: string | null;
  phase?: string | null;
  hypothesis_id?: string | null;
  section_id?: string | null;
  op_type?: string | null;
  target?: string | null;
  duration_ms?: number | null;
  note?: string | null;
  created_at?: string | null;
};

export type SessionTrajectoryDTO = {
  session_id: string;
  started_at?: string | null;
  finished_at?: string | null;
  status?: string | null;
  terminal_reason?: string | null;
  timezone: string;
  wall_time_ms?: number | null;
  explained_time_ms: number;
  unexplained_wall_time_ms?: number | null;
  latency_by_phase: Record<string, number>;
  aggregates: Record<string, unknown>;
  deterministic_operations?: DeterministicOpDTO[];
  retrieval_events?: Array<Record<string, unknown>>;
  snapshot_revision?: string | null;
  generated_at?: string | null;
  authoritative_updated_at?: string | null;
  state?: string | null;
};

export type SnapshotMetadataDTO = {
  generation_revision?: string | null;
  current_revision?: string | null;
  state_revision?: string | null;
  generated_at?: string | null;
  authoritative_updated_at?: string | null;
  timezone?: string | null;
  state?: string | null;
  stale?: boolean;
  in_progress?: boolean;
  durable_investigation_status?: string | null;
};
