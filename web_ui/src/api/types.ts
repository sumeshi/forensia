export type CaseDTO = {
  case_name: string;
  paths: Record<string, string>;
  manifest: Record<string, unknown>;
};

export type CaseStatsDTO = {
  evtx_rows: number;
  mft_entries: number;
  channel_count: number;
  findings_accepted: number;
  findings_suppressed: number;
  active_hypotheses: number;
  resolved_hypotheses: number;
  open_gaps: number;
  sessions: number;
  total_iterations: number;
  report_human_reviewed: number;
  report_ai_exhausted: number;
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
  attack?: string[] | null;
  evidence?: Array<Record<string, unknown>> | null;
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
