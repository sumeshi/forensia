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
  session_count: number;
};

export type FindingDTO = {
  finding_id: string;
  rule_id?: string | null;
  title: string;
  summary: string;
  severity: string;
  confidence?: number | null;
  status?: string | null;
  attack?: string[] | null;
  ai_summary?: string | null;
  evidence?: Array<Record<string, unknown>> | null;
};

export type HypothesisDTO = {
  hypothesis_id: string;
  description: string;
  status: string;
  verdict?: string | null;
  summary?: string | null;
  origin?: string | null;
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

export type EventVolumePointDTO = {
  bucket: string;
  series: string;
  count: number;
};
