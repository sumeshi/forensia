import type {
  AIReviewDTO,
  AttemptPageDTO,
  AttackCoverageRowDTO,
  EntityCardDTO,
  CaseDTO,
  CaseStatsDTO,
  ClaimDTO,
  EventVolumePointDTO,
  FindingAggregatesDTO,
  FindingDTO,
  FindingPageDTO,
  HypothesesResponseDTO,
  HypothesisReasoningEntryDTO,
  InvestigationStepDTO,
  LogicalCallDTO,
  LogicalCallPageDTO,
  MftTimelineDTO,
  ProgressEventDTO,
  ProviderAttemptDTO,
  ReportSectionDTO,
  RuntimeConfigDTO,
  SessionDTO,
  SessionTrajectoryDTO,
  SnapshotMetadataDTO
} from "./types";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

async function getText(path: string): Promise<string> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return await response.text();
}

async function postJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { method: "POST" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

export const api = {
  getCase: () => getJson<CaseDTO>("/api/case"),
  getConfig: () => getJson<RuntimeConfigDTO>("/api/config"),
  getStats: () => getJson<CaseStatsDTO>("/api/stats"),
  getSnapshotMetadata: () => getJson<SnapshotMetadataDTO>("/api/snapshot-metadata"),
  getFindings: () => getJson<FindingDTO[]>("/api/findings?limit=200"),
  getFindingsPage: (limit = 100, offset = 0, status?: string, severity?: string) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    return getJson<FindingPageDTO>(`/api/findings/page?${params.toString()}`);
  },
  getFindingAggregates: () => getJson<FindingAggregatesDTO>("/api/findings/aggregates"),
  getHypotheses: () => getJson<HypothesesResponseDTO>("/api/hypotheses"),
  getHypothesesTaxonomy: () => getJson<{ hypothesis: unknown; report_section: unknown }>("/api/hypotheses/taxonomy"),
  getHypothesisReasoning: (hypothesisId: string, limit = 20) =>
    getJson<HypothesisReasoningEntryDTO[]>(`/api/hypotheses/${hypothesisId}/reasoning?limit=${limit}`),
  getSessions: () => getJson<SessionDTO[]>("/api/sessions"),
  getSteps: (sessionId: string) => getJson<InvestigationStepDTO[]>(`/api/sessions/${sessionId}/steps`),
  getReportSections: () => getJson<ReportSectionDTO[]>("/api/report-sections"),
  getReportMarkdown: () => getText("/api/report-markdown"),
  updateReportSectionStatus: (sectionKey: string, status: string) =>
    postJson<ReportSectionDTO>(
      `/api/report-sections/${sectionKey}/status?status=${encodeURIComponent(status)}`,
    ),
  getClaims: (sectionKey?: string) =>
    getJson<ClaimDTO[]>(sectionKey ? `/api/claims?section_key=${encodeURIComponent(sectionKey)}` : "/api/claims"),
  getTimeline: () => getJson<MftTimelineDTO[]>("/api/mft-timeline?limit=200"),
  getEventVolume: (
    bucket: "year" | "month" | "day" | "hour" = "day",
    source: "all" | "detected" = "all",
    start?: string,
    end?: string,
  ) => {
    const params = new URLSearchParams({ bucket, source });
    if (start) params.set("start", start);
    if (end) params.set("end", end);
    return getJson<EventVolumePointDTO[]>(`/api/event-volume?${params.toString()}`);
  },
  getAttackCoverage: () => getJson<AttackCoverageRowDTO[]>("/api/attack-coverage"),
  getEntities: () => getJson<EntityCardDTO[]>("/api/entities"),
  getLatestReasoning: (limit = 10) =>
    getJson<HypothesisReasoningEntryDTO[]>(`/api/hypotheses-reasoning?limit=${limit}`),
  getAiReviews: () => getJson<AIReviewDTO[]>("/api/ai-reviews"),
  getSessionTrajectory: (sessionId: string) =>
    getJson<SessionTrajectoryDTO>(`/api/sessions/${encodeURIComponent(sessionId)}/trajectory`),
  getLogicalCalls: (sessionId: string, params: Record<string, string | number | boolean | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") qs.set(key, String(value));
    }
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return getJson<LogicalCallPageDTO>(`/api/sessions/${encodeURIComponent(sessionId)}/logical-calls${suffix}`);
  },
  getLogicalCallAttempts: (logicalCallId: string, params: Record<string, string | number | boolean | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") qs.set(key, String(value));
    }
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return getJson<AttemptPageDTO>(`/api/logical-calls/${encodeURIComponent(logicalCallId)}/attempts${suffix}`);
  },
  connectStream(after = 0): EventSource {
    const url = new URL("/api/stream", window.location.origin);
    url.searchParams.set("after", String(after));
    return new EventSource(url);
  }
};

export function parseProgressEvent(raw: MessageEvent<string>): ProgressEventDTO {
  return JSON.parse(raw.data) as ProgressEventDTO;
}
