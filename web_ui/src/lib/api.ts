import type {
  AIReviewDTO,
  AttackCoverageRowDTO,
  EntityCardDTO,
  CaseDTO,
  CaseStatsDTO,
  ClaimDTO,
  EventVolumePointDTO,
  FindingDTO,
  HypothesesResponseDTO,
  HypothesisReasoningEntryDTO,
  InvestigationStepDTO,
  MftTimelineDTO,
  ProgressEventDTO,
  ReportSectionDTO,
  RuntimeConfigDTO,
  SessionDTO
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
  getFindings: () => getJson<FindingDTO[]>("/api/findings?limit=200"),
  getHypotheses: () => getJson<HypothesesResponseDTO>("/api/hypotheses"),
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
  connectStream(after = 0): EventSource {
    const url = new URL("/api/stream", window.location.origin);
    url.searchParams.set("after", String(after));
    return new EventSource(url);
  }
};

export function parseProgressEvent(raw: MessageEvent<string>): ProgressEventDTO {
  return JSON.parse(raw.data) as ProgressEventDTO;
}
