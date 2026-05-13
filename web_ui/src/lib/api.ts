import type {
  AIReviewDTO,
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
  SessionDTO
} from "./types";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
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
  getStats: () => getJson<CaseStatsDTO>("/api/stats"),
  getFindings: () => getJson<FindingDTO[]>("/api/findings?limit=200"),
  getHypotheses: () => getJson<HypothesesResponseDTO>("/api/hypotheses"),
  getHypothesisReasoning: (hypothesisId: string, limit = 20) =>
    getJson<HypothesisReasoningEntryDTO[]>(`/api/hypotheses/${hypothesisId}/reasoning?limit=${limit}`),
  getSessions: () => getJson<SessionDTO[]>("/api/sessions"),
  getSteps: (sessionId: string) => getJson<InvestigationStepDTO[]>(`/api/sessions/${sessionId}/steps`),
  getReportSections: () => getJson<ReportSectionDTO[]>("/api/report-sections"),
  updateReportSectionStatus: (sectionKey: string, status: string) =>
    postJson<ReportSectionDTO>(
      `/api/report-sections/${sectionKey}/status?status=${encodeURIComponent(status)}`,
    ),
  getClaims: (sectionKey?: string) =>
    getJson<ClaimDTO[]>(sectionKey ? `/api/claims?section_key=${encodeURIComponent(sectionKey)}` : "/api/claims"),
  getTimeline: () => getJson<MftTimelineDTO[]>("/api/mft-timeline?limit=200"),
  getEventVolume: (bucket = "hour", source: "all" | "detected" = "all") =>
    getJson<EventVolumePointDTO[]>(`/api/event-volume?bucket=${bucket}&source=${source}`),
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
