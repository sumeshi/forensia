import { writable } from "svelte/store";

import { api, parseProgressEvent } from "./api";
import type {
  AIReviewDTO,
  AttackCoverageRowDTO,
  EntityCardDTO,
  CaseDTO,
  CaseStatsDTO,
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

export const caseInfo = writable<CaseDTO | null>(null);
export const caseStats = writable<CaseStatsDTO | null>(null);
export const findings = writable<FindingDTO[]>([]);
export const hypotheses = writable<HypothesesResponseDTO>({ active: [], resolved: [] });
export const sessions = writable<SessionDTO[]>([]);
export const steps = writable<InvestigationStepDTO[]>([]);
export const reportSections = writable<ReportSectionDTO[]>([]);
export const timeline = writable<MftTimelineDTO[]>([]);
export const eventVolume = writable<EventVolumePointDTO[]>([]);
export const eventVolumeDetected = writable<EventVolumePointDTO[]>([]);
export const eventVolumeYears = writable<EventVolumePointDTO[]>([]);
export const aiReviews = writable<AIReviewDTO[]>([]);
export const latestReasoning = writable<HypothesisReasoningEntryDTO[]>([]);
export const attackCoverage = writable<AttackCoverageRowDTO[]>([]);
export const entities = writable<EntityCardDTO[]>([]);
export const progress = writable<ProgressEventDTO | null>(null);
export const connection = writable<"idle" | "connected" | "error">("idle");
// Hierarchical drill-down path for Event Volume:
//   []                  → bucket=year   (whole record range)
//   [2024]              → bucket=month  (within 2024)
//   [2024, 5]           → bucket=day    (within 2024-05)
//   [2024, 5, 29]       → bucket=hour   (within 2024-05-29)
export const volumeDrill = writable<number[]>([]);
export const detailsTab = writable<"findings" | "steps" | "sessions" | "activity" | "mft">("findings");
export const selectedFindingId = writable<string | null>(null);

let currentSessionId = "";
let refreshTimer: number | undefined;
let lastEventIndex = 0;

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function mergeReportSections(
  baseSections: ReportSectionDTO[],
  progressValue: ProgressEventDTO | null
): ReportSectionDTO[] {
  if (!progressValue) {
    return baseSections;
  }
  const payload = asRecord(progressValue.payload);
  const reportStatus = asRecord(payload?.report_sections);
  const focusHypothesisId = typeof payload?.focus_hypothesis_id === "string" ? payload.focus_hypothesis_id : "";
  const items = Array.isArray(reportStatus?.items) ? (reportStatus?.items as ReportSectionDTO[]) : null;
  const currentSection = typeof reportStatus?.current_section === "string" ? reportStatus.current_section : "";
  const focusSections = Array.isArray(reportStatus?.focus_sections)
    ? new Set((reportStatus.focus_sections as string[]).map(String))
    : new Set<string>();
  const overlaySource = items ?? baseSections;
  return overlaySource.map((section) => {
    const gapHypothesisIds = Array.isArray(section.gap_hypothesis_ids) ? section.gap_hypothesis_ids : [];
    return {
      ...section,
      is_writing: section.section_key === currentSection || Boolean(section.is_writing),
      is_highlighted:
        Boolean(section.is_highlighted) ||
        focusSections.has(section.section_key) ||
        (focusHypothesisId.startsWith("gap-") && gapHypothesisIds.includes(focusHypothesisId))
    };
  });
}

function scheduleRefresh(): void {
  if (refreshTimer) {
    return;
  }
  refreshTimer = window.setTimeout(async () => {
    refreshTimer = undefined;
    await refreshAll();
  }, 400);
}

function drillToParams(path: number[]): { bucket: "year" | "month" | "day" | "hour"; start?: string; end?: string } {
  // Chart granularity is always "one level finer than the picker depth":
  //   no filter  → day across all data
  //   year       → day across that year
  //   year+month → day across that month
  //   year+month+day → hour across that day
  if (path.length === 0) return { bucket: "day" };
  if (path.length === 1) {
    const [y] = path;
    return { bucket: "day", start: `${y}-01-01`, end: `${y + 1}-01-01` };
  }
  if (path.length === 2) {
    const [y, m] = path;
    const next = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, "0")}-01`;
    return { bucket: "day", start: `${y}-${String(m).padStart(2, "0")}-01`, end: next };
  }
  const [y, m, d] = path;
  const startStr = `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
  const startDate = new Date(`${startStr}T00:00:00Z`);
  const endDate = new Date(startDate.getTime() + 86400_000);
  const endStr = endDate.toISOString().slice(0, 10);
  return { bucket: "hour", start: startStr, end: endStr };
}

export async function refreshAll(): Promise<void> {
  let drillValue: number[] = [];
  volumeDrill.subscribe((value) => (drillValue = value))();
  const { bucket: volumeBucketParam, start: volumeStart, end: volumeEnd } = drillToParams(drillValue);
  const [caseResult, statsResult, findingsResult, hypothesesResult, sessionsResult, reportResult, timelineResult, eventVolumeResult, eventVolumeDetectedResult, eventVolumeYearsResult, reviewsResult, reasoningResult, coverageResult, entitiesResult] =
    await Promise.allSettled([
      api.getCase(),
      api.getStats(),
      api.getFindings(),
      api.getHypotheses(),
      api.getSessions(),
      api.getReportSections(),
      api.getTimeline(),
      api.getEventVolume(volumeBucketParam, "all", volumeStart, volumeEnd),
      api.getEventVolume(volumeBucketParam, "detected", volumeStart, volumeEnd),
      api.getEventVolume("year", "all"),
      api.getAiReviews(),
      api.getLatestReasoning(10),
      api.getAttackCoverage(),
      api.getEntities()
    ]);

  if (caseResult.status === "fulfilled") caseInfo.set(caseResult.value);
  if (statsResult.status === "fulfilled") caseStats.set(statsResult.value);
  if (findingsResult.status === "fulfilled") findings.set(findingsResult.value);
  if (hypothesesResult.status === "fulfilled") hypotheses.set(hypothesesResult.value);
  if (sessionsResult.status === "fulfilled") sessions.set(sessionsResult.value);
  let currentProgress: ProgressEventDTO | null = null;
  progress.subscribe((value) => (currentProgress = value))();
  if (reportResult.status === "fulfilled") reportSections.set(mergeReportSections(reportResult.value, currentProgress));
  if (timelineResult.status === "fulfilled") timeline.set(timelineResult.value);
  if (eventVolumeResult.status === "fulfilled") eventVolume.set(eventVolumeResult.value);
  if (eventVolumeDetectedResult.status === "fulfilled") eventVolumeDetected.set(eventVolumeDetectedResult.value);
  if (eventVolumeYearsResult.status === "fulfilled") eventVolumeYears.set(eventVolumeYearsResult.value);
  if (reviewsResult.status === "fulfilled") aiReviews.set(reviewsResult.value);
  if (reasoningResult.status === "fulfilled") latestReasoning.set(reasoningResult.value);
  if (coverageResult.status === "fulfilled") attackCoverage.set(coverageResult.value);
  if (entitiesResult.status === "fulfilled") entities.set(entitiesResult.value);

  if (sessionsResult.status === "fulfilled") {
    const latestSessionId = sessionsResult.value[0]?.session_id ?? "";
    if (latestSessionId) {
      try {
        steps.set(await api.getSteps(latestSessionId));
      } catch {
        // ignore step fetch failures
      }
    }
  }
}

export function connectProgress(): () => void {
  connection.set("idle");
  const source = api.connectStream(lastEventIndex);
  source.addEventListener("progress", async (event) => {
    const payload = parseProgressEvent(event as MessageEvent<string>);
    lastEventIndex = payload.event_index;
    progress.set(payload);
    reportSections.update((sections) => mergeReportSections(sections, payload));
    connection.set("connected");
    scheduleRefresh();
  });
  source.onerror = () => {
    connection.set("error");
  };
  return () => source.close();
}
