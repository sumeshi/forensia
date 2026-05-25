import { writable } from "svelte/store";

import { api, parseProgressEvent } from "./api";
import type {
  AIReviewDTO,
  CaseDTO,
  CaseStatsDTO,
  EventVolumePointDTO,
  FindingDTO,
  HypothesesResponseDTO,
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
export const aiReviews = writable<AIReviewDTO[]>([]);
export const progress = writable<ProgressEventDTO | null>(null);
export const connection = writable<"idle" | "connected" | "error">("idle");
export const volumeBucket = writable<"hour" | "day">("hour");
export const volumeSource = writable<"all" | "detected">("all");
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

export async function refreshAll(): Promise<void> {
  let bucketValue: "hour" | "day" = "hour";
  let sourceValue: "all" | "detected" = "all";
  volumeBucket.subscribe((value) => (bucketValue = value))();
  volumeSource.subscribe((value) => (sourceValue = value))();
  const [caseResult, statsResult, findingsResult, hypothesesResult, sessionsResult, reportResult, timelineResult, eventVolumeResult, reviewsResult] =
    await Promise.allSettled([
      api.getCase(),
      api.getStats(),
      api.getFindings(),
      api.getHypotheses(),
      api.getSessions(),
      api.getReportSections(),
      api.getTimeline(),
      api.getEventVolume(bucketValue, sourceValue),
      api.getAiReviews()
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
  if (reviewsResult.status === "fulfilled") aiReviews.set(reviewsResult.value);

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
