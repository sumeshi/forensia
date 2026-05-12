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
  const [caseData, statsData, findingsData, hypothesesData, sessionsData, reportData, timelineData, eventVolumeData, reviewsData] = await Promise.all([
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
  caseInfo.set(caseData);
  caseStats.set(statsData);
  findings.set(findingsData);
  hypotheses.set(hypothesesData);
  sessions.set(sessionsData);
  let currentProgress: ProgressEventDTO | null = null;
  progress.subscribe((value) => (currentProgress = value))();
  reportSections.set(mergeReportSections(reportData, currentProgress));
  timeline.set(timelineData);
  eventVolume.set(eventVolumeData);
  aiReviews.set(reviewsData);

  const latestSessionId = sessionsData[0]?.session_id ?? "";
  if (latestSessionId && latestSessionId !== currentSessionId) {
    currentSessionId = latestSessionId;
    steps.set(await api.getSteps(latestSessionId));
  } else if (latestSessionId) {
    steps.set(await api.getSteps(latestSessionId));
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
