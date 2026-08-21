import { writable } from "svelte/store";

import { api, parseProgressEvent } from "./api";
import type {
  AIReviewDTO,
  AttackCoverageRowDTO,
  EntityCardDTO,
  CaseDTO,
  CaseStatsDTO,
  EventVolumePointDTO,
  FindingAggregatesDTO,
  FindingDTO,
  HypothesesResponseDTO,
  HypothesisReasoningEntryDTO,
  InvestigationStepDTO,
  MftTimelineDTO,
  ProgressEventDTO,
  ReportSectionDTO,
  RuntimeConfigDTO,
  SessionDTO,
  SnapshotMetadataDTO
} from "./types";

export const caseInfo = writable<CaseDTO | null>(null);
export const runtimeConfig = writable<RuntimeConfigDTO | null>(null);
export const caseStats = writable<CaseStatsDTO | null>(null);
export const snapshotMetadata = writable<SnapshotMetadataDTO | null>(null);
export const findings = writable<FindingDTO[]>([]);
export const findingAggregates = writable<FindingAggregatesDTO | null>(null);
export const hypotheses = writable<HypothesesResponseDTO>({ active: [], resolved: [] });
export const hypothesisTaxonomy = writable<{
  hypothesis: Record<string, unknown>;
  report_section: Record<string, unknown>;
} | null>(null);
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
// Per-endpoint partial-refresh state (T-51.4): the last error seen for each
// endpoint and the timestamp of the most recent successful full refresh.
export const refreshErrors = writable<Record<string, string>>({});
export const lastRefreshAt = writable<string | null>(null);
// Free-text filter for the findings table (driven by the header search box).
export const searchQuery = writable<string>("");
// Hierarchical drill-down path for Event Volume:
//   []                  → bucket=year   (whole record range)
//   [2024]              → bucket=month  (within 2024)
//   [2024, 5]           → bucket=day    (within 2024-05)
//   [2024, 5, 29]       → bucket=hour   (within 2024-05-29)
export const volumeDrill = writable<number[]>([]);
export const detailsTab = writable<"findings" | "steps" | "sessions" | "trajectory" | "activity" | "mft">("findings");
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
  const tasks: Record<string, Promise<unknown>> = {
    case: api.getCase(),
    config: api.getConfig(),
    stats: api.getStats(),
    snapshot: api.getSnapshotMetadata(),
    findings: api.getFindingsPage(200, 0),
    hypotheses: api.getHypotheses(),
    taxonomy: api.getHypothesesTaxonomy(),
    aggregates: api.getFindingAggregates(),
    sessions: api.getSessions(),
    report: api.getReportSections(),
    timeline: api.getTimeline(),
    eventVolume: api.getEventVolume(volumeBucketParam, "all", volumeStart, volumeEnd),
    eventVolumeDetected: api.getEventVolume(volumeBucketParam, "detected", volumeStart, volumeEnd),
    eventVolumeYears: api.getEventVolume("year", "all"),
    reviews: api.getAiReviews(),
    reasoning: api.getLatestReasoning(10),
    coverage: api.getAttackCoverage(),
    entities: api.getEntities()
  };
  const results = await Promise.allSettled(Object.values(tasks));
  const errors: Record<string, string> = {};
  Object.keys(tasks).forEach((key, index) => {
    const result = results[index];
    if (result.status === "rejected") {
      errors[key] = result.reason instanceof Error ? result.reason.message : String(result.reason);
    }
  });
  refreshErrors.set(errors);

  if (results[0].status === "fulfilled") caseInfo.set(results[0].value as CaseDTO);
  if (results[1].status === "fulfilled") runtimeConfig.set(results[1].value as RuntimeConfigDTO);
  if (results[2].status === "fulfilled") caseStats.set(results[2].value as CaseStatsDTO);
  if (results[3].status === "fulfilled") snapshotMetadata.set(results[3].value as SnapshotMetadataDTO);
  if (results[4].status === "fulfilled") {
    const page = results[4].value as { items: FindingDTO[] };
    findings.set(page.items);
  }
  if (results[5].status === "fulfilled") hypotheses.set(results[5].value as HypothesesResponseDTO);
  if (results[6].status === "fulfilled") hypothesisTaxonomy.set(results[6].value as never);
  if (results[7].status === "fulfilled") findingAggregates.set(results[7].value as FindingAggregatesDTO);
  if (results[8].status === "fulfilled") sessions.set(results[8].value as SessionDTO[]);
  let currentProgress: ProgressEventDTO | null = null;
  progress.subscribe((value) => (currentProgress = value))();
  if (results[9].status === "fulfilled") reportSections.set(mergeReportSections(results[9].value as ReportSectionDTO[], currentProgress));
  if (results[10].status === "fulfilled") timeline.set(results[10].value as MftTimelineDTO[]);
  if (results[11].status === "fulfilled") eventVolume.set(results[11].value as EventVolumePointDTO[]);
  if (results[12].status === "fulfilled") eventVolumeDetected.set(results[12].value as EventVolumePointDTO[]);
  if (results[13].status === "fulfilled") eventVolumeYears.set(results[13].value as EventVolumePointDTO[]);
  if (results[14].status === "fulfilled") aiReviews.set(results[14].value as AIReviewDTO[]);
  if (results[15].status === "fulfilled") latestReasoning.set(results[15].value as HypothesisReasoningEntryDTO[]);
  if (results[16].status === "fulfilled") attackCoverage.set(results[16].value as AttackCoverageRowDTO[]);
  if (results[17].status === "fulfilled") entities.set(results[17].value as EntityCardDTO[]);

  const sessionsValue = results[8].status === "fulfilled" ? (results[8].value as SessionDTO[]) : [];
  const latestSessionId = sessionsValue[0]?.session_id ?? "";
  if (latestSessionId) {
    try {
      steps.set(await api.getSteps(latestSessionId));
    } catch (error) {
      errors.steps = error instanceof Error ? error.message : String(error);
    }
  }
  // This timestamp is explicitly the last complete refresh. A partial refresh
  // must not make stale data look current.
  refreshErrors.set(errors);
  if (Object.keys(errors).length === 0) {
    lastRefreshAt.set(new Date().toISOString());
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
