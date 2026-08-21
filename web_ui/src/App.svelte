<script lang="ts">
  import { onMount } from "svelte";

  import DetailsTabs from "./components/details/DetailsTabs.svelte";
  import ActivityBanner from "./components/layout/ActivityBanner.svelte";
  import Header from "./components/layout/Header.svelte";
  import Sidebar from "./components/layout/Sidebar.svelte";
  import Settings from "./components/Settings.svelte";
  import KpiBar from "./components/layout/KpiBar.svelte";
  import type { KpiItem } from "./components/layout/kpi_types";
  import AiActivityPanel from "./components/overview/cockpit/AiActivityPanel.svelte";
  import HypothesisStream from "./components/overview/cockpit/HypothesisStream.svelte";
  import OpenGaps from "./components/overview/cockpit/OpenGaps.svelte";
  import ReportDraftProgress from "./components/report/ReportDraftProgress.svelte";
  import VolumeTimeline from "./components/VolumeTimeline.svelte";
  import AttackCoverage from "./components/overview/AttackCoverage.svelte";
  import TopRules from "./components/overview/TopRules.svelte";
  import TopEntities from "./components/overview/TopEntities.svelte";
  import { reportProgress } from "./lib/derived/report_progress";
  import { currentTask, runningQuery } from "./lib/derived/ai_activity";
  import {
    activeHypothesesView,
    resolvedHypothesesView,
    openGapsView,
    verdictBreakdown,
    severityBreakdown,
    topRules
  } from "./lib/derived/cockpit";
  import {
    attackCoverage,
    caseInfo,
    entities,
    caseStats,
    connectProgress,
    connection,
    eventVolume,
    eventVolumeDetected,
    eventVolumeYears,
    findings,
    latestReasoning,
    progress,
    refreshAll,
  reportSections,
  runtimeConfig,
  searchQuery,
  sessions,
  snapshotMetadata,
  steps,
  timeline,
  volumeDrill,
  refreshErrors,
  lastRefreshAt
} from "./lib/stores";
  import { formatCaseStatus, getInvestigateSubphase, getPipelinePhase } from "./lib/format";

  // Initial-render decision only: DetailsTabs copies the prop once, so the
  // user keeps manual control after mount.
  const wideViewport = typeof window !== "undefined" && window.innerWidth >= 1280;

  let sidebarCollapsed = false;
  let view: "dashboard" | "settings" = "dashboard";

  function navigate(item: { id: string; view: string; anchor: string | null }) {
    view = item.view === "settings" ? "settings" : "dashboard";
    if (item.view === "settings" || !item.anchor) {
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    // Dashboard may need a frame to (re)render before the anchor exists.
    const sel = item.anchor;
    requestAnimationFrame(() => document.querySelector(sel)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  function toggleSidebar() {
    sidebarCollapsed = !sidebarCollapsed;
    try {
      localStorage.setItem("forensia:sidebar-collapsed", sidebarCollapsed ? "1" : "0");
    } catch {
      // localStorage unavailable (private mode); collapse stays in-memory only.
    }
  }

  onMount(() => {
    try {
      sidebarCollapsed = localStorage.getItem("forensia:sidebar-collapsed") === "1";
    } catch {
      // ignore
    }
    refreshAll();
    return connectProgress();
  });

  // Header search box filters the findings table only (the main data list);
  // KPI counts stay authoritative (driven by caseStats, not the filter).
  $: query = $searchQuery.trim().toLowerCase();
  $: filteredFindings = query
    ? $findings.filter((f) =>
        `${f.title ?? ""} ${f.rule_id ?? ""} ${f.summary ?? ""} ${f.severity ?? ""}`
          .toLowerCase()
          .includes(query)
      )
    : $findings;

  // Report-section gap coverage → Open Gaps KPI note.
  $: gapSectionCount = $reportSections.filter(
    (s) => (s.gap_count ?? 0) > 0 || (s.gaps?.length ?? 0) > 0
  ).length;
  $: totalSectionCount = $reportSections.length;

  // Host(s) the evidence came from, with their activity window. A machine
  // rename shows as two entries ordered by first-seen (timeline under the name).
  $: hosts = $caseStats?.hosts ?? [];

  async function updateDrill(next: number[]) {
    $volumeDrill = next;
    await refreshAll();
  }

  $: payload = ($progress?.payload ?? {}) as Record<string, unknown>;
  $: llmModel =
    typeof payload.llm_model === "string"
      ? payload.llm_model
      : ($runtimeConfig?.llm_model ?? "-");
  $: llmBaseUrl = $runtimeConfig?.llm_base_url ?? "-";
  $: updatedAt = $progress?.created_at ?? "-";
  $: stageValue = typeof $progress?.stage === "string" ? $progress.stage : null;
  $: pipelineMeta = getPipelinePhase(stageValue);
  $: subphaseMeta = getInvestigateSubphase(stageValue);
  $: currentStage = formatCaseStatus(stageValue);
  $: kpis = [
    {
      label: "Events",
      icon: "activity",
      value: Intl.NumberFormat("ja-JP").format(
        ($caseStats?.evtx_rows ?? 0) + ($caseStats?.mft_entries ?? 0) + ($caseStats?.prefetch_rows ?? 0)
      ),
      breakdown: [
        { label: "EVTX", value: $caseStats?.evtx_rows ?? 0, color: "bg-semantic-info" },
        { label: "MFT", value: $caseStats?.mft_entries ?? 0, color: "bg-mocha-teal" },
        { label: "Prefetch", value: $caseStats?.prefetch_rows ?? 0, color: "bg-mocha-peach" }
      ]
    },
    {
      label: "Findings",
      icon: "findings",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.findings_accepted ?? 0),
      tone: "text-semantic-warn",
      breakdown: [
        { label: "High", value: $severityBreakdown.highAccepted, color: "bg-semantic-danger" },
        { label: "Medium", value: $severityBreakdown.mediumAccepted, color: "bg-semantic-warn" },
        { label: "Low", value: $severityBreakdown.lowAccepted, color: "bg-semantic-ok" }
      ]
    },
    {
      label: "Hypotheses",
      icon: "hypotheses",
      value: Intl.NumberFormat("ja-JP").format(
        ($caseStats?.active_hypotheses ?? 0) + ($caseStats?.resolved_hypotheses ?? 0)
      ),
      tone: "text-semantic-accent",
      breakdown: [
        { label: "Active", value: $verdictBreakdown.active, color: "bg-semantic-accent" },
        { label: "Confirmed", value: $verdictBreakdown.confirmed, color: "bg-semantic-ok" },
        { label: "Refuted", value: $verdictBreakdown.refuted, color: "bg-semantic-danger" },
        { label: "Untestable", value: $verdictBreakdown.untestable, color: "bg-semantic-warn" },
        { label: "Needs Review", value: $verdictBreakdown.needs_review, color: "bg-semantic-warn" },
        { label: "Deferred", value: $verdictBreakdown.deferred, color: "bg-semantic-info" },
        { label: "Blocked", value: $verdictBreakdown.blocked, color: "bg-semantic-info" }
      ]
    },
    {
      label: "Open Gaps",
      icon: "gaps",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.open_gaps ?? 0),
      tone: "text-semantic-warn",
      note: totalSectionCount > 0 ? `${gapSectionCount} of ${totalSectionCount} sections affected` : undefined
    }
  ] satisfies KpiItem[];
</script>

<svelte:head>
  <title>forensia cockpit</title>
</svelte:head>

<div class="flex">
  <Sidebar collapsed={sidebarCollapsed} {view} onToggle={toggleSidebar} onNavigate={navigate} />

  <main id="top" class="flex min-w-0 flex-1 flex-col gap-5 p-5 2xl:px-8">
    <ActivityBanner />

    {#if view === "settings"}
      <Settings config={$runtimeConfig} />
    {:else}
    <Header
      caseName={$caseInfo?.case_name ?? "loading"}
      connection={$connection}
      currentStage={currentStage}
      phaseIndex={pipelineMeta.index}
      hosts={hosts}
      model={llmModel}
      {llmBaseUrl}
      {updatedAt}
    />

    <KpiBar items={kpis} />

    {#if Object.keys($refreshErrors).length > 0}
      <section class="panel border-semantic-danger/40 bg-semantic-danger/5 p-3 text-sm">
        <p class="mb-1 font-semibold text-semantic-danger">Partial refresh: some endpoints failed</p>
        <ul class="list-inside list-disc space-y-1 text-semantic-danger/90">
          {#each Object.entries($refreshErrors) as [endpoint, message]}
            <li><span class="font-mono">{endpoint}</span>: {message}</li>
          {/each}
        </ul>
        {#if $lastRefreshAt}
          <p class="mt-1 text-xs text-foreground/60">Last successful refresh: {$lastRefreshAt}</p>
        {/if}
      </section>
    {/if}

    {#if $snapshotMetadata}
      <section class="panel p-3 text-xs text-foreground/65">
        <span class="font-semibold">Snapshot</span>
        <span class="ml-2">{$snapshotMetadata.state ?? "unknown"}</span>
        {#if $snapshotMetadata.stale}<span class="ml-2 text-semantic-danger">stale</span>{/if}
        <span class="ml-2">revision {$snapshotMetadata.current_revision ?? $snapshotMetadata.generation_revision ?? "—"}</span>
        <span class="ml-2">generated {$snapshotMetadata.generated_at ?? "—"}</span>
        <span class="ml-2">authoritative {$snapshotMetadata.authoritative_updated_at ?? "—"}</span>
      </section>
    {/if}

    <section id="timeline" class="scroll-mt-16">
      <VolumeTimeline
        points={$eventVolume}
        detectedPoints={$eventVolumeDetected}
        yearsSummary={$eventVolumeYears}
        drill={$volumeDrill}
        onDrillChange={updateDrill}
      />
    </section>

    <!-- Wide screens: 12-col grid — main flow (8) + sticky side rail (4).
         Below xl the source order stacks: main content first, side info after. -->
    <div class="grid gap-5 xl:grid-cols-12 xl:items-start">
      <div class="flex min-w-0 flex-col gap-5 xl:col-span-8 2xl:col-span-9">
        <section id="hypotheses" class="scroll-mt-16">
          <HypothesisStream
            activeHypotheses={$activeHypothesesView}
            resolvedHypotheses={$resolvedHypothesesView}
            latestReasoningItems={$latestReasoning}
          />
        </section>

        <section id="details" class="scroll-mt-16">
          <DetailsTabs
            findings={filteredFindings}
            steps={$steps}
            sessions={$sessions}
            progress={$progress}
            timeline={$timeline}
            collapsed={!wideViewport}
          />
        </section>

        <section id="report" class="scroll-mt-16">
          <ReportDraftProgress sections={$reportSections} progress={$reportProgress} />
        </section>
      </div>

      <div class="flex min-w-0 flex-col gap-5 xl:sticky xl:top-5 xl:col-span-4 xl:max-h-[calc(100vh-2.5rem)] xl:overflow-y-auto 2xl:col-span-3">
        <AiActivityPanel currentTask={$currentTask} runningQuery={$runningQuery} />

        <section id="gaps" class="scroll-mt-16">
          <OpenGaps items={$openGapsView} />
        </section>

        <AttackCoverage items={$attackCoverage} />

        <TopRules items={$topRules} />

        <TopEntities items={$entities} />
      </div>
    </div>
    {/if}
  </main>
</div>
