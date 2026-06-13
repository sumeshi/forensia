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
    searchQuery,
    sessions,
    steps,
    timeline,
    volumeDrill
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

  // Host name(s) the evidence came from, listed under the case name.
  $: hostNames = $entities.filter((e) => e.kind === "host" && e.name).map((e) => e.name);

  async function updateDrill(next: number[]) {
    $volumeDrill = next;
    await refreshAll();
  }

  $: payload = ($progress?.payload ?? {}) as Record<string, unknown>;
  $: llmModel = typeof payload.llm_model === "string" ? payload.llm_model : "-";
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
        { label: "Inconclusive", value: $verdictBreakdown.inconclusive, color: "bg-semantic-warn" }
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
      <Settings />
    {:else}
    <Header
      caseName={$caseInfo?.case_name ?? "loading"}
      connection={$connection}
      currentStage={currentStage}
      phaseIndex={pipelineMeta.index}
      hostNames={hostNames}
      model={llmModel}
      {updatedAt}
    />

    <KpiBar items={kpis} />

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
