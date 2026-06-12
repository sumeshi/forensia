<script lang="ts">
  import { onMount } from "svelte";

  import DetailsTabs from "./components/details/DetailsTabs.svelte";
  import ActivityBanner from "./components/layout/ActivityBanner.svelte";
  import Header from "./components/layout/Header.svelte";
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
    sessions,
    steps,
    timeline,
    volumeDrill
  } from "./lib/stores";
  import { formatStage, getInvestigateSubphase, getPipelinePhase } from "./lib/format";

  // Initial-render decision only: DetailsTabs copies the prop once, so the
  // user keeps manual control after mount.
  const wideViewport = typeof window !== "undefined" && window.innerWidth >= 1280;

  onMount(() => {
    refreshAll();
    return connectProgress();
  });

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
  $: currentStage = formatStage(stageValue);
  $: kpis = [
    {
      label: "Events",
      value: Intl.NumberFormat("ja-JP").format(($caseStats?.evtx_rows ?? 0) + ($caseStats?.mft_entries ?? 0))
    },
    {
      label: "Findings",
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
      value: Intl.NumberFormat("ja-JP").format($caseStats?.open_gaps ?? 0),
      tone: "text-semantic-warn"
    }
  ] satisfies KpiItem[];
</script>

<svelte:head>
  <title>forensia cockpit</title>
</svelte:head>

<ActivityBanner />

<main class="mx-auto flex max-w-none flex-col gap-4 p-4 2xl:px-6">
  <Header
    caseName={$caseInfo?.case_name ?? "loading"}
    connection={$connection}
    pipelinePhase={`Phase ${pipelineMeta.index}/${pipelineMeta.total} ${pipelineMeta.label}`}
    currentStage={currentStage}
    subphase={subphaseMeta ? `Step ${subphaseMeta.index}/${subphaseMeta.total} ${subphaseMeta.label}` : ""}
    model={llmModel}
    {updatedAt}
  />

  <KpiBar items={kpis} />

  <VolumeTimeline
    points={$eventVolume}
    detectedPoints={$eventVolumeDetected}
    yearsSummary={$eventVolumeYears}
    drill={$volumeDrill}
    onDrillChange={updateDrill}
  />

  <!-- Wide screens: 12-col grid — main flow (8) + sticky side rail (4).
       Below xl the source order stacks: main content first, side info after. -->
  <div class="grid gap-4 xl:grid-cols-12 xl:items-start">
    <div class="flex min-w-0 flex-col gap-4 xl:col-span-8 2xl:col-span-9">
      <ReportDraftProgress sections={$reportSections} progress={$reportProgress} />

      <HypothesisStream
        activeHypotheses={$activeHypothesesView}
        resolvedHypotheses={$resolvedHypothesesView}
        latestReasoningItems={$latestReasoning}
      />

      <DetailsTabs
        findings={$findings}
        steps={$steps}
        sessions={$sessions}
        progress={$progress}
        timeline={$timeline}
        collapsed={!wideViewport}
      />
    </div>

    <div class="flex min-w-0 flex-col gap-4 xl:sticky xl:top-4 xl:col-span-4 xl:max-h-[calc(100vh-2rem)] xl:overflow-y-auto 2xl:col-span-3">
      <AiActivityPanel currentTask={$currentTask} runningQuery={$runningQuery} />

      <OpenGaps items={$openGapsView} />

      <AttackCoverage items={$attackCoverage} />

      <TopRules items={$topRules} />

      <TopEntities items={$entities} />
    </div>
  </div>
</main>
