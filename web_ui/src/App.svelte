<script lang="ts">
  import { onMount } from "svelte";

  import DetailsTabs from "./components/details/DetailsTabs.svelte";
  import ActivityBanner from "./components/layout/ActivityBanner.svelte";
  import Header from "./components/layout/Header.svelte";
  import KpiBar from "./components/layout/KpiBar.svelte";
  import type { KpiItem } from "./components/layout/kpi_types";
  import Cockpit from "./components/overview/cockpit/Cockpit.svelte";
  import ReportDraftProgress from "./components/report/ReportDraftProgress.svelte";
  import VolumeTimeline from "./components/VolumeTimeline.svelte";
  import AttackCoverage from "./components/overview/AttackCoverage.svelte";
  import TopRules from "./components/overview/TopRules.svelte";
  import TopEntities from "./components/overview/TopEntities.svelte";
  import { reportProgress } from "./lib/derived/report_progress";
  import { currentTask, runningQuery } from "./lib/derived/ai_activity";
  import {
    activeHypothesesView,
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
      tone: "text-mocha-peach",
      breakdown: [
        { label: "High", value: $severityBreakdown.highAccepted, color: "bg-mocha-red" },
        { label: "Medium", value: $severityBreakdown.mediumAccepted, color: "bg-mocha-yellow" },
        { label: "Low", value: $severityBreakdown.lowAccepted, color: "bg-mocha-green" }
      ]
    },
    {
      label: "Hypotheses",
      value: Intl.NumberFormat("ja-JP").format(
        ($caseStats?.active_hypotheses ?? 0) + ($caseStats?.resolved_hypotheses ?? 0)
      ),
      tone: "text-mocha-mauve",
      breakdown: [
        { label: "Active", value: $verdictBreakdown.active, color: "bg-mocha-mauve" },
        { label: "Confirmed", value: $verdictBreakdown.confirmed, color: "bg-mocha-green" },
        { label: "Refuted", value: $verdictBreakdown.refuted, color: "bg-mocha-red" },
        { label: "Inconclusive", value: $verdictBreakdown.inconclusive, color: "bg-mocha-yellow" }
      ]
    },
    {
      label: "Open Gaps",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.open_gaps ?? 0),
      tone: "text-mocha-yellow"
    }
  ] satisfies KpiItem[];
</script>

<svelte:head>
  <title>forensia cockpit</title>
</svelte:head>

<ActivityBanner />

<main class="mx-auto flex max-w-[1920px] flex-col gap-3 p-3 2xl:px-5">
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

  <ReportDraftProgress sections={$reportSections} progress={$reportProgress} />

  <AttackCoverage items={$attackCoverage} />

  <Cockpit
    aiTask={$currentTask}
    runningQuery={$runningQuery}
    activeHypotheses={$activeHypothesesView}
    openGaps={$openGapsView}
    latestReasoningItems={$latestReasoning}
  />

  <section class="grid gap-3 md:grid-cols-2">
    <TopRules items={$topRules} />
    <TopEntities items={$entities} />
  </section>

  <DetailsTabs
    findings={$findings}
    steps={$steps}
    sessions={$sessions}
    progress={$progress}
    timeline={$timeline}
  />
</main>
