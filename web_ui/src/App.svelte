<script lang="ts">
  import { onMount } from "svelte";

  import DetailsTabs from "./components/details/DetailsTabs.svelte";
  import ActivityBanner from "./components/layout/ActivityBanner.svelte";
  import Header from "./components/layout/Header.svelte";
  import KpiBar from "./components/layout/KpiBar.svelte";
  import Cockpit from "./components/overview/cockpit/Cockpit.svelte";
  import ImportantFindings from "./components/report/ImportantFindings.svelte";
  import ReportDraftProgress from "./components/report/ReportDraftProgress.svelte";
  import VolumeTimeline from "./components/VolumeTimeline.svelte";
  import { currentTask, runningQuery } from "./lib/derived/ai_activity";
  import {
    activeHypothesesView,
    currentHypothesis,
    nextAction,
    openGapsView,
    whatWeKnow,
    whyItMatters
  } from "./lib/derived/cockpit";
  import { reportProgress } from "./lib/derived/report_progress";
  import {
    caseInfo,
    caseStats,
    connectProgress,
    connection,
    eventVolume,
    findings,
    progress,
    refreshAll,
    reportSections,
    sessions,
    steps,
    timeline,
    volumeBucket,
    volumeSource
  } from "./lib/stores";
  import { formatStage, getInvestigateSubphase, getPipelinePhase } from "./lib/format";

  onMount(() => {
    refreshAll();
    return connectProgress();
  });

  async function updateBucket(value: "hour" | "day") {
    $volumeBucket = value;
    await refreshAll();
  }

  async function updateSource(value: "all" | "detected") {
    $volumeSource = value;
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
      tone: "text-mocha-peach"
    },
    {
      label: "Active Hyp",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.active_hypotheses ?? 0),
      tone: "text-mocha-mauve"
    },
    {
      label: "Open Gaps",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.open_gaps ?? 0),
      tone: "text-mocha-yellow"
    },
    {
      label: "Sessions",
      value: Intl.NumberFormat("ja-JP").format($caseStats?.sessions ?? 0)
    },
    {
      label: "Iteration",
      value: `${Intl.NumberFormat("ja-JP").format($caseStats?.total_iterations ?? 0)} iter / ${Intl.NumberFormat("ja-JP").format($caseStats?.session_count ?? 0)} sessions`,
      tone: "text-mocha-blue"
    },
    {
      label: "Approved",
      value: `${$reportProgress.approved}/${$reportProgress.total}`,
      tone: "text-mocha-green"
    }
  ];
</script>

<svelte:head>
  <title>forensia cockpit</title>
</svelte:head>

<ActivityBanner />

<main class="mx-auto flex max-w-[1600px] flex-col gap-3 p-3">
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
    bucket={$volumeBucket}
    source={$volumeSource}
    onBucketChange={updateBucket}
    onSourceChange={updateSource}
  />

  <Cockpit
    whatWeKnowItems={$whatWeKnow}
    currentHypothesisView={$currentHypothesis}
    whyItMattersText={$whyItMatters}
    nextActionText={$nextAction}
    aiTask={$currentTask}
    runningQuery={$runningQuery}
    activeHypotheses={$activeHypothesesView}
    openGaps={$openGapsView}
  />

  <ReportDraftProgress sections={$reportSections} progress={$reportProgress} />

  <ImportantFindings findings={$findings} />

  <DetailsTabs
    findings={$findings}
    steps={$steps}
    sessions={$sessions}
    progress={$progress}
    timeline={$timeline}
  />
</main>
