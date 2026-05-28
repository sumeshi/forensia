<script lang="ts">
  import type { HypothesisReasoningEntryDTO } from "../../../lib/types";
  import AiActivityPanel from "./AiActivityPanel.svelte";
  import OpenGaps from "./OpenGaps.svelte";
  import HypothesisStream from "./HypothesisStream.svelte";

  export let aiTask = { stageLabel: "", summary: "", iteration: 0 };
  export let runningQuery: { queryId: string | null; focusHypothesisId: string | null; stage: string | null } | null = null;
  export let activeHypotheses: Array<{
    id: string;
    description: string;
    summary: string;
    latestReasoning: HypothesisReasoningEntryDTO[];
    reasoningCount: number;
    latestIteration: number | null;
    latestReasoningAt: string | null;
  }> = [];
  export let openGaps: Array<{ sectionTitle: string; gap: string }> = [];
  export let latestReasoningItems: HypothesisReasoningEntryDTO[] = [];

  $: sortedHypotheses = [...activeHypotheses].sort((a, b) => {
    const aTime = a.latestReasoningAt ? new Date(a.latestReasoningAt).getTime() : 0;
    const bTime = b.latestReasoningAt ? new Date(b.latestReasoningAt).getTime() : 0;
    if (aTime !== bTime) return bTime - aTime;
    return (b.latestIteration ?? 0) - (a.latestIteration ?? 0);
  });
</script>

<section class="grid gap-3">
  <AiActivityPanel currentTask={aiTask} {runningQuery} />
  <HypothesisStream activeHypotheses={sortedHypotheses} {latestReasoningItems} />
  <OpenGaps items={openGaps} />
</section>
