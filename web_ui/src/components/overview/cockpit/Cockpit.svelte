<script lang="ts">
  import AiActivityPanel from "./AiActivityPanel.svelte";
  import CurrentHypothesis from "./CurrentHypothesis.svelte";
  import NextAction from "./NextAction.svelte";
  import OpenGaps from "./OpenGaps.svelte";
  import WhatWeKnow from "./WhatWeKnow.svelte";
  import WhyItMatters from "./WhyItMatters.svelte";
  import ActiveHypotheses from "./ActiveHypotheses.svelte";

  export let whatWeKnowItems: string[] = [];
  export let currentHypothesisView = { title: "", status: "", summary: "" };
  export let whyItMattersText = "";
  export let nextActionText = "";
  export let aiTask = { stageLabel: "", summary: "", iteration: 0 };
  export let runningQuery: { queryId: string | null; focusHypothesisId: string | null; stage: string | null } | null = null;
  export let activeHypotheses: Array<{
    id: string;
    description: string;
    summary: string;
    latestReasoning: Array<{
      entry_id: string;
      hypothesis_id: string;
      iteration: number;
      phase: string;
      verdict?: string | null;
      body: string;
      created_at?: string | null;
    }>;
    reasoningCount: number;
    latestIteration: number | null;
    latestReasoningAt: string | null;
  }> = [];
  export let openGaps: Array<{ sectionTitle: string; gap: string }> = [];
</script>

<section class="grid gap-3 2xl:grid-cols-[minmax(0,1.25fr)_minmax(0,0.95fr)]">
  <div class="grid min-w-0 gap-3">
    <WhatWeKnow items={whatWeKnowItems} />
    <div class="grid gap-3 md:grid-cols-2">
      <CurrentHypothesis {...currentHypothesisView} />
      <WhyItMatters text={whyItMattersText} />
    </div>
    <NextAction text={nextActionText} />
  </div>
  <div class="grid min-w-0 gap-3">
    <AiActivityPanel currentTask={aiTask} {runningQuery} />
    <ActiveHypotheses items={activeHypotheses} />
    <OpenGaps items={openGaps} />
  </div>
</section>
