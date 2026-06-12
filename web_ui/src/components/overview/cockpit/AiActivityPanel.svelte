<script lang="ts">
  import CurrentAiTask from "./CurrentAiTask.svelte";

  export let currentTask: { stageLabel: string; summary: string; iteration: number };
  export let runningQuery: { queryId: string | null; focusHypothesisId: string | null; stage: string | null } | null = null;
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">AI Activity</h3>
  <CurrentAiTask {...currentTask} />
  <div class="mt-3 grid gap-2 text-xs text-semantic-fg-muted">
    <div class="rounded-lg bg-semantic-bg/70 px-3 py-2">
      <span class="text-semantic-fg-muted">Running Query</span>
<div class="mt-1 truncate whitespace-nowrap text-semantic-fg">{runningQuery?.queryId ?? "None"}</div>
     </div>
     <div class="rounded-lg bg-semantic-bg/70 px-3 py-2">
       <span class="text-semantic-fg-muted">Focus Hypothesis</span>
       <div class="mt-1 truncate whitespace-nowrap text-semantic-fg">{runningQuery?.focusHypothesisId ?? "None"}</div>
    </div>
  </div>
</section>
