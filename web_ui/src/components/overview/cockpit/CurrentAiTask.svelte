<script lang="ts">
  export let stageLabel = "Idle";
  export let summary = "";
  export let iteration = 0;
</script>

<section class="rounded-lg bg-semantic-bg/70 px-3 py-3">
  <div class="mb-2 flex items-center justify-between gap-2">
    <span class="chip chip-accent">{stageLabel}</span>
    <span class="text-xs font-mono tabular-nums text-semantic-fg-muted">iter {iteration}</span>
  </div>
  <p class="line-clamp-3 min-h-[3.75rem] text-sm text-semantic-fg-muted">{summary}</p>
</section>
