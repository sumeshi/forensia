<script lang="ts">
  export let title = "No active hypothesis";
  export let status = "Idle";
  export let summary = "";
</script>

<section class="panel min-w-0 p-4">
  <div class="mb-3 flex items-center justify-between gap-2">
    <h3 class="panel-title">Current Hypothesis</h3>
    <span class="chip chip-muted">{status}</span>
  </div>
  <h4 class="truncate text-sm font-semibold text-semantic-fg">{title}</h4>
  <p class="mt-2 line-clamp-4 min-h-[6rem] text-sm text-semantic-fg-muted">{summary}</p>
</section>
