<script lang="ts">
  export let caseName = "loading";
  export let connection: "idle" | "connected" | "error" = "idle";
  export let pipelinePhase = "Phase 0/4";
  export let currentStage = "Idle";
  export let subphase = "";
  export let model = "-";
  export let updatedAt = "-";
</script>

<header class="panel px-4 py-3">
  <div class="flex flex-wrap items-start justify-between gap-4">
    <div class="min-w-0">
      <div class="flex min-w-0 flex-wrap items-center gap-2">
        <strong class="truncate text-lg font-semibold text-semantic-fg">{caseName}</strong>
        <span class="chip-muted">{pipelinePhase}</span>
        <span class="chip">{currentStage}</span>
        {#if subphase}
          <span class="chip text-semantic-accent">{subphase}</span>
        {/if}
      </div>
      <div class="mt-2 flex flex-wrap items-center gap-3 text-xs text-semantic-fg-muted">
        <span class="font-mono tabular-nums">Model {model}</span>
        <span class="font-mono tabular-nums">Updated {updatedAt}</span>
      </div>
    </div>
    <div class="shrink-0">
      <span class={`chip ${connection === "connected" ? "text-semantic-ok" : connection === "error" ? "text-semantic-danger" : "text-semantic-fg-faint"}`}>{connection}</span>
    </div>
  </div>
</header>
