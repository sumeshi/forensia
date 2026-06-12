<script lang="ts">
  import { onDestroy } from "svelte";
  import { progress, connection } from "../../lib/stores";
  import { formatActionVerb } from "../../lib/format";

  let flashKey = "";
  let isCheckFlash = false;
  let flashTimer: number | undefined;

  $: stage = $progress?.stage ?? null;
  $: verb = formatActionVerb(stage);
  $: detail = ($progress?.summary ?? "").trim();
  $: iteration = $progress?.iteration ?? 0;
  $: currentQuery = $progress?.current_query ?? null;
  $: payload = ($progress?.payload ?? {}) as Record<string, unknown>;
  $: flashHypothesisId = typeof payload.hypothesis_id === "string" ? payload.hypothesis_id : "";
  $: isLive =
    $connection === "connected" &&
    !!stage &&
    stage !== "completed" &&
    stage !== "investigate/report-cycle-done";
  $: nextFlashKey = stage === "investigate/check" ? `${flashHypothesisId}:${detail}` : "";
  $: if (nextFlashKey && nextFlashKey !== flashKey) {
    flashKey = nextFlashKey;
    isCheckFlash = true;
    window.clearTimeout(flashTimer);
    flashTimer = window.setTimeout(() => {
      isCheckFlash = false;
    }, 3000);
  }

  onDestroy(() => {
    window.clearTimeout(flashTimer);
  });
</script>

<aside
  class={`sticky top-0 z-30 flex items-center gap-3 border-b px-4 py-2 backdrop-blur ${
    isCheckFlash
      ? "border-semantic-warn/40 bg-semantic-warn/10"
      : "border-mocha-surface0 bg-semantic-bg/90"
  }`}
  aria-live="polite"
  role="status"
>
  <span class="relative flex h-2.5 w-2.5 shrink-0" aria-hidden="true">
    {#if isLive}
      <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-semantic-accent opacity-70"></span>
    {/if}
    <span
      class={`relative inline-flex h-2.5 w-2.5 rounded-full ${
        isLive ? "bg-semantic-accent" : $connection === "error" ? "bg-semantic-danger" : "bg-mocha-overlay0"
      }`}
    ></span>
  </span>

  <span class="shrink-0 text-xs uppercase text-semantic-fg-muted">Current</span>

  <span class="min-w-0 truncate text-sm font-medium text-semantic-fg">
    {verb}{isLive ? "..." : ""}
  </span>

  {#if detail && detail !== verb}
    <span class="hidden min-w-0 truncate text-xs text-semantic-fg-muted md:inline">— {detail}</span>
  {/if}

  <span class="ml-auto flex shrink-0 items-center gap-3 text-xs text-semantic-fg-faint">
    {#if currentQuery}
      <span class="font-mono tabular-nums">{currentQuery}</span>
    {/if}
    {#if iteration > 0}
      <span class="font-mono tabular-nums">iter {iteration}</span>
    {/if}
  </span>
</aside>
