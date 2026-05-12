<script lang="ts">
  import { progress, connection } from "../../lib/stores";
  import { formatActionVerb } from "../../lib/format";

  $: stage = $progress?.stage ?? null;
  $: verb = formatActionVerb(stage);
  $: detail = ($progress?.summary ?? "").trim();
  $: iteration = $progress?.iteration ?? 0;
  $: currentQuery = $progress?.current_query ?? null;
  $: isLive =
    $connection === "connected" &&
    !!stage &&
    stage !== "completed" &&
    stage !== "investigate/report-cycle-done";
</script>

<aside
  class="sticky top-0 z-30 flex items-center gap-3 border-b border-mocha-surface0 bg-mocha-mantle/90 px-4 py-2 backdrop-blur"
  aria-live="polite"
  role="status"
>
  <span class="relative flex h-2.5 w-2.5 shrink-0" aria-hidden="true">
    {#if isLive}
      <span class="absolute inline-flex h-full w-full animate-ping rounded-full bg-mocha-mauve opacity-70"></span>
    {/if}
    <span
      class={`relative inline-flex h-2.5 w-2.5 rounded-full ${
        isLive ? "bg-mocha-mauve" : $connection === "error" ? "bg-mocha-red" : "bg-mocha-overlay0"
      }`}
    ></span>
  </span>

  <span class="shrink-0 text-[11px] uppercase tracking-[0.16em] text-mocha-subtext0">現在</span>

  <span class="min-w-0 truncate text-sm font-medium text-mocha-text">
    {verb}{isLive ? "..." : ""}
  </span>

  {#if detail && detail !== verb}
    <span class="hidden min-w-0 truncate text-xs text-mocha-subtext1 md:inline">— {detail}</span>
  {/if}

  <span class="ml-auto flex shrink-0 items-center gap-3 text-[11px] text-mocha-overlay1">
    {#if currentQuery}
      <span class="font-mono">{currentQuery}</span>
    {/if}
    {#if iteration > 0}
      <span>iter {iteration}</span>
    {/if}
  </span>
</aside>
