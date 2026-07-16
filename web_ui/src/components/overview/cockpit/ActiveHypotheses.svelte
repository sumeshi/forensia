<script lang="ts">
  import { api } from "../../../lib/api";
  import {
    formatReasoningPhase,
    formatRelativeTime,
    formatVerdict,
    reasoningToneClass,
    truncateText
  } from "../../../lib/format";
  import type { HypothesisReasoningEntryDTO } from "../../../lib/types";

  type HypothesisThread = {
    id: string;
    description: string;
    summary: string;
    verdict?: string | null;
    latestReasoning: HypothesisReasoningEntryDTO[];
    reasoningCount: number;
    latestIteration: number | null;
    latestReasoningAt: string | null;
    blockedReason: string | null;
    sufficiencyStatus: string | null;
    sufficiencyScore: number | null;
    sufficiencyReason: string | null;
    humanReviewRequired: boolean;
  };

  export let items: HypothesisThread[] = [];
  export let embedded = false;
  export let emptyMessage = "No active hypotheses.";

  let openId = "";
  let loadingId = "";
  let error = "";
  let detailEntries: Record<string, HypothesisReasoningEntryDTO[]> = {};
  let showAllId = "";

  async function loadReasoning(hypothesisId: string): Promise<void> {
    loadingId = hypothesisId;
    error = "";
    try {
      detailEntries = {
        [hypothesisId]: await api.getHypothesisReasoning(hypothesisId, 20)
      };
    } catch (err) {
      error = err instanceof Error ? err.message : "failed to load reasoning";
    } finally {
      loadingId = "";
    }
  }

  async function toggle(hypothesisId: string): Promise<void> {
    if (openId === hypothesisId) {
      openId = "";
      detailEntries = {};
      showAllId = "";
      error = "";
      return;
    }
    openId = hypothesisId;
    detailEntries = {};
    showAllId = "";
    await loadReasoning(hypothesisId);
  }

  $: openItem = items.find((item) => item.id === openId) ?? null;
  $: openLatestEntryId = openItem?.latestReasoning?.[0]?.entry_id ?? "";
  $: openEntries = openId ? (detailEntries[openId] ?? []) : [];
  $: if (
    openId &&
    openLatestEntryId &&
    openEntries.length > 0 &&
    !openEntries.some((entry) => entry.entry_id === openLatestEntryId) &&
    loadingId !== openId
  ) {
    loadReasoning(openId);
  }
</script>

<svelte:element this={embedded ? "div" : "section"} class={embedded ? "min-w-0" : "panel min-w-0 p-4"}>
  {#if !embedded}
    <div class="mb-3 flex items-center justify-between gap-2">
      <h3 class="panel-title">Active Hypotheses</h3>
      {#if items.length > 0}
        <span class="text-xs uppercase text-semantic-fg-faint">{items.length} threads</span>
      {/if}
    </div>
  {/if}

  {#if items.length === 0}
    <p class="text-sm text-semantic-fg-muted">{emptyMessage}</p>
  {:else}
    <div class="max-h-[420px] space-y-2 overflow-y-auto pr-1">
      {#each items as item}
        {@const latest = item.latestReasoning[0]}
        <article class="min-w-0 rounded-xl border border-mocha-surface1 bg-semantic-bg/70">
          <button
            class="flex min-w-0 w-full items-start gap-3 px-3 py-3 text-left"
            type="button"
            on:click={() => toggle(item.id)}
            aria-expanded={openId === item.id}
          >
            <span class="mt-0.5 text-xs text-semantic-fg-muted">{openId === item.id ? "▼" : "▶"}</span>

            <div class="min-w-0 flex-1">
              <div class="flex items-start gap-2">
                <span class="rounded-full border border-mocha-surface1 bg-semantic-bg px-2 py-0.5 text-xs font-semibold font-mono tabular-nums text-semantic-accent">
                  {item.id}
                </span>
                {#if item.verdict}
                  <span class="flex items-center gap-1 chip text-semantic-fg-muted">
                    <span class={`h-1.5 w-1.5 rounded-full ${reasoningToneClass(item.verdict)}`}></span>
                    {formatVerdict(item.verdict)}
                  </span>
                {/if}
                {#if item.sufficiencyStatus}
                  <span
                    class="chip text-semantic-fg-muted"
                    title={item.sufficiencyReason ?? "Evidence sufficiency assessment"}
                  >
                    evidence: {item.sufficiencyStatus}
                    {#if item.sufficiencyScore !== null}
                      ({Math.round(item.sufficiencyScore * 100)}%)
                    {/if}
                  </span>
                {/if}
                {#if item.blockedReason}
                  <span class="chip text-semantic-warn" title={item.blockedReason}>blocked</span>
                {/if}
                {#if item.humanReviewRequired}
                  <span class="chip text-semantic-warn">human review</span>
                {/if}
                <p class="min-w-0 flex-1 truncate text-sm font-medium text-semantic-fg">{item.description}</p>
              </div>

              <div class="mt-2 flex items-start gap-2 text-xs text-semantic-fg-muted">
                <span class={`mt-1 h-2 w-2 rounded-full ${reasoningToneClass(latest?.verdict)}`}></span>
                {#if latest}
                  <p class="min-w-0 flex-1">
                    <span class="mr-1 rounded bg-semantic-bg px-1.5 py-0.5 font-mono text-xs text-semantic-fg-muted">
                      [{formatReasoningPhase(latest.phase)}]
                    </span>
                    {truncateText(latest.body, 80)}
                  </p>
                {:else}
                  <p class="min-w-0 flex-1">No reasoning yet.</p>
                {/if}
              </div>
            </div>

            <div class="shrink-0 text-right text-xs text-semantic-fg-muted">
              <div class="font-mono tabular-nums">{item.latestIteration ?? 0} iter</div>
              <div class="mt-1 font-mono tabular-nums">{formatRelativeTime(item.latestReasoningAt)}</div>
            </div>
          </button>

          {#if openId === item.id}
<div class="border-t border-mocha-surface1 px-3 py-3">
               {#if loadingId === item.id}
                 <p class="text-xs text-semantic-fg-muted">Loading reasoning...</p>
               {:else if error}
                 <p class="text-xs text-semantic-danger">{error}</p>
               {:else if openEntries.length === 0}
                 <p class="text-xs text-semantic-fg-muted">No reasoning yet.</p>
               {:else}
                 <div class="space-y-2">
                   {#each [...openEntries].reverse().slice(0, showAllId === item.id ? 20 : 10) as entry}
                     <div class="flex gap-3">
                       <div class="flex w-16 shrink-0 flex-col items-center">
                         <span class={`mt-1 h-2.5 w-2.5 rounded-full ${reasoningToneClass(entry.verdict)}`}></span>
                          <span class="h-full w-px bg-semantic-bg-raised"></span>
                        </div>
                        <div class="min-w-0 flex-1 rounded-lg bg-semantic-bg/80 px-3 py-2">
                      <div class="flex min-w-0 flex-wrap items-center gap-2 text-xs text-semantic-fg-faint">
                            <span class="font-mono tabular-nums">[{formatReasoningPhase(entry.phase)}]</span>
                            <span class="font-mono tabular-nums">{entry.iteration} iter</span>
                            {#if entry.verdict}
                              <span class="text-semantic-fg-muted">{formatVerdict(entry.verdict)}</span>
                            {/if}
                            <span class="font-mono tabular-nums">{formatRelativeTime(entry.created_at)}</span>
                          </div>
                          <p class="mt-1 break-words text-sm text-semantic-fg">{entry.body}</p>
                       </div>
                     </div>
                   {/each}
                 </div>

                 {#if openEntries.length > 10}
                   <button
                      class="mt-3 text-xs font-medium text-semantic-info hover:text-semantic-accent"
                     type="button"
                     on:click={() => (showAllId = showAllId === item.id ? "" : item.id)}
                   >
                     {showAllId === item.id ? "Show less" : "Show all"}
                   </button>
                 {/if}
               {/if}
             </div>
           {/if}
        </article>
      {/each}
    </div>
  {/if}
</svelte:element>
