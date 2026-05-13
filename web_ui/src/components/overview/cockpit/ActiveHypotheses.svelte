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
    latestReasoning: HypothesisReasoningEntryDTO[];
    reasoningCount: number;
    latestIteration: number | null;
    latestReasoningAt: string | null;
  };

  export let items: HypothesisThread[] = [];

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

<section class="panel min-w-0 p-4">
  <div class="mb-3 flex items-center justify-between gap-2">
    <h3 class="panel-title">Active Hypotheses</h3>
    {#if items.length > 0}
      <span class="text-[11px] uppercase tracking-[0.16em] text-mocha-overlay1">{items.length} threads</span>
    {/if}
  </div>

  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">アクティブな仮説はありません。</p>
  {:else}
    <div class="max-h-[420px] space-y-2 overflow-y-auto pr-1">
      {#each items as item}
        {@const latest = item.latestReasoning[0]}
        <article class="min-w-0 rounded-xl border border-mocha-surface0 bg-mocha-mantle/70">
          <button
            class="flex min-w-0 w-full items-start gap-3 px-3 py-3 text-left"
            type="button"
            on:click={() => toggle(item.id)}
            aria-expanded={openId === item.id}
          >
            <span class="mt-0.5 text-xs text-mocha-subtext1">{openId === item.id ? "▼" : "▶"}</span>

            <div class="min-w-0 flex-1">
              <div class="flex items-start gap-2">
                <span class="rounded-full border border-mocha-surface1 bg-mocha-base px-2 py-0.5 text-[10px] font-semibold tracking-[0.12em] text-mocha-mauve">
                  {item.id}
                </span>
                <p class="min-w-0 flex-1 truncate text-sm font-medium text-mocha-text">{item.description}</p>
              </div>

              <div class="mt-2 flex items-start gap-2 text-xs text-mocha-subtext0">
                <span class={`mt-1 h-2 w-2 rounded-full ${reasoningToneClass(latest?.verdict)}`}></span>
                {#if latest}
                  <p class="min-w-0 flex-1">
                    <span class="mr-1 rounded bg-mocha-base px-1.5 py-0.5 font-mono text-[10px] text-mocha-subtext1">
                      [{formatReasoningPhase(latest.phase)}]
                    </span>
                    {truncateText(latest.body, 80)}
                  </p>
                {:else}
                  <p class="min-w-0 flex-1">まだ reasoning はありません。</p>
                {/if}
              </div>
            </div>

            <div class="shrink-0 text-right text-[11px] text-mocha-overlay1">
              <div>{item.latestIteration ?? 0} iter</div>
              <div class="mt-1">{formatRelativeTime(item.latestReasoningAt)}</div>
            </div>
          </button>

          {#if openId === item.id}
            <div class="border-t border-mocha-surface0 px-3 py-3">
              {#if loadingId === item.id}
                <p class="text-xs text-mocha-subtext1">reasoning を読込中です。</p>
              {:else if error}
                <p class="text-xs text-mocha-red">{error}</p>
              {:else if openEntries.length === 0}
                <p class="text-xs text-mocha-subtext1">reasoning はまだありません。</p>
              {:else}
                <div class="space-y-2">
                  {#each [...openEntries].reverse().slice(0, showAllId === item.id ? 20 : 10) as entry}
                    <div class="flex gap-3">
                      <div class="flex w-16 shrink-0 flex-col items-center">
                        <span class={`mt-1 h-2.5 w-2.5 rounded-full ${reasoningToneClass(entry.verdict)}`}></span>
                        <span class="h-full w-px bg-mocha-surface1"></span>
                      </div>
                      <div class="min-w-0 flex-1 rounded-lg bg-mocha-base/80 px-3 py-2">
                <div class="flex min-w-0 flex-wrap items-center gap-2 text-[11px] text-mocha-overlay1">
                          <span class="font-mono">[{formatReasoningPhase(entry.phase)}]</span>
                          <span>{entry.iteration} iter</span>
                          {#if entry.verdict}
                            <span class="text-mocha-subtext0">{formatVerdict(entry.verdict)}</span>
                          {/if}
                          <span>{formatRelativeTime(entry.created_at)}</span>
                        </div>
                        <p class="mt-1 break-words text-sm text-mocha-text">{entry.body}</p>
                      </div>
                    </div>
                  {/each}
                </div>

                {#if openEntries.length > 10}
                  <button
                    class="mt-3 text-xs font-medium text-mocha-blue hover:text-mocha-sapphire"
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
</section>
