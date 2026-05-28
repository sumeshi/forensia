<script lang="ts">
  import { formatRelativeTime, formatVerdict, reasoningToneClass } from "../../lib/format";
  import type { HypothesisReasoningEntryDTO } from "../../lib/types";

  export let items: HypothesisReasoningEntryDTO[] = [];
  export let embedded = false;
</script>

<svelte:element this={embedded ? "div" : "section"} class={embedded ? "min-w-0" : "panel min-w-0 p-4"}>
  {#if !embedded}
    <h3 class="panel-title mb-3">Latest Reasoning</h3>
  {/if}
  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">No reasoning entries yet.</p>
  {:else}
    <div class="max-h-[420px] space-y-1.5 overflow-y-auto pr-1">
      {#each items as entry}
        <div class="flex gap-2 rounded-lg px-2 py-1.5 text-xs hover:bg-mocha-mantle/50">
          <span class={`mt-1 h-2 w-2 shrink-0 rounded-full ${reasoningToneClass(entry.verdict)}`}></span>
          <span class="shrink-0 font-mono text-mocha-mauve">{entry.hypothesis_id}</span>
          <span class="shrink-0 text-mocha-overlay1">[{entry.phase}]</span>
          <p class="min-w-0 flex-1 truncate text-mocha-text">{entry.body}</p>
          <span class="shrink-0 whitespace-nowrap text-mocha-subtext0">{formatRelativeTime(entry.created_at)}</span>
        </div>
      {/each}
    </div>
  {/if}
</svelte:element>
