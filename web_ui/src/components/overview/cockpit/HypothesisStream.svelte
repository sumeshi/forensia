<script lang="ts">
  import ActiveHypotheses from "./ActiveHypotheses.svelte";
  import LatestReasoning from "../LatestReasoning.svelte";
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
  };

  export let activeHypotheses: HypothesisThread[] = [];
  export let resolvedHypotheses: HypothesisThread[] = [];
  export let latestReasoningItems: HypothesisReasoningEntryDTO[] = [];

  let tab: "active" | "resolved" | "reasoning" = "active";
</script>

<section class="panel min-w-0 p-4">
  <div class="mb-3 flex items-center justify-between gap-2">
    <h3 class="panel-title">Hypotheses</h3>
    <div class="flex gap-1">
      <button
        class={`btn-ghost ${tab === "active" ? "bg-semantic-accent/10 text-semantic-accent border-semantic-accent/40" : ""}`}
        type="button"
        on:click={() => (tab = "active")}
      >
        Active ({activeHypotheses.length})
      </button>
      <button
        class={`btn-ghost ${tab === "resolved" ? "bg-semantic-accent/10 text-semantic-accent border-semantic-accent/40" : ""}`}
        type="button"
        on:click={() => (tab = "resolved")}
      >
        Resolved ({resolvedHypotheses.length})
      </button>
      <button
        class={`btn-ghost ${tab === "reasoning" ? "bg-semantic-accent/10 text-semantic-accent border-semantic-accent/40" : ""}`}
        type="button"
        on:click={() => (tab = "reasoning")}
      >
        Reasoning ({latestReasoningItems.length})
      </button>
    </div>
  </div>

  {#if tab === "active"}
    <ActiveHypotheses items={activeHypotheses} embedded />
  {:else if tab === "resolved"}
    <ActiveHypotheses items={resolvedHypotheses} embedded emptyMessage="No resolved hypotheses yet." />
  {:else}
    <LatestReasoning items={latestReasoningItems} embedded />
  {/if}
</section>
