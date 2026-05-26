<script lang="ts">
  import { detailsTab, selectedFindingId } from "../../lib/stores";
  import type { FindingDTO } from "../../lib/types";

  export let findings: FindingDTO[] = [];

  const important = (rows: FindingDTO[]) =>
    rows.filter((row) => row.status !== "suppressed" && ["critical", "high"].includes(row.severity)).slice(0, 5);

  function openFinding(findingId: string): void {
    detailsTab.set("findings");
    selectedFindingId.set(findingId);
  }
</script>

<section class="panel p-4">
  <div class="mb-4 flex items-center justify-between gap-3">
    <h2 class="panel-title">Important Findings</h2>
    <span class="text-xs text-mocha-subtext0">{important(findings).length}</span>
  </div>
  <div class="space-y-2">
    {#if important(findings).length === 0}
      <p class="text-sm text-mocha-subtext1">No important findings.</p>
    {:else}
      {#each important(findings) as finding}
        <button class="flex w-full items-center justify-between rounded-xl border border-mocha-surface1 bg-mocha-mantle/70 px-4 py-3 text-left hover:border-mocha-peach" on:click={() => openFinding(finding.finding_id)}>
          <div class="min-w-0">
            <div class="text-xs uppercase tracking-wide text-mocha-peach">{finding.severity}</div>
            <div class="truncate text-sm font-semibold text-mocha-text">{finding.title}</div>
          </div>
          <span class="text-xs text-mocha-subtext0">{finding.finding_id}</span>
        </button>
      {/each}
    {/if}
  </div>
</section>
