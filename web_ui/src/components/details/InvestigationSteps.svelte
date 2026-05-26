<script lang="ts">
  import type { InvestigationStepDTO } from "../../lib/types";

  export let steps: InvestigationStepDTO[] = [];
</script>

<div class="space-y-2 text-sm">
  {#each steps as step}
    <article class="rounded-xl border border-mocha-surface1 bg-mocha-mantle/70 px-3 py-2">
      <div class="flex items-center justify-between gap-2">
        <span class="chip chip-muted">{step.phase}</span>
        <span class="text-xs text-mocha-subtext0">iter {step.iteration}</span>
      </div>
      <div class="mt-2 text-xs text-mocha-subtext0">{step.created_at ?? "-"}</div>
    </article>
  {/each}
</div>
