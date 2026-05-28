<script lang="ts">
  export let items: Array<{ ruleId: string; accepted: number; suppressed: number; title: string }> = [];

  $: maxTotal = Math.max(...items.map((i) => i.accepted + i.suppressed), 1);
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">Top Rules</h3>
  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">No rules triggered.</p>
  {:else}
    <div class="space-y-1">
      {#each items as item}
        {@const total = item.accepted + item.suppressed}
        {@const pct = (total / maxTotal) * 100}
        <div class="flex items-center gap-2 text-xs">
          <span class="w-8 shrink-0 text-right font-mono text-mocha-subtext0">{total}</span>
          <div class="relative h-5 flex-1 overflow-hidden rounded bg-mocha-surface0">
            <div class="h-full rounded bg-mocha-mauve/60" style="width: {pct}%"></div>
            {#if item.suppressed > 0}
              <div class="absolute inset-y-0 rounded bg-mocha-surface1/60" style="left: {(item.accepted / maxTotal) * 100}%; width: {(item.suppressed / maxTotal) * 100}%"></div>
            {/if}
          </div>
          <span class="w-4 text-right text-mocha-subtext0" title="suppressed">{item.suppressed > 0 ? item.suppressed : ""}</span>
        </div>
        <p class="-mt-1 truncate pl-10 text-[11px] text-mocha-subtext1">{item.title}</p>
      {/each}
    </div>
  {/if}
</section>
