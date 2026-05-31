<script lang="ts">
  export let items: Array<{ ruleId: string; accepted: number; title: string }> = [];

  $: maxAccepted = Math.max(...items.map((i) => i.accepted), 1);
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">Top Rules</h3>
  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">No rules triggered.</p>
  {:else}
    <div class="space-y-1">
      {#each items as item}
        {@const pct = (item.accepted / maxAccepted) * 100}
        <div class="flex items-center gap-2 text-xs">
          <span class="w-8 shrink-0 text-right font-mono text-mocha-subtext0">{item.accepted}</span>
          <div class="relative h-5 flex-1 overflow-hidden rounded bg-mocha-surface0">
            <div class="h-full rounded bg-mocha-mauve/60" style="width: {pct}%"></div>
          </div>
        </div>
        <p class="-mt-1 truncate pl-10 text-[11px] text-mocha-subtext1">{item.title}</p>
      {/each}
    </div>
  {/if}
</section>
