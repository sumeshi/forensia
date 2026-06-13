<script lang="ts">
  export let items: Array<{ ruleId: string; accepted: number; title: string }> = [];

  $: maxAccepted = Math.max(...items.map((i) => i.accepted), 1);
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">Top Rules</h3>
  {#if items.length === 0}
    <p class="text-sm text-semantic-fg-muted">No rules triggered.</p>
  {:else}
    <div class="space-y-1">
      {#each items as item}
        {@const pct = (item.accepted / maxAccepted) * 100}
        <div class="flex items-center gap-2 text-xs">
          <span class="w-8 shrink-0 text-right font-mono tabular-nums text-semantic-fg-muted">{item.accepted}</span>
          <div class="relative h-5 flex-1 overflow-hidden rounded bg-semantic-bg-inset">
            <div class="h-full rounded bg-semantic-accent/70" style="width: {pct}%"></div>
          </div>
        </div>
        <p class="-mt-1 truncate pl-10 text-xs text-semantic-fg-muted">{item.title}</p>
      {/each}
    </div>
  {/if}
</section>
