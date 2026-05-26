<script lang="ts">
  export let items: Array<{ sectionTitle: string; gap: string }> = [];
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">Open Gaps</h3>
  <div class="max-h-[20rem] space-y-2 overflow-auto pr-1">
    {#if items.length === 0}
      <p class="text-sm text-mocha-subtext1">No unresolved gaps.</p>
    {:else}
      {#each items as item}
        <article class="rounded-lg border border-mocha-surface1 bg-mocha-mantle/70 px-3 py-2">
          <div class="text-xs text-mocha-peach">{item.sectionTitle}</div>
          <div class="mt-1 line-clamp-3 text-sm text-mocha-subtext1">{item.gap}</div>
        </article>
      {/each}
    {/if}
  </div>
</section>
