<script lang="ts">
  export let items: Array<{ id: string; description: string; summary: string }> = [];
</script>

<section class="panel p-4">
  <h3 class="panel-title mb-3">Active Hypotheses</h3>
  <div class="space-y-2">
    {#if items.length === 0}
      <p class="text-sm text-mocha-subtext1">アクティブな仮説はありません。</p>
    {:else}
      {#each items as item}
        <article class="rounded-lg bg-mocha-mantle/70 px-3 py-2">
          <div class="text-xs text-mocha-mauve">{item.id}</div>
          <div class="mt-1 text-sm text-mocha-text">{item.description}</div>
          <div class="mt-1 text-xs text-mocha-subtext0">{item.summary}</div>
        </article>
      {/each}
    {/if}
  </div>
</section>
