<script lang="ts">
  export let items: string[] = [];
</script>

<section class="panel p-4">
  <h3 class="panel-title mb-3">What We Know</h3>
  <ul class="space-y-2 text-sm text-mocha-subtext1">
    {#if items.length === 0}
      <li>まだ要約できる情報はありません。</li>
    {:else}
      {#each items as item}
        <li class="rounded-lg bg-mocha-mantle/70 px-3 py-2">{item}</li>
      {/each}
    {/if}
  </ul>
</section>
