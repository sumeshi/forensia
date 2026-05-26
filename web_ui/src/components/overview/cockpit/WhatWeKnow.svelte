<script lang="ts">
  export let items: string[] = [];
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">What We Know</h3>
  <ul class="space-y-2 text-sm text-mocha-subtext1">
    {#if items.length === 0}
      <li>No information to summarize yet.</li>
    {:else}
      {#each items as item}
        <li class="line-clamp-2 rounded-lg bg-mocha-mantle/70 px-3 py-2">{item}</li>
      {/each}
    {/if}
  </ul>
</section>
