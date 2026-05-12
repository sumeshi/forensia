<script lang="ts">
  export let title: string;
  export let body: string[] = [];
  export let empty = "情報はまだありません。";
</script>

<section class="panel p-4">
  <h3 class="panel-title mb-3">{title}</h3>
  <div class="space-y-2 text-sm text-mocha-subtext1">
    {#if body.length === 0}
      <p>{empty}</p>
    {:else}
      {#each body as line}
        <p>{line}</p>
      {/each}
    {/if}
  </div>
</section>
