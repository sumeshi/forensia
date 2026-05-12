<script lang="ts">
  export let items: Array<{ label: string; value: string; tone?: string }> = [];
</script>

<section class="grid grid-cols-2 gap-2 xl:grid-cols-7">
  {#each items as item}
    <article class="panel px-3 py-2">
      <div class="text-[11px] uppercase tracking-wide text-mocha-subtext0">{item.label}</div>
      <div class={`mt-1 text-lg font-semibold ${item.tone ?? "text-mocha-text"}`}>{item.value}</div>
    </article>
  {/each}
</section>
