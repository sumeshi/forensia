<script lang="ts">
  export let items: Array<{ label: string; value: string; tone?: string }> = [];
</script>

<section class="grid grid-cols-2 gap-2 md:grid-cols-4 2xl:grid-cols-8">
  {#each items as item}
    <article class="panel min-w-0 px-3 py-2">
      <div class="truncate whitespace-nowrap text-[11px] uppercase tracking-wide text-mocha-subtext0">{item.label}</div>
      <div class={`mt-1 truncate whitespace-nowrap text-base font-semibold md:text-lg ${item.tone ?? "text-mocha-text"}`}>{item.value}</div>
    </article>
  {/each}
</section>
