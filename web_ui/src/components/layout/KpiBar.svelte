<script lang="ts">
  import type { KpiBreakdownSegment, KpiItem } from "./kpi_types";

  export let items: KpiItem[] = [];

  function totalOf(segments: KpiBreakdownSegment[]): number {
    return segments.reduce((sum, s) => sum + s.value, 0);
  }

  function tooltipFor(segments: KpiBreakdownSegment[]): string {
    const total = totalOf(segments);
    if (total === 0) return "";
    return segments
      .filter((s) => s.value > 0)
      .map((s) => {
        const pct = ((s.value / total) * 100).toFixed(0);
        return `${s.label}: ${s.value} (${pct}%)`;
      })
      .join(" / ");
  }
</script>

<section class="grid grid-cols-2 gap-2 md:grid-cols-4">
  {#each items as item}
    <article class="panel min-w-0 px-3 py-2">
      <div class="truncate whitespace-nowrap text-[11px] uppercase tracking-wide text-mocha-subtext0">{item.label}</div>
      <div class="mt-1 flex items-center gap-2">
        <div class={`min-w-0 truncate whitespace-nowrap text-base font-semibold md:text-lg ${item.tone ?? "text-mocha-text"}`}>{item.value}</div>
        {#if item.breakdown && totalOf(item.breakdown) > 0}
          <div class="flex h-1.5 flex-1 overflow-hidden rounded-full bg-mocha-surface0" title={tooltipFor(item.breakdown)}>
            {#each item.breakdown as seg}
              {#if seg.value > 0}
                <div class={seg.color} style="width: {(seg.value / totalOf(item.breakdown)) * 100}%"></div>
              {/if}
            {/each}
          </div>
        {/if}
      </div>
      {#if item.breakdown && totalOf(item.breakdown) > 0}
        <div class="mt-1 flex flex-wrap gap-x-2 text-[10px] text-mocha-subtext0">
          {#each item.breakdown as seg}
            {#if seg.value > 0}
              <span class="flex items-center gap-1">
                <span class={`inline-block h-1.5 w-1.5 rounded-sm ${seg.color}`}></span>
                <span>{seg.label} {seg.value}</span>
              </span>
            {/if}
          {/each}
        </div>
      {/if}
    </article>
  {/each}
</section>
