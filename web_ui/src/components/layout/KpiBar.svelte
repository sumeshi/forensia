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
    <article class="min-w-0 px-3 py-2">
      <div class="truncate whitespace-nowrap text-[11px] uppercase tracking-wide text-semantic-fg-muted">{item.label}</div>
      <div class="mt-1 flex items-center gap-2">
        <div class="min-w-0 truncate whitespace-nowrap text-base font-semibold md:text-lg tabular-nums font-mono {item.tone ?? 'text-semantic-fg'}">{item.value}</div>
        {#if item.breakdown && totalOf(item.breakdown) > 0}
          <div class="flex h-1.5 flex-1 overflow-hidden rounded-full bg-semantic-bg-raised" title={tooltipFor(item.breakdown)}>
            {#each item.breakdown as seg}
              {#if seg.value > 0}
                <div class={seg.color} style="width: {(seg.value / totalOf(item.breakdown)) * 100}%"></div>
              {/if}
            {/each}
          </div>
        {/if}
      </div>
      {#if item.breakdown && totalOf(item.breakdown) > 0}
        <div class="mt-1 flex flex-wrap gap-x-2 text-xs text-semantic-fg-muted">
          {#each item.breakdown as seg}
            {#if seg.value > 0}
              <span class="flex items-center gap-1">
                <span class={`inline-block h-1.5 w-1.5 rounded-sm ${seg.color}`}></span>
                <span class="tabular-nums font-mono">{seg.label} {seg.value}</span>
              </span>
            {/if}
          {/each}
        </div>
      {/if}
    </article>
  {/each}
</section>
