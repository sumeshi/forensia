<script lang="ts">
  import Icon from "../Icon.svelte";
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

<section class="grid grid-cols-2 gap-3 md:grid-cols-4">
  {#each items as item}
    <article class="panel min-w-0 px-4 py-3.5">
      <div class="flex items-center justify-between gap-2">
        <div class="truncate whitespace-nowrap text-[11px] font-medium uppercase tracking-wider text-semantic-fg-muted">{item.label}</div>
        {#if item.icon}
          <span class="shrink-0 text-semantic-fg-faint {item.tone ?? ''}"><Icon name={item.icon} size={16} /></span>
        {/if}
      </div>
      <div class="mt-1.5 min-w-0 truncate whitespace-nowrap text-2xl font-semibold tabular-nums font-mono {item.tone ?? 'text-semantic-fg'}">{item.value}</div>
      {#if item.breakdown && totalOf(item.breakdown) > 0}
        <div class="mt-3 flex h-1.5 w-full overflow-hidden rounded-full bg-semantic-bg-inset" title={tooltipFor(item.breakdown)}>
          {#each item.breakdown as seg}
            {#if seg.value > 0}
              <div class={seg.color} style="width: {(seg.value / totalOf(item.breakdown)) * 100}%"></div>
            {/if}
          {/each}
        </div>
        <div class="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-semantic-fg-muted">
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
      {#if item.note}
        <div class="mt-2.5 text-[11px] text-semantic-fg-muted">{item.note}</div>
      {/if}
    </article>
  {/each}
</section>
