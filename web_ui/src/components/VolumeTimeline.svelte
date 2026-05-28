<script lang="ts">
  import { onDestroy } from "svelte";
  import Chart from "chart.js/auto";
  import type { ChartConfiguration, ChartDataset } from "chart.js";

  import type { EventVolumePointDTO } from "../lib/types";

  export let points: EventVolumePointDTO[] = [];
  export let detectedPoints: EventVolumePointDTO[] = [];
  export let yearsSummary: EventVolumePointDTO[] = [];
  export let drill: number[] = [];
  export let onDrillChange: (next: number[]) => void = () => {};

  const palette = ["#cba6f7", "#89b4fa", "#89dceb", "#94e2d5", "#a6e3a1", "#f9e2af", "#fab387", "#eba0ac"];
  const monthLabels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  let canvas: HTMLCanvasElement | null = null;
  let chart: Chart | null = null;

  // Chart bucket unit is always one step finer than picker depth.
  $: chartUnit = (drill.length === 3 ? "hour" : "day") as "day" | "hour";

  // Available years come from the dedicated year summary (independent of drill).
  $: availableYears = (() => {
    const set = new Set<number>();
    for (const p of yearsSummary) {
      const y = Number.parseInt(p.bucket.slice(0, 4), 10);
      if (Number.isFinite(y)) set.add(y);
    }
    return [...set].sort((a, b) => a - b);
  })();

  // Available months when a year is selected — derive from the chart's day data.
  $: availableMonths = (() => {
    if (drill.length < 1) return [] as number[];
    const set = new Set<number>();
    for (const p of points) {
      const m = Number.parseInt(p.bucket.slice(5, 7), 10);
      if (Number.isFinite(m)) set.add(m);
    }
    return [...set].sort((a, b) => a - b);
  })();

  // Available days when a month is selected — derive from the chart's day data.
  $: availableDays = (() => {
    if (drill.length < 2) return [] as number[];
    const set = new Set<number>();
    for (const p of points) {
      const d = Number.parseInt(p.bucket.slice(8, 10), 10);
      if (Number.isFinite(d)) set.add(d);
    }
    return [...set].sort((a, b) => a - b);
  })();

  function parseBucket(key: string): Date {
    const normalized = key.includes("T") ? key : key.replace(" ", "T");
    return new Date(normalized.endsWith("Z") ? normalized : normalized + "Z");
  }

  function bucketKeyFor(date: Date, unit: "day" | "hour"): string {
    const iso = date.toISOString();
    if (unit === "day") return iso.slice(0, 10) + "T00:00:00";
    return iso.slice(0, 13) + ":00:00";
  }

  function normalizeKey(raw: string, unit: "day" | "hour"): string {
    return bucketKeyFor(parseBucket(raw), unit);
  }

  function formatLabel(key: string, unit: "day" | "hour", depth: number): string {
    const d = parseBucket(key);
    if (unit === "hour") return String(d.getUTCHours()).padStart(2, "0") + ":00";
    const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(d.getUTCDate()).padStart(2, "0");
    // depth 0 = whole range (could span years) → include year
    // depth 1 = single year (day chart across months) → "MM-DD"
    // depth 2 = single month (day chart within a month) → "DD"
    if (depth === 0) return `${d.getUTCFullYear()}-${mm}-${dd}`;
    if (depth === 1) return `${mm}-${dd}`;
    return dd;
  }

  function rangeKeys(unit: "day" | "hour", path: number[], observedKeys: string[]): string[] {
    if (unit === "hour") {
      const [y, m, d] = path;
      return Array.from({ length: 24 }, (_, i) =>
        bucketKeyFor(new Date(Date.UTC(y, m - 1, d, i)), "hour"),
      );
    }
    if (path.length === 2) {
      const [y, m] = path;
      const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
      return Array.from({ length: days }, (_, i) =>
        bucketKeyFor(new Date(Date.UTC(y, m - 1, i + 1)), "day"),
      );
    }
    if (path.length === 1) {
      const [y] = path;
      const out: string[] = [];
      for (let m = 0; m < 12; m++) {
        const days = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
        for (let d = 1; d <= days; d++) {
          out.push(bucketKeyFor(new Date(Date.UTC(y, m, d)), "day"));
        }
      }
      return out;
    }
    // Whole range — observed days only, sorted.
    return [...new Set(observedKeys)].sort();
  }

  function buildChartConfig(
    data: EventVolumePointDTO[],
    detData: EventVolumePointDTO[],
    unit: "day" | "hour",
    path: number[],
  ): ChartConfiguration {
    const bucketMap = new Map<string, Map<string, number>>();
    const seriesOrder: string[] = [];

    for (const point of data) {
      const key = normalizeKey(point.bucket, unit);
      if (!bucketMap.has(key)) bucketMap.set(key, new Map());
      const entry = bucketMap.get(key)!;
      entry.set(point.series, (entry.get(point.series) ?? 0) + point.count);
      if (!seriesOrder.includes(point.series)) seriesOrder.push(point.series);
    }

    const detMap = new Map<string, number>();
    for (const point of detData) {
      const key = normalizeKey(point.bucket, unit);
      detMap.set(key, (detMap.get(key) ?? 0) + point.count);
    }

    const axisKeys = rangeKeys(unit, path, Array.from(bucketMap.keys()));
    const labels = axisKeys.map((k) => formatLabel(k, unit, path.length));

    const barDatasets: ChartDataset<"bar">[] = seriesOrder.map((seriesName, index) => ({
      type: "bar",
      label: seriesName,
      data: axisKeys.map((k) => bucketMap.get(k)?.get(seriesName) ?? 0),
      backgroundColor: palette[index % palette.length],
      borderColor: palette[index % palette.length],
      borderWidth: 0,
      borderRadius: 3,
      borderSkipped: false,
      stack: "volume",
      maxBarThickness: 32,
      yAxisID: "volume",
    }));

    const lineDataset: ChartDataset<"line"> = {
      type: "line",
      label: "Detected",
      data: axisKeys.map((k) => detMap.get(k) ?? 0),
      borderColor: "#f38ba8",
      backgroundColor: "rgba(243, 139, 168, 0.15)",
      pointBackgroundColor: "#f38ba8",
      pointRadius: 2,
      pointHoverRadius: 4,
      borderWidth: 2,
      tension: 0.2,
      fill: false,
      yAxisID: "detected",
    };

    return {
      type: "bar",
      data: { labels, datasets: [...barDatasets, lineDataset] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#181825",
            titleColor: "#cdd6f4",
            bodyColor: "#cdd6f4",
            borderColor: "#45475a",
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            stacked: true,
            grid: { color: "rgba(255, 255, 255, 0.08)" },
            ticks: {
              color: "#a6adc8",
              autoSkip: true,
              maxRotation: 0,
              minRotation: 0,
              maxTicksLimit: 24,
            },
          },
          volume: {
            type: "linear",
            position: "left",
            stacked: true,
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.06)" },
            ticks: { color: "#a6adc8" },
            title: { display: true, text: "events", color: "#6c7086" },
          },
          detected: {
            type: "linear",
            position: "right",
            beginAtZero: true,
            grid: { display: false },
            ticks: { color: "#f38ba8", precision: 0 },
            title: { display: true, text: "detected", color: "#f38ba8" },
          },
        },
      },
    };
  }

  function renderChart(): void {
    if (!canvas) return;
    chart?.destroy();
    chart = new Chart(canvas, buildChartConfig(points, detectedPoints, chartUnit, drill));
  }

  $: if (canvas) {
    void points;
    void detectedPoints;
    void drill;
    renderChart();
  }

  onDestroy(() => {
    chart?.destroy();
    chart = null;
  });

  function pickYear(y: number) {
    if (drill[0] === y) onDrillChange([]);
    else onDrillChange([y]);
  }
  function pickMonth(m: number) {
    if (drill[1] === m) onDrillChange([drill[0]]);
    else onDrillChange([drill[0], m]);
  }
  function pickDay(d: number) {
    if (drill[2] === d) onDrillChange([drill[0], drill[1]]);
    else onDrillChange([drill[0], drill[1], d]);
  }

  function rangeLabel(): string {
    if (drill.length === 0) return "All";
    if (drill.length === 1) return `${drill[0]}`;
    if (drill.length === 2) return `${drill[0]}-${String(drill[1]).padStart(2, "0")}`;
    return `${drill[0]}-${String(drill[1]).padStart(2, "0")}-${String(drill[2]).padStart(2, "0")}`;
  }

  function btnClass(active: boolean): string {
    return `rounded px-2 py-0.5 text-xs ${
      active
        ? "bg-mocha-mauve text-mocha-base"
        : "bg-mocha-surface0 text-mocha-subtext0 hover:text-mocha-text"
    }`;
  }
</script>

<section class="panel p-4">
  <div class="flex items-center justify-between gap-3">
    <h2 class="panel-title">Event Volume <span class="ml-2 text-xs text-mocha-subtext0">{rangeLabel()}</span></h2>
    {#if drill.length > 0}
      <button
        class="rounded-full border border-mocha-surface1 px-3 py-0.5 text-xs text-mocha-subtext0 hover:text-mocha-text"
        type="button"
        on:click={() => onDrillChange([])}
      >
        Reset
      </button>
    {/if}
  </div>

  <div class="mt-3 space-y-1.5">
    {#if availableYears.length > 0}
      <div class="flex flex-wrap items-center gap-1">
        <span class="mr-2 w-12 shrink-0 text-[10px] uppercase tracking-wider text-mocha-overlay1">Year</span>
        {#each availableYears as y}
          <button class={btnClass(drill[0] === y)} type="button" on:click={() => pickYear(y)}>{y}</button>
        {/each}
      </div>
    {/if}

    {#if drill.length >= 1}
      <div class="flex flex-wrap items-center gap-1">
        <span class="mr-2 w-12 shrink-0 text-[10px] uppercase tracking-wider text-mocha-overlay1">Month</span>
        {#each Array.from({ length: 12 }, (_, i) => i + 1) as m}
          {@const hasData = availableMonths.includes(m)}
          <button
            class={`${btnClass(drill[1] === m)} ${!hasData ? "opacity-30" : ""}`}
            type="button"
            disabled={!hasData}
            on:click={() => pickMonth(m)}
          >
            {monthLabels[m - 1]}
          </button>
        {/each}
      </div>
    {/if}

    {#if drill.length >= 2}
      <div class="flex flex-wrap items-center gap-1">
        <span class="mr-2 w-12 shrink-0 text-[10px] uppercase tracking-wider text-mocha-overlay1">Day</span>
        {#each availableDays as d}
          <button class={btnClass(drill[2] === d)} type="button" on:click={() => pickDay(d)}>{String(d).padStart(2, "0")}</button>
        {/each}
      </div>
    {/if}
  </div>

  {#if points.length === 0}
    <div class="mt-4 rounded-xl border border-dashed border-mocha-surface1 px-4 py-8 text-center text-sm text-mocha-subtext0">
      No timeline points
    </div>
  {:else}
    <div class="mt-4 h-[360px] rounded-xl border border-mocha-surface1 bg-mocha-base/30 p-3">
      <canvas bind:this={canvas}></canvas>
    </div>
  {/if}
</section>
