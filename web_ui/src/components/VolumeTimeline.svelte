<script lang="ts">
  import { onDestroy } from "svelte";
  import Chart from "chart.js/auto";
  import type { ChartConfiguration, ChartDataset } from "chart.js";

  import type { EventVolumePointDTO } from "../lib/types";

  export let points: EventVolumePointDTO[] = [];
  export let bucket: "hour" | "day" = "hour";
  export let source: "all" | "detected" = "all";
  export let onBucketChange: (value: "hour" | "day") => void = () => {};
  export let onSourceChange: (value: "all" | "detected") => void = () => {};

  const palette = ["#cba6f7", "#89b4fa", "#89dceb", "#94e2d5", "#a6e3a1", "#f9e2af", "#fab387", "#eba0ac"];

  let canvas: HTMLCanvasElement | null = null;
  let chart: Chart<"bar"> | null = null;

  function formatBucketLabel(value: string): string {
    if (bucket === "day") {
      return value.slice(0, 10);
    }
    return value.replace("T", " ").slice(5, 16);
  }

  function buildChartConfig(data: EventVolumePointDTO[]): ChartConfiguration<"bar"> {
    const bucketMap = new Map<string, Map<string, number>>();
    const seriesOrder: string[] = [];

    for (const point of data) {
      if (!bucketMap.has(point.bucket)) {
        bucketMap.set(point.bucket, new Map());
      }
      const bucketEntry = bucketMap.get(point.bucket)!;
      bucketEntry.set(point.series, (bucketEntry.get(point.series) ?? 0) + point.count);
      if (!seriesOrder.includes(point.series)) {
        seriesOrder.push(point.series);
      }
    }

    const bucketKeys = Array.from(bucketMap.keys()).sort();
    const labels = bucketKeys.map((bucketKey) => formatBucketLabel(bucketKey));
    const datasets: ChartDataset<"bar">[] = seriesOrder.map((seriesName, index) => ({
      label: seriesName,
      data: bucketKeys.map((bucketKey) => bucketMap.get(bucketKey)?.get(seriesName) ?? 0),
      backgroundColor: palette[index % palette.length],
      borderColor: palette[index % palette.length],
      borderWidth: 0,
      borderRadius: 3,
      borderSkipped: false,
      stack: "volume",
      maxBarThickness: bucket === "day" ? 28 : 18
    }));

    return {
      type: "bar",
      data: {
        labels,
        datasets
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: "index",
          intersect: false
        },
        animation: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            backgroundColor: "#181825",
            titleColor: "#cdd6f4",
            bodyColor: "#cdd6f4",
            borderColor: "#45475a",
            borderWidth: 1
          }
        },
        scales: {
          x: {
            stacked: true,
            grid: {
              color: "rgba(69, 71, 90, 0.28)"
            },
            ticks: {
              color: "#a6adc8",
              autoSkip: true,
              maxRotation: 0,
              minRotation: 0
            }
          },
          y: {
            stacked: true,
            beginAtZero: true,
            grid: {
              color: "rgba(69, 71, 90, 0.24)"
            },
            ticks: {
              color: "#a6adc8"
            },
            title: {
              display: true,
              text: "count",
              color: "#6c7086"
            }
          }
        }
      }
    };
  }

  function renderChart(): void {
    if (!canvas) {
      return;
    }
    chart?.destroy();
    chart = new Chart(canvas, buildChartConfig(points));
  }

  $: if (canvas) {
    renderChart();
  }

  onDestroy(() => {
    chart?.destroy();
    chart = null;
  });
</script>

<section class="panel p-4">
  <div class="flex flex-wrap items-start justify-between gap-3">
    <div>
      <h2 class="panel-title">Event Volume</h2>
      <p class="mt-1 text-xs text-mocha-subtext0">Stacked bar chart of the number of artifacts by time</p>
    </div>
    <div class="flex flex-wrap items-center gap-2">
      <div class="flex rounded-full border border-mocha-surface1 bg-mocha-surface0 p-1">
        {#each ["hour", "day"] as option}
          <button
            class={`rounded-full px-3 py-1 text-xs ${bucket === option ? "bg-mocha-mauve text-mocha-base" : "text-mocha-subtext0"}`}
            on:click={() => onBucketChange(option as "hour" | "day")}
          >
            {option}
          </button>
        {/each}
      </div>
      <div class="flex rounded-full border border-mocha-surface1 bg-mocha-surface0 p-1">
        {#each ["all", "detected"] as option}
          <button
            class={`rounded-full px-3 py-1 text-xs ${source === option ? "bg-mocha-blue text-mocha-base" : "text-mocha-subtext0"}`}
            on:click={() => onSourceChange(option as "all" | "detected")}
          >
            {option}
          </button>
        {/each}
      </div>
    </div>
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
