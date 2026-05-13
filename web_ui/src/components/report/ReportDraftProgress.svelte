<script lang="ts">
  import { api } from "../../lib/api";
  import type { ReportSectionDTO } from "../../lib/types";
  import ReportSectionRow from "./ReportSectionRow.svelte";

  export let sections: ReportSectionDTO[] = [];
  export let progress = {
    percent: 0,
    humanReviewed: 0,
    aiExhausted: 0,
    stable: 0,
    draft: 0,
    total: 0,
    gaps: 0,
    writing: null as string | null
  };

  let exportBusy = false;

  function formatReportFilename(now: Date): string {
    const yy = String(now.getFullYear()).slice(-2);
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const hh = String(now.getHours()).padStart(2, "0");
    const mi = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");
    return `report_${yy}${mm}${dd}${hh}${mi}${ss}.md`;
  }

  async function downloadMarkdown(): Promise<void> {
    exportBusy = true;
    try {
      const markdown = await api.getReportMarkdown();
      const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = formatReportFilename(new Date());
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
    } finally {
      exportBusy = false;
    }
  }

  function openReport(): void {
    window.open("/api/report-html", "_blank", "noopener,noreferrer");
  }
</script>

<section class="panel p-4">
  <div class="mb-4 flex items-center justify-between gap-3">
    <div>
      <h2 class="panel-title">Report Draft Progress</h2>
      <p class="mt-1 text-xs text-mocha-subtext0">Human reviewed {progress.percent}% / {progress.humanReviewed} of {progress.total} sections</p>
    </div>
    <div class="flex flex-col items-end gap-2 text-right text-xs text-mocha-subtext0">
      <div class="flex flex-wrap justify-end gap-2">
        <button
          class="rounded-md border border-mocha-blue/40 px-3 py-1.5 text-mocha-blue disabled:opacity-50"
          on:click={openReport}
          type="button"
        >
          Open Report
        </button>
        <button
          class="rounded-md border border-mocha-green/40 px-3 py-1.5 text-mocha-green disabled:opacity-50"
          on:click={downloadMarkdown}
          disabled={exportBusy}
          type="button"
        >
          {exportBusy ? "Preparing..." : "Download report.md"}
        </button>
      </div>
      <div>Draft {progress.draft} / Stable {progress.stable} / AI Exhausted {progress.aiExhausted} / Human Reviewed {progress.humanReviewed}</div>
      <div>Open gaps {progress.gaps}</div>
      <div>{progress.writing ? `Writing ${progress.writing}` : "No section writing now"}</div>
    </div>
  </div>
  <div class="space-y-2">
    {#each sections as section}
      <ReportSectionRow {section} />
    {/each}
  </div>
</section>
