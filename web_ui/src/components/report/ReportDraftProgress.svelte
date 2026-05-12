<script lang="ts">
  import type { ReportSectionDTO } from "../../lib/types";
  import ReportSectionRow from "./ReportSectionRow.svelte";

  export let sections: ReportSectionDTO[] = [];
  export let progress = {
    percent: 0,
    approved: 0,
    stable: 0,
    draft: 0,
    total: 0,
    gaps: 0,
    writing: null as string | null
  };
</script>

<section class="panel p-4">
  <div class="mb-4 flex items-center justify-between gap-3">
    <div>
      <h2 class="panel-title">Report Draft Progress</h2>
      <p class="mt-1 text-xs text-mocha-subtext0">承認 {progress.percent}% / {progress.approved} of {progress.total} sections</p>
    </div>
    <div class="text-right text-xs text-mocha-subtext0">
      <div>Draft {progress.draft} / Stable {progress.stable} / Approved {progress.approved}</div>
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
