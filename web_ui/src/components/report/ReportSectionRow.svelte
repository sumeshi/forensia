<script lang="ts">
  import { api } from "../../lib/api";
  import { reportSections } from "../../lib/stores";
  import type { ReportSectionDTO } from "../../lib/types";

  export let section: ReportSectionDTO;

  let busy = false;

  function statusTone(status: string): string {
    if (status === "human_reviewed") return "bg-mocha-green/20 text-mocha-green ring-mocha-green/40";
    if (status === "ai_exhausted") return "bg-mocha-teal/20 text-mocha-teal ring-mocha-teal/40";
    if (status === "stable") return "bg-mocha-blue/20 text-mocha-blue ring-mocha-blue/40";
    return "bg-mocha-surface1 text-mocha-subtext1 ring-mocha-surface2";
  }

  async function updateStatus(status: string): Promise<void> {
    busy = true;
    try {
      const updated = await api.updateReportSectionStatus(section.section_key, status);
      reportSections.update((items) => items.map((item) => (item.section_key === updated.section_key ? { ...item, ...updated } : item)));
    } finally {
      busy = false;
    }
  }
</script>

<details class={`rounded-xl border ${section.is_highlighted ? "border-mocha-lavender" : "border-mocha-surface1"} ${section.is_writing ? "ring-1 ring-mocha-pink" : ""} bg-mocha-surface0/90`} open={section.is_writing}>
  <summary class="flex cursor-pointer items-center justify-between gap-3 px-4 py-3">
    <div class="min-w-0">
      <div class="text-xs text-mocha-subtext0">{section.section_key}</div>
      <div class="truncate text-sm font-semibold text-mocha-text">{section.title}</div>
    </div>
    <div class="flex items-center gap-2 text-xs text-mocha-subtext0">
      <span class="tabular-nums">{section.update_count} iter</span>
      <span class={`rounded-full px-2 py-1 ring-1 ${statusTone(section.status)}`}>{section.status}</span>
      <span>{section.gap_count} gaps</span>
      {#if section.is_writing}<span class="chip text-mocha-pink">writing now</span>{/if}
    </div>
  </summary>
    <div class="border-t border-mocha-surface1 px-4 py-3">
    <div class="mb-2 flex items-center justify-between gap-3 text-xs text-mocha-subtext0">
      <span>{section.last_filled_at ?? "-"}</span>
      <div class="flex items-center gap-2">
        <span>confidence {(section.confidence ?? 0).toFixed(2)}</span>
        {#if section.status !== "human_reviewed"}
          <button class="rounded-md border border-mocha-green/40 px-2 py-1 text-mocha-green disabled:opacity-50" on:click={() => updateStatus("human_reviewed")} disabled={busy}>
            Mark reviewed
          </button>
        {:else}
          <button class="rounded-md border border-mocha-surface2 px-2 py-1 disabled:opacity-50" on:click={() => updateStatus("stable")} disabled={busy}>
            Reopen
          </button>
        {/if}
      </div>
    </div>
    <pre class="whitespace-pre-wrap text-sm text-mocha-subtext1">{section.body}</pre>
  </div>
</details>
