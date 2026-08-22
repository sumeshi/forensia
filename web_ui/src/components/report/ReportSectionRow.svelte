<script lang="ts">
  import { api } from "../../lib/api";
  import { reportSections } from "../../lib/stores";
  import type { ClaimDTO, ReportSectionDTO } from "../../lib/types";

  export let section: ReportSectionDTO;

  let busy = false;
  let isOpen = section.is_writing;
  let claims: ClaimDTO[] | null = null;

  $: if (isOpen && claims === null) {
    loadClaims();
  }

  async function loadClaims(): Promise<void> {
    claims = [];
    try {
      claims = await api.getClaims(section.section_key);
    } catch {
      claims = [];
    }
  }

  function claimStatusClass(status: string): string {
    if (status === "supported") return "text-semantic-ok border-semantic-ok/30 bg-semantic-ok/10";
    if (status === "needs_review") return "text-semantic-warn border-semantic-warn/30 bg-semantic-warn/10";
    if (status === "orphaned") return "text-semantic-danger border-semantic-danger/30 bg-semantic-danger/10";
    return "text-semantic-fg-muted border-semantic-bg-raised bg-semantic-bg-inset";
  }

  function statusTone(status: string): string {
    if (status === "human_reviewed") return "bg-semantic-ok/20 text-semantic-ok ring-semantic-ok/40";
    if (status === "ai_exhausted") return "bg-semantic-info/20 text-semantic-info ring-semantic-info/40";
    return "bg-semantic-bg-raised text-semantic-fg-muted ring-semantic-bg-raised";
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

<details bind:open={isOpen} class={`rounded-xl border ${section.is_highlighted ? "border-semantic-accent" : section.is_writing ? "border-semantic-accent" : "border-semantic-bg-raised"} ${section.is_writing ? "ring-1 ring-semantic-accent" : ""} bg-semantic-bg-raised/90`}>
  <summary class="flex cursor-pointer items-center justify-between gap-3 px-4 py-3">
    <div class="min-w-0">
      <div class="text-xs text-semantic-fg-muted">{section.section_key}</div>
      <div class="truncate text-sm font-semibold text-semantic-fg">{section.title}</div>
    </div>
    <div class="flex items-center gap-2 text-xs text-semantic-fg-muted">
      <span class="font-mono tabular-nums">{section.update_count} iter</span>
      <span class={`rounded-full px-2 py-1 ring-1 ${statusTone(section.status)}`}>{section.status}</span>
      <span class="font-mono tabular-nums text-semantic-fg-faint">{section.gap_count} gaps</span>
      {#if section.is_writing}<span class="chip text-semantic-accent">writing now</span>{/if}
    </div>
  </summary>
    <div class="border-t border-semantic-bg-raised px-4 py-3">
    <div class="mb-2 flex items-center justify-between gap-3 text-xs text-semantic-fg-muted">
      <span class="font-mono tabular-nums">{section.last_filled_at ?? "-"}</span>
      <div class="flex items-center gap-2">
        <span class="font-mono tabular-nums">confidence {(section.confidence ?? 0).toFixed(2)}</span>
        {#if section.status !== "human_reviewed"}
          <button class="rounded-md border border-semantic-ok/40 px-2 py-1 text-semantic-ok disabled:opacity-55" on:click={() => updateStatus("human_reviewed")} disabled={busy}>
            Mark reviewed
          </button>
        {:else}
          <button class="rounded-md border border-semantic-bg-raised px-2 py-1 disabled:opacity-55" on:click={() => updateStatus("ai_exhausted")} disabled={busy}>
            Reopen
          </button>
        {/if}
      </div>
    </div>
    <div class="prose prose-sm prose-invert max-w-none text-sm">
      {@html section.body_html}
    </div>

    {#if section.gaps && section.gaps.length > 0}
      <div class="mt-3 space-y-1 border-t border-semantic-bg-raised pt-3">
        <div class="text-xs font-semibold text-semantic-fg-muted">Gaps</div>
        {#each section.gaps as gap}
          <div class="flex items-start gap-2 text-xs text-semantic-fg-muted">
            <span class="mt-1 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-semantic-warn"></span>
            <span>{gap}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if claims !== null && claims.length > 0}
      <div class="mt-3 border-t border-semantic-bg-raised pt-3">
        <div class="mb-2 text-xs font-semibold text-semantic-fg-muted">Claims ({claims.length})</div>
        <div class="space-y-2">
          {#each claims as claim}
            <div class="flex items-start gap-2 rounded-md border border-semantic-bg-raised px-3 py-2 text-xs">
              <span class="flex-1 text-semantic-fg">{claim.claim_text}</span>
              <span class="chip shrink-0 {claimStatusClass(claim.support_status)}">{claim.support_status}</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</details>
