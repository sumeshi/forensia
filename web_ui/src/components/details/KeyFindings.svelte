<script lang="ts">
  import { onMount } from "svelte";
  import { selectedFindingId } from "../../lib/stores";
  import type { FindingDTO } from "../../lib/types";

  export let findings: FindingDTO[] = [];

  const visible = (finding: FindingDTO) => finding.status !== "suppressed";

  let selected = "";
  selectedFindingId.subscribe((value) => {
    selected = value ?? "";
    if (selected) {
      setTimeout(() => document.getElementById(`finding-${selected}`)?.scrollIntoView({ block: "center" }), 0);
    }
  });

  function firstEvidence(finding: FindingDTO): Record<string, unknown> {
    return finding.evidence?.[0] ?? {};
  }
</script>

<div class="max-h-[40vh] overflow-auto">
  <table class="min-w-full text-left text-sm">
    <thead class="sticky top-0 bg-semantic-bg-raised">
      <tr class="text-xs uppercase text-semantic-fg-muted">
        <th class="px-3 py-2">Sev</th><th class="px-3 py-2">Title</th><th class="px-3 py-2">Target</th><th class="px-3 py-2">Time</th><th class="px-3 py-2">Conf</th><th class="px-3 py-2">ATT&CK</th><th class="px-3 py-2">Status</th>
      </tr>
    </thead>
    <tbody>
      {#each findings.filter(visible) as finding}
        {@const evidence = firstEvidence(finding)}
        <tr id={`finding-${finding.finding_id}`} class={`${selected === finding.finding_id ? "bg-semantic-accent/15" : "border-b border-mocha-surface1"}`}>
          <td class="px-3 py-2 text-xs text-semantic-warn">{finding.severity}</td>
          <td class="px-3 py-2 text-semantic-fg">{finding.title}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{String(evidence.target_user ?? evidence.subject_user ?? evidence.user_name ?? "-")}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{String(evidence.timestamp ?? finding.finding_id)}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{finding.confidence ? finding.confidence.toFixed(2) : "-"}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{finding.attack?.join(", ") ?? "-"}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{finding.status ?? "accepted"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
