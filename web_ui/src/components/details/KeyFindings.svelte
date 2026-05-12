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
    <thead class="sticky top-0 bg-mocha-surface0">
      <tr class="text-xs uppercase tracking-wide text-mocha-subtext0">
        <th class="px-3 py-2">Sev</th><th class="px-3 py-2">Title</th><th class="px-3 py-2">Target</th><th class="px-3 py-2">Time</th><th class="px-3 py-2">Conf</th><th class="px-3 py-2">ATT&CK</th><th class="px-3 py-2">Status</th>
      </tr>
    </thead>
    <tbody>
      {#each findings.filter(visible) as finding}
        {@const evidence = firstEvidence(finding)}
        <tr id={`finding-${finding.finding_id}`} class={`${selected === finding.finding_id ? "bg-mocha-mauve/15" : "border-b border-mocha-surface1"}`}>
          <td class="px-3 py-2 text-xs text-mocha-peach">{finding.severity}</td>
          <td class="px-3 py-2">{finding.title}</td>
          <td class="px-3 py-2">{String(evidence.target_user ?? evidence.subject_user ?? evidence.user_name ?? "-")}</td>
          <td class="px-3 py-2">{String(evidence.timestamp ?? finding.finding_id)}</td>
          <td class="px-3 py-2">{finding.confidence ? finding.confidence.toFixed(2) : "-"}</td>
          <td class="px-3 py-2">{finding.attack?.join(", ") ?? "-"}</td>
          <td class="px-3 py-2">{finding.status ?? "accepted"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
