<script lang="ts">
  import type { AttackCoverageRowDTO } from "../../lib/types";

  export let items: AttackCoverageRowDTO[] = [];

  const tacticOrder = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
  ];

  $: grouped = (() => {
    const map = new Map<string, AttackCoverageRowDTO[]>();
    for (const item of items) {
      const list = map.get(item.tactic) ?? [];
      list.push(item);
      map.set(item.tactic, list);
    }
    return map;
  })();

  $: maxCount = Math.max(...items.map((i) => i.count), 1);

  function cellOpacity(count: number): number {
    if (count === 0) return 0;
    return 0.2 + (Math.log2(count + 1) / Math.log2(maxCount + 1)) * 0.8;
  }

  function tacticLabel(tactic: string): string {
    const map: Record<string, string> = {
      "initial-access": "IA",
      execution: "EX",
      persistence: "PE",
      "privilege-escalation": "PR",
      "defense-evasion": "DE",
      "credential-access": "CR",
      discovery: "DI",
      "lateral-movement": "LM",
      collection: "CO",
      "command-and-control": "C2",
      exfiltration: "EXF",
      impact: "IM",
    };
    return map[tactic] ?? tactic.slice(0, 2);
  }
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">ATT&CK Coverage</h3>
  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">No ATT&CK mappings found.</p>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full text-[11px]">
        <thead>
          <tr>
            <th class="sticky left-0 z-10 bg-mocha-base pr-2 text-left text-mocha-subtext0">Technique</th>
            {#each tacticOrder as tactic}
              <th class="min-w-[28px] px-1 pb-1 text-center font-medium text-mocha-subtext0" title={tactic}>
                {tacticLabel(tactic)}
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each [...grouped.values()].flat().sort((a, b) => b.count - a.count) as row}
            <tr class="hover:bg-mocha-mantle/50">
              <td class="sticky left-0 z-10 max-w-[160px] truncate bg-mocha-base py-1 pr-2 text-mocha-text" title={`${row.technique_id}: ${row.technique_name ?? ""}`}>
                <span class="font-mono text-mocha-mauve">{row.technique_id}</span>
                {#if row.technique_name}
                  <span class="ml-1 text-mocha-subtext0">{row.technique_name}</span>
                {/if}
              </td>
              {#each tacticOrder as tactic}
                <td class="px-1 py-1 text-center">
                  {#if row.tactic === tactic}
                    <div
                      class="mx-auto h-5 w-5 rounded"
                      style="background-color: rgba(203, 166, 247, {cellOpacity(row.count)})"
                      title={`${row.technique_id}: ${row.count} (accepted: ${row.accepted}, suppressed: ${row.suppressed})`}
                    >
                      <span class="text-[9px] font-semibold leading-5 text-mocha-base">{row.count}</span>
                    </div>
                  {/if}
                </td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>
