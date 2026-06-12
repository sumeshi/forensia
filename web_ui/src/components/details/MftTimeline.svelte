<script lang="ts">
  import type { MftTimelineDTO } from "../../lib/types";
  export let timeline: MftTimelineDTO[] = [];
</script>

<div class="max-h-[40vh] overflow-auto">
  <table class="min-w-full text-left text-sm">
    <thead class="sticky top-0 bg-semantic-bg-raised">
      <tr class="text-xs uppercase text-semantic-fg-muted">
        <th class="px-3 py-2">Timestamp</th><th class="px-3 py-2">Type</th><th class="px-3 py-2">Record</th><th class="px-3 py-2">Deleted</th><th class="px-3 py-2">Path</th>
      </tr>
    </thead>
    <tbody>
      {#each timeline as row}
        <tr class={`border-b border-mocha-surface1 ${row.is_deleted ? "text-semantic-danger" : ""}`}>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{row.timestamp ?? "-"}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{row.timestamp_type ?? "-"}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{row.record_number ?? "-"}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{row.is_deleted ? "yes" : "no"}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{row.file_path ?? row.description ?? "-"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
