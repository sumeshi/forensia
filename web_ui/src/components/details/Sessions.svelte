<script lang="ts">
  import type { SessionDTO } from "../../lib/types";
  export let sessions: SessionDTO[] = [];
</script>

<div class="max-h-[36vh] overflow-auto">
  <table class="min-w-full text-left text-sm">
    <thead class="sticky top-0 bg-semantic-bg-raised">
      <tr class="text-xs uppercase text-semantic-fg-muted">
        <th class="px-3 py-2">Session</th><th class="px-3 py-2">Started</th><th class="px-3 py-2">Finished</th><th class="px-3 py-2">Iter</th><th class="px-3 py-2">Status</th>
      </tr>
    </thead>
    <tbody>
      {#each sessions as session}
        <tr class="border-b border-mocha-surface1">
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{session.session_id}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{session.started_at ?? "-"}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{session.finished_at ?? "-"}</td>
          <td class="px-3 py-2 font-mono tabular-nums text-semantic-fg-muted">{session.iterations ?? 0}</td>
          <td class="px-3 py-2 text-semantic-fg-muted">{session.status ?? "-"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
