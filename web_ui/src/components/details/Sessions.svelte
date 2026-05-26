<script lang="ts">
  import type { SessionDTO } from "../../lib/types";
  export let sessions: SessionDTO[] = [];
</script>

<div class="max-h-[36vh] overflow-auto">
  <table class="min-w-full text-left text-sm">
    <thead class="sticky top-0 bg-mocha-surface0">
      <tr class="text-xs uppercase tracking-wide text-mocha-subtext0">
        <th class="px-3 py-2">Session</th><th class="px-3 py-2">Started</th><th class="px-3 py-2">Finished</th><th class="px-3 py-2">Iter</th><th class="px-3 py-2">Status</th>
      </tr>
    </thead>
    <tbody>
      {#each sessions as session}
        <tr class="border-b border-mocha-surface1">
          <td class="px-3 py-2 text-mocha-subtext1">{session.session_id}</td>
          <td class="px-3 py-2 text-mocha-subtext1">{session.started_at ?? "-"}</td>
          <td class="px-3 py-2 text-mocha-subtext1">{session.finished_at ?? "-"}</td>
          <td class="px-3 py-2 text-mocha-subtext1">{session.iterations ?? 0}</td>
          <td class="px-3 py-2 text-mocha-subtext1">{session.status ?? "-"}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
