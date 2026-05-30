<script lang="ts">
  import type { EntityCardDTO } from "../../lib/types";

  export let items: EntityCardDTO[] = [];

  $: grouped = (() => {
    const map = new Map<string, EntityCardDTO[]>();
    for (const item of items) {
      const list = map.get(item.kind) ?? [];
      list.push(item);
      map.set(item.kind, list);
    }
    return map;
  })();

  const kindOrder = ["user", "host", "ip", "process", "service", "file", "registry", "group", "machine_account", "unknown"];
  const kindLabels: Record<string, string> = {
    user: "Users",
    host: "Hosts",
    ip: "IPs",
    process: "Processes",
    service: "Services",
    file: "Files",
    registry: "Registry",
    group: "Groups",
    machine_account: "Machine Accts",
    unknown: "Other",
  };
</script>

<section class="panel min-w-0 p-4">
  <h3 class="panel-title mb-3">Top Entities</h3>
  {#if items.length === 0}
    <p class="text-sm text-mocha-subtext1">No entities registered.</p>
  {:else}
    <div class="grid grid-cols-3 gap-3">
      {#each kindOrder as kind}
        {@const entries = grouped.get(kind)}
        {#if entries && entries.length > 0}
          <div class="min-w-0">
            <h4 class="mb-1 text-[10px] font-semibold uppercase tracking-wider text-mocha-subtext0">{kindLabels[kind] ?? kind}</h4>
            <ul class="space-y-1.5">
              {#each entries as entry}
                <li class="min-w-0">
                  <div class="truncate text-xs font-medium text-mocha-text" title={entry.name}>{entry.name}</div>
                  {#if entry.summary}
                    <p class="line-clamp-2 break-words text-[11px] leading-snug text-mocha-subtext0" title={entry.summary}>{entry.summary}</p>
                  {/if}
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      {/each}
    </div>
  {/if}
</section>
