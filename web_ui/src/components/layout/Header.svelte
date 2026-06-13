<script lang="ts">
  import Icon from "../Icon.svelte";

  export let caseName = "loading";
  export let connection: "idle" | "connected" | "error" = "idle";
  export let currentStage = "Idle";
  export let model = "-";
  export let updatedAt = "-";
  // 1-based index of the active pipeline phase (0 = idle / not started).
  export let phaseIndex = 0;
  // Host(s) the evidence came from, ordered by first-seen so a machine rename
  // reads as a timeline under the case name.
  type HostInfo = { name: string; first_seen?: string | null; last_seen?: string | null };
  export let hosts: HostInfo[] = [];

  const ym = (s: string | null | undefined): string => (s ?? "").slice(0, 7);

  const steps = ["Ingest", "Normalize", "Analyze", "Investigate"];
  const address = typeof window !== "undefined" ? window.location.host : "";

  $: connClass =
    connection === "connected"
      ? "text-semantic-ok"
      : connection === "error"
        ? "text-semantic-danger"
        : "text-semantic-fg-faint";

  $: statusDot =
    currentStage === "Investigation Complete"
      ? "bg-semantic-ok"
      : currentStage === "Idle"
        ? "bg-semantic-fg-faint"
        : "bg-semantic-accent";
</script>

<header class="panel px-5 py-4">
  <div class="flex flex-wrap items-start justify-between gap-x-6 gap-y-4">
    <!-- Case identity + pipeline position -->
    <div class="min-w-0">
      <h1 class="truncate text-2xl font-bold tracking-tight text-semantic-fg">{caseName}</h1>

      {#if hosts.length}
        <div class="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs text-semantic-fg-muted">
          <span class="text-semantic-fg-faint">Host</span>
          {#each hosts as h, i}
            {#if i > 0}<span class="text-semantic-fg-faint">→</span>{/if}
            <span class="font-medium text-semantic-fg">{h.name}</span>
            {#if ym(h.first_seen)}
              <span class="text-semantic-fg-faint">({ym(h.first_seen)}{ym(h.last_seen) && ym(h.last_seen) !== ym(h.first_seen) ? `–${ym(h.last_seen)}` : ""})</span>
            {/if}
          {/each}
        </div>
      {/if}

      <div class="mt-3 flex items-center gap-1.5 text-xs">
        <span class={`h-1.5 w-1.5 rounded-full ${statusDot}`}></span>
        <span class="font-medium text-semantic-fg">{currentStage}</span>
      </div>

      <!-- Pipeline stepper: compact inline dots; current = solid accent.
           Kept subtle on purpose — the early phases finish in a flash. -->
      <ol class="mt-3 flex items-center">
        {#each steps as step, i}
          {@const done = i + 1 < phaseIndex}
          {@const current = i + 1 === phaseIndex}
          <li class="flex items-center gap-1.5">
            <span
              class={`grid h-4 w-4 place-items-center rounded-full text-[8px] font-semibold ${
                current
                  ? "bg-semantic-accent text-semantic-bg"
                  : done
                    ? "bg-semantic-accent/25 text-semantic-accent"
                    : "bg-mocha-surface1 text-semantic-fg-faint"
              }`}
            >
              {#if done}✓{:else}{i + 1}{/if}
            </span>
            <span
              class={`whitespace-nowrap text-[10px] ${current ? "font-medium text-semantic-accent" : "text-semantic-fg-faint"}`}
              >{step}</span
            >
          </li>
          {#if i < steps.length - 1}
            <span class={`mx-1.5 h-px w-4 ${i + 1 < phaseIndex ? "bg-semantic-accent/40" : "bg-mocha-surface1"}`}></span>
          {/if}
        {/each}
      </ol>

    </div>

    <!-- Actions + connection. The card stretches to the buttons' width and is
         left-aligned, so the right cluster reads as one tidy column. -->
    <div class="flex shrink-0 flex-col items-stretch gap-2.5">
      <div class="rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/50 px-3 py-2 text-left leading-tight">
        <div class={`flex items-center gap-1.5 text-xs font-medium ${connClass}`}>
          <span class="h-1.5 w-1.5 shrink-0 rounded-full bg-current"></span>
          <span class="capitalize">{connection}</span>
        </div>
        <div class="mt-1 break-words font-mono text-xs leading-snug text-semantic-fg-muted">
          {address}{#if model && model !== "-"}&nbsp;<span class="text-semantic-fg-faint">({model})</span>{/if}
        </div>
        <div class="mt-1.5 font-mono text-[10px] tabular-nums text-semantic-fg-faint">Updated {updatedAt}</div>
      </div>

      <div class="flex gap-2">
        <a href="/api/report-html" target="_blank" rel="noopener" class="btn-ghost flex-1 justify-center gap-1.5">
          <Icon name="open" size={15} />Open Report
        </a>
        <a href="/api/report-markdown" download="report.md" class="btn-ghost flex-1 justify-center gap-1.5">
          <Icon name="export" size={15} />Export Report
        </a>
      </div>
    </div>
  </div>
</header>
