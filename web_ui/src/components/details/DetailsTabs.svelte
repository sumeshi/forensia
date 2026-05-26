<script lang="ts">
  import { detailsTab } from "../../lib/stores";
  import type { FindingDTO, InvestigationStepDTO, MftTimelineDTO, ProgressEventDTO, SessionDTO } from "../../lib/types";
  import InvestigationSteps from "./InvestigationSteps.svelte";
  import KeyFindings from "./KeyFindings.svelte";
  import MftTimeline from "./MftTimeline.svelte";
  import RawActivity from "./RawActivity.svelte";
  import Sessions from "./Sessions.svelte";

  export let findings: FindingDTO[] = [];
  export let steps: InvestigationStepDTO[] = [];
  export let sessions: SessionDTO[] = [];
  export let progress: ProgressEventDTO | null = null;
  export let timeline: MftTimelineDTO[] = [];
  export let collapsed = true;

  const tabs = [
    { id: "findings", label: "Key Findings" },
    { id: "steps", label: "Investigation Steps" },
    { id: "sessions", label: "Sessions" },
    { id: "activity", label: "Raw Activity" },
    { id: "mft", label: "MFT Timeline" }
  ] as const;

  let open = !collapsed;
</script>

<section class="panel p-4">
  <div class="mb-3 flex items-center justify-between">
    <h2 class="panel-title">Details</h2>
    <button class="chip-muted" on:click={() => (open = !open)}>{open ? "▴ collapse" : "▾ expand"}</button>
  </div>
  {#if open}
    <div class="mb-3 flex flex-wrap gap-2">
      {#each tabs as tab}
        <button class={`rounded-lg px-3 py-1.5 text-xs ${$detailsTab === tab.id ? "bg-mocha-mauve/20 text-mocha-text border border-mocha-mauve" : "bg-mocha-mantle/70 text-mocha-subtext0 border border-mocha-surface1"}`} on:click={() => detailsTab.set(tab.id)}>
          {tab.label}
        </button>
      {/each}
    </div>

    {#if $detailsTab === "findings"}
      <KeyFindings {findings} />
    {:else if $detailsTab === "steps"}
      <InvestigationSteps {steps} />
    {:else if $detailsTab === "sessions"}
      <Sessions {sessions} />
    {:else if $detailsTab === "activity"}
      <RawActivity {progress} />
    {:else}
      <MftTimeline {timeline} />
    {/if}
  {/if}
</section>
