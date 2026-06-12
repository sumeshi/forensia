<script lang="ts">
  import type { ProgressEventDTO } from "../../lib/types";
  export let progress: ProgressEventDTO | null = null;

  function tag(line: string): { label: string; tone: string } {
    const found = line.match(/^\[([a-z-]+)\]/i)?.[1]?.toLowerCase() ?? "other";
    const tones: Record<string, string> = {
      plan: "text-semantic-accent",
      do: "text-semantic-info",
      check: "text-semantic-warn",
      act: "text-semantic-ok",
      hypothesis: "text-semantic-accent",
      report: "text-semantic-accent"
    };
    return { label: found, tone: tones[found] ?? "text-semantic-fg-faint" };
  }
</script>

<div class="space-y-2 text-sm">
  {#if progress}
    {#each ((progress.payload.recent_logs as string[] | undefined) ?? []) as line}
      {@const info = tag(line)}
      <article class="flex gap-3 rounded-xl border border-mocha-surface1 bg-semantic-bg/70 px-3 py-2">
        <span class={`chip ${info.tone}`}>[{info.label}]</span>
        <span class="text-semantic-fg-muted">{line.replace(/^\[[^\]]+\]\s*/, "")}</span>
      </article>
    {/each}
  {:else}
    <p class="text-sm text-semantic-fg-muted">Waiting for progress events.</p>
  {/if}
</div>
