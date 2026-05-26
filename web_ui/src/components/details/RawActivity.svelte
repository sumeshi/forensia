<script lang="ts">
  import type { ProgressEventDTO } from "../../lib/types";
  export let progress: ProgressEventDTO | null = null;

  function tag(line: string): { label: string; tone: string } {
    const found = line.match(/^\[([a-z-]+)\]/i)?.[1]?.toLowerCase() ?? "other";
    const tones: Record<string, string> = {
      plan: "text-mocha-lavender",
      do: "text-mocha-blue",
      check: "text-mocha-peach",
      act: "text-mocha-green",
      hypothesis: "text-mocha-mauve",
      report: "text-mocha-pink"
    };
    return { label: found, tone: tones[found] ?? "text-mocha-overlay1" };
  }
</script>

<div class="space-y-2 text-sm">
  {#if progress}
    {#each ((progress.payload.recent_logs as string[] | undefined) ?? []) as line}
      {@const info = tag(line)}
      <article class="flex gap-3 rounded-xl border border-mocha-surface1 bg-mocha-mantle/70 px-3 py-2">
        <span class={`chip ${info.tone}`}>[{info.label}]</span>
        <span class="text-mocha-subtext1">{line.replace(/^\[[^\]]+\]\s*/, "")}</span>
      </article>
    {/each}
  {:else}
    <p class="text-sm text-mocha-subtext1">Waiting for progress events.</p>
  {/if}
</div>
