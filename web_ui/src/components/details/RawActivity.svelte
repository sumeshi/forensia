<script lang="ts">
  import type { ProgressEventDTO } from "../../lib/types";
  export let progress: ProgressEventDTO | null = null;

  type ActivityLevel = "info" | "success" | "warning" | "error";
  type ActivityLogEntry = { tag: string; level: ActivityLevel; message: string };

  function tone(level: ActivityLevel): string {
    const tones: Record<ActivityLevel, string> = {
      info: "border-semantic-info/40 bg-semantic-info/10 text-semantic-info",
      success: "border-semantic-ok/40 bg-semantic-ok/10 text-semantic-ok",
      warning: "border-semantic-warn/40 bg-semantic-warn/10 text-semantic-warn",
      error: "border-semantic-danger/40 bg-semantic-danger/10 text-semantic-danger"
    };
    return tones[level];
  }

  function activityEntries(value: ProgressEventDTO | null): ActivityLogEntry[] {
    if (!value) return [];
    const structured = value.payload.recent_log_entries;
    if (Array.isArray(structured)) {
      return structured.filter((item): item is ActivityLogEntry => {
        if (!item || typeof item !== "object") return false;
        const entry = item as Record<string, unknown>;
        return typeof entry.tag === "string" && typeof entry.message === "string" &&
          ["info", "success", "warning", "error"].includes(String(entry.level));
      });
    }
    // Backward compatibility for snapshots written before structured logs.
    const legacy = (value.payload.recent_logs as string[] | undefined) ?? [];
    return legacy.map((line) => ({
      tag: line.match(/^\[([^\]]+)\]/)?.[1]?.toUpperCase() ?? "ACTIVITY",
      level: "info",
      message: line.replace(/^\[[^\]]+\]\s*/, "")
    }));
  }
</script>

<div class="space-y-2 text-sm">
  {#if progress}
    {#each activityEntries(progress) as entry}
      <article class="flex gap-3 rounded-xl border border-mocha-surface1 bg-semantic-bg/70 px-3 py-2">
        <span class={`chip ${tone(entry.level)}`}>[{entry.tag.toUpperCase()}]</span>
        <span class={`chip min-w-16 justify-center ${tone(entry.level)}`}>{entry.level.toUpperCase()}</span>
        <span class="text-semantic-fg-muted">{entry.message}</span>
      </article>
    {/each}
  {:else}
    <p class="text-sm text-semantic-fg-muted">Waiting for progress events.</p>
  {/if}
</div>
