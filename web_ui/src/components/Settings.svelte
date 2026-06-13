<script lang="ts">
  import type { RuntimeConfigDTO } from "../lib/types";

  export let config: RuntimeConfigDTO | null = null;

  $: llm = [
    { label: "LLM Base URL", value: config?.llm_base_url ?? "not configured" },
    { label: "Model", value: config?.llm_model ?? "not configured" },
    { label: "Max tokens", value: String(config?.llm_max_tokens ?? "-") }
  ];
  $: investigation = [
    { label: "Report queries / section", value: String(config?.llm_report_max_queries_per_section ?? "-") },
    { label: "Outage budget (seconds)", value: String(config?.llm_outage_wall_clock_budget_s ?? "-") },
    { label: "Probe interval (seconds)", value: String(config?.llm_outage_probe_interval_s ?? "-") }
  ];
</script>

<div class="mx-auto w-full max-w-3xl">
  <div>
    <h1 class="text-2xl font-bold tracking-tight text-semantic-fg">Settings</h1>
    <p class="mt-1 text-sm text-semantic-fg-muted">
      Effective read-only configuration loaded by the Forensia backend.
    </p>
  </div>

  <section class="panel mt-5 p-5">
    <h2 class="panel-title mb-4">LLM Connection</h2>
    <div class="grid gap-4 sm:grid-cols-2">
      {#each llm as field}
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase tracking-wider text-semantic-fg-muted">{field.label}</span>
          <input
            type="text"
            value={field.value}
            readonly
            class="w-full rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/60 px-3 py-2 font-mono text-sm text-semantic-fg focus:border-semantic-accent/50 focus:outline-none"
          />
        </label>
      {/each}
      <label class="block">
        <span class="mb-1 block text-xs font-medium uppercase tracking-wider text-semantic-fg-muted">Output language</span>
        <select
          disabled
          class="w-full rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/60 px-3 py-2 text-sm text-semantic-fg focus:border-semantic-accent/50 focus:outline-none"
        >
          <option>{config?.llm_output_language ?? "-"}</option>
        </select>
      </label>
    </div>
  </section>

  <section class="panel mt-5 p-5">
    <h2 class="panel-title mb-4">Investigation</h2>
    <div class="grid gap-4 sm:grid-cols-3">
      {#each investigation as field}
        <label class="block">
          <span class="mb-1 block text-xs font-medium uppercase tracking-wider text-semantic-fg-muted">{field.label}</span>
          <input
            type="text"
            value={field.value}
            readonly
            class="w-full rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/60 px-3 py-2 font-mono text-sm text-semantic-fg focus:border-semantic-accent/50 focus:outline-none"
          />
        </label>
      {/each}
    </div>
  </section>

  <section class="panel mt-5 p-5">
    <h2 class="panel-title mb-4">Appearance</h2>
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium text-semantic-fg">Theme</div>
        <div class="text-xs text-semantic-fg-muted">Dark is the only theme for now.</div>
      </div>
      <span class="chip text-semantic-accent">Dark</span>
    </div>
  </section>

  <p class="mt-5 text-right text-xs text-semantic-fg-muted">
    Values are loaded when the backend process starts. Restart it after editing <code class="text-semantic-accent">.env</code>.
  </p>
</div>
