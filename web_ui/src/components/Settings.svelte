<script lang="ts">
  // Mock settings view — read-only placeholder UI. Values are illustrative and
  // not yet wired to the backend; the real config still lives in the .env file.
  const llm = [
    { label: "LLM Base URL", value: "http://127.0.0.1:1234" },
    { label: "Model", value: "google/gemma-4-e2b" },
    { label: "Max tokens", value: "4096" }
  ];
  const investigation = [
    { label: "Max iterations", value: "20" },
    { label: "Max queries / hypothesis", value: "5" },
    { label: "Max LLM calls (0 = unlimited)", value: "0" }
  ];
  const langs = ["ja", "en"];
</script>

<div class="mx-auto w-full max-w-3xl">
  <div>
    <h1 class="text-2xl font-bold tracking-tight text-semantic-fg">Settings</h1>
    <p class="mt-1 text-sm text-semantic-fg-muted">
      Configuration overview (mock). Live values are still read from <code class="text-semantic-accent">.env</code>.
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
          class="w-full rounded-lg border border-mocha-surface1 bg-semantic-bg-inset/60 px-3 py-2 text-sm text-semantic-fg focus:border-semantic-accent/50 focus:outline-none"
        >
          {#each langs as lang}
            <option selected={lang === "ja"}>{lang}</option>
          {/each}
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

  <div class="mt-5 flex justify-end gap-2">
    <button type="button" class="btn-ghost" disabled>Reset</button>
    <button type="button" class="btn-ghost" disabled>Save changes</button>
  </div>
</div>
