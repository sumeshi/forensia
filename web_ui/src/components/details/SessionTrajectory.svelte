<script lang="ts">
  import { api } from "../../lib/api";
  import type {
    AttemptPageDTO,
    HypothesisDTO,
    HypothesisReasoningEntryDTO,
    InvestigationStepDTO,
    LogicalCallDTO,
    LogicalCallPageDTO,
    SessionDTO,
    SessionTrajectoryDTO
  } from "../../lib/types";
  import { findingAggregates, sessions } from "../../lib/stores";

  export let sessionsProp: SessionDTO[] = [];

  let sessionId: string | null = null;
  let trajectory: SessionTrajectoryDTO | null = null;
  let calls: LogicalCallPageDTO | null = null;
  let hypotheses: HypothesisDTO[] = [];
  let hypothesisId = "";
  let reasoning: HypothesisReasoningEntryDTO[] = [];
  let steps: InvestigationStepDTO[] = [];
  let expanded: Record<string, AttemptPageDTO | null> = {};
  let attemptErrors: Record<string, string> = {};
  let error: string | null = null;
  let loading = false;
  let phaseFilter = "";
  let statusFilter = "";
  let pageOffset = 0;
  const pageSize = 50;

  $: sessionList = sessionsProp.length ? sessionsProp : $sessions;
  $: if (!sessionId && sessionList.length) sessionId = sessionList[0]?.session_id ?? null;
  $: chain = [
    ...reasoning.map((entry) => ({ kind: "reasoning" as const, at: entry.created_at ?? "", entry })),
    ...steps.map((entry) => ({ kind: "step" as const, at: entry.created_at ?? "", entry })),
    ...(calls?.items ?? []).map((entry) => ({ kind: "call" as const, at: entry.created_at ?? "", entry }))
  ].sort((a, b) => a.at.localeCompare(b.at));

  async function load() {
    if (!sessionId) {
      trajectory = null;
      calls = null;
      return;
    }
    loading = true;
    error = null;
    try {
      const hypothesisResponse = await api.getHypotheses();
      hypotheses = [...hypothesisResponse.active, ...hypothesisResponse.resolved];
      if (!hypothesisId && hypotheses.length) hypothesisId = hypotheses[0]?.hypothesis_id ?? "";
      trajectory = await api.getSessionTrajectory(sessionId);
      calls = await api.getLogicalCalls(sessionId, {
        limit: pageSize,
        offset: pageOffset,
        hypothesis_id: hypothesisId || undefined,
        phase: phaseFilter || undefined,
        status: statusFilter || undefined
      });
      const sessionSteps = await api.getSteps(sessionId);
      steps = sessionSteps.filter((step) => !hypothesisId || step.hypothesis_id === hypothesisId);
      reasoning = hypothesisId
        ? (await api.getHypothesisReasoning(hypothesisId, 200)).filter((entry) => entry.session_id === sessionId)
        : [];
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      trajectory = null;
      calls = null;
      reasoning = [];
      steps = [];
    } finally {
      loading = false;
    }
  }

  async function toggleAttempts(call: LogicalCallDTO) {
    const id = call.logical_call_id;
    if (expanded[id]) {
      expanded = { ...expanded, [id]: null };
      attemptErrors = { ...attemptErrors, [id]: "" };
      return;
    }
    try {
      expanded = { ...expanded, [id]: await api.getLogicalCallAttempts(id, { limit: 50, offset: 0 }) };
    } catch (e) {
      attemptErrors = { ...attemptErrors, [id]: e instanceof Error ? e.message : String(e) };
    }
  }

  $: sessionId, hypothesisId, phaseFilter, statusFilter, pageOffset, load();
</script>

<div class="space-y-4 text-sm">
  <div class="flex items-center gap-2">
    <label class="text-xs uppercase tracking-wide text-foreground/60" for="traj-session">Session</label>
    <select
      id="traj-session"
      class="rounded border border-foreground/20 bg-transparent px-2 py-1"
      bind:value={sessionId}
      on:change={load}
    >
      {#each sessionList as s}
        <option value={s.session_id}>{s.session_id} · {s.status}</option>
      {/each}
    </select>
    {#if $findingAggregates}
      <span class="ml-auto text-xs text-foreground/50">
        {($findingAggregates.total ?? 0)} findings · aggregates authoritative
      </span>
    {/if}
  </div>

  {#if loading}
    <p class="text-foreground/50">Loading trajectory…</p>
  {:else if error}
    <p class="text-semantic-danger">Failed to load trajectory: {error}</p>
  {:else if trajectory}
    <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <div class="panel-card">
        <div class="metric-label">Wall time</div>
        <div class="metric-value">{trajectory.wall_time_ms != null ? `${(trajectory.wall_time_ms / 1000).toFixed(1)}s` : "—"}</div>
      </div>
      <div class="panel-card">
        <div class="metric-label">Explained</div>
        <div class="metric-value">{trajectory.explained_time_ms != null ? `${(trajectory.explained_time_ms / 1000).toFixed(1)}s` : "—"}</div>
      </div>
      <div class="panel-card">
        <div class="metric-label">Unexplained</div>
        <div class="metric-value">{trajectory.unexplained_wall_time_ms != null ? `${(trajectory.unexplained_wall_time_ms / 1000).toFixed(1)}s` : "—"}</div>
      </div>
      <div class="panel-card">
        <div class="metric-label">State</div>
        <div class="metric-value">{trajectory.state ?? "—"}</div>
      </div>
    </div>

    <div class="panel-card">
      <div class="metric-label mb-1">Terminal reason</div>
      <p class="text-foreground/80">{trajectory.terminal_reason ?? "—"}</p>
      <p class="mt-1 text-xs text-foreground/50">
        timezone {trajectory.timezone} · revision {trajectory.snapshot_revision ?? "—"} ·
        authoritative {trajectory.authoritative_updated_at ?? "—"}
      </p>
    </div>

    {#if trajectory.latency_by_phase && Object.keys(trajectory.latency_by_phase).length}
      <div class="panel-card">
        <div class="metric-label mb-1">Latency by phase</div>
        <div class="flex flex-wrap gap-2">
          {#each Object.entries(trajectory.latency_by_phase) as [phase, ms]}
            <span class="rounded bg-foreground/10 px-2 py-0.5 text-xs">{phase}: {(ms / 1000).toFixed(2)}s</span>
          {/each}
        </div>
      </div>
    {/if}

    {#if trajectory.deterministic_operations?.length}
      <div class="panel-card">
        <div class="metric-label mb-1">Deterministic operations</div>
        <div class="space-y-1 text-xs">
          {#each trajectory.deterministic_operations as operation}
            <div>{operation.op_type ?? "operation"} · {operation.target ?? "—"} · {(operation.duration_ms ?? 0) / 1000}s</div>
          {/each}
        </div>
      </div>
    {/if}
    {#if trajectory.retrieval_events?.length}
      <div class="panel-card">
        <div class="metric-label mb-1">Retrieval / context decisions</div>
        <div class="space-y-1 text-xs">
          {#each trajectory.retrieval_events as retrieval}
            <div>{String(retrieval.phase ?? "?")} · {String(retrieval.source_kind ?? "?")} · selected {String(retrieval.selected_chars ?? 0)} chars / budget {String(retrieval.budget ?? 0)}</div>
          {/each}
        </div>
      </div>
    {/if}

    <div>
      <div class="mb-2 flex items-center justify-between">
        <div>
          <h3 class="panel-title">Hypothesis reasoning chain</h3>
          <p class="text-xs text-foreground/50">plan → provider attempts → execution/check → settlement</p>
        </div>
        <div class="flex items-center gap-2 text-xs text-foreground/50">
          <select bind:value={hypothesisId} aria-label="Select hypothesis" class="max-w-72 rounded border border-foreground/20 bg-transparent px-1 py-0.5">
            {#each hypotheses as hypothesis}
              <option value={hypothesis.hypothesis_id}>{hypothesis.hypothesis_id} · {hypothesis.description}</option>
            {/each}
          </select>
          <select bind:value={phaseFilter} aria-label="Filter phase" class="rounded border border-foreground/20 bg-transparent px-1 py-0.5">
            <option value="">all phases</option>
            {#each [...new Set((calls?.items ?? []).map((call) => call.phase).filter(Boolean))] as phase}
              <option value={phase}>{phase}</option>
            {/each}
          </select>
          <select bind:value={statusFilter} aria-label="Filter status" class="rounded border border-foreground/20 bg-transparent px-1 py-0.5">
            <option value="">all statuses</option>
            {#each [...new Set((calls?.items ?? []).map((call) => call.status).filter(Boolean))] as status}
              <option value={status}>{status}</option>
            {/each}
          </select>
          <span>{chain.length} events</span>
        </div>
      </div>
      <div class="chain-list">
        {#each chain as item}
          <article class="chain-item">
            <div class="mb-1 flex items-center gap-2 text-xs">
              <span class="chain-kind">{item.kind}</span>
              <span>{item.entry.phase ?? "?"}</span>
              <span class="ml-auto text-foreground/40">{item.at || "time unavailable"}</span>
            </div>
            {#if item.kind === "reasoning"}
              <p class="whitespace-pre-wrap text-foreground/80">{item.entry.body}</p>
              <div class="mt-1 text-xs text-foreground/50">
                {item.entry.query_id ?? "no query"} · verdict {item.entry.verdict ?? "—"}
              </div>
            {:else if item.kind === "step"}
              <details>
                <summary class="cursor-pointer text-foreground/80">Host step · inspect deterministic input/output</summary>
                <div class="transcript-grid">
                  <pre>{JSON.stringify(item.entry.input_json, null, 2)}</pre>
                  <pre>{JSON.stringify(item.entry.output_json, null, 2)}</pre>
                </div>
              </details>
            {:else}
              <button class="flex w-full items-center justify-between text-left" on:click={() => toggleAttempts(item.entry)}>
                <span class="font-mono text-xs">{item.entry.logical_call_id}</span>
                <span class="text-xs text-foreground/60">{item.entry.attempt_count} provider attempts · {item.entry.status ?? "?"}</span>
              </button>
              {#if expanded[item.entry.logical_call_id] || attemptErrors[item.entry.logical_call_id]}
                <div class="mt-2 space-y-2 border-t border-foreground/10 pt-2">
                  {#if attemptErrors[item.entry.logical_call_id]}
                    <p class="text-semantic-danger text-xs">{attemptErrors[item.entry.logical_call_id]}</p>
                  {:else}
                    {#each expanded[item.entry.logical_call_id]?.items ?? [] as attempt}
                      <div class="rounded bg-foreground/5 p-2 text-xs">
                        <div class="flex justify-between">
                          <span class="font-mono">{attempt.attempt_id}</span>
                          <span>{attempt.status} · {(attempt.duration_ms ?? 0) / 1000}s</span>
                        </div>
                        <div class="text-foreground/60">
                          in {attempt.input_tokens ?? 0} / out {attempt.output_tokens ?? 0} tokens ·
                          {attempt.retry_ordinal > 0 ? `retry #${attempt.retry_ordinal}` : "initial"} ·
                          {attempt.finish_reason ?? attempt.error_type ?? "—"}
                        </div>
                        <details class="mt-2">
                          <summary class="cursor-pointer">Exact request / response</summary>
                          <div class="transcript-grid">
                            <pre>{JSON.stringify(attempt.request_body, null, 2)}</pre>
                            <pre>{attempt.response_body ?? "No provider response (transport failure or timeout)"}</pre>
                          </div>
                        </details>
                      </div>
                    {/each}
                  {/if}
                </div>
              {/if}
            {/if}
          </article>
        {/each}
        {#if !chain.length}
          <p class="panel-card text-foreground/50">No chain events are linked to this hypothesis in the selected session.</p>
        {/if}
      </div>
      <div class="mt-2 flex items-center justify-between text-xs">
        <button class="btn-ghost" disabled={pageOffset === 0} on:click={() => (pageOffset = Math.max(0, pageOffset - pageSize))}>Previous</button>
        <span class="text-foreground/50">{calls?.offset ?? 0}–{(calls?.offset ?? 0) + (calls?.items.length ?? 0)} / {calls?.total ?? 0}</span>
        <button class="btn-ghost" disabled={!calls?.is_sample} on:click={() => (pageOffset += pageSize)}>Next</button>
      </div>
    </div>
  {:else}
    <p class="text-foreground/50">No trajectory available.</p>
  {/if}
</div>

<style>
  .panel-card {
    border: 1px solid rgb(255 255 255 / 0.08);
    border-radius: 0.5rem;
    padding: 0.75rem;
  }
  .metric-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: rgb(255 255 255 / 0.5);
  }
  .metric-value {
    font-size: 1.1rem;
    font-weight: 600;
  }
  .panel-title {
    font-size: 0.9rem;
    font-weight: 600;
  }
  .chain-list {
    border-left: 1px solid rgb(255 255 255 / 0.15);
    margin-left: 0.45rem;
    padding-left: 1rem;
  }
  .chain-item {
    position: relative;
    border: 1px solid rgb(255 255 255 / 0.08);
    border-radius: 0.5rem;
    margin-bottom: 0.6rem;
    padding: 0.75rem;
  }
  .chain-item::before {
    background: rgb(148 163 184);
    border-radius: 9999px;
    content: "";
    height: 0.5rem;
    left: -1.28rem;
    position: absolute;
    top: 0.9rem;
    width: 0.5rem;
  }
  .chain-kind {
    border-radius: 0.25rem;
    background: rgb(255 255 255 / 0.1);
    padding: 0.1rem 0.35rem;
    text-transform: uppercase;
  }
  .transcript-grid {
    display: grid;
    gap: 0.5rem;
    grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
    margin-top: 0.5rem;
  }
  .transcript-grid pre {
    background: rgb(0 0 0 / 0.3);
    border-radius: 0.35rem;
    max-height: 28rem;
    overflow: auto;
    padding: 0.6rem;
    white-space: pre-wrap;
    word-break: break-word;
  }
</style>
