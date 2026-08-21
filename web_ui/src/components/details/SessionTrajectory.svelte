<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../../lib/api";
  import type {
    AttemptPageDTO,
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

  async function load() {
    if (!sessionId) {
      trajectory = null;
      calls = null;
      return;
    }
    loading = true;
    error = null;
    try {
      trajectory = await api.getSessionTrajectory(sessionId);
      calls = await api.getLogicalCalls(sessionId, {
        limit: pageSize,
        offset: pageOffset,
        phase: phaseFilter || undefined,
        status: statusFilter || undefined
      });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      trajectory = null;
      calls = null;
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

  onMount(load);
  $: sessionId, phaseFilter, statusFilter, pageOffset, load();
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
        <h3 class="panel-title">Logical calls</h3>
        <div class="flex items-center gap-2 text-xs text-foreground/50">
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
          <span>{calls?.total ?? 0} calls</span>
        </div>
      </div>
      <div class="space-y-2">
        {#each calls?.items ?? [] as call}
          <div class="panel-card">
            <button class="flex w-full items-center justify-between text-left" on:click={() => toggleAttempts(call)}>
              <span class="font-mono text-xs">{call.logical_call_id}</span>
              <span class="text-xs text-foreground/60">{call.phase ?? "?"} · {call.attempt_count} attempts</span>
            </button>
            {#if expanded[call.logical_call_id] || attemptErrors[call.logical_call_id]}
              <div class="mt-2 space-y-1 border-t border-foreground/10 pt-2">
                {#if attemptErrors[call.logical_call_id]}
                  <p class="text-semantic-danger text-xs">{attemptErrors[call.logical_call_id]}</p>
                {:else}
                  {#each expanded[call.logical_call_id]?.items ?? [] as attempt}
                    <div class="rounded bg-foreground/5 p-2 text-xs">
                      <div class="flex justify-between">
                        <span class="font-mono">{attempt.attempt_id}</span>
                        <span>{attempt.status}</span>
                      </div>
                      <div class="text-foreground/60">
                        {(attempt.duration_ms ?? 0) / 1000}s · in {attempt.input_tokens ?? 0} / out {attempt.output_tokens ?? 0}
                        tokens · {attempt.retry_ordinal > 0 ? `retry #${attempt.retry_ordinal}` : "initial"}
                        · limit {attempt.effective_output_limit ?? "—"}
                        · {attempt.finish_reason ?? attempt.error_type ?? "—"}
                        {#if attempt.duplicate_of} · duplicate of {attempt.duplicate_of}{/if}
                        {#if attempt.error_type} · {attempt.error_type}{/if}
                      </div>
                      {#if attempt.prompt_metadata}
                        <div class="mt-1 text-foreground/50">prompt: {JSON.stringify(attempt.prompt_metadata)}</div>
                      {/if}
                    </div>
                  {/each}
                {/if}
              </div>
            {/if}
          </div>
        {/each}
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
</style>
