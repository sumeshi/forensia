# Development

Development environment setup, testing policy, helper scripts, and CLI flags.

---

## 1. Development environment

### 1.1 Python

```bash
git clone https://github.com/sumeshi/forensia
cd forensia
uv sync
```

Create `.env`:

```bash
cp .env.example .env
# edit .env for your local LLM endpoint/model
```

`.env.example` contains every supported environment variable. Optional values are
commented so copying the file does not pin tuning knobs unnecessarily. Invalid integer
values fall back to the defaults below; values below the documented minimum are clamped.

| Variable | Default / automatic behavior | Runtime owner |
|---|---|---|
| `LLM_BASE_URL` | Unset. Required only for LLM-backed investigation/report writing; CLI `--llm-base-url` overrides it. | CLI LLM configuration |
| `LLM_API_KEY` | Unset; when present, sent only as a Bearer `Authorization` header to the configured LLM endpoint. It is not returned by `/api/config` or written to LLM audit logs. | LLM HTTP client |
| `LLM_MODEL` | Unset. Required with an LLM endpoint; CLI `--model` overrides it. | CLI LLM configuration |
| `LLM_CONTEXT_WINDOW_TOKENS` | `0` (unknown/automatic); optional total provider context limit used to reserve input space before sending output budget. | LLM HTTP client |
| `LLM_MAX_TOKENS` | `4096`; output ceiling per completion, minimum 1. It is not a model context-window setting. | LLM HTTP client |
| `LLM_REASONING_RESERVE_TOKENS` | `0`; added to the completion ceiling for providers that count hidden reasoning in `max_tokens`. | LLM HTTP client |
| `FORENSIA_PROMPT_BUDGET_TOKENS` | `12000` when unset or `0`; total plan/check input budget. Set this first when tuning context size. | Prompt assembly/trimming |
| `FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS` | Automatic when unset or `0`: twice the total prompt-token budget. Advanced override for generated DFIR guidance only. | Playbook/context builders |
| `FORENSIA_MEMORY_MAX_BYTES` | Automatic when unset or `0`: `prompt tokens × 4/3`, clamped to 4096–65536 bytes. Advanced override for overview compaction. | Working Memory |
| `FORENSIA_OUTPUT_LANGUAGE` | `ja`; accepts `ja` or `en` and controls human-facing prompts and generated report language. Invalid values fall back to `ja`. | Prompt/report builders |
| `FORENSIA_REPORT_MAX_QUERIES_PER_SECTION` | `3`, minimum 1; CLI `--report-max-queries-per-section` overrides it. | Report section agent |
| `FORENSIA_REPORT_MARKDOWN_MAX_ROWS` | `200`, minimum 1; rows beyond this stay in durable data but are not rendered directly into Markdown. | Structured report renderer |
| `LLM_OUTAGE_WALL_CLOCK_BUDGET_S` | `28800`, minimum 1; maximum recovery-wait duration after an LLM outage. | LLM recovery loop |
| `LLM_OUTAGE_PROBE_INTERVAL_S` | `60`, minimum 1; recovery probe interval, capped at the wall-clock outage budget. | LLM recovery loop |
| `FORENSIA_API_BASE_URL` | `http://127.0.0.1:8000`; frontend development proxy target. The root `.env` is read by Vite. | `web_ui/vite.config.ts` only |
| `FORENSIA_UI_ORIGINS` | Local Vite origins when unset; otherwise a comma-separated FastAPI CORS allow-list. | FastAPI app |

`LLM_THINKING_LANGUAGE` was previously listed but never consumed. It has been removed;
internal reasoning instructions remain implementation-owned English prompts.

Capacity-dependent values cannot be inferred reliably from a model name or an
OpenAI-compatible `/v1/models` response. Forensia therefore uses a conservative total
prompt default and derives its subordinate system/Memory budgets locally; explicit
overrides remain available for known model context windows.

### 1.2 Web UI

```bash
cd web_ui
pnpm install
```

### 1.3 Common commands

```bash
# Backend tests
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m pytest tests/ -q

# Frontend
cd web_ui
pnpm test
pnpm build

# Local run
uv run forensia investigate ./cases/demo ./path/to/evidence --profile windows-basic --max-iter 20
uv run forensia report ./cases/demo
uv run forensia report ./cases/demo --write
uv run forensia serve ./cases/demo
```

---

## 2. Testing policy

Keep the test suite finishing in seconds.

- **Do not write tests that make real LLM calls**. A full cycle of `investigate(...)` or a real-server-dependent section refresh has too many side effects (DuckDB writes, memory I/O, file walks) to stay lightweight. When exercising `run_section_block_agent` and similar, keep it within structured answer / deterministic builder / mocked JSON responses
- **Do not write tests that hit a real LLM server**. The previous `tests/test_benchmark_e2e_real_llm.py` (gated by `FORENSIA_LLM_BASE_URL`) was removed for the same reason
- Instead, cover with: unit tests for pure-function helpers (`_quality_gate_section`, `_render_structured_answer_markdown`, etc.), DB-only persistence tests, and CLI / HTTP tests that do not import the LLM module
- **Determinism-gate regression tests**: verdict consistency gates, fallback demotion, memory filters, and extracted finding validation are covered in `tests/test_checker_gates.py`; early untestable resolution is covered in `tests/test_hypothesis_seeding.py`. Whenever you change these gates, update them at the same time
- When you genuinely want to observe investigation-loop behavior, run `forensia investigate ...` against a local model and inspect `ai_logs/` by eye. Do not turn it into a pytest

---

## 3. Helper scripts and `forensia doctor`

`scripts/` is a set of offline audits that keep the declaration layer / code / documentation aligned. They are not runtime; `forensia doctor` runs them together.

| Script | Purpose |
|---|---|
| `scripts/audit_schema_coverage.py` | AST-parses the `query` SQL of all rule YAML files with sqlglot and extracts referenced `event_id` values. Checks coverage and QuestionSpec contract against `event_ids.yaml` / `question_routing.yaml` / `question_routing_eval.yaml` |
| `scripts/regenerate_playbook.py` | Regenerates the `<!-- AUTO-FROM: ... -->` sections of `_schema/playbook/*.md` from source YAML. `--check` detects drift (exit 1); with no arguments it writes |
| `scripts/cycle_summary.py <case_dir>` | Parses `progress_events.json` and renders per-cycle hypothesis deltas and benchmark progress as a Markdown table. Debugging aid |
| `forensia doctor` | CLI command. Runs 8 checks in order — schema coverage / playbook drift / import layer contract (`scripts/check_imports.py`) / verdict taxonomy AST scan / report template policy / report validation self-check / ruff lint / pytest — and exits 0 only when all pass |

`scripts/` is not a Python package. Tests that import from `scripts/` rely on `conftest.py` adding the repository root to `sys.path`.

---

## 4. CLI

| Command | Role |
|---|---|
| `add` | Ingest additional artifacts into an existing case |
| `investigate` | For a new case: case creation + ingest → normalize → analyze → investigate → report. For an existing case: continue the hypothesis loop |
| `report` | Render Markdown / HTML from existing `report_sections`. With `--write`, re-fill sections from current evidence before rendering |
| `serve` | Serve FastAPI and the Svelte UI |
| `doctor` | Hidden. Runs the 8 health checks together (see section 3) |
| `templates-export` | Hidden. Exports the bundled report templates |

### 4.1 Investigation flags

| Flag | Default | When to care |
|---|---|---|
| `--max-iter` | `20` | Increase only when you want to run longer |
| `--max-llm-calls` | `0` (unlimited) | Opt-in hard cap on total LLM calls per `investigate`. Specify explicitly when using a cloud API to prevent cost runaway |
| `--max-queries-per-hypothesis` | `5` | Search depth per hypothesis |
| `--no-progress-limit` | `3` | Relax when you want to tolerate low-signal cycles |
| `--report-every-n-cycles` | `3` | Increase when report re-fill cost is too high |
| `--report-max-queries-per-section` | `0` | Maximum number of queries for the section block agent. `0` uses the `FORENSIA_REPORT_MAX_QUERIES_PER_SECTION` setting (default 3) |
| `--profile` | `windows-basic` | Switch to a different rule profile |
| `--report-only` | `false` | Re-fill the report only, without running the hypothesis loop |
| `--rerun` | `false` | Reset case tables and runtime outputs, then redo normalize / analyze using the existing `raw/` |

### 4.2 Rerun semantics

- `forensia investigate <case_dir> <input_dir>` runs from new case creation through ingest / normalize / analyze / investigate / report
- Running `forensia investigate <case_dir>` on an existing case continues the hypothesis loop, inheriting the previous state
- To reset the output directory and start over, use `--rerun`. `raw/` is preserved, and when `input_dir` is omitted it re-normalizes from the existing raw
- `report` is render only
- `report --write` re-fills sections and then renders

`_reset_case_tables()` invoked by `--rerun` must clear not only the evidence-derived normalized tables but also the derived workflow state. At minimum include `findings` / `hypotheses` / `report_sections` / `claims` / `section_facts` / `section_evidence` / `section_runs` / `section_questions` / `query_cache` / trace tables (including `retrieval_events`) / `ingested_files` / `prefetch_timeline`. When you add a new mutable table, update `_reset_case_tables()` and the reset test in `tests/test_case_db_maintenance.py` at the same time.

### 4.3 Schema changes and migrations

Changing `CREATE TABLE IF NOT EXISTS` in `db/schema.py` is not applied to existing case DBs. When adding columns to an existing table, always add a migration (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) to `_apply_migration_once("<key>", ...)` in `db/database.py` (examples: `hypotheses_source_decl_id`, `mft_entries_fn_name`).

---

## 5. UI details

### 5.1 Cockpit layout

`web_ui/src/App.svelte` from top to bottom:

1. `Header`: Case name, current phase, LLM model, last-updated timestamp
2. `KpiBar`: 4 KPIs — Events / Findings / Hypotheses / Open Gaps. The Findings tile has a severity breakdown (High/Medium/Low), and the Hypotheses tile has a thin stacked bar of verdict breakdown (Active/Confirmed/Refuted/Inconclusive)
3. `VolumeTimeline`: Chart.js composite chart. Default is the full range at day resolution. Narrow down with the range picker (year → month → day); selecting a single day switches to hour resolution. Detection findings are a line overlay
4. `ReportDraftProgress`: Fill state per section
5. `AttackCoverage`: tactic × technique matrix from `findings.attack`
6. `Cockpit`: `AiActivityPanel`, `HypothesisStream` that tab-switches between Active / Resolved Hypotheses (`latestReasoningAt` desc) and the Latest Reasoning stream, and `OpenGaps`
7. `TopRules` + `TopEntities` (2-column grid)
8. `DetailsTabs`: raw-data tabs for findings / steps / sessions / activity / mft

### 5.2 Event Volume API contract

`GET /api/event-volume` accepts `bucket=year|month|day|hour`, `source=all|detected`, and optional `start` / `end` ISO timestamps. Resolution order in [web/app.py](../src/forensia/web/app.py):

1. For a full-range query, a snapshot file (`reports/api/event_volume_<bucket>_<source>.json`)
2. A live `CaseDB` query
3. If the DB is locked and no exact snapshot exists, aggregate from a finer snapshot via `aggregate_event_volume` (year / month views can be reconstructed from day / hour snapshots)

`list_event_volume_dto` drops year < 1980 (Windows epoch 1601 garbage) and year > today + 5 (NTFS FILETIME overflow, 3220 / 30828, etc.). The same filter is applied in `aggregate_event_volume`.

All snapshot refresh paths also write `reports/api/snapshot_metadata.json`. Use
`GET /api/snapshot-metadata` when diagnosing UI/report drift: it reports the generated
revision, current revision, generation time, and `current`/`in-progress`/`stale` state.
Do not diagnose drift from file timestamps alone.

### 5.3 Server-side date sanity

Wherever the API or report writer receives a timestamp from raw evidence, apply the sanity range 1980 ≤ year ≤ today + 5. The report writer's quality gate also detects out-of-range dates in narratives ([report-pipeline.md](report-pipeline.md)). Do not assume MFT / EVTX timestamps are valid.

### 5.4 Frontend timestamp parsing

The reason `web_ui/src/lib/format.ts:parseServerTimestamp` exists is that the backend's `datetime.isoformat()` returns a string without a `Z` suffix for naive UTC datetimes. JS `new Date()` interprets this as local time, breaking the "X ago" display. Any UI code that compares a server timestamp with `Date.now()` must go through this function.
