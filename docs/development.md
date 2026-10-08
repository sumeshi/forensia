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
| `LLM_API_KEY` | Unset; when present, sent only as a Bearer `Authorization` header to the configured LLM endpoint. It is not written to LLM audit logs. | LLM HTTP client |
| `LLM_MODEL` | Unset. Required with an LLM endpoint; CLI `--model` overrides it. | CLI LLM configuration |
| `LLM_CONTEXT_WINDOW_TOKENS` | `0` (unknown/automatic); optional total provider context limit used to reserve input space before sending output budget. | LLM HTTP client |
| `LLM_MAX_TOKENS` | `4096`; hard output ceiling per completion, minimum 1. Per-role requests and truncation recovery cannot exceed it. It is not a model context-window setting. | LLM HTTP client |
| `LLM_TEMPERATURE` | `0.0`; OpenAI-compatible sampling temperature, clamped to `0.0`–`2.0`. Keep `0.0` for reproducibility; raise deliberately when deterministic repetition is undesirable. | LLM HTTP client |
| `LLM_REASONING_RESERVE_TOKENS` | `0`; added to the completion ceiling for providers that count hidden reasoning in `max_tokens`. | LLM HTTP client |
| `FORENSIA_PROMPT_BUDGET_TOKENS` | `12000` when unset or `0`; total plan/check input budget. Set this first when tuning context size. | Prompt assembly/trimming |
| `FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS` | Automatic when unset or `0`: twice the total prompt-token budget. Advanced override for generated DFIR guidance only. | Playbook/context builders |
| `FORENSIA_MEMORY_MAX_BYTES` | Automatic when unset or `0`: `prompt tokens × 4/3`, clamped to 4096–65536 bytes. Advanced override for overview compaction. | Working Memory |
| `FORENSIA_OUTPUT_LANGUAGE` | `ja`; accepts `ja` or `en` and controls human-facing prompts and generated report language. Invalid values fall back to `ja`. | Prompt/report builders |
| `FORENSIA_REPORT_MAX_QUERIES_PER_SECTION` | `3`, minimum 1; CLI `--report-max-queries-per-section` overrides it. | Report section agent |
| `FORENSIA_REPORT_MARKDOWN_MAX_ROWS` | `200`, minimum 1; rows beyond this stay in durable data but are not rendered directly into Markdown. | Structured report renderer |
| `LLM_OUTAGE_WALL_CLOCK_BUDGET_S` | `28800`, minimum 1; maximum recovery-wait duration after an LLM outage. | LLM recovery loop |
| `LLM_OUTAGE_PROBE_INTERVAL_S` | `60`, minimum 1; recovery probe interval, capped at the wall-clock outage budget. | LLM recovery loop |

`LLM_THINKING_LANGUAGE` was previously listed but never consumed. It has been removed;
internal reasoning instructions remain implementation-owned English prompts.

Capacity-dependent values cannot be inferred reliably from a model name or an
OpenAI-compatible `/v1/models` response. Forensia therefore uses a conservative total
prompt default and derives its subordinate system/Memory budgets locally; explicit
overrides remain available for known model context windows.

### 1.2 Common commands

```bash
# Backend tests
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m pytest tests/ -q

# Local run
uv run forensia investigate ./cases/demo ./path/to/evidence --profile windows-basic --max-iter 20
uv run forensia report ./cases/demo
uv run forensia report ./cases/demo --write
```

---

## 2. Testing policy

Keep tests only where a failure would violate a responsibility boundary or a meaningful
user-visible contract. Their maintenance and execution cost must match that guarantee.

- Keep pytest offline and use disposable cases. Replace LLM responses and injected external failures at their boundaries; keep actual case state, tools, persistence, and projections on the path being verified. Do not call a real LLM server from pytest
- Test observable behavior at its responsibility boundary: deterministic evaluation, real temporary DB/file persistence, and CLI results with LLM responses mocked where necessary. Prefer extending an existing scenario over adding overlapping helper and adapter tests
- Give each invariant one primary test owner. Avoid repeated per-field/type checks, SQL-string or mock-forwarding assertions, and private cache/counter/layout assertions when the public result already protects the behavior. Keep separate cases for distinct failure paths and safety boundaries
- Runtime contracts own the design. Do not retain obsolete APIs, fallback algorithms, or mock-specific branches to satisfy a test. Update or remove the test when the design changes; confirm the resulting behavior through the real temporary-case/CLI path
- Retain regression coverage for Evidence/provenance, Assessment/Sufficiency/Settlement, admitted work and termination, persistence/resume, and bounded execution. Use actual output checks for routine presentation/helper changes rather than adding tests that merely mirror the implementation
- Test editable knowledge through its executable semantics and contracts, not exact file counts or prose snapshots. Do not use machine-dependent wall-clock thresholds as correctness checks; measure performance separately
- **Determinism-gate regression tests**: verdict consistency gates, fallback demotion, memory filters, and extracted finding validation are covered in `tests/test_checker_gates.py`; early untestable resolution is covered in `tests/test_hypothesis_seeding.py`. Whenever you change these gates, update them at the same time
- When you genuinely want to observe investigation-loop behavior, run `forensia investigate ...` against a local model and inspect `ai_logs/` by eye. Do not turn it into a pytest

---

## 3. Helper scripts and `forensia doctor`

`scripts/` is a set of offline audits that keep the declaration layer / code / documentation aligned. They are not runtime; `forensia doctor` runs them together.

| Script | Purpose |
|---|---|
| `scripts/audit_schema_coverage.py` | AST-parses the `query` SQL of all rule YAML files with sqlglot and extracts referenced `event_id` values. Checks coverage and QuestionSpec contract against `event_ids.yaml` / `question_routing.yaml` / `question_routing_eval.yaml` |
| `scripts/regenerate_playbook.py` | Regenerates the `<!-- AUTO-FROM: ... -->` sections of `_schema/playbook/*.md` from source YAML. `--check` detects drift (exit 1); with no arguments it writes |
| `scripts/cycle_summary.py <case_dir>` | Reads the bounded recent progress events in `db/trace.duckdb` and renders per-cycle hypothesis deltas and benchmark progress as a Markdown table. Debugging aid; older cycles may have been pruned |
| `forensia doctor` | CLI command. Runs 8 checks in order — schema coverage / playbook drift / import layer contract (`scripts/check_imports.py`) / verdict taxonomy AST scan / report template policy / report validation self-check / ruff lint / pytest — and exits 0 only when all pass |

`scripts/` is not a Python package. Tests that import from `scripts/` rely on `conftest.py` adding the repository root to `sys.path`.

Doctor's pytest step excludes `test_memory.py`, `test_ingest.py`,
and `test_persistence.py`. Round completion still requires the separate full
`pytest tests/ -q` gate.

---

## 4. CLI

| Command | Role |
|---|---|
| `add` | Ingest additional artifacts into an existing case |
| `investigate` | For a new case: case creation + ingest → normalize → analyze → investigate → report. For an existing case: continue the hypothesis loop. Thin display adapter over `forensia.pipeline.run_investigation` (GOAL §6.3) |
| `report` | Render Markdown / HTML from existing `report_sections`. With `--write`, re-fill sections from current evidence before rendering |
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
| `--report-only` | `false` | Render the current report without running the hypothesis loop; use `forensia report --write` to re-fill sections |
| `--rerun` | `false` | Reset case tables and runtime outputs, then redo normalize / analyze using the existing `raw/` |

### 4.2 Rerun semantics

- `forensia investigate <case_dir> <input_dir>` runs from new case creation through ingest / normalize / analyze / investigate / report
- Running `forensia investigate <case_dir>` on an existing case continues the hypothesis loop, inheriting the previous state
- To reset the output directory and start over, use `--rerun`. `raw/` is preserved, and when `input_dir` is omitted it re-normalizes from the existing raw
- `report` is render only
- `report --write` re-fills sections and then renders

`reset_case_tables()` invoked by `--rerun` must clear not only the evidence-derived normalized tables but also the derived workflow state. At minimum include `findings` / `hypotheses` / `report_sections` / `claims` / `section_facts` / `section_evidence` / `section_runs` / `section_questions` / `query_cache` / trace tables (including `retrieval_events`) / `ingested_files` / `prefetch_timeline`. When you add a new mutable table, update `reset_case_tables()` and the reset test in `tests/test_case_db_maintenance.py` at the same time.

### 4.3 Latest-only case schema

`db/schema.py` owns the complete current schema and `SCHEMA_VERSION`. A new case
creates core and trace databases, each with a `forensia_schema(version)` marker.
Reopening a current case creates connection-local trace views and preserves durable
case state. There is no automatic migration, backfill, or verdict repair on open.

When changing an incompatible schema or persisted meaning, update every consumer and
bump `SCHEMA_VERSION` together. Unversioned or mismatched core/trace databases and
incomplete database pairs are rejected before persistent DDL/DML. Preserve old cases
and ingest their original artifacts into a **new case directory** for current runs;
`--rerun` does not upgrade an unsupported case. Any future data conversion is separate,
explicit work on a frozen copy, with provenance and recovery checks.

---

## 5. Run entry and display adapters

`forensia.pipeline.run_investigation` is the one display-agnostic entry that
assembles case open/init, the optional `--rerun` reset, knowledge indexing,
ingest → normalize → analyze → `investigator.investigate` → report. The CLI
(`cli/app.py`) is a thin adapter over it; a future TUI calls the same entry
(GOAL §6.3). Adapter contract:

- importing `forensia.pipeline` (and the kernel) pulls no typer/rich and no
  HTTP transport; `core/log.log` prints plain text, so terminal styling is the
  adapter's concern;
- invalid user inputs raise `pipeline.UsageError`, which the CLI maps to
  `typer.BadParameter`; `LLMServerUnavailableError` propagates and the CLI
  prints the abort line with exit code 2;
- status lines flow through the injected `status` callback; the
  `pre_investigation` hook renders profile/timezone advice before the loop;
- structured progress is persisted in the trace DB (`db/progress.py`, capped
  recent view of 1000 rows); audit receipts remain in the trace tables;
- SIGINT capture and stop application stay in `investigator.investigate`, and
  the session terminal receipt is persisted before fallible projections, so an
  interrupted run finalizes lifecycle and report without a UI.

`reports/` contains only report artifacts (`report.md`, `report.html`,
`report_brief.json`, debug/evidence dumps, structured CSV/JSON). There are no
`reports/api/*.json` snapshot files.

Wherever the report writer receives a timestamp from raw evidence, apply the
sanity range 1980 ≤ year ≤ today + 5. The report writer's quality gate also
detects out-of-range dates in narratives ([report-pipeline.md](report-pipeline.md)). Do not assume MFT / EVTX timestamps are valid.
