# Contributing to forensia

forensia is a local-first DFIR investigation tool. Contributions are welcome, but the project prioritizes architectural stability over feature breadth.

This document is implementation-facing. It focuses on invariants, state boundaries, and responsibilities that should remain stable even when the code changes.

## Priorities

The current implementation is built around these constraints:

- Raw evidence must not leave the local environment.
- Small local LLMs are assumed to be weak and must be constrained by structure.
- Every durable conclusion must remain traceable back to evidence.
- A case must be resumable without reconstructing state from chat history.

## Setup

### Python

```bash
git clone https://github.com/sumeshi/forensia
cd forensia
uv sync
```

Example `.env`:

```dotenv
LLM_BASE_URL="http://127.0.0.1:1234"
LLM_MODEL="qwen/qwen3-8b"
LLM_MAX_TOKENS=4096
LLM_THINKING_LANGUAGE=en
LLM_OUTPUT_LANGUAGE=ja
LLM_MEMORY_MAX_BYTES=16384
```

| Variable | Meaning |
|---|---|
| `LLM_BASE_URL` | LLM API base URL |
| `LLM_MODEL` | Model name used for investigation and report writing |
| `LLM_MAX_TOKENS` | Max tokens per response |
| `LLM_THINKING_LANGUAGE` | Language used for internal reasoning prompts |
| `LLM_OUTPUT_LANGUAGE` | Language used for human-facing output |
| `LLM_MEMORY_MAX_BYTES` | Compaction threshold for selected memory files |
| `LLM_REPORT_PARALLELISM` | Default parallelism for report section filling |
| `FORENSIA_API_BASE_URL` | API base URL used by the UI dev workflow |
| `FORENSIA_UI_ORIGINS` | Comma-separated CORS allowlist for FastAPI |

The CLI flag for the base URL is `--llm-base-url`.

### Web UI

```bash
cd web_ui
npx pnpm install
```

## Common commands

### Backend

```bash
UV_CACHE_DIR=/tmp/uv-cache PYTHONPATH=src uv run python -m unittest discover -s tests
```

### Frontend

```bash
cd web_ui
npx svelte-check
npx pnpm test
npx pnpm build
```

### Local execution

```bash
forensia run ./sample/DESKTOP-001 --out ./dist/DESKTOP-001 --profile windows-basic --max-iter 20
forensia status ./dist/DESKTOP-001
forensia serve ./dist/DESKTOP-001
```

## CLI surface

| Command | Role |
|---|---|
| `init` | Initialize an empty case directory |
| `add` | Incrementally ingest new artifacts into an existing case |
| `report` | Render Markdown and HTML from existing `report_sections` |
| `report-write` | Refill report sections from current evidence, then render |
| `run` | Execute ingest → normalize → analyze → investigate → report |
| `investigate` | Continue the hypothesis loop on an existing case |
| `status` | Show current case state in read-only form |
| `serve` | Serve FastAPI and the built Svelte UI |

## Repository map

| Layer | Main location | Responsibility |
|---|---|---|
| Ingest | `src/forensia/ingest` | Convert source artifacts into raw JSONL |
| Normalize | `src/forensia/normalize` | Load normalized evidence into DuckDB |
| Rules | `src/forensia/rules` and `src/forensia/rulepacks` | Execute YAML rules and generate findings |
| Investigation | `src/forensia/ai/investigator.py` | Run the hypothesis loop |
| Planner / Checker | `src/forensia/ai/planner.py` and `src/forensia/ai/checker.py` | Propose SQL checks and evaluate results |
| Memory | `src/forensia/core/memory.py` | Maintain structured working memory |
| Report | `src/forensia/report` | Fill report sections and render reports |
| API | `src/forensia/api` and `src/forensia/web.py` | FastAPI, DTOs, and SSE |
| UI | `web_ui/` | Svelte 5 UI |

## Case layout

```text
case001/
  manifest.yaml
  allowlist.yaml
  raw/
  db/
    case.duckdb
    trace.duckdb
  findings/
  report_template/
  ai_logs/
  memory/
    overview.md
    facts.md
    timeline.md
    tasks.md
    archive/
      refuted.md
      resolved_gaps.md
      timeline_archive.md
    entities/
      user/
      host/
      ip/
    hypotheses/
    keypoints/
    evidence/
      suspicious.md
    details/
      fact-001.md
  reports/
    report.html
    report.md
    api/
```

### Directory responsibilities

| Path | Responsibility |
|---|---|
| `raw/` | Reprocessable raw JSONL generated during ingest |
| `db/case.duckdb` | Durable investigation state tied to evidence and report output |
| `db/trace.duckdb` | Durable execution trace for sessions, steps, and progress |
| `allowlist.yaml` | Rule-scoped suppression configuration |
| `memory/` | Regeneratable working context for LLM calls |
| `ai_logs/` | Per-call LLM request and response logs |
| `reports/` | Human-facing rendered output and API snapshots |

## Architectural invariants

### Three state classes

forensia separates state into three classes with different trust levels and lifetimes.

| State class | Storage | Purpose |
|---|---|---|
| Case State | `db/case.duckdb` | Normalized evidence and durable investigation objects derived from that evidence |
| Trace State | `db/trace.duckdb` | Investigation sessions, per-step I/O, reasoning trail, and progress history |
| Structured Memory | `memory/**/*.md` | Regeneratable working context assembled for LLM consumption |

These classes must remain separate.

- Case State is the source of truth for evidence-backed investigation results.
- Trace State is the source of truth for execution history.
- Structured Memory is a projection, not an authority.

### LLM output is never the source of truth

The implementation records LLM activity, but does not treat raw model output as authoritative state.

- LLM request and response bodies are stored under `ai_logs/<session_id>/`.
- Investigation step `input_json` and `output_json` are stored in `trace.investigation_steps`.
- Durable objects such as findings, hypotheses, claims, and report sections live in DuckDB.
- Memory markdown is derived state and may be regenerated or compacted.

If a new feature needs durable state, it should be represented in the database rather than only in markdown or logs.

### Evidence traceability is required

Durable conclusions must remain tied to evidence identifiers.

- Evidence tables store normalized primary records.
- Findings carry structured evidence references.
- Memory facts and timeline anchors include evidence references.
- Claims store linked `finding_ids`, `hypothesis_ids`, and `evidence_ids`.

Any new abstraction that summarizes or ranks evidence should preserve a path back to concrete evidence rows.

## Structured memory model

Structured memory is not a chat transcript. It is a bounded working set optimized for repeated LLM calls.

### Current memory files

| Path | Role | Durability |
|---|---|---|
| `memory/overview.md` | High-level case summary and current investigation policy | Regeneratable, compactable |
| `memory/tasks.md` | Active unresolved tasks and gaps | Regeneratable, compactable |
| `memory/facts.md` | Confirmed facts currently worth carrying in context | Regeneratable, not compacted by local trimming |
| `memory/timeline.md` | Important time anchors for active reasoning | Regeneratable, rotated into archive when long |
| `memory/entities/{user,host,ip}/*.md` | Stable cards for important entities | Regeneratable, LLM-compactable |
| `memory/hypotheses/*.md` | Per-hypothesis state cards | Regeneratable, LLM-compactable |
| `memory/keypoints/*.md` | Cards synced from the current findings snapshot | Regeneratable |
| `memory/evidence/suspicious.md` | Compact table of suspicious evidence selected during checks | Regeneratable, compactable |
| `memory/details/fact-NNN.md` | Detailed body for indexed facts | Regeneratable from durable evidence-backed updates |
| `memory/archive/*.md` | Archived but still readable historical memory fragments | Regeneratable |

### Memory update rules

Memory updates are append-only or upsert-style projections from investigation output.

- Facts are appended with deduplication based on normalized text plus evidence IDs.
- A fact written to `facts.md` is indexed and expanded into `memory/details/fact-NNN.md`.
- Timeline anchors are appended and rotated into `archive/timeline_archive.md` when the active list grows too long.
- Tasks are appended with a constrained kind: `internal_db_check`, `external_lookup`, or `human_decision`.
- Refuted hypotheses and resolved gaps are archived rather than deleted.
- Entity cards and hypothesis cards are upserted by stable identifiers.
- Keypoint cards are synchronized from the current findings snapshot and stale cards are removed.

### Memory compaction policy

Compaction exists to keep context small without destroying durable state.

- `overview.md` may be compacted with the LLM when it exceeds `LLM_MEMORY_MAX_BYTES`.
- Entity cards and hypothesis cards may also be compacted with the LLM.
- `tasks.md` and `evidence/suspicious.md` are compacted by trimming older rows.
- `facts.md`, `timeline.md`, `archive/refuted.md`, and `archive/resolved_gaps.md` are intentionally exempt from generic local compaction.

This means memory files do not share the same retention policy. Do not generalize one file's behavior to all memory files.

### Memory should stay reconstructable

Structured memory should remain a projection from database state plus prior evidence-backed investigation output.

- Do not store exclusive business logic only in memory markdown.
- Do not introduce state that can only be recovered from the latest prompt context.
- Prefer stable identifiers in filenames and index entries.
- Prefer additive history over in-place narrative rewriting, except for explicitly summarized files such as `overview.md`.

## Database responsibilities

### Split between `case.duckdb` and `trace.duckdb`

The database layer is intentionally split.

- `case.duckdb` stores evidence and durable investigation products.
- `trace.duckdb` stores execution trace and operational history.

At runtime, `trace.duckdb` is attached as the `trace` schema, and trace tables are also exposed through temporary views for reads. This allows query code to read a unified logical schema while preserving physical separation between durable case state and trace state.

### What belongs in Case State

The following categories belong in `case.duckdb`:

- Normalized evidence tables
- Findings produced from rules or evidence review
- Hypothesis records and their current durable status
- Report section bodies, support confidence, and gap state
- Claims that link report text back to evidence and findings
- Ingest bookkeeping such as file hashes

Case State should answer: "What does the case currently contain?"

### What belongs in Trace State

The following categories belong in `trace.duckdb`:

- Investigation session lifecycle
- Per-step planner and checker I/O
- Hypothesis reasoning trail entries
- Progress events emitted for UI or status tracking
- AI review history

Trace State should answer: "How did the system reach the current state?"

### Do not collapse the split

Do not use trace tables as a substitute for durable case objects. Do not put evidence-backed case conclusions only in trace history.

If a datum is needed after compaction, replay, or UI refresh as part of the current case state, it belongs in `case.duckdb`.

## Main DuckDB tables

### Core tables in `case.duckdb`

| Table | Responsibility |
|---|---|
| `evtx_events` | Normalized EVTX records |
| `mft_entries` | Normalized MFT entries |
| `mft_timeline` | Timeline rows derived from MFT timestamps |
| `findings` | Evidence-backed findings and their reviewable metadata |
| `hypotheses` | Durable hypothesis registry and current status |
| `report_sections` | Report body, confidence, status, gaps, and fill history |
| `claims` | Links between report assertions and supporting findings, hypotheses, and evidence |
| `ingested_files` | File identity and deduplication bookkeeping |

### Trace tables in `trace.duckdb`

| Table | Responsibility |
|---|---|
| `trace.ai_reviews` | AI review outputs tied to findings |
| `trace.investigation_sessions` | Investigation run boundaries and final status |
| `trace.investigation_steps` | Per-step planner/checker inputs and outputs |
| `trace.hypothesis_reasoning` | Reasoning trail per hypothesis |
| `trace.progress_events` | UI-facing progress stream history |

## Core model boundaries

| Term | Meaning |
|---|---|
| Evidence | Normalized raw records such as EVTX or MFT rows |
| Finding | An observed condition or signal derived from evidence |
| Hypothesis | An interpretation to validate or refute |
| Claim | A report statement presented to the human reader |
| Gap | Missing information that blocks confidence |

These boundaries matter.

- Evidence is raw or normalized source material.
- Findings are still evidence-near.
- Hypotheses are interpretive.
- Claims are report-facing.
- Gaps represent what is still unknown.

Mixing these layers makes it harder to audit reasoning and harder to resume a case safely.

## Finding lifecycle

`suppressed` is not deletion.

- A suppressed finding remains part of the durable case record.
- Suppression changes presentation and workflow semantics, not evidence existence.
- Evidence links must remain available even when a finding is suppressed.

## Report section state

`report_sections.status` currently uses four states:

- `draft`: the section still has evidence gaps or weak support
- `stable`: the section currently has no known gap from the AI workflow
- `ai_exhausted`: the AI workflow stopped producing meaningful additional leads
- `human_reviewed`: a human explicitly reviewed the section

These are workflow states, not evidence states.

## Report templates

Report templates are contributor-defined section contracts, not durable report state.

### Template ownership boundary

- Template files live under `src/forensia/report_template/`.
- Each initialized case also gets a case-local `report_template/` directory copied from the packaged defaults.
- CLI report generation prefers the case-local template directory when present.
- Contributors may also point `report-write` at an explicit `--template-dir`.

This means template files are inputs to report generation, while the generated section bodies live in `report_sections` in DuckDB.

### Template contract

Each template is a Markdown document with optional YAML frontmatter.

Current stable frontmatter fields are:

- `section`: stable section key used as the report section identity
- `title`: human-facing section title
- `prompt`: section-specific writing instructions for the LLM
- `evidence_queries`: read-only SQL queries whose results are summarized and supplied to the LLM

The template body is the structural scaffold the LLM completes. It is not stored as the durable section body after generation.

### Section identity and ordering

- Templates are discovered by filename pattern `[0-9]*_*.md`.
- Template refresh order is the lexical filename order.
- The durable `section_key` is taken from frontmatter `section` when present, otherwise the file stem is used.
- Report rendering orders sections by `section_key`.

Contributors should therefore treat section keys as stable identifiers. Renaming a file is less important than changing a section key.

### What belongs in templates

Templates should define:

- report structure
- section-local writing requirements
- evidence access requirements through `evidence_queries`
- explicit placeholders for unsupported statements

Templates should be authored in English.

- Frontmatter such as `title` and `prompt` should be written in English.
- The scaffold Markdown headings, table headers, comments, and placeholders should also be written in English.
- Output language for generated reports remains a runtime concern controlled by LLM settings; template authoring language is a contributor-facing convention.

Templates should not define:

- durable workflow state
- mutable report status
- provenance storage rules
- current section body as authoritative state

Those concerns belong in DuckDB, especially `report_sections` and `claims`.

### Template interaction with DB state

The template system writes durable report state back into the database.

- Completed section bodies are UPSERTed into `report_sections`.
- Confidence is derived from gap markers found in the generated body.
- Claims are extracted from the generated body and written into `claims`.
- Claim provenance is computed from the evidence query summaries, not from free-text citations alone.
- Gaps are parsed from explicit insufficient-evidence markers and fed back into later investigation cycles.

This is why section templates are not merely presentation assets. They define the contract between evidence-backed reporting and the investigation loop.

## SQL safety model

LLM-proposed SQL is treated as read-only evidence access.

- Only `SELECT` and `WITH` statements are accepted.
- Multiple statements are rejected.
- Destructive SQL is rejected.
- Queries are restricted to an allowlisted set of tables.

This boundary is fundamental to the current architecture. The model can propose evidence access, but it does not mutate the database through generated SQL.

## Built-in rule coverage

The bundled Windows rulepacks currently focus on:

- authentication and logon activity
- Kerberos and NTLM
- RDP
- PowerShell and LOLBas execution
- service- and task-based persistence
- account operations
- log tampering and audit changes
- Defender-related activity
- reboot and shutdown artifacts

Rules live under `src/forensia/rulepacks/windows/` and currently combine SQL, finding templates, and ATT&CK metadata.

## Profiles and rulepacks

Profiles define rule selection policy. Rulepacks define the actual detection logic.

### Rulepack contract

Rulepack files currently live under `src/forensia/rulepacks/windows/` and are YAML rule definitions.

Each rule has a stable contributor-facing shape:

- `id`: stable rule identifier
- `title`: human-facing rule title
- `severity`: default severity for generated findings
- `confidence`: default confidence for generated findings
- `query`: read-only SQL executed against normalized evidence
- `finding.title`: title template rendered from query row fields
- `finding.summary`: summary template rendered from query row fields
- `tags`: classification tags
- `attack`: ATT&CK mappings

Each result row from a rule query becomes one finding, with the originating row stored as structured evidence on that finding.

### Profile contract

Profiles currently live under `src/forensia/profiles/` and select subsets of the available rules.

Current stable profile fields are:

- `name`: profile name
- `rulepacks`: directories or paths under the rulepack root to include
- `rule_ids`: optional allowlist of specific rule IDs within the selected rulepacks

Conceptually:

- rulepacks choose the broad detection domain
- `rule_ids` narrows within that domain

Profiles are selection metadata. They should not duplicate rule logic.

### What should remain stable

- Rule IDs should be treated as persistent external identifiers.
- A profile should continue to mean "which rules are active", not "how those rules execute".
- Rule queries should remain read-only and evidence-oriented.
- Finding templates should remain row-driven so each finding preserves evidence traceability.
- Packaged rule metadata and finding text templates should be authored in English.

If contributors need new behavior that changes execution semantics rather than selection semantics, it likely belongs in the rule engine, not in the profile format.

### Allowlist and suppression model

`allowlist.yaml` is conceptually adjacent to profiles and rules, but it does not select rules.

- Profiles decide which rules run.
- Rules decide which candidate findings are generated.
- The allowlist decides which generated findings should be marked `suppressed` based on rule-scoped field matches.

The current allowlist model matches:

- one `rule_id`
- one or more field predicates under `when`
- values taken from the first structured evidence row on the generated finding

This is a post-generation presentation and triage control. It is not a pre-filter on evidence ingestion or rule execution.

### File layout conventions

- Keep packaged defaults in `src/forensia/report_template/`, `src/forensia/profiles/`, and `src/forensia/rulepacks/`.
- Treat case-local `report_template/` as an overrideable input copied at case initialization.
- Do not rely on case-local copies for profiles or rulepacks today; those are resolved from the package tree.

## UI considerations

- `forensia serve` serves the built UI through FastAPI.
- `web_ui/dist/` is a build artifact used for serving.
- When DuckDB is unavailable due to a lock, the UI falls back to `reports/api/*.json` snapshots.

## README boundary

Keep public-facing material in `README.md`.

README should cover:

- value proposition
- user-facing workflow
- high-level architecture
- installation and usage

`CONTRIBUTING.md` should cover:

- architectural invariants
- state ownership
- schema responsibilities
- investigation and memory semantics
- contributor-facing implementation constraints

## Investigation flags

| Flag | Default | When it matters |
|---|---|---|
| `--max-iter` | `20` | Increase only when longer investigation loops are needed |
| `--max-queries-per-hypothesis` | `5` | Tune how deeply one hypothesis can be explored |
| `--no-progress-limit` | `3` | Relax when you want to tolerate more low-signal cycles |
| `--report-every-n-cycles` | `1` | Increase when report refresh cost is too high |
| `--report-parallelism` | `1` | Increase only if the local LLM backend can handle concurrency |
| `--profile` | `windows-basic` | Switch to a different rule profile |
| `--report-only` | `false` | Refill report sections without running the hypothesis loop |

## Rerun semantics

- `forensia run` includes investigation by default.
- To reinitialize an output directory, use `--init`.
- `report` is render-only.
- `report-write` performs section refill before rendering.
