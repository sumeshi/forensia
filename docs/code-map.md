# Code Map

A list of responsibilities for each file in `src/forensia/**`. A directory to use instead of grep.

## Interfaces and shared knowledge

| Path | Responsibilities |
|---|---|
| [src/forensia/cli/app.py](../src/forensia/cli/app.py) | Typer command declarations (`investigate` / `add` / `report` / `serve`) |
| [src/forensia/cli/stages.py](../src/forensia/cli/stages.py) | Pipeline stage runners used by `investigate` |
| [src/forensia/cli/support.py](../src/forensia/cli/support.py) | Case open/reset, progress, profile/template/timezone resolution |
| [src/forensia/cli/doctor.py](../src/forensia/cli/doctor.py) | Repository and installation health checks |
| [src/forensia/web/app.py](../src/forensia/web/app.py) | FastAPI routes and snapshot/DB fallback |
| [src/forensia/config.py](../src/forensia/config.py) | `.env`-based settings retrieval (`get_llm_settings`) |
| [src/forensia/knowledge/questions.py](../src/forensia/knowledge/questions.py) | Structured question specs and semantic routing |
| [src/forensia/knowledge/catalog.py](../src/forensia/knowledge/catalog.py) | Declarative DFIR catalog readers and SQL expansion |
| [src/forensia/knowledge/external.py](../src/forensia/knowledge/external.py) | Lazy scanning and section loading for an optional local knowledge folder |
| [src/forensia/knowledge/retrieval.py](../src/forensia/knowledge/retrieval.py) | Deterministic query-term generation and bounded knowledge snippet selection |

## core/

| Path | Responsibilities |
|---|---|
| [src/forensia/core/case.py](../src/forensia/core/case.py) | `Case` dataclass. Directory structure definition + `extract_time_range` |
| [src/forensia/core/case_tasks.py](../src/forensia/core/case_tasks.py) | `CaseTasks`: per-stage task bookkeeping |
| [src/forensia/core/memory.py](../src/forensia/core/memory.py) | `MemoryManager`. Read/write abstraction for `memory/*.md`, `EvidenceOnlyMemory` / `memory_for_section` |
| [src/forensia/core/memory_compaction.py](../src/forensia/core/memory_compaction.py) | LLM-based compaction of oversized memory files |
| [src/forensia/core/memory_context.py](../src/forensia/core/memory_context.py) | Scope-safe context assembly, hierarchical memory index, and `read_more` path allow-list |
| [src/forensia/core/compaction.py](../src/forensia/core/compaction.py) | Deterministic text compaction and truncation markers |
| [src/forensia/core/frontmatter.py](../src/forensia/core/frontmatter.py) | Markdown frontmatter parsing without workflow policy |
| [src/forensia/core/memory_writers.py](../src/forensia/core/memory_writers.py) | Fact / timeline / task / entity-card write helpers |
| [src/forensia/core/session.py](../src/forensia/core/session.py) | `SessionState` / `Hypothesis` / `PlannedQuery` Pydantic models |
| [src/forensia/core/verdicts.py](../src/forensia/core/verdicts.py) | Verdict allow-list from `verdict_taxonomy.yaml`, `assert_valid_verdict` |
| [src/forensia/core/evidence.py](../src/forensia/core/evidence.py) | evidence_id formatting helpers |
| [src/forensia/core/progress_event.py](../src/forensia/core/progress_event.py) | Typed progress event payloads |
| [src/forensia/core/log.py](../src/forensia/core/log.py) / [textutil.py](../src/forensia/core/textutil.py) / [timeutil.py](../src/forensia/core/timeutil.py) | Logging / text / time utilities |

## DB

| Path | Responsibilities |
|---|---|
| [src/forensia/db/database.py](../src/forensia/db/database.py) | `CaseDB` class. DuckDB connection (case + attached trace DB) + schema initialization + migration |
| [src/forensia/db/query.py](../src/forensia/db/query.py) | Query helpers (`fetch_records`, `normalize_value`) |
| [src/forensia/db/schema.py](../src/forensia/db/schema.py) | Table DDL definitions (case tables + `trace.*` tables) |

## Evidence (ingest + normalize)

| Path | Responsibilities |
|---|---|
| [src/forensia/evidence/ingest.py](../src/forensia/evidence/ingest.py) | `ingest_all` entry point. Scans input and dispatches to the appropriate parser |
| [src/forensia/evidence/artifacts.py](../src/forensia/evidence/artifacts.py) | Artifact adapter protocol, built-ins, and public registration point |
| [src/forensia/evidence/normalize.py](../src/forensia/evidence/normalize.py) / [invalidation.py](../src/forensia/evidence/invalidation.py) | raw JSONL → normalized DuckDB tables; optional source-key differential selection; removed referenced-evidence invalidation |
| [src/forensia/evidence/evtx.py](../src/forensia/evidence/evtx.py) / [mft.py](../src/forensia/evidence/mft.py) / [prefetch.py](../src/forensia/evidence/prefetch.py) | Per-artifact module: raw extraction (ingest half) + normalization SQL (normalize half) |
| [src/forensia/evidence/registry.py](../src/forensia/evidence/registry.py) | Content-based REGF/log detection, conservative dataset admission, lazy pinned `reg2es` streaming seam, and minimal lossless artifact/timeline projection |
| [src/forensia/db/evidence_lookup.py](../src/forensia/db/evidence_lookup.py) | Generic evidence ID lookup, including `registry-` IDs from `registry_artifacts` |
| [src/forensia/evidence/timeline_sql.py](../src/forensia/evidence/timeline_sql.py) | Timeline-staging SQL for Prefetch and legacy MFT timeline-only JSONL |
| [src/forensia/evidence/timezone.py](../src/forensia/evidence/timezone.py) | `infer_timezone`: source timezone inference from evidence |

## Knowledge (rules / rulepacks / profiles)

| Path | Responsibilities |
|---|---|
| [src/forensia/knowledge/resources.py](../src/forensia/knowledge/resources.py) | Canonical paths for packaged knowledge data (`rulepacks_dir`/`schema_dir`/`profiles_dir`/`profile_path`) |
| [src/forensia/knowledge/rules/loader.py](../src/forensia/knowledge/rules/loader.py) | Loads `rulepacks/**/*.yaml` + profile filtering + `resolve_active_packs` (auto-rulepacks) |
| [src/forensia/knowledge/rules/models.py](../src/forensia/knowledge/rules/models.py) | Pydantic models (`Rule`, `Finding`, `HypothesisDeclaration`, `AttackEntry`, ...) |
| [src/forensia/knowledge/rules/engine.py](../src/forensia/knowledge/rules/engine.py) | Rule SQL execution + finding generation + `fallback_search` + timeline feeding |
| [src/forensia/knowledge/rulepacks/](../src/forensia/knowledge/rulepacks/) | YAML rule definitions (windows/, leakage/, _schema/) |
| [src/forensia/knowledge/profiles/](../src/forensia/knowledge/profiles/) | Profile YAML (rule selection policy) |

## AI — investigation loop (`ai/investigation/`)

| Path | Responsibilities |
|---|---|
| [src/forensia/ai/investigation/investigator.py](../src/forensia/ai/investigation/investigator.py) | `investigate(...)` entry point: plan-cycle loop, report phase, termination, LLM budget |
| [src/forensia/ai/investigation/investigation_cycle.py](../src/forensia/ai/investigation/investigation_cycle.py) | One plan cycle: broad plan (gap identify → hypothesis draft) + hypothesis loop body |
| [src/forensia/ai/investigation/investigation_session.py](../src/forensia/ai/investigation/investigation_session.py) | Session setup, memory-context caches, step logging, keypoint-card sync |
| [src/forensia/ai/investigation/planner.py](../src/forensia/ai/investigation/planner.py) | `plan_hypothesis_query`: bounded action eligibility/validation (`memory.read_more` → `sql.query`) → scoped memory evaluation → query intent → SQL self-check → SQL composition (≤3 validation retries) |
| [src/forensia/ai/investigation/memory_sync.py](../src/forensia/ai/investigation/memory_sync.py) | `_apply_memory_updates`: checker output → facts / timeline / tasks / entities / hypothesis cards |
| [src/forensia/ai/report_gap.py](../src/forensia/ai/report_gap.py) | Report status building + gap → hypothesis injection |
| [src/forensia/ai/investigation/progress.py](../src/forensia/ai/investigation/progress.py) | `HypothesisProgressTracker`: query fingerprinting, auto-confirm / refute / pivot decisions |
| [src/forensia/ai/audit.py](../src/forensia/ai/audit.py) | `LLMCallLogger`: per-phase prompt/response logs under `ai_logs/`, call counting |
| [src/forensia/ai/compaction.py](../src/forensia/ai/compaction.py) | Fail-open LLM compaction with deterministic fallback and required-token validation |
| [src/forensia/ai/retrieval_telemetry.py](../src/forensia/ai/retrieval_telemetry.py) | Observational retrieval events plus the versioned tool-receipt and one-attempt Retrieval Evaluation contracts; never assigns Evidence roles or verdicts |
| [src/forensia/ai/case_profile.py](../src/forensia/ai/case_profile.py) | Case profile (observed event IDs / artifact families) + profile advisor |

## AI — subpackages

| Path | Responsibilities |
|---|---|
| [src/forensia/ai/llm/](../src/forensia/ai/llm/) | LLM transport: `llm_client.py` (HTTP + outage recovery), `llm_gateway.py` (`request_llm_json`), `json_response.py` (JSON parse/repair), `schemas.py` (output JSON schemas) |
| [src/forensia/ai/prompts/](../src/forensia/ai/prompts/) | Prompt builders: `prompt_investigation.py` (planner/checker), `prompt_sections.py` (section agent), `prompt_context.py` (context slimming, budget guard), `prompt_playbook.py` (`_dfir_playbook`), `sql_schema.py` (schema cards, allowed tables), `sql_templates.py` (query template catalog from `_schema/query_templates.yaml` + `validate_select_sql`) |
| [src/forensia/ai/hypotheses/](../src/forensia/ai/hypotheses/) | Hypothesis lifecycle: `hypothesis_model.py` (parsing), `hypothesis_manager.py` (merge/dedup/resolve), `hypothesis_store.py` (DB persistence), `hypothesis_runner.py` (per-hypothesis orchestration), `execution.py` (existing SQL fallback and receipt assembly), `seeding.py` (rule-seeded findings/hypotheses) |
| [src/forensia/core/verification.py](../src/forensia/core/verification.py) | Versioned `VerificationSpec` model and lossless legacy-field normalization/projection used by all hypothesis creation and persistence paths |
| [src/forensia/ai/checking/](../src/forensia/ai/checking/) | Query-result boundaries: `checker.py` (LLM proposal/finding extraction/memory updates), `assessment.py` (`VerificationSpec` + observation → Evidence role), `sufficiency.py` (assessed-link aggregation), `settlement.py` (settlement gates/state transition), `check_guardrails.py` (checker proposal and correlation consistency), `check_normalize.py` (result summarization), `check_apply.py` (DB application) |
| [src/forensia/ai/sections/](../src/forensia/ai/sections/) | Report-section agents: `section_refresher.py` (refresh entry point), `section_agent.py` (per-block agent), `section_block_plan.py` / `section_block_context.py` / `section_block_narrative.py` (plan / context / narrate phases), `section_exec.py` (query execution), `section_answers.py` (structured answer formatting), `section_run_store.py` (run/evidence/fact persistence) |

## Report

| Path | Responsibilities |
|---|---|
| [src/forensia/report/render/writer.py](../src/forensia/report/render/writer.py) | Final report output: `build_report_markdown_from_db`, `render_written_report` (report.md + HTML) |
| [src/forensia/report/sections/template_parsing.py](../src/forensia/report/sections/template_parsing.py) | Template frontmatter / block-hint parsing |
| [src/forensia/report/sections/section_assembly.py](../src/forensia/report/sections/section_assembly.py) | Section render request assembly (`prepare_section_request`, block requests, keypoints) |
| [src/forensia/report/sections/section_finalize.py](../src/forensia/report/sections/section_finalize.py) | `finalize_section`: quality gates → claims → persistence → gaps |
| [src/forensia/report/sections/section_quality.py](../src/forensia/report/sections/section_quality.py) | Section body validation: evidence-id checks, claim gaps, confidence, `collect_gaps` |
| [src/forensia/report/sections/quality_gates.py](../src/forensia/report/sections/quality_gates.py) | `_quality_gate_section`: deterministic checks inferred from report Markdown and evidence context |
| [src/forensia/report/sections/section_store.py](../src/forensia/report/sections/section_store.py) | `report_sections` / `claims` DB access + debug JSON dumps |
| [src/forensia/report/answers/keypoint_catalog.py](../src/forensia/report/answers/keypoint_catalog.py) | `REPORT_KEYPOINTS` catalog + `_default_keypoints_for_section` |
| [src/forensia/report/answers/keypoint_sql.py](../src/forensia/report/answers/keypoint_sql.py) + [keypoints_*.py](../src/forensia/report/answers/) | Keypoint resolver implementations (activity / host-account / overview-IOC / report-meta) |
| [src/forensia/report/answers/answer_store.py](../src/forensia/report/answers/answer_store.py) | Structured answer normalization, Markdown rendering, JSON/CSV persistence (`reports/structured/`) |
| [src/forensia/report/answers/answer_registry.py](../src/forensia/report/answers/answer_registry.py) + [answer_builders_*.py](../src/forensia/report/answers/) | Deterministic answer builders (host / artifact questions) + universal question probes |
| [src/forensia/report/report_brief.py](../src/forensia/report/report_brief.py) | `report_brief.json` builder (LLM context summary) |
| [src/forensia/report/render/markdown.py](../src/forensia/report/render/markdown.py) | Markdown table utilities, timestamp rendering with timezone |
| [src/forensia/report/render/html.py](../src/forensia/report/render/html.py) | Markdown → HTML rendering + report page build (jinja2 templates in [templates/](../src/forensia/report/render/templates/)) |
| [src/forensia/report/evidence_refs.py](../src/forensia/report/evidence_refs.py) / [evidence_map.py](../src/forensia/report/render/evidence_map.py) | evidence_id patterns / evidence map export |
| [src/forensia/report/finding_themes.py](../src/forensia/report/finding_themes.py) | Finding theme classification / titles for overview & HTML (definitions in `_schema/finding_themes.yaml`) |
| [src/forensia/report/answers/gap_tables.py](../src/forensia/report/answers/gap_tables.py) / [summary_rows.py](../src/forensia/report/answers/summary_rows.py) / [table_registry.py](../src/forensia/report/answers/table_registry.py) | Deterministic table builders (`mode: table` blocks) |
| [src/forensia/report/report_validation.py](../src/forensia/report/report_validation.py) | Final report output validation (doctor self-check) |
| [src/forensia/report/benign_auth.py](../src/forensia/report/benign_auth.py) / [narrative_review.py](../src/forensia/report/sections/narrative_review.py) / [section_taxonomy.py](../src/forensia/report/sections/section_taxonomy.py) | Benign-auth scoping (policy in `_schema/benign_auth.yaml`) / narrative review / section family taxonomy |

## API / Web

| Path | Responsibilities |
|---|---|
| [src/forensia/api/dto.py](../src/forensia/api/dto.py) | Pydantic DTO definitions |
| [src/forensia/api/service.py](../src/forensia/api/service.py) | DB → DTO conversion. Aggregation queries for UI / report_brief |
| [src/forensia/api/cache.py](../src/forensia/api/cache.py) | API snapshot writes (`write_volatile_api_snapshots` / `write_full_api_snapshots` / `write_progress_snapshot`) and durable revision metadata |
| [src/forensia/api/progress.py](../src/forensia/api/progress.py) | Persist and list progress events |
| [src/forensia/report/section_views.py](../src/forensia/report/section_views.py) | Report-section DTO projection and server-side Markdown/HTML body rendering |
| [src/forensia/web/app.py](../src/forensia/web/app.py) | FastAPI router. Returns `/api/*` from snapshot or DB fallback and exposes live snapshot staleness metadata |
| [web_ui/](../web_ui/) | Svelte + Vite + Tailwind frontend. UI updates via snapshot polling |

Report admission is implemented in `ai/report_gap.py` using the existing Gap/Task
rows; `report_cycle_progress` compares semantic Case State snapshots.

## Related: root documents / templates

| Path | Contents |
|---|---|
| [scripts/](../scripts/) | Auxiliary scripts (`audit_schema_coverage.py`, `regenerate_playbook.py`, `check_imports.py`, etc.) |
| [tests/](../tests/) | pytest tests (split per module under test) |
| [src/forensia/knowledge/rulepacks/_schema/](../src/forensia/knowledge/rulepacks/_schema/) | Schema definition YAML (`evtx_events.yaml`, `question_routing.yaml`, `verdict_taxonomy.yaml`, `playbook/`, etc.) |
| [src/forensia/report/templates/](../src/forensia/report/templates/) | Default report template Markdown (copied into each case) |
| [src/forensia/report/render/templates/](../src/forensia/report/render/templates/) | jinja2 templates for the HTML report page (`report.html.j2` + `report.css.j2`) |
