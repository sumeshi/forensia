# Code Map

A list of responsibilities for each file in `src/forensia/**`. A directory to use instead of grep.

## Interfaces and shared knowledge

| Path | Responsibilities |
|---|---|
| [src/forensia/pipeline.py](../src/forensia/pipeline.py) | Display-agnostic run entry (`run_investigation`): case open/init, `--rerun` reset, knowledge indexing, investigation-policy input resolution (`resolve_forensia_policy_input`), ingest/normalize/analyze/investigate/report stage assembly, `CaseTasks` wiring, `UsageError` for adapter-translatable input errors, and the trace-DB progress pusher. Imports no typer/rich; terminal text goes through the injected `status` callback |
| [src/forensia/cli/app.py](../src/forensia/cli/app.py) | Typer command declarations (`investigate` / `add` / `report`): thin adapter over the kernel entry; maps `UsageError` to `typer.BadParameter`, renders status/advise output, owns the LLM outage exit code |
| [src/forensia/cli/support.py](../src/forensia/cli/support.py) | CLI-facing status printing, case open (`_open_case_or_die`), LLM flag resolution |
| [src/forensia/cli/doctor.py](../src/forensia/cli/doctor.py) | Repository and installation health checks |
| [src/forensia/config.py](../src/forensia/config.py) | `.env`-based settings retrieval (`get_llm_settings`) |
| [src/forensia/knowledge/questions.py](../src/forensia/knowledge/questions.py) | Structured question specs and semantic routing |
| [src/forensia/knowledge/catalog.py](../src/forensia/knowledge/catalog.py) | Declarative DFIR catalog readers and SQL expansion |
| [src/forensia/knowledge/external.py](../src/forensia/knowledge/external.py) | Lazy scanning and section loading for an optional local knowledge folder |
| [src/forensia/knowledge/retrieval.py](../src/forensia/knowledge/retrieval.py) | Deterministic query-term generation and bounded knowledge snippet selection |

## core/

| Path | Responsibilities |
|---|---|
| [src/forensia/core/case.py](../src/forensia/core/case.py) | `Case` dataclass. Directory structure definition + `extract_time_range`; module-level `resolve_timezone`/`case_timezone` (explicit flag wins over manifest) |
| [src/forensia/core/case_tasks.py](../src/forensia/core/case_tasks.py) | `CaseTasks`: per-stage task bookkeeping (case_dir/tasks.md) |
| [src/forensia/core/memory.py](../src/forensia/core/memory.py) | `MemoryManager`. Read/write abstraction for `memory/*.md`, `EvidenceOnlyMemory` / `memory_for_section` |
| [src/forensia/core/memory_compaction.py](../src/forensia/core/memory_compaction.py) | LLM-based compaction of oversized memory files and the deterministic `timeline.md` regeneration from `case_timeline`. Every LLM-written condensation re-used in prompts carries a `> condensed:` source/currentness label (DB-derived cards regeneratable, authored files marked not retained); the zero-caller timeline projection validator was removed (R10) |
| [src/forensia/core/memory_context.py](../src/forensia/core/memory_context.py) | Scope-safe context assembly, hierarchical memory index, and `read_more` path allow-list |
| [src/forensia/core/compaction.py](../src/forensia/core/compaction.py) | Deterministic text compaction and truncation markers |
| [src/forensia/core/frontmatter.py](../src/forensia/core/frontmatter.py) | Markdown frontmatter parsing without workflow policy |
| [src/forensia/core/memory_writers.py](../src/forensia/core/memory_writers.py) | Fact / timeline / task / entity-card write helpers |
| [src/forensia/core/session.py](../src/forensia/core/session.py) | `SessionState` / `Hypothesis` / `PlannedQuery` Pydantic models. `Hypothesis` converts rule/LLM declarations into `verification_spec` once (before-validator) and exposes `confirm_when`/`refute_when`/`evidence_requirements` as derived properties |
| [src/forensia/core/verdicts.py](../src/forensia/core/verdicts.py) | Verdict allow-list from `verdict_taxonomy.yaml`, `assert_valid_verdict` |
| [src/forensia/core/evidence.py](../src/forensia/core/evidence.py) | evidence_id formatting helpers |
| [src/forensia/core/progress_event.py](../src/forensia/core/progress_event.py) | Typed progress event payloads |
| [src/forensia/core/log.py](../src/forensia/core/log.py) / [textutil.py](../src/forensia/core/textutil.py) / [timeutil.py](../src/forensia/core/timeutil.py) | Plain-text kernel log (`log`), structured-log parsing/normalization / text / time utilities |

## DB

| Path | Responsibilities |
|---|---|
| [src/forensia/db/database.py](../src/forensia/db/database.py) | `CaseDB` class. DuckDB connection (case + attached trace DB) + current schema initialization and latest-only version admission |
| [src/forensia/db/query.py](../src/forensia/db/query.py) | Query helpers (`fetch_records`, `normalize_value`) |
| [src/forensia/db/schema.py](../src/forensia/db/schema.py) | Table DDL definitions (case tables + `trace.*` tables) |
| [src/forensia/db/progress.py](../src/forensia/db/progress.py) | Durable progress-event recording/reading in the trace DB (`record_progress_event`, `list_progress_events`, cap of 1000 rows = bounded recent view) |

## Evidence (ingest + normalize)

| Path | Responsibilities |
|---|---|
| [src/forensia/evidence/ingest.py](../src/forensia/evidence/ingest.py) | `ingest_all` entry point. Scans input and dispatches to the appropriate parser |
| [src/forensia/evidence/artifacts.py](../src/forensia/evidence/artifacts.py) | Artifact adapter protocol, built-ins, and public registration point |
| [src/forensia/evidence/normalize.py](../src/forensia/evidence/normalize.py) / [invalidation.py](../src/forensia/evidence/invalidation.py) | raw JSONL → normalized DuckDB tables; optional source-key differential selection; dependent invalidation when a referenced ID is removed or (fingerprint survey) its backing content changed in place |
| [src/forensia/evidence/content_identity.py](../src/forensia/evidence/content_identity.py) | Canonical content fingerprint of a normalized evidence row (shared by link admission, read-time currentness, and the ingest-time invalidation survey) |
| [src/forensia/evidence/evtx.py](../src/forensia/evidence/evtx.py) / [mft.py](../src/forensia/evidence/mft.py) / [prefetch.py](../src/forensia/evidence/prefetch.py) | Per-artifact module: raw extraction (ingest half) + normalization SQL (normalize half) |
| [src/forensia/evidence/registry.py](../src/forensia/evidence/registry.py) | Content-based REGF/log detection, conservative dataset admission, lazy pinned `reg2es` streaming seam, and minimal lossless artifact/timeline projection |
| [src/forensia/db/evidence_lookup.py](../src/forensia/db/evidence_lookup.py) | Generic evidence ID lookup, including `registry-` IDs from `registry_artifacts` |
| [src/forensia/evidence/timeline_sql.py](../src/forensia/evidence/timeline_sql.py) | Timeline-staging SQL for the Prefetch timeline JSONL |
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
| [src/forensia/knowledge/coverage.py](../src/forensia/knowledge/coverage.py) | Coverage projection from `evidence_sources` (refresh/summary) + capability declaration reader + `derive_required_capabilities`, the single derivation owner for required capabilities (declared spec list → support-conditions inference). Also the spec/coverage ↔ schema/recipe correspondence owner (V2-08): `capability_disclosure_tables`/`disclosure_tables_for_spec` map Spec capabilities to the artifact families' tables/primary cards read from `artifact_capabilities.yaml` — the same declaration file Coverage uses |

## AI — investigation loop (`ai/investigation/`)

| Path | Responsibilities |
|---|---|
| [src/forensia/ai/investigation/investigator.py](../src/forensia/ai/investigation/investigator.py) | `investigate(...)` entry point: plan-cycle loop, report phase, termination, LLM budget. Installs the SIGINT owner (signal → `ctx.interrupted` flag) and persists the session terminal receipt before fallible projections in its `finally` |
| [src/forensia/ai/investigation/investigation_cycle.py](../src/forensia/ai/investigation/investigation_cycle.py) | One plan cycle: broad plan (gap identify → hypothesis draft) + hypothesis loop body; delegates eligibility/ranking to the single selector in `selection.py`. Imports the HTTP transport lazily inside the broad-plan function |
| [src/forensia/ai/investigation/work_judgment.py](../src/forensia/ai/investigation/work_judgment.py) | The one read-side work judgment (V2-03): `judge_work` per work ref (runnable/blockers+owner, ready = any `available`/`partial` Coverage row), `spec_capabilities`/`load_spec_capabilities`, `coverage_readiness`, `open_work_refs` (linked Gap/Task/Hypothesis merged into one ref), and the inconclusive counter. Also `work_context_snapshot` (V2-07): the deterministic per-attempt Case/Trace context (work/spec, unmet conditions, assessed support/contradiction by derivation root with currentness, open requirements) rendered by `prompt_investigation.render_work_context`. Read result only — no Agenda table/cache/status; written output stays in `work_state.py` |
| [src/forensia/ai/investigation/selection.py](../src/forensia/ai/investigation/selection.py) | Next-best hypothesis selection: deterministic priority scoring (admitted-work references, evidence-facing factors; no report-prose/stale/confidence terms), eligibility via the shared work judgment, focus selection |
| [src/forensia/ai/investigation/work_state.py](../src/forensia/ai/investigation/work_state.py) | Write owner of stop-time classification into Gap/Task work (capability/source snapshot, `retry_condition` from the shared judgment), and of reopen: the saved `retry_condition` is checked against current readiness, not re-derived from `kind` |
| [src/forensia/ai/investigation/case_policy.py](../src/forensia/ai/investigation/case_policy.py) | The one FORENSIA.md investigation-policy owner (V2-05): input shape, section extraction (objective/scope/priority/constraints/guidance), run-start adoption decision against the recorded receipt (`decide_policy` — resume re-applies the recorded revision and surfaces a differing file; explicit path is the reload), the `forensia-md` step receipt, objective extraction for the work-admission objective seam, and the host-fixed `<CASE_INSTRUCTIONS>` prompt framing for the investigation roles |
| [src/forensia/ai/investigation/investigation_session.py](../src/forensia/ai/investigation/investigation_session.py) | Session setup, memory-context caches, step logging, keypoint-card sync, `persist_session_terminal_receipt`; records the adopted `forensia-md` and `report-input` receipts at session start. `reconcile_stale_sessions` abandons only an expired `running` lease and keeps past terminal reasons as written (R07) |
| [src/forensia/ai/investigation/planner.py](../src/forensia/ai/investigation/planner.py) | `plan_hypothesis_query`: bounded action eligibility (`memory.read_more` → `sql.query`) → one LLM recipe/fallback-SQL decision → deterministic host validation. Builds the deterministic `<WORK_CONTEXT source="case_db">` from Case/Trace (V2-07), deduplicates Trace reasoning delivery (check bodies live only in `<PRIOR_ATTEMPTS>`), and assembles the V2-08 single disclosure pathway: spec capabilities → schema cards / template subset / playbook gating through the coverage correspondence, with the adopted selection persisted in the `plan-hypothesis` step `"_disclosure"` payload |
| [src/forensia/ai/investigation/memory_sync.py](../src/forensia/ai/investigation/memory_sync.py) | `_apply_memory_updates`: checker output → facts / timeline / tasks / entities / hypothesis cards |
| [src/forensia/ai/report_gap.py](../src/forensia/ai/report_gap.py) | Report status building + gap → hypothesis injection; `evaluation_snapshot`/`report_cycle_progress` compare durable semantic state (open work refs, observation/contradiction roots, source/Coverage identity) at the loop's commit point; prose never qualifies |
| [src/forensia/ai/investigation/progress.py](../src/forensia/ai/investigation/progress.py) | `HypothesisProgressTracker`: query fingerprinting, duplicate-attempt pivot, and consecutive inconclusive counters passed to Settlement |
| [src/forensia/ai/audit.py](../src/forensia/ai/audit.py) | `LLMCallLogger`: per-phase prompt/response logs under `ai_logs/`, call counting |
| [src/forensia/ai/llm_telemetry.py](../src/forensia/ai/llm_telemetry.py) | Session-scoped logical-call/provider-attempt/deterministic-operation receipts in the existing Trace DB |
| [src/forensia/ai/compaction.py](../src/forensia/ai/compaction.py) | Fail-open LLM compaction with deterministic fallback and required-token validation. The context-overflow reduction (`structured_compact`) is one-way: it keeps the latest sections verbatim, preserves essential refs, and states what is preserved — no version/regeneratable labels (R10) |
| [src/forensia/ai/retrieval_telemetry.py](../src/forensia/ai/retrieval_telemetry.py) | Observational retrieval events plus the versioned tool-receipt and one-attempt Retrieval Evaluation contracts; never assigns Evidence roles or verdicts |
| [src/forensia/ai/case_profile.py](../src/forensia/ai/case_profile.py) | Session-owned case profile (observed event IDs / artifact families), current DB availability reads, profile advisor; no process-wide case cache |

## AI — subpackages

| Path | Responsibilities |
|---|---|
| [src/forensia/ai/llm/](../src/forensia/ai/llm/) | LLM transport: `llm_client.py` (chat-completion client with retry/outage recovery/context handling; imports httpx lazily so kernel imports stay display-free), `attempt.py` (one HTTP attempt as a durable provider-attempt receipt), `request_metadata.py` (bounded fingerprints/section metadata), `llm_gateway.py` (`request_llm_json`), `json_response.py` (JSON parse/repair), `schemas.py` (output JSON schemas) |
| [src/forensia/ai/prompts/](../src/forensia/ai/prompts/) | Prompt builders: `prompt_investigation.py` (planner/checker builders; the plan-side builders prepend the adopted `<CASE_INSTRUCTIONS>` policy block, the checker builders never receive it; both disclose from the V2-08 single spec/capability pathway — playbook artifact gating, `<TEMPLATE_CATALOG>` executable subset, and schema-card selection passed by the planner), `prompt_sections.py` (section agent), `report_evidence_projection.py` (report-only semantic projection of large evidence sets; persisted IDs remain authoritative), `prompt_context.py` (context slimming, budget guard; `_build_schema_guidance` multi-card selection and knowledge-block telemetry with `doc#heading` refs), `prompt_playbook.py` (`_dfir_playbook`), `sql_schema.py` (schema cards, allowed tables), `sql_templates.py` (query template catalog from `_schema/query_templates.yaml` + `validate_select_sql` + `query_template_catalog_for_tables`, the bounded template disclosure subset keyed to a work's artifact tables) |
| [src/forensia/ai/hypotheses/](../src/forensia/ai/hypotheses/) | Hypothesis lifecycle: `hypothesis_model.py` (parsing), `hypothesis_manager.py` (merge/dedup/resolve), `hypothesis_store.py` (DB persistence), `hypothesis_runner.py` (per-hypothesis orchestration), `execution.py` (existing SQL fallback and receipt assembly), `seeding.py` (rule-seeded findings/hypotheses) |
| [src/forensia/core/verification.py](../src/forensia/core/verification.py) | Versioned `VerificationSpec` model, the one-time declaration→spec conversion seam (`from_declaration`, incl. `co_observed_event_ids` sanitization), and the shared evaluable support-condition vocabulary (`EVALUABLE_CONDITION_KEYS`) that admission and Assessment both use. Hypothesis state and storage carry the spec only. |
| [src/forensia/ai/checking/](../src/forensia/ai/checking/) | Query-result boundaries: `checker.py` (LLM proposal/finding extraction/memory updates), `assessment.py` (`VerificationSpec` + observation → Evidence role; evaluates the shared condition vocabulary incl. `event_contexts` via the co-observation adapter, unsupported keys fail closed with an explicit reason; the derivation root derives from the observed content, never the query), `sufficiency.py` (assessed-link aggregation; `derivation_root_key` groups links by declared root or evidence row+source, read-time `evidence_link_currentness` incl. the content fingerprint), `settlement.py` (settlement gates/state transition, same root grouping), `check_guardrails.py` (checker proposal and correlation consistency), `check_normalize.py` (result summarization), `check_apply.py` (DB application); `sufficiency.py` writes each link with its own judgment grounds (`assessment_reason`/`matched_conditions`, schema v5) and never updates an existing link — re-evaluation adds a new one (R08) |
| [src/forensia/ai/sections/](../src/forensia/ai/sections/) | Report-section agents: `section_refresher.py` (refresh entry point), `section_agent.py` (per-block agent), `section_block_plan.py` / `section_block_context.py` / `section_block_narrative.py` (plan / context / narrate phases), `section_exec.py` (query execution), `section_answers.py` (structured answer formatting), `section_run_store.py` (run/evidence/fact persistence) |

## Report

| Path | Responsibilities |
|---|---|
| [src/forensia/report/render/writer.py](../src/forensia/report/render/writer.py) | Final report output: `build_report_markdown_from_db`, `render_written_report` (report.md + HTML) |
| [src/forensia/report/sections/template_parsing.py](../src/forensia/report/sections/template_parsing.py) | Template frontmatter / block-hint parsing |
| [src/forensia/report/sections/report_input.py](../src/forensia/report/sections/report_input.py) | REPORT.md / `--template-dir` → `SectionSource` normalization (`#` heading = section, `##` = block, `NN_<slug>` revision-local keys, duplicate headings rejected); adopted revision selection, active section keys, and the input/output same-file guard |
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
| [src/forensia/report/metrics.py](../src/forensia/report/metrics.py) | DuckDB-authoritative report metrics (event counts, normalized hosts, artifact/source coverage) shared by tables and prompts |
| [src/forensia/report/report_validation.py](../src/forensia/report/report_validation.py) | Final report output validation and deterministic publication-readiness projection |
| [src/forensia/report/render/markdown.py](../src/forensia/report/render/markdown.py) | Markdown table utilities, timestamp rendering with timezone |
| [src/forensia/report/render/html.py](../src/forensia/report/render/html.py) | Markdown → HTML rendering + report page build (jinja2 templates in [templates/](../src/forensia/report/render/templates/)) |
| [src/forensia/report/evidence_refs.py](../src/forensia/report/evidence_refs.py) / [evidence_map.py](../src/forensia/report/render/evidence_map.py) | evidence_id patterns / evidence map export |
| [src/forensia/report/finding_themes.py](../src/forensia/report/finding_themes.py) | Finding theme classification / titles for overview & HTML (definitions in `_schema/finding_themes.yaml`) |
| [src/forensia/report/answers/gap_tables.py](../src/forensia/report/answers/gap_tables.py) / [summary_rows.py](../src/forensia/report/answers/summary_rows.py) / [table_registry.py](../src/forensia/report/answers/table_registry.py) | Deterministic table builders (`mode: table` blocks) |
| [src/forensia/report/report_validation.py](../src/forensia/report/report_validation.py) | Final report output validation (doctor self-check) |
| [src/forensia/report/benign_auth.py](../src/forensia/report/benign_auth.py) / [narrative_review.py](../src/forensia/report/sections/narrative_review.py) / [section_taxonomy.py](../src/forensia/report/sections/section_taxonomy.py) | Benign-auth scoping (policy in `_schema/benign_auth.yaml`) / narrative review / section family taxonomy |

Report admission is implemented in `ai/report_gap.py` using the existing Gap/Task
rows; `report_cycle_progress` compares `evaluation_snapshot` reads (open work
refs, observation/contradiction derivation roots, source/Coverage identity) taken
at the loop's state-commit point.
