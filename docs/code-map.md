# Code Map

A list of responsibilities for each file in `src/forensia/**`. A directory to use instead of grep.

## CLI / Core

| Path | Responsibilities |
|---|---|
| [src/forensia/cli.py](../src/forensia/cli.py) | typer-based CLI command declarations (`investigate` / `add` / `report` / `templates-export`, etc.), DB lifecycle, progress emit |
| [src/forensia/config.py](../src/forensia/config.py) | `.env`-based settings retrieval (`get_llm_settings`) |
| [src/forensia/core/case.py](../src/forensia/core/case.py) | `Case` dataclass. Directory structure definition + `extract_time_range` (extracts first/last event from DuckDB) |
| [src/forensia/core/memory.py](../src/forensia/core/memory.py) | `MemoryManager`. Read/write abstraction for `memory/*.md` |

## DB

| Path | Responsibilities |
|---|---|
| [src/forensia/db/database.py](../src/forensia/db/database.py) | `CaseDB` class. DuckDB connection + schema initialization + migration |
| [src/forensia/db/query.py](../src/forensia/db/query.py) | Query helpers (`fetch_records`, `normalize_value`) |
| [src/forensia/db/schema.py](../src/forensia/db/schema.py) | Table DDL definitions |

## Ingest

| Path | Responsibilities |
|---|---|
| [src/forensia/ingest/__init__.py](../src/forensia/ingest/__init__.py) | `ingest_all` entry point. Scans raw/ and dispatches to the appropriate parser |
| [src/forensia/ingest/evtx.py](../src/forensia/ingest/evtx.py) | EVTX → `evtx_events` ingestion |
| [src/forensia/ingest/mft.py](../src/forensia/ingest/mft.py) | MFT → `mft_entries` + `mft_timeline` ingestion |
| [src/forensia/ingest/prefetch.py](../src/forensia/ingest/prefetch.py) | Prefetch → `prefetch_executions` + `prefetch_timeline` ingestion |

## Rules

| Path | Responsibilities |
|---|---|
| [src/forensia/rules/loader.py](../src/forensia/rules/loader.py) | Loads `rulepacks/**/*.yaml` + profile filtering |
| [src/forensia/rules/models.py](../src/forensia/rules/models.py) | Pydantic models (`Rule`, `Finding`, `Hypothesis`, `AttackEntry`, ...) |
| [src/forensia/rules/engine.py](../src/forensia/rules/engine.py) | Rule SQL execution + finding generation + `fallback_search` triggering |
| [src/forensia/rulepacks/](../src/forensia/rulepacks/) | YAML rule definitions (windows/, leakage/, _schema/) |

## AI / Hypothesis investigation

| Path | Responsibilities |
|---|---|
| [src/forensia/ai/investigator.py](../src/forensia/ai/investigator.py) | Hypothesis investigation loop. `broad_plan` / `_investigate_one_hypothesis` / `_apply_memory_updates` / tracking |
| [src/forensia/ai/planner.py](../src/forensia/ai/planner.py) | Hypothesis verification query planning. `plan_hypothesis_query` runs three stages: `query_intent_planner` → `sql_self_check` → `sql_composer` |
| [src/forensia/ai/checker.py](../src/forensia/ai/checker.py) | Hypothesis verdict. `_check_query` calls `verdict_reviewer` → `finding_extractor` → `memory_updater` |
| [src/forensia/ai/section_agent.py](../src/forensia/ai/section_agent.py) | Per-block report section flow: query → narrate → finalize. Narrator logic such as `_narrate_paragraph_with_retry` |
| [src/forensia/ai/section_refresher.py](../src/forensia/ai/section_refresher.py) | Regeneration entry point for existing sections |
| [src/forensia/ai/prompts.py](../src/forensia/ai/prompts.py) | LLM prompt construction (`build_*_messages` functions) |
| [src/forensia/ai/schemas.py](../src/forensia/ai/schemas.py) | LLM output JSON schemas (`MEMORY_UPDATER_SCHEMA`, `VERDICT_REVIEW_SCHEMA`, `PARAGRAPH_NARRATE_SCHEMA`, ...) |
| [src/forensia/ai/llm_client.py](../src/forensia/ai/llm_client.py) | OpenAI-compatible LLM client (`chat_completion` / `async_chat_completion`). HTTP retry + schema mode auto-downgrade + `_SCHEMA_MODE_CACHE` |
| [src/forensia/ai/json_response.py](../src/forensia/ai/json_response.py) | JSON-returning LLM calls (`request_llm_json` / `async_request_llm_json`) |
| [src/forensia/ai/sql_schema.py](../src/forensia/ai/sql_schema.py) | SQL generation support. Retrieves live schema from `information_schema` and injects it into prompts |
| [src/forensia/ai/sql_templates.py](../src/forensia/ai/sql_templates.py) | Template SQL catalog (template_id → SQL) |
| [src/forensia/questions.py](../src/forensia/questions.py) | Structured question templates + answer_spec → builder routing |
| [src/forensia/ai/report_gap.py](../src/forensia/ai/report_gap.py) | Gap detection in report sections + conversion to hypotheses |

## Report

| Path | Responsibilities |
|---|---|
| [src/forensia/report/writer.py](../src/forensia/report/writer.py) | Main report formatting body. `REPORT_KEYPOINTS` catalog, `build_report_markdown_from_db`, `finalize_section`, `_render_structured_answer_markdown`, claim extraction, coverage aggregation |
| [src/forensia/report/html.py](../src/forensia/report/html.py) | Markdown → HTML conversion |

## API / Web

| Path | Responsibilities |
|---|---|
| [src/forensia/api/dto.py](../src/forensia/api/dto.py) | Pydantic DTO definitions |
| [src/forensia/api/service.py](../src/forensia/api/service.py) | DB → DTO conversion. Aggregation queries for UI / report_brief |
| [src/forensia/api/cache.py](../src/forensia/api/cache.py) | API snapshot writes (`write_volatile_api_snapshots` / `write_full_api_snapshots` / `write_progress_snapshot`) |
| [src/forensia/api/progress.py](../src/forensia/api/progress.py) | Persist and list progress events |
| [src/forensia/web.py](../src/forensia/web.py) | FastAPI router. Returns `/api/*` from snapshot or DB fallback |
| [web_ui/](../web_ui/) | Svelte + Vite + Tailwind frontend. UI updates via snapshot polling |

## Related: root documents / templates

| Path | Contents |
|---|---|
| [scripts/](../scripts/) | Auxiliary scripts (`audit_schema_coverage.py`, etc.) |
| [tests/](../tests/) | pytest tests |
| [src/forensia/rulepacks/_schema/](../src/forensia/rulepacks/_schema/) | Schema definition YAML (`evtx_events.yaml`, `mft_entries.yaml`, `question_routing.yaml`, etc.) |
| [src/forensia/report_template/](../src/forensia/report_template/) | Default report template Markdown |
