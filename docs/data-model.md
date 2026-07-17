# Data Model

Definition of the persistent data handled by forensia. It is split into three layers.

- **DuckDB tables**: Structured data inside `db/case.duckdb`
- **Memory files**: LLM persistent memory in `memory/*.md`
- **API DTO**: Pydantic models the API exposes for the UI / reports

---

## 1. DuckDB tables

Schema initialization is performed in `CaseDB.__init__` in [src/forensia/db/database.py](../src/forensia/db/database.py).

### 1.1 Normalized evidence data

| Table | Role | Main columns |
|---|---|---|
| `evtx_events` | Normalized Windows events | `evidence_id`, `timestamp`, `computer`, `event_id`, `channel`, `user_name`, `target_user`, `subject_user`, `src_ip`, `logon_type`, `process_name`, `command_line`, `service_name`, `raw_json` |
| `mft_entries` | Per-file NTFS MFT records | `evidence_id`, `record_number`, `file_path`, `file_name`, `fn_name`, `extension`, `is_deleted`, `size`, `si_created`, `si_modified`, `si_accessed`, `fn_created`, `fn_modified`, `fn_accessed` |
| `mft_timeline` | MFT entries expanded by timestamp_type | `timeline_id`, `evidence_id`, `record_number`, `file_path`, `timestamp`, `timestamp_type`, `description` |
| `prefetch_executions` | Prefetch aggregate (latest one per binary) | `evidence_id`, `executable_name`, `exec_count`, `last_exec_time`, `prefetch_hash`, `filenames`, `volumes`, `raw_json` |
| `prefetch_timeline` | Prefetch execution history (up to 8 rows per binary) | `timeline_id`, `evidence_id`, `executable_name`, `prefetch_hash`, `exec_time`, `exec_index` |
| `ingested_files` | Hash table for ingest deduplication | `path`, `hash`, `source_kind`, `ingested_at` |
| `evidence_sources` | Authoritative per-source ingest/normalize state and scope | `source_id`, `artifact_family`, `ingest_status`, `channel`, `hosts`, analysis-eligible `min_time`/`max_time`, `row_count`, error fields |
| `evidence_coverage` | Deterministic capability observability projection | `capability`, `host`, `channel`, `source_family`, `state`, `reason_code`, `source_ids`, analysis time range, `excluded_timestamps`, `confidence` |
| `case_timeline` | Deterministic timeline | `entry_id`, `timestamp`, `source` (`finding`/`verdict`/`structured`/`keypoint`), `ref_id`, `host`, `summary`, `evidence_id` |

`case_timeline` is fed by three deterministic feeders: (a) the first-evidence timestamp of findings with severity ≥ medium (`feed_findings_to_timeline` in [rules/engine.py](../src/forensia/knowledge/rules/engine.py)), (b) the decisive query row of resolved hypotheses, and (c) the matching rows of structured answers declared with `timeline: true` in `question_routing.yaml`.

Raw timestamps are retained in artifact rows and `raw_json`. Source and
capability time ranges are a separate analysis projection governed by
`timestamp_policy` in `artifact_capabilities.yaml`. Coverage records every
excluded observation by reason instead of silently dropping sentinel,
overflow, parser-invalid, or case-window outlier values.

`evidence_id` is the cross-table evidence identifier. Naming conventions:
- EVTX: `evtx-<channel>-<sequence>` (e.g. `evtx-security-000000001166`)
- MFT: `mft-<record_number>-<seq>` (e.g. `mft-000000023554-00`)
- Prefetch: `prefetch-<executable>-<hash>` (e.g. `prefetch-iexplore-exe-4b6c9213`)

Host identification:
- Only `evtx_events` has `computer` / `user_name` columns
- `mft_*` / `prefetch_*` assume a single volume, so they have no host column

### 1.2 Rule detections and hypotheses

| Table | Role | Main columns |
|---|---|---|
| `findings` | Rule detection results | `finding_id`, `rule_id`, `title`, `summary`, `severity`, `confidence`, `status` (`new`/`accepted`/`suppressed`), `tags`, `attack`, `evidence`, `ai_summary`, `missing_checks`, `created_at` |
| `hypotheses` | Hypotheses under investigation | Existing hypothesis fields plus `evidence_requirements`, selection/retry state, blocking state, sufficiency status/score/reason and human-review flag |
| `hypothesis_relations` | Validated hypothesis graph | endpoint IDs, `relation_type`, `origin`, `confidence`, `rationale`, creation session/time |
| `hypothesis_evidence` | Typed, deduplicated evidence-to-hypothesis provenance | hypothesis/evidence/query IDs, `role`, `source_family`, `derivation_group`, `strength` |
| `hypothesis_reasoning` | Reasoning history of hypothesis verification | `entry_id`, `hypothesis_id`, `session_id`, `iteration`, `phase` (including `sufficiency`), `verdict`, `query_id`, `body`, `created_at` |

`findings.attack` is a JSON string in `[{tactic, technique_id, technique_name}]` form. It is aggregated into a tactic × technique matrix by `list_attack_coverage_dto` ([src/forensia/api/service.py](../src/forensia/api/service.py)).

`findings.evidence` is a list of dicts containing the original evidence_id. Recursive extraction is performed by [`_evidence_ids_from_payload`](../src/forensia/api/service.py).

### 1.3 Sessions and steps

| Table | Role | Main columns |
|---|---|---|
| `investigation_sessions` (trace DB) | Execution unit of hypothesis investigation / report generation | `session_id`, `started_at`, `finished_at`, `iterations`, `status` |
| `investigation_steps` (trace DB) | Each step within a session (plan / do / check) | `step_id`, `session_id`, `hypothesis_id`, `iteration`, `phase`, `input_json`, `output_json` |
| `retrieval_events` (trace DB) | Observability for memory and external-knowledge retrieval; not used as ranking feedback | `event_id`, `session_id`, `scope_kind`, `scope_id`, `phase`, `source_kind`, `query_terms`, `candidate_count`, `selected_refs`, `rejected_refs`, `selected_chars`, `budget`, `created_at` |
| `progress_events` | Progress event stream for the UI | `event_index`, `stage`, `status`, `iteration`, `current_query`, `summary`, `payload` |
| `query_cache` | Result cache for SQL emitted by the LLM | `sql_hash`, `sql_text`, `result_json`, `executed_at` |
| `investigation_state` | Singleton case objective/lifecycle | `objective`, `status`, `termination_policy`, stable `stop_reason_code`, human-readable `stop_reason`, machine-readable `stop_summary` |
| `investigation_tasks` | Non-SQL evidence acquisition, external lookup and human work | `kind`, `status`, linked Gap/Hypothesis, `owner_phase`, `retry_condition`, required capability/source, blocked reason |

### 1.4 Report generation

| Table | Role | Main columns |
|---|---|---|
| `report_sections` | Section body | `section_key`, `title`, `body`, `confidence`, `status` (`draft`/`stable`/`ai_exhausted`/`human_reviewed`), `update_count`, `gaps`, `last_filled_session`, `last_filled_at`, `stale` |
| `section_runs` | Execution history of section blocks (debug) | `run_id`, `section_key`, `block_heading`, `iteration`, `phase`, `payload`, `created_at` |
| `section_evidence` | Evidence referenced by a section | `section_key`, `block_heading`, `evidence_id`, `role`, `source_query`, `created_at` |
| `section_facts` | Reusable facts within a section | `fact_id`, `fact_type`, `fact_key`, `fact_value`, `evidence_ids`, `source_query`, `source_section`, `confidence` |
| `section_run_coverage` | Per-block keypoint coverage | `section_key`, `block_heading`, `keypoint`, `queried`, `rows`, `used_in_answer` |
| `claims` | Claims extracted from report paragraphs | `claim_id`, `section_key`, `claim_text`, `support_status`, `finding_ids`, `hypothesis_ids`, `evidence_ids` |
| `report_gaps` | Authoritative normalized work gaps | section/block, description, kind, lifecycle `status`, `origin`, linked Claim/Hypothesis/Task, Coverage reason |

INSERTs into `section_evidence` happen in a single place: [`_store_section_evidence` in ai/sections/section_run_store.py](../src/forensia/ai/sections/section_run_store.py).

`section_facts.source_section` takes:
- A normal section key (e.g. `1_overview`)
- The special value `__case_probe__` — the result of a universal_question (such as `last_human_logon`). By default it is filtered out by [`_load_reusable_section_facts`](../src/forensia/ai/sections/section_run_store.py) so it is not reused by other sections. The optional external-template section `6_appendix` passes `include_case_probe=True`.

### 1.5 Review and audit

| Table | Role | Main columns |
|---|---|---|
| `ai_reviews` (trace DB) | LLM review results | `review_id`, `finding_id`, `verdict`, `report_text`, `missing_checks`, `confidence_adjustment`, `notes`, `raw_response` |
| `schema_migrations` | Schema version management | `version`, `applied_at` |

---

## 2. Memory files (`memory/*.md`)

Read and written by `MemoryManager` ([src/forensia/core/memory.py](../src/forensia/core/memory.py)). DuckDB remains authoritative for evidence, hypotheses, findings, decisions, and recorded LLM update events. The Markdown files are a materialized working-memory layer: compact, human-readable projections plus provisional notes used to assemble prompts. They must not be treated as stronger evidence than their DB/evidence references.

Prompt assembly uses progressive disclosure. Core long-term memory (`facts.md`,
`timeline.md`, `tasks.md`) remains available even when the overview is omitted;
entity/keypoint cards are relevance-filtered; a bounded hierarchical
`<MEMORY_INDEX scope="H-NNN">` exposes counts and relevant exact paths; and
`read_more` adds requested cards without replacing the initial context. In a
hypothesis scope, only shared confirmed/core memory plus the current hypothesis
card and scratch are readable. Other hypothesis scratch/cards and archives are
rejected at the loader boundary and recorded in `trace.retrieval_events`. The
final prompt is the volatile layer and is rebuilt for every role call.

### 2.1 File layout

```
memory/
├─ overview.md              · Short summary of the entire case (compacted by the LLM)
├─ facts.md                 · Append-only log of confirmed facts
├─ timeline.md              · Observation points with timestamps
├─ tasks.md                 · Follow-up notes plus a DB-regenerated investigation-task section
├─ evidence/
│  └─ suspicious.md         · Notes on suspicious evidence
├─ entities/
│  ├─ user/<name>.md        · User card
│  ├─ host/<name>.md        · Host card
│  ├─ ip/<name>.md          · IP card
│  ├─ process/<name>.md
│  ├─ service/<name>.md
│  ├─ file/<name>.md
│  ├─ registry/<name>.md
│  ├─ group/<name>.md
│  ├─ machine_account/<name>.md
│  └─ unknown/<name>.md
├─ hypotheses/<id>.md       · Scratch per hypothesis + summary once resolved
├─ keypoints/KP-NNNN.md     · Keypoint card tied to a finding
├─ scratch/H-NNN/           · Provisional notes during hypothesis verification (moved to archive on refute)
└─ archive/
   ├─ refuted.md            · Log of refuted hypotheses
   └─ resolved_gaps.md      · Log of resolved gaps
```

### 2.2 Entity card format

Generated by [`_render_entity_memory` in ai/memory_sync.py](../src/forensia/ai/investigation/memory_sync.py).

```markdown
# user: alice

- type: user
- name: alice
- role: attacker
- notes: created malicious scheduled task at 03:14 UTC
```

The allowed values for `role` are `attacker` / `victim` / `actor_candidate` / `observed_user` / `suspicious_user` / `newly_created_user` / `machine_account` / `unknown` (defined by the `ENTITY_ROLES` constant).

### 2.3 Update paths

| Path | Function |
|---|---|
| Hypothesis investigation loop (verdict reflection) | [`_apply_memory_updates` (ai/memory_sync.py)](../src/forensia/ai/investigation/memory_sync.py) reads the LLM's `memory_updates` output and reflects it into facts / timeline / tasks / overview / refuted_hypotheses / resolved_gaps / entities |
| Section agent | [`_sync_keypoint_cards` (ai/investigation_session.py)](../src/forensia/ai/investigation/investigation_session.py) syncs findings → keypoint cards |
| On hypothesis resolution | `memory.upsert_hypothesis` rewrites `memory/hypotheses/<id>.md` (on refute it also appends to `archive/refuted.md`) |

The structure of `memory_updates` is defined in `MEMORY_UPDATER_SCHEMA` ([src/forensia/ai/llm/schemas.py](../src/forensia/ai/llm/schemas.py)). For details on the LLM output schema, see [llm-roles.md](llm-roles.md).

---

## 3. API DTO

Defined as Pydantic models in `src/forensia/api/dto.py`. The `extra="ignore"` setting means old DTOs can still read snapshot JSON even if new keys are added.

### 3.1 Case overview

| DTO | Content | Origin tables |
|---|---|---|
| `CaseDTO` | Case name / paths / manifest | `manifest.yaml` |
| `CaseStatsDTO` | Aggregated counts (evtx_rows, mft_entries, findings_accepted, active_hypotheses, ...) | Multiple `COUNT(*)` |

### 3.2 Detections and hypotheses

| DTO | Content | Origin tables |
|---|---|---|
| `FindingDTO` | One finding | `findings` |
| `HypothesisDTO` | One hypothesis + recent reasoning, selection/block and sufficiency state | `hypotheses` + `hypothesis_reasoning` |
| `HypothesisRelationDTO` / `HypothesisEvidenceLinkDTO` | Graph edges and evidence provenance | `hypothesis_relations` / `hypothesis_evidence` |
| `HypothesesResponseDTO` | `{active: [...], resolved: [...]}` | Partition of the above |
| `HypothesisReasoningEntryDTO` | One row of reasoning history | `hypothesis_reasoning` |

`FindingDTO` extracts `evidence_ids` / `evidence_count` from the `findings.evidence` JSON.

### 3.3 Sessions

| DTO | Content | Origin tables |
|---|---|---|
| `SessionDTO` | One session | `sessions` |
| `InvestigationStepDTO` | One step | `investigation_steps` |
| `ProgressEventDTO` | Progress event | `progress_events` |

### 3.4 Reports

| DTO | Content | Origin tables |
|---|---|---|
| `ReportSectionDTO` | One section + `section_evidence` aggregate | `report_sections` + `section_evidence` |
| `SectionQuestionDTO` | Resolution state of a structured question | (structured question table) |
| `ClaimDTO` | Claim extracted from a report paragraph | `claims` |

`ReportSectionDTO` carries per-section `evidence_ids` / `evidence_count` aggregated from the `section_evidence` table.

### 3.5 Peripheral information

| DTO | Content | Origin |
|---|---|---|
| `EntityCardDTO` | One entity card (kind, name, mention_count, summary) | `memory/entities/<kind>/<name>.md` |
| `AttackCoverageRowDTO` | tactic × technique aggregate | aggregated from `findings.attack` JSON |
| `EventVolumePointDTO` | One point in the event time series (bucket, series, count) | `evtx_events` + `mft_entries` |
| `MftTimelineDTO` | One MFT timeline row | `mft_timeline` |
| `AIReviewDTO` | LLM review result | `ai_reviews` |

For which API endpoint uses which DTO, see [src/forensia/web/app.py](../src/forensia/web/app.py). For the snapshot-based serving mechanism, see the "API snapshots and UI" section of [architecture.md](architecture.md).
