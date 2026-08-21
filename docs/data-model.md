# Data Model

Definition of the persistent data handled by forensia. It is split into three layers.

- **DuckDB tables**: Structured data inside `db/case.duckdb`
- **Memory files**: LLM persistent memory in `memory/*.md`
- **API DTO**: Pydantic models the API exposes for the UI / reports

## Registry evidence boundary

Registry ingest adds three narrow projections in Case State:

- `registry_datasets` records the admitted member source IDs, grouping reason,
  parser/version/configuration, raw JSONL path, and run status.
- `registry_artifacts` stores the lossless reg2es ECS document plus only stable
  lookup fields (plugin, hive, key/value, and parser-provided `@timestamp`).
- `registry_timeline` projects only valid parser-provided `@timestamp` values;
  missing or invalid timestamps are not synthesized. `source_ids` remains the
  conservative full dataset contributor set.

Dataset and artifact IDs use source-content IDs, parser configuration, and
stable parsed fields/line ordinal. Collection/display paths never participate;
an explicit trusted host/acquisition identity is included only at the dataset
boundary to prevent cross-host collisions.

Operational member paths are excluded from dataset identity. They are used only
to supersede a prior unattributed dataset when the complete path set is equal;
directory co-location and partial path overlap never authorize grouping or
replacement.

Registry Coverage is deliberately `partial` with
`parser_plugin_completeness_unproven` when records exist. A successful parser
return or zero rows does not establish per-plugin completeness or negative
evidence.

After normalization, member `evidence_sources` reflect the dataset result. Because
reg2es output cannot be honestly allocated to one hive or transaction log, the dataset
row count is stored once on the stable representative member; other contributing members
remain traceable as `normalized/0`. A valid zero-row run projects members as `empty`.
`failed`/`partial` outcomes and structured error codes are projected atomically to every
member while preserving prior successful row metadata where applicable.

Registry tables are exposed to the existing SQL schema-card and read-only
fallback validation. Registry evidence IDs resolve through the generic
evidence lookup and report evidence map. Timestamped Registry projections are
also fed into `case_timeline`; no Registry-specific planner, agent, DTO, or UI
is introduced.

## Hypothesis verification policy

Each row in `hypotheses` has one canonical `verification_spec` JSON object
(currently version `"1"`). It owns the normalized support/refute conditions,
required entities, scope/correlation policy, and evidence requirements used by
the investigation kernel. The legacy `confirm_when`, `refute_when`, and
`evidence_requirements` columns remain lossless compatibility projections while
existing planner/checker callers migrate. Case opening backfills the canonical
object for older databases and is idempotent.

## Working and API projections

Memory keypoint cards include a generation revision/time/state and keep finding/evidence
drill-down IDs. `reports/api/snapshot_metadata.json` records the durable-state fingerprint,
generation time, authoritative update time, and current/in-progress state. The
`/api/snapshot-metadata` endpoint compares that fingerprint with live Case State and marks
the projection stale when they differ. Case statistics count terminal hypotheses from the
durable `confirmed`, `refuted`, and `untestable` status taxonomy.

`refute_when` is persisted explicitly; it is never inferred from a checker or
final verdict. A hypothesis loaded from Case State always receives a validated
`VerificationSpec`, including hypotheses created by rule seeding, broad
planning, report gaps, follow-ups, and resume.

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
| `registry_datasets` | Conservative Registry dataset admission and parser run state | `dataset_id`, trusted `identity`, `member_source_ids`, grouping reason, parser version/config, raw path, status/error, `row_count` |
| `registry_artifacts` | Lossless reg2es ECS records with query projections | `artifact_id`, `dataset_id`, contributor `source_ids`, plugin, hive, key/value, timestamp, `raw_json` |
| `registry_timeline` | Valid parser-provided Registry timestamps | `timeline_id`, `artifact_id`, `dataset_id`, contributor `source_ids`, timestamp/kind, summary |
| `ingested_files` | Hash table for ingest deduplication | `path`, `hash`, `source_kind`, `ingested_at` |
| `evidence_sources` | Authoritative per-source ingest/normalize state and scope | `source_id`, `artifact_family`, `ingest_status`, `channel`, `hosts`, analysis-eligible `min_time`/`max_time`, `row_count`, error fields |
| `evidence_coverage` | Deterministic capability observability projection | `capability`, `host`, `channel`, `source_family`, `state`, `reason_code`, `source_ids`, analysis time range, `excluded_timestamps`, `confidence` |
| `case_timeline` | Deterministic timeline | `entry_id`, `timestamp`, `source` (`finding`/`verdict`/`structured`/`keypoint`/`registry`), `ref_id`, `host`, `summary`, `evidence_id` |

`case_timeline` is fed by deterministic projections: the first-evidence
timestamp of findings with severity ≥ medium, the decisive query row of
resolved hypotheses, matching structured-answer rows declared with
`timeline: true`, and valid parser-provided Registry timeline rows.

Raw timestamps are retained in artifact rows and `raw_json`. Source and
capability time ranges are a separate analysis projection governed by
`timestamp_policy` in `artifact_capabilities.yaml`. Coverage records every
excluded observation by reason instead of silently dropping sentinel,
overflow, parser-invalid, or case-window outlier values.

`evidence_id` is the cross-table evidence identifier. Naming conventions:
- EVTX: `evtx-<channel>-<sequence>` (e.g. `evtx-security-000000001166`)
- MFT: `mft-<record_number>-<seq>` (e.g. `mft-000000023554-00`)
- Prefetch: `prefetch-<executable>-<hash>` (e.g. `prefetch-iexplore-exe-4b6c9213`)
- Registry: `registry-<dataset/plugin/location/timestamp/ordinal hash>`; display paths are excluded

Host identification:
- Only `evtx_events` has `computer` / `user_name` columns
- `mft_*` / `prefetch_*` assume a single volume, so they have no host column

### 1.2 Rule detections and hypotheses

| Table | Role | Main columns |
|---|---|---|
| `findings` | Rule detection results | `finding_id`, `rule_id`, `title`, `summary`, `severity`, `confidence`, `status` (`new`/`accepted`/`suppressed`), `tags`, `attack`, `evidence`, `ai_summary`, `missing_checks`, `created_at` |
| `hypotheses` | Hypotheses under investigation | Existing hypothesis fields plus `evidence_requirements`, selection/retry state, blocking state, sufficiency status/score/reason and human-review flag |
| `hypothesis_relations` | Validated hypothesis graph | endpoint IDs, `relation_type`, `origin`, `confidence`, `rationale`, creation session/time |
| `hypothesis_evidence` | Typed, deduplicated assessed evidence-to-hypothesis provenance | hypothesis/evidence/query IDs, `assessment_id` (`EA-v1-*` for deterministic assessments), `role`, `source_family`, `derivation_group`, `strength` |
| `hypothesis_reasoning` | Reasoning history of hypothesis verification | `entry_id`, `hypothesis_id`, `session_id`, `iteration`, `phase` (including `sufficiency`), `verdict`, `query_id`, `body`, `created_at` |

`findings.attack` is a JSON string in `[{tactic, technique_id, technique_name}]` form. It is aggregated into a tactic × technique matrix by `list_attack_coverage_dto` ([src/forensia/api/service.py](../src/forensia/api/service.py)).

`findings.evidence` is a list of dicts containing the original evidence_id. Recursive extraction is performed by [`_evidence_ids_from_payload`](../src/forensia/api/service.py).
Investigation/checker Findings are persisted as `accepted` only when the current
query result contains an observed evidence ID. If sampled rows are omitted, a
minimal `{evidence_id}` reference is retained; an evidence-less new lead remains
in the investigation/check trace and does not create a Finding row.

### 1.3 Sessions and steps

| Table | Role | Main columns |
|---|---|---|
| `investigation_sessions` (trace DB) | Execution unit of hypothesis investigation / report generation | `session_id`, `started_at`, `finished_at`, `iterations`, `status`, structured `terminal_reason` |
| `investigation_steps` (trace DB) | Each step within a session (plan / do / check) | `step_id`, `session_id`, `hypothesis_id`, `iteration`, `phase`, `input_json`, `output_json` |
| `retrieval_events` (trace DB) | Observability for memory and external-knowledge retrieval; not used as ranking feedback | `event_id`, `session_id`, `scope_kind`, `scope_id`, `phase`, `source_kind`, `query_terms`, `candidate_count`, `selected_refs`, `rejected_refs`, `selected_chars`, `budget`, `created_at` |
| `llm_logical_calls` (trace DB) | One application-level model decision, independent of retry count | `logical_call_id`, session/phase/scope IDs, request fingerprint, status |
| `llm_provider_attempts` (trace DB) | One actual provider request, including failed attempts and retry lineage | attempt/parent/logical IDs, effective limits, usage source, prompt metadata, HTTP/provider error, finish/parse/truncation state, timing |
| `llm_deterministic_ops` (trace DB) | Non-LLM render/validate/query/wait work; never contributes LLM tokens or call latency | `op_id`, session/phase/scope, operation type, target, duration |
| `progress_events` | Progress event stream for the UI | `event_index`, `stage`, `status`, `iteration`, `current_query`, `summary`, `payload` |
| `query_cache` | Result cache for SQL emitted by the LLM | `sql_hash`, `sql_text`, `result_json`, `executed_at` |
| `investigation_state` | Singleton case objective/lifecycle | `objective`, `status`, `termination_policy`, stable `stop_reason_code`, human-readable `stop_reason`, machine-readable `stop_summary` |
| `investigation_tasks` | Non-SQL evidence acquisition, external lookup and human work | `kind`, `status`, linked Gap/Hypothesis, `owner_phase`, `retry_condition`, required capability/source, blocked reason |

SQL `do` steps embed a versioned `tool_receipt` and one-attempt
`retrieval_evaluation` in `investigation_steps.output_json`. These are trace
observations; contributor/derivation sources are provenance and the payload
does not assign Evidence roles, cumulative sufficiency, or verdicts.

The three LLM trajectory tables deliberately separate a logical decision from
its provider retries and from deterministic rendering. Token counts carry a
source (`provider_actual`, `local_estimate`, or `unknown`); configured output,
reasoning reserve, requested output, and effective wire output are separate
fields. Prompt telemetry stores named section sizes and selected IDs rather
than secrets or unbounded prompt/error bodies. A terminal session receipt is
written before fallible Memory/report projections so the API can reconstruct
failure and abandonment without treating rolling progress text as authority.

Evidence assessment is the narrow boundary between retrieval and sufficiency.
For an adequate, non-empty observation group, `assessment.py` matches the
supported `VerificationSpec` event/host/time conditions against observed rows;
unsupported condition types remain contextual. The existing link stores the
resulting `assessment_id`, role, query/evidence IDs, and source/derivation
provenance columns; it does not persist the full assessment object. Legacy
links with an empty assessment ID are retained for compatibility and are not
represented as independently assessed history or counted by Sufficiency and
Settlement. Sufficiency consumes assessed links without assigning their roles.
The existing settlement guard remains the state-transition boundary.

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

When source replacement removes a referenced evidence ID, assessed
`hypothesis_evidence` links are retained for history, but linked Hypotheses and
Claims move to review and affected `report_sections` become stale. Claim
existence checks use the normalized EVTX, MFT, Prefetch, and Registry evidence
tables; provenance alone does not keep a removed artifact supported.

There is no separate Investigation Requirement table. A report request is a
`report_gaps` row; an associated `investigation_tasks` row stores ownership and
retry state for external or human work. Admission first links equivalent work.
For a new internal candidate, it normalizes and validates the
`VerificationSpec` before persisting a Hypothesis. Rejected or review outcomes
remain on the Gap lifecycle/reason fields without creating a Hypothesis.

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
