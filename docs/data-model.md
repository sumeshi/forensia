# Data Model

Definition of the persistent data handled by forensia. It is split into three layers.

- **DuckDB tables**: Structured data inside `db/case.duckdb`
- **Memory files**: LLM persistent memory in `memory/*.md`
- **Trace tables**: Operational receipts/log history inside `db/trace.duckdb`

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

Each row in `hypotheses` carries one canonical `verification_spec` JSON object
(currently version `"1"`). It is the only stored condition representation: the
normalized support/refute conditions, declared capabilities, scope/correlation
policy, and evidence requirements all live in it. Rule and LLM declarations
(`confirm_when` / `refute_when` / `evidence_requirements`) are the planning
vocabulary of rulepacks, the drafter/checker schemas, and report-gap drafts;
`Hypothesis` converts them into a spec exactly once at construction
(mode="before" validator in `core/session.py` calling
`VerificationSpec.from_legacy` in `core/verification.py`, which also sanitizes
`co_observed_event_ids` entries to finding/event IDs). After admission the
model, storage, and evaluators read only the spec: `Hypothesis.confirm_when`,
`.refute_when`, and `.evidence_requirements` are derived read-only properties
over it, and there are no declaration-shaped storage columns.

The `hypotheses` table (schema version 2) stores `verification_spec` JSON plus
the projection columns hypothesis metadata needs directly (`required_entities`
among them). The former `confirm_when`, `refute_when`, and
`evidence_requirements` columns were removed together with every read/write
path. Schema version 4 added `hypothesis_evidence.verification_spec_fingerprint`
and version 3 added `hypothesis_evidence.content_fingerprint`
(evidence/content_identity.py). Case databases with a different
`forensia_schema` version (including all earlier shapes) are rejected before any
persistent DDL/DML
(`db/database._check_schema_version`); existing cases are preserved on disk and
their artifacts are re-ingested into new cases. A stored spec that fails
validation is likewise an explicit load failure (`hypothesis_store` /
`work_state` / `selection` raise), never reinterpreted from other stored data.

`VerificationSpec` field status (evidence: readers/producers searched across
`src/`, `tests/`, and `scripts/`):

| Field | Status | Consumers / producers |
|---|---|---|
| `spec_version` | wired | Validation (`Literal["1"]`) |
| `support_conditions` | wired | Admission pre-screen + Assessment co-observation adapter (`EVALUABLE_CONDITION_KEYS` in `core/verification.py`); primary inference input of the shared capability derivation |
| `refute_conditions` | wired | Settlement gates (e.g. `zero_rows`) |
| `required_capabilities` | read-wired, no pipeline producer | Readers: `hypothesis_runner.py`, `sufficiency.py`, `settlement.py`, and the shared derivation owner `derive_required_capabilities` in `knowledge/coverage.py` (used by `selection.py` and `work_state.py`). Nothing in the pipeline writes a declared list yet; canonical support event IDs are mapped through the existing artifact capability catalog. |
| `evidence_requirements` | wired | Sufficiency policy (`evidence_sufficiency.yaml`, e.g. `minimum_independent_groups`) |
| `scope` | unsupported for absence certification by design | Nonempty values make `sql_absence_scope` return "unknown", so the settlement gate refuses to certify an absence it cannot observe. Evaluated correlation lives in `support_conditions`; no pipeline producer for the dedicated field. |
| `correlation` | unsupported for absence certification by design | Same single consumer as `scope` (`sql_absence_scope`); evaluated correlation constraints live in `support_conditions`. |

The earlier declared-but-unwired policy fields — `required_entities`,
`required_source_families`, `derivation_dedup_policy`,
`allowed_settlement_states`, and `untestable_conditions` — were removed.
`required_entities` stays on the `Hypothesis` model and its own
`hypotheses.required_entities` column (its only previous spec-side use was the
persistence round-trip itself); the other four had no reader or producer
anywhere and last-only storage no longer tolerates their presence in a stored
spec (`extra="forbid"` rejects them explicitly). Deduplication happens via
derivation groups on evidence links, settlement states come from the existing
settlement gates, and untestable classification comes from stop/sufficiency
states.

## Working Memory and report projections

Memory keypoint cards include a generation revision/time/state and keep finding/evidence
drill-down IDs. Memory and the rendered report are projections of the durable DuckDB
state: the report builder reads the current tables, and stale sections are re-filled
through the existing section pipeline. Case statistics count terminal hypotheses from the
durable `confirmed`, `refuted`, and `untestable` status taxonomy.

`refute_conditions` are persisted explicitly; they are never inferred from a
checker or final verdict. A hypothesis loaded from Case State always receives a
validated `VerificationSpec`, including hypotheses created by rule seeding,
broad planning, report gaps, follow-ups, and resume.

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
| `ingested_files` | Hash table for ingest deduplication | `sha256`, `path`, `source_kind`, `size`, `ingested_at` |
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

Source identity:
- Every artifact ingest computes the file's SHA-256 (`ingest_all`) and the
  adapter parsers require it: the `source_file` column in `evtx_events`,
  `mft_entries`, `mft_timeline`, `prefetch_executions`, and `prefetch_timeline`
  stores that SHA verbatim. No parser falls back to the file path or basename.
- `evidence_sources.source_id`, the Coverage source_values lookups, and
  `evidence_link_currentness` all read the same SHA identity; a mismatch is
  surfaced as a failed/empty source status instead of being silently re-matched
  against an old path value.
- Legacy case data whose normalized rows were keyed by a path keeps its rows on
  disk but is no longer re-matched; re-ingesting the same artifact into a new or
  refreshed case is the supported path.
- Registry dataset/contributor identity (`registry_datasets`, `source_ids`) is a
  separate content-ID responsibility and is unaffected.

### 1.2 Rule detections and hypotheses

| Table | Role | Main columns |
|---|---|---|
| `findings` | Rule detection results | `finding_id`, `rule_id`, `title`, `summary`, `severity`, `confidence`, `status` (`new`/`accepted`/`suppressed`), `tags`, `attack`, `evidence`, `ai_summary`, `missing_checks`, `created_at` |
| `hypotheses` | Hypotheses under investigation | Hypothesis fields plus canonical `verification_spec` (`required_entities` column), selection/retry state, blocking state, sufficiency status/score/reason and human-review flag |
| `hypothesis_relations` | Validated hypothesis graph | endpoint IDs, `relation_type`, `origin`, `confidence`, `rationale`, creation session/time |
| `hypothesis_evidence` | Typed, deduplicated assessed evidence-to-hypothesis provenance (historical records; current support is derived at read time) | hypothesis/evidence/query IDs, `assessment_id` (`EA-v1-*` for deterministic assessments), `role`, `source_family`, `derivation_group`, `content_fingerprint`, `strength` |
| `hypothesis_reasoning` | Reasoning history of hypothesis verification | `entry_id`, `hypothesis_id`, `session_id`, `iteration`, `phase` (including `sufficiency`), `verdict`, `query_id`, `body`, `created_at` |

`findings.attack` is a JSON string in `[{tactic, technique_id, technique_name}]` form, persisted on the finding row. The Web-only matrix aggregation that consumed it (`list_attack_coverage_dto`) was removed together with the Web layer; no Case/Trace producer writes attack coverage beyond the declared rule metadata.

`findings.evidence` is a list of dicts containing the original evidence_id; recursive extraction for finding evidence lives in the checker/apply path ([src/forensia/ai/checking/check_normalize.py](../src/forensia/ai/checking/check_normalize.py)) and in the report keypoint/evidence selection downstream consumers.
Investigation/checker Findings are persisted as `accepted` only when the current
query result contains an observed evidence ID. If sampled rows are omitted, a
minimal `{evidence_id}` reference is retained; an evidence-less new lead remains
in the investigation/check trace and does not create a Finding row.

### 1.3 Sessions and steps

| Table | Role | Main columns |
|---|---|---|
| `investigation_sessions` (trace DB) | Execution unit and durable worker lease for hypothesis investigation / report generation | `session_id`, `started_at`, `finished_at`, `iterations`, `status`, structured `terminal_reason`, `owner_id`, `heartbeat_at`, `phase`, `status_reason` |
| `investigation_steps` (trace DB) | Each step within a session (plan / do / check) | `step_id`, `session_id`, `hypothesis_id`, `iteration`, `phase`, `input_json`, `output_json` |
| `retrieval_events` (trace DB) | Observability for memory and external-knowledge retrieval; not used as ranking feedback | `event_id`, `session_id`, `scope_kind`, `scope_id`, `phase`, `source_kind`, `query_terms`, `candidate_count`, `selected_refs`, `rejected_refs`, `selected_chars`, `budget`, `created_at` |
| `llm_logical_calls` (trace DB) | One application-level model decision, independent of retry count | `logical_call_id`, session/phase/scope IDs, request fingerprint, status |
| `llm_provider_attempts` (trace DB) | One actual provider request, including failed attempts and retry lineage | attempt/parent/logical IDs, exact API `request_body`, raw `response_body`, effective limits, usage source, prompt metadata, HTTP/provider error, finish/parse/truncation state, timing |
| `llm_deterministic_ops` (trace DB) | Non-LLM render/validate/query/wait work; never contributes LLM tokens or call latency | `op_id`, session/phase/scope, operation type, target, duration |
| `progress_events` | Bounded recent progress view for display and debugging | `event_index`, `stage`, `status`, `iteration`, `current_query`, `summary`, `payload` |
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
than secrets or unbounded prompt/error bodies. API reads never reconcile or
mutate session state. The owning worker refreshes `heartbeat_at` and records
its current phase/reason; startup may abandon only an expired lease. A terminal
session receipt is written before fallible Memory/report projections so the API
can reconstruct failure and abandonment without treating rolling progress text
as authority.

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

Settlement also carries the runner-computed scope-wise absence judgment
(`SettlementInput.absence_scope`/`absence_note`). A rule-declared
`refute_when.zero_rows` auto-refutation is admissible only when the absence
is observable: valid retrieval scope, observable emptiness from the latest
RetrievalEvaluation, and every required capability in state `available` in
the Coverage projection. Unknown/partial coverage, a rejected scope, or an
incomplete retrieval downgrade the repeated zero-row/same-missing paths to
`untestable` with the blocking reason; absence of telemetry is not a disproof.

### 1.4 Report generation

| Table | Role | Main columns |
|---|---|---|
| `report_sections` | Section body | `section_key`, `title`, `body`, `confidence`, `status` (`draft`/`ai_exhausted`/`human_reviewed`), `update_count`, `gaps`, `last_filled_session`, `last_filled_at`, `stale` |
| `section_runs` | Execution history of section blocks (debug) | `run_id`, `section_key`, `block_heading`, `iteration`, `phase`, `payload`, `created_at` |
| `section_evidence` | Evidence referenced by a section | `section_key`, `block_heading`, `evidence_id`, `role`, `source_query`, `created_at` |
| `section_facts` | Reusable facts within a section | `fact_id`, `fact_type`, `fact_key`, `fact_value`, `evidence_ids`, `source_query`, `source_section`, `confidence` |
| `section_run_coverage` | Per-block keypoint coverage | `section_key`, `block_heading`, `keypoint`, `queried`, `rows`, `used_in_answer` |
| `claims` | Claims extracted from report paragraphs | `claim_id`, `section_key`, `claim_text`, `support_status`, `finding_ids`, `hypothesis_ids`, `evidence_ids` |
| `report_gaps` | Authoritative normalized work gaps | section/block, description, kind, lifecycle `status`, `origin`, linked Claim/Hypothesis/Task, Coverage reason |

When source replacement removes or changes a referenced evidence ID, assessed
`hypothesis_evidence` links are retained for history. Linked Hypotheses reopen
as active with sufficiency `needs_review` and their prior selection cooldown
cleared, so they can be investigated again. Claims move to review and affected
`report_sections` become stale — including
sections holding reusable `section_facts` that cite the removed ID. The removal
survey covers `hypothesis_evidence`, `section_evidence`, `claims.evidence_ids`,
`section_facts.evidence_ids`, and `case_timeline.evidence_id`; `case_timeline`
rows are historical records of a regeneratable projection and are kept as-is.
Claim existence checks use the normalized EVTX, MFT, Prefetch, and Registry
evidence tables; provenance alone does not keep a removed artifact supported.

Whether a `hypothesis_evidence` link still counts as usable support is not
stored on the link. Sufficiency, settlement, and the confirmed-verdict
invariant share a read-time currentness predicate (`evidence_link_currentness`):
1. the referenced evidence row must still exist under the same `source_file`
   identity (registry rows are content-derived `artifact_id`s and skip the
   source-file match);
2. the link's `content_fingerprint` (schema version 3) must match a fresh
   fingerprint of the row ([evidence/content_identity.py](../src/forensia/evidence/content_identity.py)).
   The fingerprint canonically hashes the full record (including the parsed
   `raw_json`) minus top-level administrative insert/ingest timestamps, so an idempotent
   re-normalization of unchanged material does not invalidate judgments while
   an in-place content change of the same ID under the same source is
   detected (`content_changed`).
3. the link's `verification_spec_fingerprint` must match the Hypothesis's
   current canonical `VerificationSpec`; otherwise it is historical and
   excluded as `verification_spec_changed`.
Unverifiable identities (row missing, unknown source, empty fingerprint) are
excluded and require reassessment; the judgment input is never silently
refilled. New admission captures the source and the content fingerprint from
normalized Evidence. A new source, content fingerprint, assessment ID, or
derivation root creates a new link even if the query ID is reused; identical
observations are deduplicated. Read-time checks never fill a historical blank
source using today's row. Excluded links remain
historical records in `hypothesis_evidence`.

Two grouped sources also move dependents to review at ingest time
(`evidence/invalidation.py`): removal of a referenced ID, and a content
fingerprint change of an ID that remains materialized under the same source
identity.

When `_merge_hypothesis_fields` adds verification conditions after an
Assessment, the Hypothesis is reopened as active with its verdict cleared.
Each EvidenceLink keeps the fingerprint of the Spec used for its judgment, so
old links remain historical and cannot satisfy current support or Settlement.
The evidence and Spec fingerprints identify the backing row and declared
verification contract; they do not reconstruct the complete Assessment
reasoning or retrieval context.
Sufficiency policy is re-derived when it runs; historical links are never
retroactively re-assessed under changed policy.

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
| `forensia_schema` (each of core / trace DB) | Latest-only format contract; mismatched or unversioned cases are rejected without automatic migration | `version` |

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

There is no separate API/DTO projection store: consumers (the CLI today, the
TUI later) read the same authoritative DuckDB case/trace owners, and
deterministic read helpers live with their owners (for example
[db/progress.py](../src/forensia/db/progress.py) for the bounded progress view
and [report/metrics.py](../src/forensia/report/metrics.py) for DuckDB-authoritative
report metrics).
