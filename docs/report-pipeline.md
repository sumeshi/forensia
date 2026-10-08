# Report Pipeline

Detailed specification of report section filling.

---

## 1. Report section state

`report_sections.status` has 3 canonical values:

| Value | Meaning |
|---|---|
| `draft` | Evidence gap exists / weak support |
| `ai_exhausted` | No known gaps remain or the AI workflow no longer produces meaningful leads |
| `human_reviewed` | A human has explicitly reviewed it |

These are workflow states, not evidence states.

---

## 2. Report template contract

Templates are a contract for sections defined by contributors, not durable report state.

### 2.1 Ownership boundary

- Template files live under `src/forensia/report/templates/`
- When a new case is created, a case-local `report_template/` is copied from the package default
- CLI report generation prefers the case-local templates when they exist
- `report --write --template-dir` can specify external templates explicitly

Templates are inputs; the generated section bodies are persisted in `report_sections`.

### 2.2 Frontmatter fields

Each template is a Markdown file with optional YAML frontmatter.

| Field | Role |
|---|---|
| `type` | Document kind. Bundled sections use `report-section-template` |
| `title` | Human-readable knowledge-document title |
| `description` | Short statement of the section's purpose and coverage |
| `tags` | Searchable topic labels for catalogs and external knowledge tools |
| `timestamp` | Last intentional template revision date (`YYYY-MM-DD`) |
| `instructions` | Natural-language, section-wide writing guidance. It is supplied to the LLM for every block in the section and is not rendered into the report |

```yaml
---
type: report-section-template
title: Investigation Overview
description: Executive incident assessment, scope, impact, and conclusion.
tags: [incident-response, executive-summary, scope, impact]
timestamp: 2026-07-12
instructions: |
  Write for decision-makers. Distinguish observed facts from assessments,
  explain material uncertainty, and do not infer impact beyond the evidence.
---
```

Use `instructions` for prose that a report author should be able to understand and
customize without reading Python. Keep only deterministic routing and rendering
contracts in HTML comment hints. The section title is extracted from the body
heading, and per-block requirements are expressed via `##` headings and hints
(`evidence_keypoints` / `mode` / `builder` / `answer_id` / `answer_spec` /
`question`).

### 2.3 Report wording and format policy

User-editable deterministic report wording lives in `report/templates/_formats/report.yaml` (packaged) or a case/template dir `_formats/report.yaml`. It controls narrative fallback sentences, structured-answer headings and preview limits, and forensic-gap copy. `forensia templates-export <dir>` exports this file with the Markdown section templates, and `--template-dir <dir>` loads `_formats/report.yaml` from that directory as a recursive override of packaged defaults.

Keep data selection, escaping, evidence validation, and Markdown table construction in Python. Move wording or limits to `_formats/` only when a report author may reasonably customize them. Internal logs, debug messages, SQL, and evidence-dependent branching remain code.

### 2.4 Section identity and ordering

- Templates are discovered via the filename pattern `[0-9]*_*.md`
- Refill order is the lexical order of filenames
- The durable `section_key` is the file stem
- Report output is sorted by `section_key`

Treat the section key as a **stable identifier**. Renaming a file is less impactful than changing a key.

### 2.5 What templates declare / do not declare

Declare:
- Report structure
- Section-specific writing requirements (`##` blocks and comment hints)
- Per-block keypoint / structured answer hints
- Placeholders for insufficient evidence

Do not declare:
- Durable workflow state
- Mutable report status
- Provenance preservation rules
- The source of truth for section bodies (that is the `report_sections` table)

Template authoring is kept in English. Scaffold headings, table headers, comments, and placeholders are all English. The output language is controlled at runtime via `FORENSIA_OUTPUT_LANGUAGE`.

### 2.6 DB integration

- Filled section bodies are UPSERTed into `report_sections`
- confidence is determined from the body's initial score, quality gates, evidence_id validation, claim support, and extra gaps
- claims are extracted from the body and written to `claims`
- claim provenance is computed from finding_id / hypothesis_id / evidence_id in the body and verification results; support status reflects currently-usable evidence only — historical or non-current `hypothesis_evidence` links (evidence row removed, source identity no longer matching, or the row's content fingerprint changed — see `evidence/content_identity.py`) are excluded from sufficiency support counting while remaining stored as history
- gaps are aggregated from explicit insufficient-evidence markers, section agent extra gaps, quality gates, and claim/evidence validation, and become hypothesis candidates for the next cycle
- If a block has `question` / `answer_spec` / `mode: structured`, `questions.py` resolves it to a QuestionSpec in `question_routing.yaml` and saves the result to `section_questions`. Case-wide probes are saved with `section_key='__case_probe__'`
- Structured answers are persisted to `reports/structured/answers.json` and CSV, and per-section resolution results are dumped to `reports/debug/<section>_questions.json`

### 2.7 Separation of bundled templates and evaluation templates

| Location | Purpose |
|---|---|
| `src/forensia/report/templates/` | The generic incident report bundled with the package. Copied into each case's `report_template/` on new case creation |
| External template directory (`--template-dir`) | A working copy for local evaluation and case-specific reports. Run `forensia templates-export <dir>` to copy the default templates, then edit them |

Benchmark evaluation also uses the normal `--template-dir` path. Its optional
`6_appendix.md` contains scored structured questions and is deliberately not part
of the bundled generic incident report. Because the public repository does not
bundle real data or derived case directories, evaluation templates and artifacts
are managed in a local working directory. See [BENCHMARK.md](../BENCHMARK.md) /
[BENCHMARK-ANSWERS.md](../BENCHMARK-ANSWERS.md) for scored questions and expected values.

---

## 3. Report quality gates

After each section body is filled, `quality_gate_section` ([report/sections/quality_gates.py](../src/forensia/report/sections/quality_gates.py)) runs registered static checks, adding a gap per detection and lowering confidence down to a cap. The checks are template-independent and apply to all sections.

Publication readiness is a separate deterministic gate from section workflow status. The
report validation projection checks that confirmed hypotheses have evidence and that the
hypothesis loop produced `do`/`check` receipts. If no confirmed, evidenced investigation
is available, the report is marked `needs_review` / `incomplete`, rule findings are labeled
deterministic signals/review candidates, and overview/conclusion/recommendation prompts are
constrained from presenting them as confirmed incident conclusions. An `ai_exhausted`
section or a high prose score does not imply high evidence confidence.

Quality checks infer their applicability from the generated Markdown structure and
evidence context. Templates do not expose Python feature flags. Timeline checks
recognize timestamp-first tables; recommendation checks recognize relevant
headings and titles.

### 3.1 Check list

| Check | Firing condition | confidence cap |
|---|---|---|
| Placeholder entity | matches `PLACEHOLDER_ENTITY_PATTERN` | 0.5 |
| Template marker leak | matches `HTML_FILL_PATTERN` | 0.3 |
| Heading / title mismatch | The leading `#` heading of the body diverges from `report_sections.title` | 0.65 |
| Timeline ordering | A timestamp-first Markdown table is non-monotonic | 0.6 |
| Recommendations strength | Recommendation/action headings lack evidence-strength or verification-related wording | 0.65 |
| Verdict inflation | The source verdict has no `confirmed`, but the body uses strong assertive wording | 0.6 |
| Raw evidence dump | A raw evidence table full of NULL / None is mixed in | 0.55 |
| Output language drift | The body language diverges from `FORENSIA_OUTPUT_LANGUAGE` | 0.4 |
| Open-question markers | `?` / `？` / `TBD` / `TODO` / `FIXME` / `XXX` | 0.55 |
| Empty body | Substantive body excluding tables / headings / quotes is under 80 characters | 0.3 |
| Bullet-only | Only bullet lines with no narrative | 0.6 |
| Hedge without citation | Contains `may` / `could` / `possibly` / `appears to` etc. but cites neither timestamp nor finding_id | 0.5 |
| Citation token without finding_id | Contains `evidence` / `finding_id` / `according to` etc. but has no finding_id | 0.75 |
| Duplicate paragraph | Two identical paragraphs of length 40 or more | 0.5 |
| Out-of-range timestamp | A `YYYY-MM-DD` in the body exceeds today + 1 or is before 1990 | 0.4 |
| Overused evidence id | The same evidence_id is cited in 3 or more sections | 0.7 |
| JSON object leak | A raw LLM response-like JSON object leaks into the body | 0.3 |
| Failure marker spam | `Section block failed` / `Block skipped` mixed into the body | 0.15 |

Gap notes accumulate in `report_sections.gaps` and are treated as additional hypotheses in the next cycle. When adding a new gate, keep it self-contained in one function + one note string; do not write template-specific logic.

---

## 4. Prompt assembly

LLM input is not a fixed string; it is assembled step by step according to phase and context.

1. **DFIR playbook injection (phase-aware)**: `_dfir_playbook(phase)` reads `_schema/playbook/<phase>.md`. For planning phases (`broad_plan`, `hypothesis_plan`), Application Catalog / Artifact-to-Application Inference / FP Reduction are intentionally omitted (these are for evidence interpretation). For interpretation phases (`check`, `report_section`, `section_agent_check`), the full set is injected
2. **schema_card + SQL cookbook injection**: planner / checker receive the `<SCHEMA_CARDS>` and 6 kinds of `<SQL_COOKBOOK>` for the target table, so they never write SQL from scratch. The SQL validator's allowed tables follow `get_allowed_tables(db)` and the live schema
3. **Dynamic context**: The case's `time_range`, `uncovered_keypoints`, active / resolved hypotheses, recent history, and observed_keypoints are inserted by role-specific builders in [ai/prompts/](../src/forensia/ai/prompts/), which drop null / empty fields and aggregate repeated rule patterns before serialization. Large aggregate evidence sets keep their complete IDs in DuckDB/persisted results; report prompts receive a deterministic projection containing counts, semantic distributions, and real temporal/bucket representatives selected from DuckDB metadata. Section-agent planning additionally scopes Event ID/playbook material to the block, keypoint, question, and template context and compacts report brief, findings, catalogs, and prior runs for that role.
4. **Per-section slimming of report_brief**: `_slim_report_brief_for_section` looks at the section key and, except for `1_overview`, trims down to only `time_range` / `source_timezone` / `investigation_objective`. Section planning uses the stricter `project_section_plan_brief` projection and a compact prior-run representation; it does not dump top_findings or all hypotheses wholesale (for 2/3/4/5 series it selectively restores scoped `top_findings` / `confirmed_hypotheses` / `active_hypotheses`).
5. **Section-agent token budget guard**: section planning and checking call `_trim_dynamic_content()` with the configured prompt budget. It trims the user / dynamic side while protecting the system side; other LLM roles rely on their own scoped projections and the transport's context-window checks

---

## 5. Hypothesis verification loop details

### 5.1 Flow of one cycle (`plan_cycle`)

```
broad_plan → for each active hypothesis: plan → exec(+fallback) → check → track → resolve → refresh_report(stale-first) → inject_gaps_as_new_hypotheses
```

- `plan_cycle` is capped by `--max-iter`
- Query attempts per hypothesis are capped by `--max-queries-per-hypothesis`
- Report refilling runs every `--report-every-n-cycles` cycles

### 5.2 Entry points for hypotheses

Hypotheses that enter `state.active_hypotheses` come from 3 routes.

1. `rule.hypotheses`: Generated from templates when a rule fires. `source_rule_ids` is populated
2. `gap_identifier` + `hypothesis_drafter`: Drafted from gap areas. `source_rule_ids` is empty
3. `follow_up_questions`: Automatically derived from confirmed hypotheses that carry `source_rule_ids`

Gap hypotheses emitted by the report writer pass through `_inject_gap_hypotheses`, are shaped by `GapHypothesisOutput` Pydantic validation, and if the LLM drops `required_entities` / `confirm_when`, a heuristic safety net fills them in.

### 5.3 Planner

Single LLM decision: `build_query_intent_messages` returns a complete bounded SQL action (recipe `template_id`+`params` or a raw SELECT).

- **schema cards** (`<SCHEMA_CARDS>`): `core_columns` (a short list shown to the planner, 5–13 columns) + `column_descriptions` (one-line descriptions) + `columns` (full list for the SQL validator) from `knowledge/rulepacks/_schema/*.yaml`. The intent planner's `target_table` is chosen mainly from `evtx_events` / `mft_entries` / `mft_timeline` / `prefetch_executions`. The validator's allowlist is built by `get_allowed_tables(db)` from the live DB and also permits derived tables such as `findings` / `prefetch_timeline` / `report_*` / `section_*` as needed
- **SQL cookbook** (`<SQL_COOKBOOK>`): SELECT templates (catalog in `_schema/query_templates.yaml`) — event_id enumeration / time range / GROUP BY / COALESCE / MFT path LIKE / Prefetch. Weak LLMs are expected to copy-edit these rather than synthesize from scratch
- **Host validation**: after the single decision, `validate_select_sql` and the EXPLAIN dry-run check table/column/SELECT-only/allow-list/row-limit deterministically; an invalid action mutates no durable state and returns narrow repair hints

### 5.4 Executor and fallback

The executor runs the planned SQL. On 0 rows, if the hypothesis has `source_rule_ids` + `fallback_search` declarations, fallback phases are tried in declared order. The fallback SQL is assembled by `engine.execute_fallback_search` in code; the LLM is not involved.

If a fallback hits, `fallback_info = {phase, source_rule_id}` is passed to the checker prompt, and the verdict reflects that it originated from a fallback.

### 5.5 Checker

`build_verdict_review_messages` returns only three fields: verdict / rationale / confidence. The default criteria are correlation-based:

- `confirmed`: `required_entities` co-occur in the same rows
- `refuted`: 0 rows or contradictory entities
- `inconclusive`: Only some `required_entities` are observed → the rationale must name the missing entities

Unnamed hedges such as "direct causation is not proven" or "further investigation is needed" are explicitly forbidden phrases.

The verdict is not adopted as-is from LLM output; it passes through a code-side consistency gate (`_verify_verdict_consistency`): if the Event IDs a confirmed verdict claims (from confirm_when + event representations in the rationale) do not exist in the set of event_ids in the result rows, or if the `required_entities` columns are NULL across all rows, it is downgraded to inconclusive. A confirmed verdict from rows originating in a fallback search is downgraded to newlead by `_guardrail_check_payload`.

Only when verdict==confirmed is `build_finding_extractor_messages` invoked to extract structured findings, which are persisted to the `findings` table (`rule_id='hypothesis-extraction'`) after verification. `build_memory_updater_messages` proposes durable memory updates after the verdict is finalized (result row samples and observed evidence_ids are passed in the prompt; entity names and evidence_ids that do not actually exist in the rows are discarded on the code side).

### 5.6 Progress Tracker

`HypothesisProgressTracker` is a per-hypothesis dataclass that records `(query_fingerprint, verdict, row_count)` for each query. On every check it makes the following deterministic decisions.

| Method | Condition | Effect |
|---|---|---|
| `should_auto_confirm(rule_context, rows, hypothesis)` | `_co_observation_satisfied` ([ai/checking/check_guardrails.py](../src/forensia/ai/checking/check_guardrails.py)) groups rows by `same_host` and all `co_observed_event_ids` co-occur within the `within_minutes` time window | Forces confirmed, ignoring the LLM verdict. Rows without time / host columns are treated as unsatisfied. A hypothesis without a declared `co_observed_event_ids` is not auto-confirmed |
| `should_auto_refute(threshold=3)` | 3 consecutive 0-row inconclusive (and no partial signal) | Refuted only when the rule declares `refute_when.zero_rows` AND the runner judged the absence observable (`SettlementInput.absence_scope == "observable"`: valid retrieval scope, observable emptiness, and all required capabilities `available` in Coverage). Otherwise untestable — partial/unknown/unavailable coverage, a rejected scope, or an incomplete retrieval never refute — with the blocking reason recorded in `absence_note` |
| `should_pivot(fp)` | The same query fingerprint appears 2 or more times | Instructs the planner to pivot |
| `_unavailable_missing_event_ids` | The inconclusive `missing_questions` reference only Event IDs that do not exist in the case (with no mft/prefetch alternative path) | Immediately untestable on the first check |
| `_investigate_one_hypothesis` short-circuit ([ai/hypotheses/hypothesis_runner.py](../src/forensia/ai/hypotheses/hypothesis_runner.py)) | The first plan cannot compose SQL or a template | No observable absence is established; a planning failure cannot justify refutation |

The runner certifies absence scope only for direct case-wide EVTX event-ID
lookups matching the canonical Spec, without host/time/keyword narrowing,
sampling, derived rows or offset. The Coverage check uses the queried EVTX
family, so unavailable MFT coverage neither proves nor vetoes EVTX absence.
Other scopes remain unknown; safe SELECT validation alone is insufficient.

`refuted` (disproven by evidence) and `untestable` (cannot be verified because required telemetry is absent) are distinguished, and untestable ones are listed in the report's Gap section with the missing telemetry.

When the investigation reaches a stop condition, `work_state.py` transitions
every still-active hypothesis into `deferred`, `blocked`, `needs_review`, or
`untestable` and creates the linked normalized Gap/Task records. Section
refresh (`inject_gap_hypotheses`) only touches gaps with `origin=section`; it
cannot accidentally close configuration or termination gaps. On a later
session, persisted retry conditions are evaluated after Coverage refresh, and
only affected hypotheses return to `active`. Conclusive resolution (a linked
hypothesis reaching `confirmed`/`refuted`) closes their linked work records.

Gap resolution distinguishes report-side edits from actual outcomes
(GOAL §9.4):

- **Conclusion**: when the linked hypothesis reaches `confirmed` or `refuted`,
  `resolve_linked_work` closes the Gap and its Task. A linked hypothesis that
  is `untestable` does NOT resolve the Gap: the request could not be answered
  in this scope, so the Gap stays open with
  `coverage_reason='linked_hypothesis_untestable'` until acquisition completes.
- **Editorial change**: disappearance or rewording of a request keeps its
  admitted Gap and Tasks open. Neither text similarity nor a shared section
  establishes resolution. Absent requests receive `report_request_absent` in
  the existing reason fields when no more specific reason is recorded. New
  admission still links equivalent existing hypotheses through its owner.

Completion therefore never reads the report's prose gap array
(`report_status.total_gaps`): the loop counts durable open `report_gaps`
(`open`/`in_progress`/`needs_review`) and open `investigation_tasks`
(`open`/`in_progress`), and `no_gaps_no_hypotheses` is reported only when both
durable sets are empty. With prose gaps exhausted but durable work open, the
loop falls through to the no-progress machinery and stops with a reason
instead of completing.

`query_fingerprint` canonicalizes the sqlglot AST and hashes it together with event_id / computer markers. It absorbs whitespace and alias differences. When sqlglot is unavailable, it falls back to string normalization.

After each adequate check, the deterministic assessment/sufficiency/settlement boundary applies independently of the checker verdict:

- `assess_evidence_group` classifies the observation group against the canonical `VerificationSpec` conditions only. Its identity hashes the hypothesis, the spec conditions, the observed evidence IDs, the role, and the derivation root — the query ID is acquisition history only, so re-observing the same evidence is the same assessment.
- Evidence links record the observation (`query_id`), the assessment, the source SHA, and a content fingerprint (`evidence/content_identity.py`). Without an explicit derivation group, a link's derivation root is its own evidence row within its source; the same evidence re-fetched by a different query is one root, never multiple independent groups.
- Sufficiency groups assessed, current links by that derivation root (`derivation_root_key`) and counts roots — not query attempts — as independent support. Links whose backing row no longer exists, whose source identity no longer matches, or whose content fingerprint changed are excluded as historical records.
- Settlement re-reads the current links (`load_evidence_links(current_only=True)`) and re-applies the same grouping, so a blocked confirmation cannot be resurrected by acquisition history, stale rows, or refilled content.

`_merge_active_hypotheses` enforces `MAX_ACTIVE_HYPOTHESES = 8`. Updates to existing hypotheses do not count toward the limit; only new entries beyond the cap are dropped (`[CAP]` log).

### 5.7 Hypothesis dedup

Hypothesis identity judgment is fully completed on the code side.

- `_hypothesis_similarity` (`ai/hypotheses/hypothesis_manager.py`): similarity based on a (actor / action / target) triple
- `admit_new_hypothesis` (`ai/hypotheses/hypothesis_manager.py`): unified admission gate for drafter / checker / gap-derived hypotheses — rejects near-duplicates of active AND resolved hypotheses (similarity > 0.85), claims matching refuted-hypothesis tokens, and invalid entity names
- `_best_hypothesis_match` (`ai/hypotheses/hypothesis_manager.py`): determines the upsert target using the same threshold judgment inside `_merge_active_hypotheses`

### 5.8 Resolver

When a hypothesis is finalized, `_resolve_hypothesis` does the following.

1. Moves it to `state.resolved_hypotheses` and upserts `status` to `confirmed` / `refuted` in the DB
2. For each `source_rule_id`, looks up the rule via the cached `load_rule_by_id` and finds the `HypothesisDeclaration` whose id matches
3. From the declaration:
   - Adds `decl.report_sections` to `stale_sections`
   - When confirmed, adds `decl.follow_up_questions` as new active hypotheses (deduped by description)
4. Issues `UPDATE report_sections SET stale = TRUE WHERE section_key = ?` for the relevant sections

### 5.9 Termination

A cycle ends when any of the following holds:

- All active hypotheses are resolved, broad_plan returns `stop`, and the durable open Gap/Task rows (`open`/`in_progress`/`needs_review` gaps, `open`/`in_progress` tasks) are empty — not the report prose `total_gaps`
- 3 consecutive cycles with no progress (`--no-progress-limit`)
- `--max-iter` cycles completed

"No progress" is based on semantic Case State deltas: Gap/Task/Hypothesis
lifecycle, distinct assessed evidence groups, contradiction, or Coverage
improvement. Formatting-only edits, paragraph growth, repeated queries, reused
evidence, and successful LLM calls are excluded. A section gap is admitted
through the existing Gap/Task request first; equivalent work is linked before a
candidate Hypothesis is normalized and admitted.
