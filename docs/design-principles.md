# Design Principles

Design principles that forensia preserves beyond code changes. Use them as decision material when adding new features.

---

## 1. Three-layer state separation

forensia separates three kinds of state that differ in trust level and lifetime.

| Type | Location | Role |
|---|---|---|
| Case State | `db/case.duckdb` | Normalized evidence derived from ingested artifacts, plus the persistent investigation objects derived from it. Evidence rows are closer to immutable, but workflow state such as findings / hypotheses / report_sections is updated |
| Trace State | `db/trace.duckdb` | Investigation session lifecycle, step I/O, and progress history. Append-only in principle |
| Structured Memory | `memory/**/*.md` | Context reconstructed from Case and Trace for LLM consumption. Regeneratable |

Hierarchy of authority:
- Case State is the source of truth for "what the case currently contains"
- Trace State is the source of truth for "how the current state was reached"
- Memory is a **projection**, not an authority

If a new feature requires persistent state, represent it in a DuckDB table, not only in Markdown or logs.

---

## 2. Handling LLM output

The implementation records LLM activity but does not treat raw output as persistent state.

- LLM requests / responses are saved under `ai_logs/<session_id>/`
- Each step's `input_json` / `output_json` is saved in `trace.investigation_steps`
- findings / hypotheses / claims / report_sections are persisted in DuckDB
- Memory Markdown is derived state and regeneratable

---

## 3. Preserve traceability to evidence

Durable conclusions can be traced back to an evidence_id.

- Evidence tables hold the normalized source records
- Findings carry structured evidence references
- memory facts / timeline include evidence references
- claims link to `finding_ids` / `hypothesis_ids` / `evidence_ids`

When adding a new abstraction that summarizes or ranks evidence, always preserve the reference path back to the source evidence.

---

## 4. Role granularity: one LLM role = a purpose writable in one sentence

If the opening of a builder becomes a multi-sentence block, such as `<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent.</TASK>`, it is a sign that the granularity is broken.

- **Do not hand routing, template matching, or formatting to the LLM**. `validate_select_sql` / `HypothesisProgressTracker` / `admit_new_hypothesis` / `_format_structured_answer` / `execute_fallback_search` all run deterministically on the code side
- When adding a new role, check whether you can write its `<TASK>` in one sentence

For the list of LLM roles and their input/output schemas, see [llm-roles.md](llm-roles.md).

---

## 5. Place knobs in the rule declaration layer

When adding new AI-driven behavior, first ask "can this be written as a one-sentence `<TASK>`?" and "can it be expressed on the code side?". If the answers are No / Yes, check whether it can be expressed as a rule declaration knob. Before increasing hardcoded branches on rule_id or event_id in Python, always consider the declaration layer (`src/forensia/rulepacks/_schema/`).

The main knobs that can change behavior through rules:

| Knob | Declaration location | Effect |
|---|---|---|
| `correlate_with` | rule | Hint in the planner prompt to "also look at these event ids" |
| `confirm_when.co_observed_event_ids` | `hypotheses[]` | tracker auto-confirm criteria |
| `refute_when.zero_rows` | `hypotheses[]` | checker default refutation |
| `fallback_search` | rule | 0-row recovery without LLM |
| `follow_up_questions` | `hypotheses[]` | auto-derive next investigation on confirmed |
| `report_sections` | `hypotheses[]` | sections to stale-mark on resolution |

---

## 6. Context isolation per hypothesis

Provisional facts / timeline / tasks under verification are confined to `memory/scratch/<hypothesis_id>/`, promoted to shared memory on confirmed, and retreated to archive on refuted. Do not let provisional information from other hypotheses leak in.

`_apply_memory_updates` ([ai/memory_sync.py](../src/forensia/ai/memory_sync.py)) routes the write destination based on `hypothesis_id` and `verdict`. Hypothesis-originated memory writes must always carry `hypothesis_id` (dropping it causes unconditional writes to shared memory and breaks this lifecycle).

The same contamination prevention applies between report sections:
- `_summarize_context_sections`: pass prior section bodies as title + first 120 characters only
- `current_section_outline`: pass preceding blocks in the same section as a list of heading + 120-character summary
- `_filter_prior_runs_by_heading`: adopt only prior_runs matching the current `block_heading`
- `_load_reusable_section_evidence` / `_load_reusable_section_facts`: scope with exact `section_key = ?` match only

---

## 7. Verdict values are an enum, not free strings

Verdict strings are an allow-list. Allowed values are declared in `src/forensia/rulepacks/_schema/verdict_taxonomy.yaml` and enforced by `forensia.core.verdicts.assert_valid_verdict` at three write boundaries.

| Layer | Enforcement site |
|---|---|
| `hypothesis_verdict` | `ai/hypotheses/hypothesis_manager.py:_upsert_hypothesis()` + `Hypothesis.verdict` field validator |
| `section_verdict` | `ai/sections/section_run_store.py:_store_section_run()` |
| `structured_status` | `report/answer_store.py:_normalize_structured_answer()` |

To add a new verdict value, edit `verdict_taxonomy.yaml`. Bypassing the validator from Python is treated as a bug.

The taxonomy file also declares cross-layer mappings (`hypothesis_to_section` etc.), but the code-side `map_verdict()` helper was removed as unused — the mappings are currently declaration-only. If you need cross-layer conversion, reintroduce a reader for the taxonomy mappings rather than hardcoding a table in Python.

---

## 8. SQL safety

SQL produced by the LLM is treated as read-only evidence access.

- Only `SELECT` and `WITH` are allowed
- Multi-statement queries are rejected
- Destructive SQL is rejected
- Tables are restricted by an allowlist (`get_allowed_tables(db)` + `_LEGACY_ALLOWED_TABLES`)

The LLM may "propose" evidence access, but generated SQL cannot mutate the DB.

---

## 9. Total LLM call count is an opt-in hard cap

`audit.LLMCallLogger` records every call.

- `investigator.investigate(max_llm_calls=...)` (CLI: `--max-llm-calls`) is an opt-in hard cap
- The default is `0` (unlimited). It is disabled by default because cost is not a concern with a local LLM
- When using a cloud API, explicitly specify a positive value (exceeding it raises `RuntimeError` and terminates the loop, not a soft warning)

Prompt assembly has a separate token budget guard, where `_assemble_messages_with_budget()` trims only the user/dynamic side while protecting the system message.

---

## 10. Token budget is a hard cap, but the system is protected

- system prompts are not subject to token budget trimming
- trim user / dynamic content first
- do not bypass the budget guard by concatenating directly into the system

---

## 11. Conceptual model boundaries

| Term | Meaning |
|---|---|
| Evidence | Normalized raw record such as an EVTX / MFT row |
| Finding | Observed condition or signal derived from evidence |
| Hypothesis | Interpretation to verify or refute |
| Claim | Description presented to the reader in the report |
| Gap | Unknown that blocks confidence |

Mixing these boundaries makes inference auditing and safe resumption difficult. Evidence and Finding sit close to the evidence, Hypothesis is interpretation, Claim is for the report, and Gap is the unknown.

A `suppressed` finding is not a deletion:
- a suppressed finding remains part of the durable case record
- suppression only changes display and workflow semantics, not the existence of the evidence
- even if a finding is suppressed, the evidence link is retained

---

## 12. Structured memory is reconstructable

Keep structured memory as a projection from the DB and preceding evidence-backed output.

- Do not place exclusive business logic in memory Markdown alone
- Do not create state that can only be restored from the most recent prompt context
- Use stable ids for file names and index entries
- Except for explicitly summarized files (such as `overview.md`), prefer append history over in-place rewrites

When structured / benchmark / appendix blocks view narrative memory, block answers get pulled toward already-formed conclusions, so the `core.memory.EvidenceOnlyMemory` wrapper exposes only `facts` / `keypoints` / `entities`. The switch happens in a single place: `core.memory.memory_for_section(memory, structured_mode=...)`.
