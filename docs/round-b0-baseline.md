# B0 baseline (current main)

Working notes for [TASKS.md](../TASKS.md) T00. Baseline revision is `242ca6a96b3c5382d857fc3ecda68a45205e2908`
(checked out in `/tmp/opencode/forensia-b0`, kept as the frozen comparison tree).
Observations are facts observed at that revision; they are not intended output for
[M0](../GOAL.md) (§15.2 explicitly records known-wrong refutes/completions as data, not as good answers).

## 1. Environment

| Item | Observed |
|---|---|
| Worktree venv | `uv sync` created a self-contained `.venv` in `/tmp/opencode/forensia-b0`; all pytest/ruff runs used it (no PYTHONPATH fallback needed) |
| Python | CPython 3.14.3, duckdb 1.5.3, pytest 9.0.3, ruff 0.15.17 |
| LLM endpoint | `.env` at the main tree declares `LLM_BASE_URL`, `LLM_MODEL` (`Ornith-1.5-9B`), `LLM_API_KEY` (presence only; no value printed) |
| Endpoint reachability | `curl -m 2 $LLM_BASE_URL/v1/models` → timeout (curl exit 28, http 000). Not started, not modified |
| LLM measurements | **NOT RUN** — endpoint unreachable from this environment |

## 2. Focused suite (GOAL §18.1)

```
rtk proxy .venv/bin/python -m pytest tests/test_planner.py tests/test_sufficiency.py \
  tests/test_settlement.py tests/test_gap_task_integration.py tests/test_investigation_state.py \
  tests/test_source_invalidation.py tests/test_hypothesis_relations.py \
  tests/test_retrieval_telemetry.py tests/test_llm_compaction.py -q
```

Exact result line: **`162 passed, 4 subtests passed in 23.38s`** — the same counts GOAL §15.4
recorded at this revision.

## 3. Reproduction corpus (existing, deterministic, no LLM)

| Concern in GOAL §15.2 | Existing test scenario |
|---|---|
| Condition match/mismatch | `tests/test_planner.py::test_auto_confirm_requires_all_co_observed_event_ids`; `tests/test_sufficiency.py::test_assessment_uses_spec_and_tracks_condition_version`, `test_assessment_fails_closed_for_unproven_observations`, `test_legacy_unassessed_link_is_not_evidence`, `test_unobservable_coverage_with_no_evidence_is_unobservable` |
| Telemetry shortage | `tests/test_retrieval_telemetry.py::test_empty_sql_receipt_is_not_negative_evidence_or_support`, `test_memory_retrieval_evaluation_distinguishes_empty_from_rejected_scope`, `test_fallback_receipt_keeps_pre_limit_count_and_truncation` |
| Source replacement | `tests/test_source_invalidation.py::test_replacement_invalidates_dependents_without_deleting_link_history`, `test_claim_support_lookup_recognizes_registry_artifacts` |
| Contradiction | `tests/test_settlement.py` contradiction/untestable gates (`test_confirmed_without_evidence_links_becomes_needs_review`, `test_zero_row_consecutive_refute`, `test_unavailable_event_ids_untestable`); `tests/test_sufficiency.py::test_contradictory_evidence_flags_review`, `test_same_derivation_group_not_independent`; `tests/test_checker_verdicts.py` phased verdict paths |
| Context overflow | `tests/test_llm_compaction.py` (budget tests: `test_budget_never_exceeded`, `test_preserves_recent_verbatim_and_summarizes_older`, follow-up compaction, marker/section-plan budgets) |
| Stop / resume | `tests/test_gap_task_integration.py::test_stop_classifies_and_persists_linked_work`, `test_section_refresh_does_not_resolve_termination_gap`; `tests/test_investigation_state.py::test_resume_preserves_objective_and_json_policy`, `test_v2_migration_backfills_legacy_sources_and_gaps`; `tests/test_investigator_wiring.py::test_stopped_cycle_persists_state_before_final_refresh`, `test_live_session_lease_blocks_startup_reconciliation` |

## 4. B0 boundary reproductions

The table above records the baseline suite at the time of B0. The latest-only
cleanup on 2026-10-08 retired the old-schema backfill scenario; current schema
reopen and unsupported-case preservation are now checked at
`tests/test_case_db_maintenance.py`. That retirement does not change the recorded
B0 outcomes.

Scripts are `scripts/eval/b0_repro_*.py` (copied to the main tree for B1 re-runs; see §6).
All four ran offline via the worktree `.venv` and ruff passes (`rtk uv run ruff check scripts/eval`).

| ID | Entry point | Observed at B0 | Expected shape |
|---|---|---|---|
| L1 | `assess_evidence_group` with `VerificationSpec` support conditions `event_contexts` + `co_observed_event_ids` + `same_host`, eligible EVTX rows (4624 + 4104) | `role="contextual"`, `reason="observed but conditions were not satisfied"`, `matched_conditions=[]`, `spec_version="1"` — although the same spec passes admission (`qualify_event_contexts` binds `event_contexts`; admitted keys: `co_observed_event_ids`, `event_contexts`, `same_host`) | admitted-but-unevaluable condition vocabulary |
| L3 | `decide_settlement` with `checker_verdict="inconclusive"`, `consecutive_zero_row_inconclusive=3`, `has_rule_refute_when_zero_rows=True` | `verdict="refuted"` with `gates_passed=["auto_refute_zero_rows"]` for every relevant capability state (**partial, unavailable, and unknown alike**; reason string identical in all three cases) | refuted before coverage state is consulted |
| L5 | `_check_termination` with a temp Case DB holding one open durable `report_gaps` row (`origin='termination'`), `broad_plan_stop=True`, no active hypotheses, `report_after={"total_gaps": 0}` | returns `("completed", 0, "no_gaps_no_hypotheses")` with `durable_open_gaps=1` — `_check_termination` takes no DB handle and cannot see the row | durable Gap ignored by the stop gate |
| L8 | `load_evidence_links` + `evaluate_sufficiency` after `DELETE FROM evtx_events WHERE evidence_id=…` | evidence rows after delete: `0`, but `links_loaded=1`, `independent_groups=1`, `score=0.65`, `sufficiency_status="sufficient"` | deleted evidence still counted as live support |

Script outputs (exact JSON, ruff-clean, each < 80 lines):

```json
{"admission_check": "qualify_event_contexts binds event_contexts at admission", "admitted_support_condition_keys": ["co_observed_event_ids", "event_contexts", "same_host"], "matched_conditions": [], "reason": "observed but conditions were not satisfied", "role": "contextual", "spec_version": "1"}
{"cases": [{"capability_state": "partial", "gates_passed": ["auto_refute_zero_rows"], "reason": "Auto-refuted: repeated 0-row inconclusive results, consistent with rule-declared refute_when.zero_rows condition.", "verdict": "refuted"}, …same for "unavailable" and "unknown"…]}
{"durable_open_gaps": 1, "no_progress_count": 0, "stop_reason": "no_gaps_no_hypotheses", "terminal_status": "completed", "termination_reads_report_gaps": false}
{"evidence_rows_after_delete": 0, "independent_groups": 1, "links_loaded": 1, "loaded_link_roles": ["supporting"], "score": 0.65, "sufficiency_status": "sufficient"}
```

L4 (report-gap wording vs. resolution sync) is covered by existing contract tests —
`tests/test_investigation_state.py::test_gap_sync_resolves_task_and_projects_memory` and
`tests/test_gap_task_integration.py::test_section_refresh_does_not_resolve_termination_gap` — so it has no new script.

## 5. Complexity census relevant to M0

Line numbers refer to revision `242ca6a` (`src/forensia/` base).

Duplicated condition-key sets (the same keys re-interpreted in several owners):

- `ai/checking/assessment.py:42-48` — `supported = {co_observed_event_ids, same_host, within_minutes, same_entities, min_count}`; any other key (e.g. `event_contexts`) fails the whole condition (L1).
- `ai/checking/check_guardrails.py:168-216` — `_co_observation_satisfied` re-parses the same five keys, plus a second parse site at `check_guardrails.py:36` and `check_guardrails.py:340,377`.
- `ai/checking/settlement.py:598-629` — third re-extraction of `co_observed_event_ids`/`same_host`/`within_minutes` from `confirm_when` with its own int-coercion loop.
- `ai/investigation/progress.py:183-216` and `ai/investigation/investigation_cycle.py:226-249` — two more reads/mutations of `co_observed_event_ids` outside any shared vocabulary.

Legacy `confirm_when`/`refute_when` projections (≈200 non-prompt occurrences): canonical owner is `core/verification.py:44-93` (`VerificationSpec.from_legacy` / `legacy_fields`, `core/session.py:87-99` re-normalization), but read-heavy consumers still work on the projections, e.g. `ai/hypotheses/hypothesis_model.py:212-301` (merge/clean on legacy dicts), `ai/hypotheses/hypothesis_store.py` (persisted legacy fields), `ai/checking/check_guardrails.py`, `ai/checking/settlement.py` and `ai/investigation/progress.py` as above. String capability inference: `knowledge/coverage.py:492` (`infer_capabilities`, table-name substring + numeric event-ID regex) with call sites `ai/investigation/selection.py:90`, `ai/investigation/work_state.py:70`, `ai/checking/sufficiency.py:518`; readiness is judged differently per caller — `selection.py:694-701` requires any `state == "available"`, `work_state.py:94-97` blocks on `unavailable`/`degraded` only, `sufficiency.py:267-272` treats all-`unavailable`/`degraded` as `unobservable` (L2 divergence).

## 6. Re-running the reproductions for B1

The comparison tree at `/tmp/opencode/forensia-b0` is kept. Run the frozen B0
scripts there:

```bash
cd /tmp/opencode/forensia-b0 && rtk uv sync          # recreate the B0 venv if needed
rtk proxy .venv/bin/python scripts/eval/b0_repro_assessment.py
rtk proxy .venv/bin/python scripts/eval/b0_repro_settlement.py
rtk proxy .venv/bin/python scripts/eval/b0_repro_termination.py
rtk proxy .venv/bin/python scripts/eval/b0_repro_stale_support.py
```

The copies in the main tree now target the M0 (post-T01/T03/T04/T05) contracts —
`_check_termination` takes durable counts (T05), `load_evidence_links` gained
`current_only` (T04), `SettlementInput` gained `absence_scope` (T03), and rows
must carry the catalog-declared channel/provider plus the `computer` field that
`same_host` groups on (T01).  Run them in the changed tree with
`rtk proxy uv run python scripts/eval/<script>.py` and compare against the B0
values below.

## 7. Initial B1 observations (2026-10-07, before review fixes)

Deterministic outputs of the updated scripts, observed 2026-10-07 (offline; the
LLM endpoint remained unreachable, so only boundary behavior was compared):

| ID | B0 behavior | B1 behavior (observed) |
|---|---|---|
| L1 | `role="contextual"` for the admitted `event_contexts` spec | qualified (channel/provider-carrying) rows → `role="supporting"`, `matched_conditions=[co_observed_event_ids, event_contexts, same_host]`; rows that do not carry the declared context → still `contextual` fail-closed |
| L3 | `refuted` / `auto_refute_zero_rows` for coverage partial, unavailable, AND unknown | `untestable` / `auto_untestable_zero_rows` for all three states with the reason naming the unobservable absence; with `absence_scope="observable"` → `refuted` / `auto_refute_zero_rows` preserved |
| L5 | `("completed", 0, "no_gaps_no_hypotheses")` with `durable_open_gaps=1` | open durable gap → `terminal_status=null` (falls through to the no-progress machinery); after the gap is resolved → `("completed", 0, "no_gaps_no_hypotheses")` |
| L8 | `links_loaded=1`, `score=0.65`, `sufficient` from a deleted evidence row | raw loader keeps the historical link (`links_loaded_raw_loader=1`); `current_only=True` returns 0 links → `insufficient`, `score=0.0`; link row untouched in `hypothesis_evidence` |

L4 gained no new script: `tests/test_gap_task_integration.py::ProseChangeResolutionTests`
and `tests/test_investigator_wiring.py::TerminationDurableWorkTests` now pin the
separated semantics (prose absence ≠ resolution, untestable ≠ acquisition
completion, completion reads durable work).

## 8. Not measured

- Any end-to-end LLM investigation outcome, call/token/time totals, or quality deltas: the configured local endpoint was unreachable; all LLM-keyed figures are **NOT RUN / unknown** for both B0 and this document.
- Real-case FP/FN, seed/temperature variance, hardware conditions (GOAL §15.2 requires fixing these before claiming performance differences): not started.
- Benchmark answers deliberately live in the evaluation layer (`scripts/eval/`), not in core logic.

## 9. Implementation review and corrections (2026-10-08)

The initial B1 suite passed, but did not exercise four defects at their real
boundaries. These are correctness corrections, not measured LLM performance
gains. T04 is partial; documentation of a limitation does not satisfy its
content/Spec/policy invalidation acceptance criteria.

| Reproduced defect in initial B1 | Corrected behavior and regression path |
|---|---|
| RDP field constraints could be satisfied on a different host/entity or outside the co-observation window | Filter rows by context and per-event fields before the shared host/entity/window predicate. Assessment stays contextual and Settlement rejects confirmation for split witnesses; a matching witness passes. Existing sufficiency test now covers both gates |
| An unrelated question in the same section closed an older Gap/Task; completing only the new work then allowed completion | Remove inferred successor resolution. Old work stays open with `report_request_absent`; durable completion remains blocked. Gap integration tests exercise admission and termination |
| Runner-admitted evidence links did not capture source identity; source changes retained sufficient support | Capture source from normalized Evidence at admission. Exclude unverifiable or changed sources, keep historical links, and append a source-bound link on reassessment. CurrentLinkTests use the runner's actual link-creation helper |
| No actual SQL producer provided valid absence scope, and canonical capability lists had no producer | Canonical event IDs derive capabilities from the existing catalog. Recognize only direct case-wide exact EVTX event-ID lookups. Runner-path tests cover planner validation → execution → persisted RetrievalEvaluation → Settlement; available EVTX coverage can refute, while partial/unknown/unavailable, wrong/narrowed scope, sampling or derived rows cannot |

Canonical conditions now take precedence over legacy/prose capability inference
in selection, work state, runner, sufficiency and settlement. Retrieval and
Settlement use the same required-capability/family matching function. Coverage
still loses host/time detail; unsupported scopes remain unknown.

Cleanup removes the report successor heuristic, the test-only field-constraint
wrapper, the unused unlinkable-observation wrapper and a no-op time gate. A
redundant positive-only field constraint test becomes the shared-witness
regression; two manual absence-scope tests are removed in favor of real
runner-path coverage. The sole broad-planning
consumer now owns its finding-label projection helper. No new table, schema,
status, authority, LLM call, retry layer or general planner is introduced.

Remaining T04 work: same-ID/same-source content changes and Spec/policy changes
can still retain old support without invalidation. No migration or live case
was modified. End-to-end LLM quality, token and latency differences remain
unmeasured.

Final verification after cleanup: **1034 passed, 2 skipped, 137 subtests passed
in 142.00s** for `pytest tests/ -q`; Ruff (`src tests scripts`) and import-layer
checks pass. `forensia doctor` passed all eight checks before deleting the
unused wrapper and two redundant tests; the full suite and static gates were
rerun after that cleanup. All reproduction databases were temporary; no live
case, migration or model endpoint was modified.
