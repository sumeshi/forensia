# tasks.md — Architecture Refactoring Plan (R4, 2026-06-11)

Design review of the whole repository (post-R3, commit `3781cf4`, 738 tests
green). Scope of this round: **behavior-preserving refactoring only** — small,
reviewable, revertible steps. No feature work, no prompt changes, no rule
changes. Every task below must end with `uv run pytest tests/ -q` fully green
and a diff a human can review in one sitting.

## Implementation review (2026-06-12, post-implementation)

All 12 tasks landed; final state: **738 tests green**, `scripts/check_imports.py`
green, `forensia doctor` green. The review found and fixed these issues in the
delivered implementation:

1. **Latent order-dependent test exposed** —
   `test_report_section_prompt_includes_ioc_catalog` only ever passed because
   `test_investigator_wiring` leaked the module-global case profile (filtered
   the 55 KB Event-ID narrative under the 24 KB budget). It failed on HEAD when
   run alone, and R4-11's cleaner wiring removed the accidental crutch. Fixed:
   the test now sets a small profile explicitly (with cleanup), and the wiring
   test resets the global in tearDown.
2. **Semantic regression in `get_profile_event_ids`** — the R4-11 dataclass
   collapsed "profile with zero event IDs" (empty set; e.g. MFT-only case) into
   "no profile" (None). Restored the None/empty-set distinction
   (`event_ids: set[int] | None = None`).
3. **`check_imports.py` failed on the delivered tree** — `report/probes.py` and
   `report/structured_answers.py` still imported `forensia.ai`
   (question_registry + two dead `chat_completion` imports). Fixed by removing
   the dead imports and executing R4-09 step 3: `question_registry` moved to
   `forensia/questions.py` (routing knowledge below both layers) with a compat
   shim at `forensia/ai/question_registry.py`. The move also broke a relative
   schema path (`parent.parent` → `parent`), which silently emptied the
   QuestionSpec registry — caught by 7 failing tests, fixed.
4. **`writer ⇄ structured_answers` residual cycle** — `_build_host_note` lived
   in probes and was lazily imported back through writer. Moved to
   `report/markdown.py` (pure text helper); both consumers import it top-level.
5. **R4-12 wiring missing** — `check_imports.py` existed but was not called
   from `forensia doctor` nor documented. Wired in and documented in
   CONTRIBUTING.md. While wiring it, found the doctor's pre-existing
   verdict-enforcement check matched only attribute-style calls and always
   reported 0; fixed to count plain-name calls (now ✓ 4 files).

## Follow-up round (2026-06-12, same day): deferred items closed

Per review feedback ("fix it if it can be fixed"), the items initially deferred
to R5 were implemented immediately. Final state: **739 tests green**,
`check_imports.py` green, no module cycles except the allowlisted runtime-lazy
import inside `writer.fill_section`.

1. **`ai.report_gap ⇄ ai.hypothesis_manager` cycle removed** — the three
   hypothesis-construction helpers (`_gap_hypothesis_id`,
   `_extract_entities_from_text`, `_propose_confirm_when`) moved verbatim into
   `hypothesis_manager`; `report_gap` imports them top-level. The deferred
   import inside `_resolve_hypothesis` is gone.
2. **Duplication bug found by the cleanup**: the R4 writer split had left
   `fill_section` (~40 lines) and the `TemplateMeta` dataclass **defined twice**
   (writer.py and probes.py) — two distinct `TemplateMeta` classes is a latent
   identity/typing hazard. Deduplicated: canonical `TemplateMeta` lives in
   `report/probes.py`; writer imports it; the probes copy of `fill_section`
   (zero callers) was deleted, and writer's standalone
   `_render_section_from_request` shim wrapper was inlined into `fill_section`
   as the single documented runtime-lazy call.
3. **Compat shims removed** — `ai/lmstudio.py` and `ai/question_registry.py`
   deleted after migrating all remaining consumers (`section_agent`,
   `scripts/audit_schema_coverage.py`, `tests/test_lmstudio.py`,
   `tests/test_timezone.py`, `tests/test_writer_rq_regressions.py`) and the
   stale path references in `docs/`.
4. **`section_agent.py` split** — deterministic block-support layer (status
   classification, run/evidence/fact persistence, catalogs, evidence chains,
   structured-answer formatting, narrative fallbacks; 68 names) moved verbatim
   to `ai/section_blocks.py` (1,578 lines). `section_agent.py` keeps the LLM
   agent loop (1,102 lines, under the 2,500 soft limit); moved names are
   re-exported for compatibility.
5. **Playbook budget bug fixed (found during review)** — with no case profile
   set (e.g. standalone `forensia report --write`), the unfiltered Event ID
   Reference (~55 KB) exceeded the 24 KB budget and the serial drop loop
   discarded **every** guidance section, leaving a 3 KB playbook. Now the
   events section is first truncated to the declarative `priority_events`
   list (logon_types.yaml) and only then does section-dropping proceed; 7 of 8
   sections survive. Regression test added (`test_playbook_budget.py`).
6. While wiring doctor: fixed its verdict-enforcement check that matched only
   attribute-style calls and therefore always reported 0 enforcement sites.

Remaining (recorded, low priority): `writer.fill_section` keeps one
runtime-lazy import of `ai.section_refresher` (public embedding API with no
internal callers; allowlisted in check_imports); the writer re-export facade
stays until external consumers are ruled out.

Executor notes (read first):
- Python 3.13 + uv. Run tests: `uv run pytest tests/ -q` (≈30 s, no LLM server).
- Behavior-preserving means: same outputs, same DB writes, same prompts, same
  log text. When moving code, move it verbatim; do not "improve" logic in the
  same PR (CLAUDE.md Rule 3).
- Import compatibility is a hard requirement: existing
  `from forensia.report.writer import X` / `from forensia.ai.section_agent
  import Y` statements in tests and modules must keep working via re-exports
  until a dedicated cleanup task removes them.
- One task = one PR. Do them in numeric order unless marked parallel-safe.

---

## 1. Current design overview

```
cli ──► artifacts/ingest/normalize ──► db (DuckDB: case + trace)
                 │                          ▲
                 ▼                          │
            rules (YAML rulepacks + engine) ┤  findings / case_timeline
                 │                          │
                 ▼                          │
            ai (LLM roles: planner/checker/investigator/section_agent)
                 │                          │
                 ▼                          │
            report (keypoints, structured answers, gates, markdown)
                 │
                 ▼
            api (DTO/snapshots) ──► web (FastAPI) ──► web_ui (Svelte)
core: Case / SessionState / MemoryManager (markdown memory)
knowledge: rulepacks/_schema/*.yaml (event IDs, IOC catalog, FP rules, questions)
```

Strengths worth preserving: declarative knowledge layer (rulepacks), a single
LLM JSON entry point (`request_llm_json`), DB-as-authority state model,
deterministic gates around LLM output, fast DB-free test suite (738 tests).

## 2. Main design problems (measured)

| # | Problem | Evidence |
|---|---|---|
| P1 | God modules | `report/writer.py` **6,269 lines / 236 functions** mixing ≥7 concerns (keypoint catalog, structured-answer builders, quality gates, markdown table munging, probes/timeline feeders, report brief, CSV/JSON export, claims provenance, tz rendering). `ai/section_agent.py` 2,674; `ai/investigator.py` 2,068; `ai/prompts.py` 2,008 |
| P2 | Layer violations & cycles | `core/memory.py` imports `ai.lmstudio.chat_completion` (domain/state layer doing LLM HTTP). Package-level cycle `ai ⇄ report` (`writer ⇄ section_agent`, worked around by **13+6 deferred imports**). Module cycles `investigator ⇄ hypothesis_manager`, `hypothesis_manager ⇄ report_gap` |
| P3 | Oversized functions | `_investigate_one_hypothesis` 308 lines; `run_section_block_agent` 194; `_apply_memory_updates` 190; `_write_block_body` 178; `apply_check_result` 164; `check_query_result` 153; `plan_hypothesis_query` 146 (orchestration + policy + I/O interleaved) |
| P4 | Duplication | 3 timestamp parsers (`case._parse_dt`, `checker._parse_timestamp`, `engine._parse_event_ts`); 3 `_slugify` (audit, core/evidence, core/memory); ≥3 token-similarity implementations (memory `_jaccard_similarity`, hypothesis_manager `_hypothesis_similarity` internals, investigator overview dedup); evidence-id family classification in investigator / api.service / scripts/eval_run |
| P5 | Two logging idioms | `investigator._log` (print-based, imported via deferred imports from hypothesis_manager — a dependency inversion) vs `logging` module in memory/prompts/planner |
| P6 | Hidden global state | `case_profile.set_case_profile` module globals; `lru_cache` singletons for YAML knowledge spread across prompts/writer/engine/section_agent (each with its own loader); `lmstudio._SCHEMA_MODE_CACHE` |
| P7 | Misleading names | `writer.py` is not a writer; `lmstudio.py` is a generic OpenAI-compatible client; `prompts.py` also loads knowledge YAML and enforces budgets; `_build_*` returns rows in some places and full answer dicts in others |
| P8 | Boundary blur | Prompt builders take live `db` handles (`_build_schema_guidance(table, db)`); checker mixes LLM call + parse + guardrails + persistence in one function; report orchestration (`_render_section_from_request` in writer) calls back up into `ai.section_agent` |

## 3. Priority improvements (ordered)

1. Shared utilities + one logging seam (kills P4/P5 and most deferred imports
   between investigator/hypothesis_manager). → R4-01
2. One knowledge-loader module (kills the scattered YAML lru_caches; collapses
   several writer⇄section_agent/prompts edges). → R4-02
3. Break `core → ai` (memory compaction via injected summarizer). → R4-03
4. Split `report/writer.py` into a package behind a re-export facade, four
   mechanical steps. → R4-05..R4-08
5. Break the `ai ⇄ report` cycle by making `report` a passive library and
   moving section orchestration into `ai`. → R4-09
6. Decompose investigator / checker long functions. → R4-10
7. Replace case-profile globals with an explicit context object. → R4-11
8. Enforce the layer contract mechanically (doctor check). → R4-12

## 4. High-risk areas (touch with extra care, never mix with other changes)

- `db/database.py::_route_trace_write` — regex-based SQL rewriting; subtle.
- Schema migrations (`_apply_migration_once`) — existing case DBs depend on it.
- `ai/lmstudio.py` retry/JSON-schema degradation cache — tuned for weak local
  models; behavior changes break real runs invisibly to tests.
- `prompts._dfir_playbook` + `_enforce_system_budget` — output size affects
  small-model quality; verbatim moves only, golden-output test recommended.
- `report` orchestration (`fill_section` / `finalize_section` /
  `build_report_markdown_from_db`) — R3 just stabilized it; keep diffs minimal.
- `question_registry.resolve_question_spec` matching — benchmark and report
  routing both depend on its scoring.

## 5. Quick wins (small, behavior-preserving)

- `core/timeutil.py`: single `parse_timestamp()` replacing 3 copies.
- `core/textutil.py`: `slugify`, `normalize_text`, `token_set_similarity`,
  `jaccard_similarity` replacing scattered copies.
- `core/logging.py` (or `core/log.py`): `log(tag, msg)` with today's print
  format; investigator/hypothesis_manager import it (removes the
  hypothesis_manager→investigator deferred imports).
- Rename `ai/lmstudio.py` → `ai/llm_client.py` with a one-line compat shim.
- Move `_load_benign_context_rules` out of `prompts.py` (knowledge, not prompt).
- Evidence-id family classifier (`evidence_id_family(eid)`) in one place,
  reused by investigator / api.service / scripts/eval_run.

## 6. Mid-term design direction

Target dependency rule (enforced in R4-12):

```
config, core(utils/case/session) ← db ← rules ← report(passive) ← ai(active) ← api ← web/cli
knowledge loaders: importable from rules/report/ai, import nothing above db
```

- `report` becomes a passive library (SQL→rows, rows→markdown, gates,
  persistence). It never imports `ai`.
- `ai` orchestrates: loops, LLM calls, section filling. `ai.section_agent`
  imports `report.*` freely.
- `core` owns state and utilities; it never imports `ai`/`report` (LLM access
  arrives via injected callables).
- LLM access stays behind `ai/json_response.py` + `ai/llm_client.py` only;
  `core.memory` loses its direct import (R4-03).

## 7. Testability separation policy

- Pure-function first: SQL predicate builders, ranking, similarity, claim
  splitting, markdown table rendering take plain data, no `db`/LLM arguments.
- Single LLM seam: tests inject a fake via one patch point
  (`forensia.ai.json_response.request_llm_json`) instead of per-module paths;
  `core.memory` compaction takes a `summarize: Callable[[str], str] | None`.
- Knowledge loaders expose `cache_clear()` and accept an override path for
  fixtures (R4-02), eliminating cross-test cache leakage.
- No module-level mutable state: case profile becomes an object on the session
  context (R4-11); `lmstudio` schema-mode cache gets a reset function used by
  test teardown.
- Keep the existing tempdir + `CaseDB` pattern; add one `tests/helpers.py`
  factory (`make_case_db()`) to stop copy-pasting it.

## 8. File split / responsibility / naming map

| Current | Target | Contents |
|---|---|---|
| `report/writer.py` (6,269) | `report/keypoints.py` | `REPORT_KEYPOINTS`, aliases, resolvers, `_report_keypoint_rows` |
| | `report/markdown.py` | `_markdown_table`, table cell/sort/strip helpers, `_render_answer_block`, timestamp/tz rendering |
| | `report/quality_gates.py` | `_GateCtx`, all `_check_*`, `_quality_gate_section` |
| | `report/structured_answers.py` | `_STRUCTURED_ANSWER_BUILDERS`, `build_structured_answer`, persist/export, interpretation templates |
| | `report/probes.py` | `ensure_universal_question_probes`, `_feed_structured_to_timeline`, report brief |
| | `report/writer.py` (≤1,500) | `fill_section`, `finalize_section`, `build_report_markdown_from_db`, snapshots glue + re-export facade |
| `ai/section_agent.py` (2,674) | `ai/section_blocks.py` | `_BlockContext`, block builders (`_build_daily_session_timeline`…), digest, placeholder text |
| | `ai/section_agent.py` | agent loop, narrate/outline calls only |
| `ai/prompts.py` (2,008) | `knowledge/loaders.py` (new pkg or `rules/knowledge.py`) | `_load_dfir_yamls`, benign rules, event-id hints, IOC catalog accessors (move from writer too) |
| | `ai/prompts.py` | message builders + playbook rendering + budget only |
| `ai/investigator.py` (2,068) | `ai/progress.py` | `HypothesisProgressTracker`, `_query_fingerprint` |
| | `ai/memory_sync.py` | `_apply_memory_updates` + helpers (`_has_multi_source_evidence`…) |
| | `ai/seeding.py` | `_seed_findings`, `_seed_rule_hypotheses`, keypoint scan order |
| `ai/lmstudio.py` | `ai/llm_client.py` | rename; shim `lmstudio.py` re-exports for one release |
| naming | | builders returning rows end in `_rows`; returning structured answer dicts end in `_answer`; `_render_*` returns markdown only |

## 9. First PR (R4-01) — smallest useful step

Utilities + logging seam. ~6 files, zero behavior change, removes the worst
deferred-import knot. Definition below.

---

# Task list

### R4-01 Shared utils + logging seam (FIRST PR)

- [x] **Priority: P0 / size S**
- **Goal**: deduplicate parsers/slugify/similarity; one log function; remove
  `hypothesis_manager → investigator` deferred imports.
- **Steps**:
  1. New `src/forensia/core/timeutil.py`: `parse_timestamp(value) -> datetime | None`
     — move the most tolerant implementation (`checker._parse_timestamp` handles
     datetime/float/ISO; fold `case._parse_dt` + `engine._parse_event_ts` string
     handling into it). Keep thin wrappers at old call sites only if return-type
     differences matter (case/engine want naive datetime; checker wants epoch
     float — provide `parse_timestamp()` and `parse_epoch_seconds()`).
  2. New `src/forensia/core/textutil.py`: `slugify` (from core/memory),
     `normalize_text` (from report_gap), `jaccard_similarity` (from core/memory),
     `token_set_similarity` (the overview-dedup ratio from investigator).
     Replace the copies in `core/evidence.py`, `core/memory.py`, `ai/audit.py`,
     `ai/report_gap.py`, `ai/investigator.py`.
  3. New `src/forensia/core/log.py`: `log(tag: str, message: str)` reproducing
     `investigator._log`'s exact print format; `investigator._log` becomes an
     alias; `hypothesis_manager` imports `core.log.log` directly (delete its
     `from forensia.ai.investigator import _log` deferred imports).
  4. No other logic changes.
- **Verify**: full suite green; `grep -rn "def _slugify\|def _parse_dt\|def _parse_event_ts" src/forensia` → only wrappers/none; `grep -n "from forensia.ai.investigator import _log" src/forensia/ai/hypothesis_manager.py` → empty.
- **Risk**: low. Parser folding must keep microsecond/`Z`/offset handling —
  port the union of the three implementations' accepted formats and add a
  parametrized unit test covering all previously accepted inputs.

### R4-02 Knowledge loader consolidation

- [x] **Priority: P0 / size M** (after R4-01)
- **Goal**: one module owns all `rulepacks/_schema/*.yaml` access; caches are
  resettable; prompts/writer/engine/section_agent stop owning loaders.
- **Steps**:
  1. New `src/forensia/knowledge.py` (single module is enough): move
     `prompts._load_dfir_yamls`, `prompts._load_event_id_hints`,
     `prompts._load_benign_context_rules`, `engine._load_finding_benign_context_rules`,
     `writer._ioc_catalog` + `_catalog_*` accessors + `_exe_glob_sql` +
     `_matches_exe_globs`, `section_agent._load_event_class_definitions`.
     Verbatim moves; keep function names (drop leading underscore for the
     public ones: `load_dfir_yamls`, `ioc_catalog`, `catalog_exe_globs`, …).
  2. Old locations re-export (`_ioc_catalog = knowledge.ioc_catalog` etc.) so
     tests and callers keep working; switch internal callers to `knowledge.`.
  3. Add `knowledge.clear_caches()` calling every `cache_clear()`; call it from
     existing test teardowns that currently clear individual caches.
- **Verify**: suite green; `grep -rn "yaml.safe_load" src/forensia/ai/prompts.py src/forensia/report/writer.py src/forensia/rules/engine.py` shows no `_schema/` loads left (allowlist/profile loads in engine/loader stay).
- **Risk**: low-medium; watch for `lru_cache` identity assumptions in tests.

### R4-03 Break `core → ai`: injected memory summarizer

- [x] **Priority: P0 / size S**
- **Goal**: `core/memory.py` no longer imports `forensia.ai.lmstudio`.
- **Steps**:
  1. `MemoryManager.__init__(..., summarize: Callable[[list[dict]], str] | None = None)`
     — actually inspect the two `_llm_call` call sites (`compact_overview_if_needed`,
     `compact_oversized_with_llm`) and define the narrowest callable signature
     that covers both (likely `Callable[[list[dict[str,str]], int], str]`:
     messages + max_tokens).
  2. Compaction methods use `self._summarize`; when None, skip compaction with
     a `log()` note (current behavior when LLM unreachable is an exception
     caught by callers — replicate the effective no-op outcome).
  3. Construction sites (`investigator._init_session`, `cli`, `section_refresher`)
     pass a summarizer built from `ai.llm_client.chat_completion` with the same
     parameters as today.
  4. Remove the import from `core/memory.py`.
- **Verify**: suite green; `grep -rn "forensia.ai" src/forensia/core/` → empty;
  compaction unit test passes a fake summarizer and asserts the same file
  output as before.
- **Risk**: medium — compaction triggers only on oversized memory; add a test
  that forces the threshold.

### R4-04 Rename `lmstudio` → `llm_client` (+ cache reset hook)

- [x] **Priority: P1 / size XS** (parallel-safe after R4-03)
- **Steps**: `git mv` to `ai/llm_client.py`; create `ai/lmstudio.py` shim
  (`from forensia.ai.llm_client import *  # backward-compat, remove in R5`);
  update internal imports; add `reset_schema_mode_cache()` and use it in tests
  that exercise degradation (`tests/test_lmstudio.py` keeps its name for now).
- **Verify**: suite green; `grep -rn "from forensia.ai.lmstudio" src/` → only the shim remains unused internally.

### R4-05 Writer split 1/4: `report/markdown.py` + `report/keypoints.py`

- [x] **Priority: P1 / size M** (after R4-02)
- **Steps**:
  1. Create `report/markdown.py`: move the pure rendering helpers
     (`_markdown_table`, `_split/_join_markdown_table_cells`,
     `_sort_markdown_table_by_first_column`, `_strip_hidden_*`,
     `_render_answer_block`, `_render_timestamp_with_timezone`,
     `_local_time_from_utc`, `_tz_offset_str`, heading/text key helpers).
     These must be importable with **no db/case imports** beyond `Case` typing.
  2. Create `report/keypoints.py`: `REPORT_KEYPOINTS`, `REPORT_KEYPOINT_ALIASES`,
     `_report_keypoint_rows`, `_default_keypoints_for_section`, and the row
     helpers they call (`_hypothesis_rows`, `_extract_needed_evidence`, …).
  3. `writer.py` does `from forensia.report.markdown import *`-equivalent
     explicit re-exports (keep underscore names available:
     `_markdown_table = markdown._markdown_table` style) so every existing
     import keeps resolving.
  4. Add module docstrings stating the layering rule (markdown: pure; keypoints: db-read only).
- **Verify**: suite green; `python -c "from forensia.report.writer import _markdown_table, REPORT_KEYPOINTS"` works; `wc -l src/forensia/report/writer.py` drops by ≥1,500.
- **Risk**: medium (sheer volume). Verbatim moves; no signature changes.

### R4-06 Writer split 2/4: `report/quality_gates.py`

- [x] **Priority: P1 / size S** (after R4-05)
- **Steps**: move `_GateCtx`, every `_check_*` gate, `_quality_gate_section`,
  gate constants (`PLACEHOLDER_ENTITY_PATTERN`, failure-marker lists, language
  detection `_detect_body_language`). Re-export from writer. Update
  `section_agent`'s deferred imports of `_detect_body_language` to the new
  module (direct top-level import — no cycle once gates live below).
- **Verify**: suite green (test_writer_rq_regressions imports keep working);
  deferred-import count in section_agent decreases.

### R4-07 Writer split 3/4: `report/structured_answers.py`

- [x] **Priority: P1 / size L** (after R4-06)
- **Steps**: move `_STRUCTURED_ANSWER_BUILDERS` and all `_build_*` answer
  builders, `build_structured_answer`, `_structured_answer`,
  `_normalize_structured_answer`, persist/export (`_persist_structured_answer`,
  `_dump_structured_*`), interpretation templates + `_structured_answer_interpretation`,
  `_render_structured_answer_markdown`, `UNIVERSAL_QUESTION_SPECS`.
  Note: `_build_daily_session_timeline` body currently lives in
  `ai/section_agent.py` and is imported by a writer wrapper — move the
  implementation here too (it is deterministic SQL, not agent logic) and have
  `section_agent` re-export for compatibility.
- **Verify**: suite green; benchmark/regression tests (test_regression_rq)
  untouched and green; `report/structured_answers.py` imports nothing from `ai`
  except `question_registry` (which should later migrate — note only).
- **Risk**: medium-high volume; do not reorder dict entries (snapshot diffs).

### R4-08 Writer split 4/4: `report/probes.py` + slim orchestrator

- [x] **Priority: P1 / size M** (after R4-07)
- **Steps**: move `ensure_universal_question_probes`,
  `_feed_structured_to_timeline`, `_build_report_brief` (+ slimming helpers),
  api-snapshot helpers that are report-side. Target: `writer.py` ≤1,500 lines
  containing only `prepare_section_request`, `fill_section`,
  `finalize_section`, `_render_section_from_request`,
  `build_report_markdown_from_db`, `write_report*`, and the re-export facade.
- **Verify**: suite green; `wc -l` target met; facade exports listed explicitly
  in one block with a `# compat re-exports (R4)` banner.

### R4-09 Break the `ai ⇄ report` cycle

- [x] **Priority: P1 / size M** (after R4-08)
- **Goal**: `report` never imports `ai.section_agent`; direction becomes
  `ai → report` only.
- **Steps**:
  1. Move `_render_section_from_request` (the only writer code calling
     `run_section_block_agent`) from `report/writer.py` into
     `ai/section_refresher.py` (it is orchestration). Writer keeps a compat
     re-export that does a lazy import (documented as deprecated).
  2. In `section_agent`, replace the 13 deferred `from forensia.report.writer
     import …` with top-level imports from the new passive modules
     (`report.markdown`, `report.keypoints`, `report.structured_answers`,
     `report.quality_gates`) — possible now because those don't import `ai`.
  3. Confirm `question_registry` location: it is knowledge/routing, imported by
     both sides; move it to `forensia/questions.py` or leave in `ai` with a
     note — choose the move only if it requires no other change.
- **Verify**: the import-graph script (below, R4-12) reports no `report → ai`
  edge except the deprecated lazy shim; suite green.

### R4-10 Decompose investigator (mechanical extraction)

- [x] **Priority: P2 / size M** (after R4-01; parallel-safe with R4-05..09)
- **Steps**:
  1. `ai/progress.py`: `HypothesisProgressTracker`, `_query_fingerprint`.
  2. `ai/memory_sync.py`: `_apply_memory_updates` + its private helpers
     (`_has_multi_source_evidence`, hard-claim/dedup logic). Keep function
     bodies verbatim; investigator re-exports for tests.
  3. `ai/seeding.py`: `_seed_findings`, `_seed_rule_hypotheses`,
     `_family_interleaved_keypoint_names`, `_scan_report_keypoints`.
  4. Do NOT split `_investigate_one_hypothesis` in this task (logic-heavy,
     needs its own design pass — record as R5 candidate).
- **Verify**: suite green; `wc -l ai/investigator.py` ≤1,400;
  `from forensia.ai.investigator import HypothesisProgressTracker` still works.

### R4-11 Case profile globals → explicit object

- [x] **Priority: P2 / size M** (after R4-10)
- **Steps**: introduce `CaseEvidenceProfile` dataclass (profile string +
  event-id set) constructed in `investigate()`; thread it through `_Ctx`/state
  to the 4 `get_profile_event_ids()` consumer groups (prompt builders accept an
  optional `profile` param; default falls back to the legacy global for
  compatibility). Keep `set_case_profile`/getters as shims until callers are
  migrated; mark with deprecation comments. Tests stop relying on global
  teardown where touched.
- **Verify**: suite green; new unit test constructs two profiles concurrently
  without interference.

### R4-12 Layer contract enforcement in `doctor`

- [x] **Priority: P2 / size S** (last)
- **Steps**: add `scripts/check_imports.py` (stdlib `ast`, no new deps):
  builds the intra-package import graph and fails on forbidden edges:
  `core→ai`, `core→report`, `report→ai` (allowlist: the deprecated writer shim
  until removed), `db→{ai,report}`, plus a soft warning for files >2,500 lines.
  Wire into `forensia doctor` and document in CONTRIBUTING.md.
- **Verify**: script passes on the refactored tree; deliberately adding a
  forbidden import in a scratch branch fails it.

---

## Execution order

```
R4-01 → R4-02 → R4-03 → (R4-04 ∥ R4-05) → R4-06 → R4-07 → R4-08 → R4-09 → R4-10 → R4-11 → R4-12
```

After R4-05..09 land, optionally run one CFReDS rerun and diff
`reports/report.md` against the pre-refactor run — byte-identical output is the
strongest behavior-preservation signal for the report pipeline.
