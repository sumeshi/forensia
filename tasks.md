# tasks.md — Report Pipeline Simplification Plan (R3, 2026-06-11)

Diagnosis of the in-progress run `dist/cfreds/` (session `session-a17182984ef2`,
ingest 07:06 UTC, report prefill 16:38 JST, LLM section refresh still running at
17:31 JST). The user-visible symptom: the report reads as **instructions to the
reader mixed with findings**, in inconsistent languages, with internal workflow
labels in the body. Every cause below was traced to a concrete file/line and a
concrete artifact under `dist/cfreds/`.

The previous round (R2-01..R2-19 + review fixes) is complete; see git history and
`tests/test_review_regressions.py`. This file replaces that plan entirely.

## Implementation review (2026-06-11, post-implementation)

All R3 tasks were implemented; `uv run pytest tests/ -q` → **738 passed**. The
review found and fixed these defects in the delivered implementation (regression
tests appended to `tests/test_review_regressions.py`, R3 section):

1. **Skip-placeholder tripped the quality gates** — wrong_query/not_found blocks
   stored `*Block skipped: …*`, which `_check_failure_spam` treats as a failure
   marker (confidence cap 0.15 for the whole section). Replaced with a neutral
   reader-facing placeholder (`_insufficient_evidence_placeholder`, language-aware,
   free of all gate-trigger phrases).
2. **Rule 16 violations became load-bearing** — the table-block builders migrated
   the old renderers' SQL verbatim, including `LIKE '%secret_project%'` /
   `'%resignation%'` and hardcoded `CCLEANER64.EXE / ERASER.EXE / GOOGLEDRIVESYNC`
   lists, plus fixed CFReDS-flavored rows in the Recommendations/Evidence-Gaps
   tables ("OST、ブラウザ、クラウド同期…", "Eraser/CCleaner 実行は…"). All indicator
   lists now come from `dfir_ioc_catalog.yaml` via new catalog accessors
   (`_catalog_exe_globs` / `_catalog_path_terms` / `_catalog_artifact_names` /
   `_exe_glob_sql` / `_matches_exe_globs`); recommendations and evidence-gap rows
   are derived from the case's own findings/artifact families. A regression test
   greps writer.py for the forbidden literals.
3. **`co_occurs_event_ids` was silently ignored** (R3-04) — the boot-window rule
   matched any Microsoft-named service anywhere. Implemented
   `build_co_occur_index` + `_co_occurs_satisfied` (prefetched boot-event
   timestamps, same-host ± within_minutes proximity, conservative when
   unverifiable) and made every `when_all` condition require a positive match
   (missing column no longer passes).
4. **Gap cap formula ineffective** (R3-08) — capped at `len(active_hypotheses)`
   (≈8, i.e. no cap). Now `max(2, min(4, MAX_ACTIVE_HYPOTHESES - active))`.
5. **Q6 epoch note used single-cluster logic** — `_build_host_identity` showed
   only `host_epochs[0]`; now reuses `_build_host_note` (multi-epoch summary).
6. **Channels declared but invisible to the LLM** (R3-06) — SQL predicates were
   in place, but the playbook narrative ignored `channels:`; `_render_event_narrative`
   now renders "ONLY meaningful on channel(s): …". The 1100 query in
   `_antiforensic_rows` gained its missing channel guard.
7. **Leftovers** — dead `_prepend_status_badge` removed; section_agent's
   hardcoded tool-name tuple now reads the catalog; `Task List.ersy` moved into
   the Eraser catalog entry as `artifact_names`.

Known deferrals: the two Japanese fallback strings in appendix interpretation
(`writer.py` `_structured_answer_interpretation`) remain in code (generic wording,
used only when no `interpretation_template` exists); R3-10 module decomposition
was not executed in this round and stays open below.

---

## 1. What the logs show, and why it happened

### 1.1 The final report discards every LLM-written narrative section

`build_report_markdown_from_db` ([writer.py:3821-3848](src/forensia/report/writer.py#L3821-L3848))
silently **replaces** sections `1_overview` … `5_recommendations` with hardcoded
deterministic renderers whenever all five exist. The LLM section pipeline
(plan loop → outline → narrate → quality gates → claims; ~80 `report-section-*`
calls in `ai_logs/session-a17182984ef2/`) writes to `report_sections`, and its
output is then **thrown away** at report.md assembly.

Consequences observed:
- `reports/report.md` (16:38) Executive Summary / Assessment / Log Integrity /
  Recommendation Basis are renderer boilerplate hardcoded in Python with
  imperative reader-instructions: 「…確認する必要があります」「…扱わないで
  ください」「…相関してください」 ([writer.py:3401](src/forensia/report/writer.py#L3401),
  [3508](src/forensia/report/writer.py#L3508), [3661](src/forensia/report/writer.py#L3661),
  [3694](src/forensia/report/writer.py#L3694)). This is the "instructions mixed
  into the report" tone.
- The Web UI shows the *DB* bodies (LLM text), the file shows the *renderer*
  bodies — two different reports for the same case at the same moment.
- Hardcoded Japanese prose in Python also bypasses `LLM_OUTPUT_LANGUAGE` and
  violates the declarative-layer principle.

This dual path is the core structural complexity: **three competing sources for
the same section body** (template scaffold, LLM block pipeline, deterministic
renderer), reconciled nowhere.

### 1.2 Workflow status labels are stored inside the body

`_prepend_status_badge` ([section_agent.py:186](src/forensia/ai/section_agent.py#L186),
called at [2103](src/forensia/ai/section_agent.py#L2103)) prepends
`**Status:** partial` / `**Status:** wrong_query` into the persisted body.
`reports/api/report_sections.json` shows every narrative block carrying these
labels; `_strip_narrative_status_lines` removes them only in the report.md path.
A `wrong_query` block is even narrated anyway (see 5_recommendations
"Immediate Actions": status wrong_query, yet a full lateral-movement paragraph).

### 1.3 Quality gates pass garbage at section granularity

`report_sections.json`: `1_overview` = status stable, confidence **1.0**, body
in **English** under `LLM_OUTPUT_LANGUAGE=ja`; `5_recommendations` = stable /
1.0 with **fabricated evidence ids** `evtx-security-0001 … 0008` (real format:
`evtx-security-000000000xxx`). Gates run per *section* after blocks are
concatenated (`finalize_section` → `_quality_gate_section`,
[writer.py:4053-4075](src/forensia/report/writer.py#L4053)): a mostly-Japanese
multi-block body dilutes the language-drift ratio, and cited-id validation never
checks tokens against the DB. Per-block enforcement is missing.

### 1.4 False-positive findings still steer all narrative

`03-report-section-block-1_overview-Executive-Summary-04/05.json`: the outline
and paragraph lead with `windows-corr-logon-then-service-0001/0002` — boot-time
driver/service installs ("Intel(R) PRO/1000 NDIS 6 Adapter Driver", "Microsoft
Memory Module Driver") on host `37L4247F27-25`. Two compounding causes:
- R2-06 benign-context rules gate only **hypothesis verdicts**; rule-engine
  **findings** keep `critical` confidence and top `overview_top_findings`
  ranking, so every narrative block built on that keypoint inherits the FP lead.
- Epoch detection (R2-16) labels `37L4247F27-25` **active**
  (`Q6` appendix table: `37L4247F27-25 | active`) because the host has one 1100
  event on 2015-03-25; `detect_epochs` builds a single cluster per host and
  cannot see the 2010-vs-2015 split ([case.py:detect_epochs](src/forensia/core/case.py)).

### 1.5 Channel-blind event matching produces wrong citations

`2_timeline` "Log Integrity" cites Event 104 from
`evtx-microsoft-windows-diagnosis-scripted-operational-000000000004` as a
log-clear candidate. Event IDs are only meaningful per channel; 104 is
"System log cleared" only on the `System`/EventLog channel. Keypoints, rules,
and playbook text match on `event_id` alone.

### 1.6 Cost and churn

- Narrative blocks still run the iterative agent plan loop:
  `Executive-Summary-01..03` are template/SQL probing calls (one with broken SQL
  `… computer = '37L4247F27-25)`) before outline+narrate — 3 wasted calls per
  narrative block.
- Section-agent plan prompts are **49 KB system messages**
  (`sizes [48979, …]`): the R2-08 budget constrains only the playbook part, not
  the assembled system message (schema cards + keypoint catalog + cookbook are
  added afterwards).
- Broad plan drafts 8 hypotheses/cycle (8× `NN-plan-broad-draft`) while ~2 are
  investigated → `report.md` Gaps table lists **7 "not started"** hypotheses
  whose "Latest rationale" merely repeats the description and whose "Needed
  evidence" is one repeated fallback sentence.
- `memory/overview.md` again accumulates near-duplicate one-liners
  ("The hypothesis regarding X was refuted." ×10) — every refute is a
  "resolution transition" so the R2-10 gate admits each one.

## 2. Design decision (the refactoring)

**One body pipeline, one source of truth.**

```
template blocks ──┬─ mode: table       → deterministic block builder (rows + optional
                  │                      YAML interpretation template, no LLM)
                  ├─ mode: structured  → QuestionSpec path (unchanged)
                  └─ mode: narrative   → outline → narrate over the table-block rows
                                         (no agent plan loop, per-block gates)
        all blocks → report_sections (only store)  → report.md = render(DB)
                                                   → Web UI    = render(DB)
```

- The deterministic renderers' *tables* survive as table-blocks; their hardcoded
  instruction prose is deleted. Reader-facing guidance, where still wanted,
  moves to declarative YAML (`interpretation_template`-style, English source,
  rendered per `LLM_OUTPUT_LANGUAGE`).
- `build_report_markdown_from_db` loses the override branch: DB bodies are the
  report. The file and the UI can no longer diverge.
- Workflow status lives in columns, never in body text.

---

## P0 — structural fixes (do these first, in order)

### R3-01 Single report-body pipeline: remove the deterministic override

- [x] **Priority: P0 (refactor)**
- **Symptom**: report.md narrative ≠ DB/UI narrative; final report is
  instruction-tone boilerplate; LLM section work discarded (§1.1).
- **Cause**: dual generation paths blended late ("fix: report quality" band-aid)
  instead of choosing one (CLAUDE.md Rule 7).
- **Fix**:
  1. Convert each deterministic renderer (`_render_overview_section`,
     `_render_timeline_section`, `_render_technical_section`,
     `_render_gaps_section`, `_render_recommendations_section`) into **block
     builders** returning `(heading, rows, columns)` — keep the SQL, drop the
     prose. Register them like structured-answer builders, addressable from
     template block hints (`<!-- mode: table; builder: overview_key_findings -->`).
  2. Update the packaged templates (`src/forensia/report_template/*.md`) so each
     current deterministic table appears as a `mode: table` block, and each
     prose passage becomes either a `mode: narrative` block or is deleted.
  3. Delete the override branch in `build_report_markdown_from_db`
     ([writer.py:3830-3841](src/forensia/report/writer.py#L3830)); always render
     from `report_sections`.
  4. Delete the hardcoded Japanese prose strings (writer.py:3401, 3508, 3661,
     3694, and the parallel strings in the other renderers). Guidance text that
     must survive becomes English `interpretation_template` entries in
     `rulepacks/_schema/` YAML rendered via the existing template mechanism.
  5. Rebuild report.md at section-refresh completion (single call site) so file
     and UI stay in sync.
- **Files**: `src/forensia/report/writer.py`, `src/forensia/ai/section_agent.py`
  (block dispatch), `src/forensia/report_template/*.md`, `templates/*.md`
  (benchmark templates use the same hints), docs/report-pipeline.md.
- **Tests**: existing writer/regression suites must pass with the override gone;
  new test: `build_report_markdown_from_db` returns exactly the persisted bodies
  (no renderer text); template-block parse test for `mode: table` hint; absence
  test: `grep` the writer module for `してください`/`必要があります` literals → none.
- **Done when**: report.md == rendered DB sections; no Japanese literals in
  writer.py; deterministic tables still present in the output via table blocks.
- **Subagent context**: read §1.1 and §2 above; CLAUDE.md Rules 7/13/16;
  run `uv run pytest tests/ -q` (705+ tests, no LLM server needed).

### R3-02 Workflow status out of the body; wrong_query blocks are not narrated

- [x] **Priority: P0**
- **Symptom**: `**Status:** partial` / `wrong_query` rendered inside UI
  narrative; a `wrong_query` block narrated as lateral-movement prose (§1.2).
- **Cause**: `_prepend_status_badge` writes workflow state into the body;
  narration proceeds regardless of evidence status.
- **Fix**:
  1. Remove `_prepend_status_badge` from the stored-body path; persist block
     status in `section_runs` / `section_run_coverage` (columns already exist)
     and expose per-block status in `reports/api/report_sections.json` as a
     field, not body text.
  2. In `_write_block_body`: when the block's evidence status is `wrong_query`,
     `not_found`, or `not_searched`, do **not** call the narrator; store the
     template's insufficient-evidence placeholder (templates already declare
     one) and a gap note.
  3. Defensive strip of legacy `**Status:**` lines in `finalize_section`
     (one-time migration for existing case DBs).
- **Files**: `src/forensia/ai/section_agent.py`, `src/forensia/report/writer.py`,
  `src/forensia/api/service.py` (DTO field), `web_ui` consumes the new field
  (separate small PR if needed).
- **Tests**: stored body never matches `r"^\*\*Status:\*\*"`; wrong_query block
  produces placeholder + gap, zero narrator calls (mock LLM).
- **Done when**: fresh run's `report_sections.json` bodies contain no status
  lines; UI chip still shows status.
- **Depends on**: R3-01 (block dispatch refactor touches the same function).

### R3-03 Per-block language and evidence-id enforcement

- [x] **Priority: P0**
- **Symptom**: English Executive Summary under `ja` with confidence 1.0;
  fabricated `evtx-security-0001…0008` ids survive to a stable section (§1.3).
- **Cause**: gates evaluate the concatenated section; mixed-language blocks
  dilute ratios; cited ids are never resolved against the DB.
- **Fix** (deterministic, no new LLM roles):
  1. After each narrate call: detect output language (reuse the gate's detector
     on the single paragraph). On mismatch, retry once with a one-line coaching
     turn (`Write the paragraph in Japanese.` / target language); on second
     mismatch, fall back to `_fallback_narrative_body`.
  2. At block finalize: extract evidence-id-shaped tokens
     (`r"\b(evtx|mft|prefetch)-[a-z0-9-]+\b"`), check existence against the DB
     (`evidence_id IN (...)` over the three tables; cache the id set). Invalid
     ids: strip the citation, add gap note `cited evidence ids not found: […]`,
     cap block confidence 0.5.
  3. Keep section-level gates as the outer net; they now rarely fire.
- **Files**: `src/forensia/ai/section_agent.py` (narrate retry + finalize),
  `src/forensia/report/writer.py` (id-validation helper near claims provenance).
- **Tests**: narrate-retry on language mismatch (mock LLM returning EN then JA);
  invalid-id stripping with an in-memory DB; valid ids untouched.
- **Done when**: tests pass; a synthetic English paragraph under `ja` never
  reaches `report_sections` unflagged.
- **Depends on**: R3-01/02 ordering only.

---

## P1 — stop the false-positive lead story

### R3-04 Benign-context applies to findings and keypoint ranking

- [x] **Priority: P1**
- **Symptom**: Executive Summary and Key Findings lead with boot-time
  driver/service installs (`windows-corr-logon-then-service-*`) — OS noise
  presented as the case's top signal (§1.4).
- **Cause**: R2-06 gates hypothesis verdicts only; findings keep `critical`
  confidence and `overview_top_findings` ranks by confidence.
- **Fix** (declarative + deterministic):
  1. Extend `false_positive_rules.yaml` with finding-level rules, e.g.:
     ```yaml
     finding_benign_context:
       - id: boot-window-service-install
         applies_to_tags: [persistence, lateral-movement]
         when_all:
           - { column: service_name, regex: '(?i)(driver|microsoft|office|software protection)' }
           - { co_occurs_event_ids: [6005, 12], within_minutes: 10 }
         note: "Service/driver registrations during OS boot are routine."
     ```
     (Patterns are OS-generic; reviewer must reject case-specific values —
     Rule 16.)
  2. In `rules/engine.py` post-processing: annotate matching findings
     (`tags += ['benign-context:<id>']`), multiply confidence by 0.4, never
     suppress outright (visibility preserved).
  3. `overview_top_findings` (and the new table-block builders from R3-01)
     exclude `benign-context:*`-tagged findings from the default top list;
     appendix catalog still shows them.
- **Files**: `src/forensia/rulepacks/_schema/false_positive_rules.yaml`,
  `src/forensia/rules/engine.py`, `src/forensia/report/writer.py` (keypoint).
- **Tests**: synthetic findings + 6005 rows → tagged & demoted; non-boot install
  untouched; top-findings keypoint excludes tagged rows.
- **Done when**: rerun's Executive Summary no longer leads with corr-service
  findings (verify via `scripts/eval_run.py` family metric + manual read).

### R3-05 Within-host epoch clustering (v2)

- [x] **Priority: P1**
- **Symptom**: `37L4247F27-25` labeled `active` in Q6/Systems tables although
  ~740 of its events are from 2010 (pre-deployment) and only a handful from the
  case window (§1.4).
- **Cause**: `detect_epochs` builds one cluster per host; a single recent event
  flips the whole host to active.
- **Fix**: cluster each host's event timestamps (sort, split on gaps >
  `EPOCH_GAP_DAYS`); label clusters individually; host note becomes e.g.
  `pre-deployment bulk (2010) + minor activity 2015-03-25 (n=5)`. Dominant time
  range derives from active clusters only (already wired). Keep the output
  shape `dict[host, list[cluster]]` — callers already iterate a list.
- **Files**: `src/forensia/core/case.py` (`detect_epochs`),
  `src/forensia/report/writer.py` (note rendering), `tests/test_host_epochs.py`.
- **Tests**: host with 2010 bulk + 2015 trickle → two clusters, bulk labeled
  pre-deployment; single-epoch host unchanged.
- **Done when**: tests pass; Q6 note distinguishes the epochs.

### R3-06 Channel-aware event semantics

- [x] **Priority: P1**
- **Symptom**: Diagnosis-Scripted event 104 cited as a log-clear candidate
  (§1.5).
- **Cause**: event_id-only matching in keypoints/playbook/builders.
- **Fix**: add optional `channels: [...]` to `event_ids.yaml` entries that are
  channel-specific (104, 1100, 1102, 6005/6006, 7036/7045, …). Consumers that
  read the YAML (`_load_event_id_hints`, timeline/log-integrity keypoints,
  `_build_daily_session_timeline`, antiforensic builder) add
  `AND channel ILIKE …` when channels are declared. Playbook narrative renders
  the channel qualifier so the LLM sees it too.
- **Files**: `src/forensia/rulepacks/_schema/event_ids.yaml`,
  `src/forensia/report/writer.py`, `src/forensia/ai/section_agent.py`,
  `src/forensia/ai/prompts.py`.
- **Tests**: synthetic rows with 104 on two channels → only System-channel row
  selected by the log-integrity keypoint; YAML without `channels` behaves as
  before.
- **Done when**: tests pass; rerun's Log Integrity cites only EventLog-channel
  rows.

### R3-07 Narrative fast path + real prompt budget

- [x] **Priority: P1**
- **Symptom**: 3 wasted plan-loop calls per narrative block (incl. malformed
  SQL); 49 KB system prompts on section-agent plan calls despite the 24 KB
  playbook budget (§1.6).
- **Cause**: narrative blocks reuse the full evidence-gathering agent loop; the
  budget guards only `_dfir_playbook`, not the assembled message.
- **Fix**:
  1. In `run_section_block_agent`: blocks with resolved keypoints (table-block
     rows from R3-01 or `evidence_keypoints` hits) skip the plan loop entirely —
     outline → narrate only. The plan loop remains for blocks with zero
     pre-resolved evidence.
  2. Move budget enforcement to message assembly: a helper
     `enforce_system_budget(system_str) -> str` applied in the section-agent and
     planner builders after full concatenation, trimming in declared order
     (cookbook → keypoint catalog → playbook sections per existing drop order),
     logging per-part sizes to `ai_logs/<session>/summary.json`.
- **Files**: `src/forensia/ai/section_agent.py`, `src/forensia/ai/prompts.py`,
  `src/forensia/ai/audit.py`.
- **Tests**: narrative block with prefetched rows performs 0 plan calls (mock);
  assembled system message ≤ budget for a fixture profile.
- **Done when**: rerun shows ≤2 LLM calls per narrative block and plan prompts
  ≤ 24 KB.

---

## P2 — churn, noise, decomposition

### R3-08 Match drafting throughput to investigation capacity; fix Gaps table

- [x] **Priority: P2**
- **Symptom**: 8 drafts/cycle vs ~2 investigations → 7 "not started" rows in
  Unresolved Hypotheses; "Latest rationale" repeats the description; "Needed
  evidence" is one repeated boilerplate sentence (§1.6, report.md:173-183).
- **Fix**:
  1. Cap `gap_areas` per cycle at `max(2, focus_count)` (the number of
     hypotheses actually investigated per cycle).
  2. Unresolved table: exclude `reasoning_count == 0` rows from the table; show
     them as one summary line ("N drafted hypotheses not yet investigated").
     Blank the rationale cell when it equals the description; blank
     needed-evidence when no `missing_questions` exist.
- **Files**: `src/forensia/ai/investigator.py` (`_run_broad_plan_step`),
  `src/forensia/report/writer.py` (gaps table-block builder from R3-01).
- **Tests**: builder fixture with 2 investigated + 5 untouched hypotheses → 2
  rows + 1 summary line; no duplicated description/rationale cells.
- **Done when**: tests pass; rerun Gaps table has no "not started" spam.

### R3-09 overview.md: resolution lines collapse

- [x] **Priority: P2**
- **Symptom**: `memory/overview.md` again holds ~10 near-identical
  "The hypothesis regarding X was refuted." lines.
- **Cause**: every refute is a transition, so the R2-10 gate admits each line;
  0.7 token-set similarity misses the paraphrase family.
- **Fix**: refuted hypotheses write only to `archive/refuted.md` (already
  happens) — overview admits resolution lines only for `confirmed` and
  `untestable`. Additionally collapse by template: normalize lines matching
  `the hypothesis regarding .* was refuted` into a counter line
  ("N hypotheses refuted so far") maintained in place.
- **Files**: `src/forensia/ai/investigator.py` (`_apply_memory_updates`),
  `src/forensia/core/memory.py`.
- **Tests**: 3 refutes → overview unchanged except counter; confirm still
  writes its line.
- **Done when**: tests pass.

### R3-10 Decompose writer.py / section_agent.py (mechanical)

- [ ] **Priority: P2 (refactor)** — NOT implemented in this round (writer.py is
  now 6,269 lines); intentionally deferred until after a verification rerun.
- **Symptom**: `report/writer.py` ≈ 5,900 lines mixing keypoints, quality gates,
  structured-answer builders, markdown rendering, timezone helpers, claims,
  epoch annotation; `ai/section_agent.py` ≈ 2,500 lines mixing block dispatch,
  builders, digesting, narration. Review and the R3-01 surgery both suffer.
- **Fix** (no behavior change, import-compatible):
  - `report/keypoints.py` (REPORT_KEYPOINTS + aliases + resolvers)
  - `report/quality_gates.py` (`_quality_gate_*`, `_GateCtx`)
  - `report/structured_answers.py` (`_STRUCTURED_ANSWER_BUILDERS`, exports)
  - `report/render.py` (markdown assembly, `_final_report_section_body`,
    timestamp/timezone rendering)
  - `writer.py` keeps `fill_section`/`finalize_section`/orchestration and
    re-exports moved names (`from .keypoints import REPORT_KEYPOINTS` …) so
    existing imports and tests keep working.
  - section_agent: extract `ai/section_blocks.py` (block context + builders)
    leaving the agent loop in place.
- **Sequencing**: do **after** R3-01..03 land (avoid moving code mid-surgery).
- **Tests**: suite green; `grep -rn "from forensia.report.writer import"` users
  unaffected.
- **Done when**: no module > ~2,000 lines in `report/`; suite green.

### R3-11 Eval metrics for this failure class

- [x] **Priority: P3**
- **Fix**: extend `scripts/eval_run.py`:
  - instruction-tone ratio: share of narrative sentences matching imperative
    admonitions (`してください|必要があります|べきです|do not treat|should be
    verified`) — flag > 10 %;
  - UI/file consistency: diff `report_sections` bodies vs report.md sections;
  - per-block language conformity rate;
  - invalid-evidence-id citation count (reuses R3-03 validator).
- **Tests**: fixture dir with seeded violations → metrics fire.
- **Done when**: `eval_run.py dist/cfreds` reports all four; BENCHMARK.md notes
  they are regression observations only (Rule 16).

---

## Suggested execution order

```
Wave 1: R3-01 → R3-02 → R3-03   (single pipeline; sequential, same files)
Wave 2: R3-04, R3-05, R3-06, R3-07   (parallel-safe)
Wave 3: R3-08, R3-09
Wave 4: R3-10 (mechanical decomposition), R3-11
```

After Wave 1, rerun the case and read `reports/report.md` end-to-end: the
acceptance bar is "no sentence addressed to the reader as an instruction, one
language throughout, status labels only in UI chips, and the lead findings are
case signal rather than boot noise".
