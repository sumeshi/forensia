# tasks.md — Report Trust & Review Round (R7, 2026-06-12)

Third report-accuracy review, driven by the post-R6 run
(`dist/cfreds` session-323ab0235299, 20 cycles + final refresh). R6 works:
sections re-rendered at cycles 06/12/15/18 and the final refresh (21) ran;
tables carry captions; citations are real 12-digit IDs. This round is about
trusting and *reading* the report: narrative quality control, full data
visibility, and traceability from citation to source record. Per Rule 16 all
fixes are general capabilities; CFREDS is the diagnostic only.

## Observed symptoms (post-R6 run)

1. **Executive Summary is a citation-heavy finding dump** — 11 inline IDs in
   one paragraph (its own prompt rule says "AT MOST 2-3"), no incident-level
   "so what", and it reads like the top finding restated. Written once, never
   re-criticized: there is no role that re-reads a written section and decides
   it is not good enough.
2. **Presentation-level truncation hides data** — `_Showing 12 of 18 rows._`
   (Chronological Events) and the appendix's 25-row cap
   (`STRUCTURED_MARKDOWN_MAX_ROWS`) cut rows the builders already selected.
   The reader has to leave the report to see rows the system decided were
   noteworthy.
3. **Citations are dead ends** — `evtx-system-000000000395` is unreadable and
   unclickable; verifying any claim means manually querying DuckDB. There is
   no id → source-record reference in either report.md or report.html.
4. **Pseudo-citations** — the Log Integrity narrative cites digest labels
   (`(antiforensic_activity)`, `(STRUCTURED_OBSERVATIONS)`) as if they were
   evidence IDs. The citation validator only checks `evtx|mft|prefetch-*`
   tokens, so label-shaped citations pass through.
5. **Cross-section number drift** — Action Plan says "9件の active
   hypothesis", Evidence Gaps says "4件", the Unresolved table shows 4.
   All three are deterministic builders, but they rendered in *different
   cycles* against different DB states, and nothing reconciles them at the
   end.
6. **Internal IDs leak into prose** — Gap Assessment narrates
   `gap-8b9254d65e`, `H-010` etc.; meaningless to a human reader.

## Root causes

- **RC12 — write-once narrative, no critic.** A narrative block is written by
  `section_outliner` → `paragraph_narrator` and accepted as-is. Deterministic
  gates (`quality_gates.py`) cap confidence but never trigger a rewrite, and
  nothing re-evaluates an already-written body against the section's own
  tables/digest. (Symptoms 1, 4, 6.)
- **RC13 — double row-limiting.** Builders already bound their result sets
  (noise control); `_markdown_table(max_rows=12)` and
  `STRUCTURED_MARKDOWN_MAX_ROWS = 25` then cut the *presentation* again.
  The second cut serves nobody. (Symptom 2.)
- **RC14 — no evidence reference layer.** `reports/evidence/*.json` stores
  per-section rows, but nothing maps a cited evidence_id back to its source
  record for the reader. `report/html.py` has its own inline-markdown
  renderer (`_render_inline_markdown`) — a natural injection point that is
  currently unused for this. (Symptom 3.)
- **RC15 — section renders are not reconciled at one DB state.** Stale-driven
  re-rendering (R6) updates sections independently; numbers derived from the
  live DB (hypothesis counts etc.) diverge between sections rendered at
  cycle 6 vs 18. The final refresh only re-renders *stale* sections, so the
  drift survives to the delivered report. (Symptom 5.)

## TODO

Ordering: R7-04 (cheap, fixes drift and gives the Executive Summary a final
rewrite hook) → R7-01 (reviewer role) → R7-02 (full rows) → R7-03 (evidence
references). Each task is one PR; `uv run pytest tests/ -q` green;
`scripts/check_imports.py` green.

- [ ] **R7-04: Final refresh renders the whole report at one DB state (RC15).**
  - Add a `force_all: bool = False` parameter to
    `async_refresh_report_sections` / `_collect_section_requests`; when set,
    every section is treated as stale. Pass it only from the final-refresh
    call in `investigate()`.
  - Cost: table/structured blocks are LLM-free; narrative blocks are ~4-6
    LLM calls once per session. The update-count cap
    (`_mark_section_stale`) must NOT block the final pass — bypass the cap
    when `force_all` (it guards per-cycle loops, not the closing render).
  - Files: `src/forensia/ai/section_refresher.py`,
    `src/forensia/ai/investigator.py`, test in
    `tests/test_stale_propagation.py`.
  - Success criteria: with all sections fresh and non-stale, a `force_all`
    refresh produces render requests for every template; counts derived from
    the DB (e.g. unresolved hypotheses) are identical across sections in the
    final report because they rendered against the same state.

- [ ] **R7-01: Section reviewer role — criticize and rewrite narrative blocks (RC12).**
  - Two stages, per Rule 5 (code answers what code can):
    1. **Deterministic rubric checks** (new `report/quality_gates.py` helpers
       or a small `narrative_review.py`): citation count > 3 in one
       paragraph; parenthetical citations that are not valid evidence-ID
       tokens (catches `(antiforensic_activity)`, `(STRUCTURED_OBSERVATIONS)`);
       internal IDs (`gap-[0-9a-f]+`, `H-\d+`, `KP-\d+`) in prose; body
       shorter than a floor or equal to the insufficient-evidence
       placeholder while the section digest has rows.
    2. **LLM `section_reviewer`** (new prompt builder in `ai/prompts.py`):
       input = heading, body, section table digest, deterministic problem
       list; output JSON `{verdict: "pass"|"rewrite", problems: [...],
       guidance: "..."}`. On `rewrite`, call the narrator ONCE more with the
       problems+guidance appended; then re-run the deterministic checks. At
       most one rewrite per block per render (cost bound), and the loop never
       blocks the section — on a second failure, keep the better body and
       record the problems as section gaps.
  - Wire into `ai/section_agent._write_block_body` after narrate (both
    benchmark-mode false paths). Reviewer runs on every narrative render —
    combined with R7-04, the Executive Summary always gets a final
    criticize-and-rewrite pass against the finished tables.
  - Exec-summary-specific rubric items stay in the prompt template, not code:
    "states what happened, who/when, and what remains open in ≤2 paragraphs;
    cites at most 3 representative IDs; does not enumerate findings".
  - Files: `src/forensia/ai/prompts.py`, `src/forensia/ai/section_agent.py`,
    new `src/forensia/report/narrative_review.py` (deterministic checks —
    report layer, no LLM), tests in `tests/test_review_regressions.py`
    (deterministic checks; prompt assembly; rewrite-once flow with a stubbed
    LLM).
  - Success criteria: a body with 11 citations or a `(label)` pseudo-citation
    is flagged deterministically; the reviewer rewrite path runs at most one
    extra narrate call; a passing body is unchanged; problems surface in
    section gaps when unresolved.

- [ ] **R7-02: Render all selected rows — kill presentation truncation (RC13).**
  - `report/probes.py:render_table_block`: pass `max_rows=0` (unlimited) to
    `_markdown_table` by default; allow per-builder override via a
    `max_rows:` key in `rulepacks/_schema/report_tables.yaml`. Builders keep
    their own selection limits (that is curation, not presentation).
  - `report/structured_answers.py`: replace the fixed
    `STRUCTURED_MARKDOWN_MAX_ROWS = 25` cut with a generous safety cap
    (default 200, env-overridable like other knobs) — below the cap render
    everything; above it keep the CSV/JSON pointer note. `_markdown_table`
    keeps its current default for non-report callers.
  - Files: `src/forensia/report/probes.py`,
    `src/forensia/report/markdown.py` (accept `max_rows=0` = unlimited),
    `src/forensia/report/structured_answers.py`,
    `src/forensia/rulepacks/_schema/report_tables.yaml`, tests in
    `tests/test_writer_rq_regressions.py`.
  - Success criteria: a builder returning 18 rows renders 18 rows and no
    `_Showing N of M rows._` marker; a structured answer with 68 rows renders
    all 68; one with >200 rows still truncates with the pointer note.

- [ ] **R7-03: Evidence reference layer — clickable, hoverable citations (RC14).**
  - **Map builder** (report layer, deterministic): after the report body is
    final, scan it with the existing evidence-ID regex
    (`report/keypoints.py:37`), look up each ID in its table
    (`evtx_events` / `mft_entries` / `prefetch_executions`), and write
    `reports/evidence_map.json`: id → `{source, timestamp, summary}` where
    summary is e.g. `4624 logon informant@informant-PC src=127.0.0.1` or
    `file Users/.../X.lnk si_modified=...` (compact, one line, generic
    per-table formatters).
  - **report.md**: append an auto-generated `## Evidence References` appendix
    block (one bullet per cited ID with its summary), and rewrite inline IDs
    as anchor links `[evtx-…](#ev-evtx-…)` during `render_written_report`.
  - **report.html**: in `_render_inline_markdown`, render evidence-ID tokens
    as `<a href="#ev-…" title="<one-line summary>">` — hover shows the
    record, click jumps to the reference entry. Pure HTML (`title`
    attribute), no JS dependency.
  - Keep it one-directional: the map is derived from the final body, so no
    section writer needs to know about it (no new coupling into ai/).
  - Files: new `src/forensia/report/evidence_map.py`,
    `src/forensia/report/writer.py` (`render_written_report` hook),
    `src/forensia/report/html.py`, tests in `tests/test_html.py` and
    `tests/test_writer_rq_regressions.py`.
  - Success criteria: every evidence ID cited in the final report.md appears
    in evidence_map.json with a non-empty summary; inline IDs in report.html
    carry `title` + anchor; an ID cited but missing from the DB is listed as
    `unresolved` in the map (and flagged as a section gap — ties into R5-01
    validation).

- [ ] **R7-05: Human-readable hypothesis references in narrative (RC12/Symptom 6).**
  - Wherever gap/hypothesis context is fed to narrative blocks (Gap
    Assessment key points, reusable facts), pass `description` (truncated
    ~100 chars) alongside the ID and instruct the narrator to use
    descriptions; the deterministic rubric (R7-01 stage 1) flags raw
    `gap-*`/`H-*` tokens in prose so the reviewer rewrites them.
  - Files: `src/forensia/ai/section_blocks.py`, `src/forensia/ai/prompts.py`
    (rule line), covered by R7-01 tests plus one prompt-assembly assertion.
  - Success criteria: narrator input contains descriptions for every
    hypothesis/gap reference; a body containing `gap-8b9254d65e`-style tokens
    is flagged for rewrite.

## DEFER (R7)

- **`/api/evidence/{evidence_id}` + web UI hover cards** — serve the
  evidence_map (or live DB lookup) through the API and render rich hover
  cards in web_ui. Do after R7-03 proves the map shape.
- **Reviewer for table captions** — captions are template-filled today; if
  R7-01 shows residual awkwardness, extend the reviewer to caption text.
  Decide after one full run.
- Carried over: R5-08 (section_agent re-export cleanup), R5-09
  (`probes.py` split — now ~2,400 lines with `render_table_block`; split
  `report/table_blocks.py` + `report/claims.py` when R7 lands), R5-10
  remainder (full fact-pack).

## DONE (R7)

- Post-R6 run verification (session-323ab0235299): stale-driven re-renders
  observed at cycles 06/12/15/18 + final refresh 21; captions present on all
  tables; citations resolve to real IDs. Symptoms 1-6 and RC12-RC15
  documented from `dist/cfreds/reports/report.md` and ai_logs.

---

# tasks.md — Report Iteration & Readability Round (R6, 2026-06-12)

Second report-accuracy review, driven by the post-R5 run
(`dist/cfreds` session-907bd96e669c, 20 cycles, 622 LLM calls, ~2 h).
R5 fixed citations (now real 12-digit IDs) and activated table-mode
rendering. Two symptoms remain; both are root-caused below. Per Rule 16 all
fixes are general DFIR/report capabilities; CFREDS is the diagnostic only.

## Observed symptoms (post-R5 run, reproduced from logs/DB)

1. **Tables render with no lead-in prose** — sections 1–5 are now mostly bare
   tables; only Executive Summary / Log Integrity / Gap Assessment /
   Recommendation Basis are narrative. A reader gets data without one
   sentence of orientation per table ("what this table shows, what stands
   out").
2. **Report still written once (cycle 03) in a 20-cycle session** — despite
   R5-03: `report_sections` ends with `update_count = 1` for all six sections
   while `stale = TRUE` on five of them, i.e. staleness was *produced* but
   never *consumed*.
3. **Narrative blocks contradict sibling tables** — "Log Integrity" returned
   the insufficient-evidence placeholder while the same report's Phase
   Summary and Antiforensic tables list 1100/log-integrity events.
4. Minor: truncation marker rendered as a fake table row
   (`| ... | Showing 12 of 18 rows. | | | |`); `technical_execution` lists
   duplicate executables (one row per prefetch file, e.g. IEXPLORE.EXE ×2).

## Root causes (code-level, confirmed)

- **RC7 — dict access on DuckDB tuple rows kills every report refresh after
  the first.** `progress_events` records, for cycles 6/9/12/15/18:
  `[report] refresh failed: tuple indices must be integers or slices, not str`.
  Crash site: `ai/section_refresher.py:50-53` —
  `row["section_key"]` over `db.execute(...).fetchall()`, which returns
  tuples (dict rows come from `fetch_records`). The set comprehension only
  executes when at least one stale row exists, so cycle 3 (no stale rows yet)
  succeeded and **every later refresh — including the R5-03 final refresh —
  crashed on its first expression**. R5-03's stale marking works; its consumer
  dies. This bug predates R5 (it also explains part of the first session's
  one-shot report) and was reachable only once stale rows existed.
- **RC8 — refresh failures are silently absorbed (Rule 12 violation).**
  `_run_report_phase` and the final-refresh wrapper catch `Exception`,
  collapse it to a one-line summary/print, and the session still terminates
  `completed`. A broken report pipeline survived 15 cycles across two
  sessions without anyone (human or gate) noticing. No traceback, no failure
  counter, no gap entry in the report.
- **RC9 — table blocks have no caption mechanism.** Builders return rows; both
  render paths emit only `_markdown_table(...)`. The appendix solves exactly
  this with declarative `interpretation_template` (YAML) + code-filled stats —
  the mechanism just was never extended to table blocks. (Symptom 1.)
- **RC10 — narrative blocks cannot see their section's own deterministic
  data.** Blocks render in template order (narrative first), and the narrative
  agent plans its own keypoints/SQL from scratch; the table rows built seconds
  later in the same section are never offered as evidence. Hence
  "insufficient evidence" placeholders and narrative/table contradictions.
  (Symptom 3.)
- **RC11 — table rendering duplicated across paths.** The async
  `_render_section_blocks` and sync `_render_section_from_request` each carry
  their own copy of the builder→columns→markdown branch (introduced during the
  R5 review fix). Two copies already diverged once (`SectionBlockResult`
  crash); they will diverge again.

## Implementation review (2026-06-12, post-implementation)

The first implementation attempt landed only two R5-02 leftovers (the
`citable: false` narrator rule and the bruteforce-rule `evidence_ids`
projection); R6-01..06 were then implemented in-session. Notes:

1. **R6-01** — `_collect_section_requests` now reads stale keys positionally
   (`row[0]`); regression test exercises the real DuckDB row shape
   (`CollectSectionRequestsTests`). This was the iteration killer.
2. **R6-02** — `_run_report_phase` returns a third value
   (`"skipped" | "ok" | "failed: <type>: <msg>"`), prints the full traceback,
   and carries the typed error into the progress event. `investigate()`
   counts failures (`report_refresh_failures` in the result dict) and prints
   a prominent end-of-run warning.
   **Revised after review feedback (unattended weekend runs):** failures do
   NOT abort the session. LLM-server outages get the investigation loop's
   wait-for-recovery treatment (`_call_with_outage_recovery`, default 8 h
   budget; per-section handling re-raises `LLMServerUnavailableError` instead
   of swallowing it as a section failure); only an exhausted outage budget
   stops the run — same policy as the rest of the loop. Programming errors
   are logged loudly and the loop continues: stale flags persist in the DB,
   so the next successful refresh (or the final refresh) catches up, and the
   failure path publishes already-persisted sections via
   `render_written_report` as a fallback.
3. **R6-03** — `rulepacks/_schema/report_tables.yaml` declares per-builder
   `caption`/`empty` templates; placeholder grammar is *shared* with
   question_routing's interpretation templates via the new
   `markdown.render_rows_template` (the old private filler in
   structured_answers now delegates to it). Empty results render the declared
   text instead of a bare `_No rows available._` table.
4. **R6-04** — `report/probes.py:render_table_block` is the single
   builder→caption→table path; both refresher paths call it. The duplicated
   inline branches (and their `_markdown_table`/`_TABLE_BLOCK_BUILDERS`
   imports) are gone from `section_refresher`.
5. **R6-05** — both render paths do a two-pass render (`_table_first_order`):
   table blocks first, collecting a bounded digest
   (`<SECTION_TABLES>`, ≤1200 chars/table, ≤4000 total), which flows into
   narrative blocks via the new `section_table_digest` kwarg →
   `_prepare_block_context` → merged into `ctx.structured_digest` → the
   narrator's observation block. Assembly keeps template order. Additionally,
   the insufficient-evidence placeholder now fires only when *no* structured
   digest exists — a narrative block sitting next to populated tables narrates
   from them instead of claiming insufficiency (and skips the outline LLM call
   when it has no query evidence of its own).
6. **R6-06** — `_markdown_table` renders the truncation marker as
   `_Showing N of M rows._` below the table; `_execution_rows` aggregates per
   executable name (exec_count summed, latest last_exec_time).

Verification: full suite green, `scripts/check_imports.py` green. The next
pipeline run should show `update_count >= 2` on narrative sections and
captions above every table.

## TODO

(empty — R6-01..06 done, see Implementation review; next candidates in DEFER)

- [x] **R6-01: Fix the stale-section tuple crash (RC7).**
  - In `ai/section_refresher.py:_collect_section_requests`, read stale keys
    via `fetch_records(db, ...)` (dict rows, codebase convention) or
    `row[0]`. Audit confirmed this is the only dict-access-on-`fetchall()`
    site in `src/` (others use `row[0]` or `fetch_records`).
  - Add the missing regression test for `_collect_section_requests` itself
    (none exists — the R5 async test bypassed it by injecting `is_stale`):
    real `CaseDB` with one stale + one fresh `report_sections` row and a
    template dir → returns exactly the stale section with `is_stale=True`,
    and a filled non-stale section is excluded.
  - Files: `src/forensia/ai/section_refresher.py`, new test in
    `tests/test_stale_propagation.py`.
  - Success criteria: with a stale section present, a report refresh produces
    a render request (and the TypeError is structurally impossible at that
    site). Verify: `uv run pytest tests/test_stale_propagation.py -q`.

- [x] **R6-02: Fail loud on report-refresh failures (RC8, Rule 12).**
  - In `_run_report_phase` and the final-refresh wrapper in
    `ai/investigator.py`: log `traceback.format_exc()` (not just `str(exc)`),
    emit the exception class + site in the progress event, and count
    failures. Persist the count into the session result
    (`investigate()` return dict) and `llm_logger.write_summary()` output.
    After 2 consecutive failed report phases, raise instead of continuing —
    an investigation whose report pipeline is dead must not finish
    `completed` silently.
  - Files: `src/forensia/ai/investigator.py`,
    `src/forensia/ai/section_refresher.py`, test in
    `tests/test_investigator_wiring.py` (inject a refresher that always
    raises; assert the session aborts with the failure surfaced, not
    `completed`).
  - Success criteria: a deliberately broken refresh shows a traceback in
    output, a non-zero `report_refresh_failures` in the result, and aborts
    after the 2nd consecutive failure.

- [x] **R6-03: Declarative captions for table blocks (RC9).**
  - Follow the appendix `interpretation_template` precedent
    (`rulepacks/_schema/question_routing.yaml` +
    `structured_answers` filling): declare a per-builder caption template
    next to the builder registry (YAML under `rulepacks/_schema/`, e.g.
    `report_tables.yaml`, keyed by builder name, per output language).
    Code fills deterministic stats: `{row_count}`, `{time_min}`, `{time_max}`,
    `{top:<column>}` (most frequent value), `{distinct:<column>}`. Render the
    filled caption as one short paragraph between the heading and the table.
    Empty tables get the declared `empty_text` instead of a bare empty table.
  - No LLM calls — captions are summarization of already-vetted rows where a
    template suffices (Rule 5: code can answer).
  - Files: new `src/forensia/rulepacks/_schema/report_tables.yaml`, caption
    filler in `src/forensia/report/probes.py` (or the new module from R6-04),
    wiring in both render paths, tests in `tests/test_writer_rq_regressions.py`.
  - Success criteria: every `mode: table` block renders caption + table; the
    caption contains the real row count and at least one value from the data;
    empty tables render the declared empty text; both render paths produce
    identical bodies for the same data.

- [x] **R6-04: Extract a single `render_table_block` helper (RC11).**
  - Move the duplicated builder→columns→caption→markdown branch out of
    `ai/section_refresher.py` (async) and `_render_section_from_request`
    (sync) into one function on the report side (e.g.
    `report/probes.py` next to `_TABLE_BLOCK_BUILDERS`, returning the body
    string + status), called by both paths. Do this together with or
    immediately after R6-03 so the caption logic lands once.
  - Files: `src/forensia/ai/section_refresher.py`,
    `src/forensia/report/probes.py`.
  - Success criteria: exactly one code path constructs table-block bodies;
    existing table tests green unchanged.

- [x] **R6-05: Narrative blocks consume their section's table data (RC10).**
  - Within a section, render deterministic blocks (table/structured) before
    narrative blocks regardless of template order (assembly keeps template
    order). Pass a bounded digest of the section's freshly built table rows
    (builder name, caption stats, top ~10 rows) into the narrative block
    context as reusable evidence — same shape as the existing
    `STRUCTURED_OBSERVATIONS` digest used for `1_overview`/`2_timeline`.
  - This is the concrete first step of R5-10 (deterministic fact-pack): the
    LLM narrates data the machine already selected, instead of re-planning
    SQL from scratch and concluding "insufficient evidence" next to a
    populated table.
  - Files: `src/forensia/ai/section_refresher.py`,
    `src/forensia/ai/section_blocks.py`, `src/forensia/ai/prompts.py`,
    prompt-assembly test in `tests/test_review_regressions.py`.
  - Success criteria: the narrative block prompt for a section contains the
    same-section table digest; a narrative block whose sibling tables have
    rows must not return the insufficient-evidence placeholder (assert via
    the deterministic placeholder path, not an LLM call).

- [x] **R6-06: Table cosmetics (deterministic, small).**
  - Move the `Showing N of M rows` marker out of the table body to a plain
    text line below the table (`_markdown_table` in `report/markdown.py`).
  - `technical_execution` builder: aggregate by executable name (sum
    `exec_count`, max `last_exec_time`) instead of one row per prefetch file.
  - Files: `src/forensia/report/markdown.py`,
    `src/forensia/report/probes.py`, tests in
    `tests/test_writer_rq_regressions.py`.
  - Success criteria: no `...` pseudo-row inside tables; one row per
    executable name.

## DEFER (R6)

- **Doctor check for row-access convention** — a grep-based check (in
  `scripts/check_imports.py` or doctor) flagging `row["` within 3 lines of a
  raw `.fetchall()`; cheap insurance against RC7 recurring.
- **LLM-polished captions** — if R6-03's template captions read too
  mechanical, add an optional one-call-per-section caption polish. Decide
  after seeing a full run with R6-03.
- Carried over from R5: R5-08 (section_agent re-export cleanup), R5-09
  (probes.py split — R6-03/04 add to it; split right after), R5-10 (full
  fact-pack; R6-05 is its first slice).

## DONE (R6)

- Diagnosis of session-907bd96e669c: per-cycle LLM call counts (sections only
  in cycle 03), `report_sections` end-state (`update_count=1`, `stale=TRUE`
  ×5 unconsumed), `progress_events` showing
  `refresh failed: tuple indices must be integers or slices, not str` at
  cycles 6/9/12/15/18, resolution cadence (31 resolved across cycles 2–20),
  crash-site identification at `section_refresher.py:50-53`, and confirmation
  that R5 citation/table fixes took effect in the rendered report.

---

# tasks.md — Report Quality Structural Round (R5, 2026-06-12)

Design review focused on report accuracy, driven by inspection of
`dist/cfreds` outputs (session-89dae1d15b9a, 20 plan cycles) and the code paths
that produced them. Per Rule 16 every fix below is framed as a general DFIR
capability; CFREDS artifacts are used only as diagnostics.

## Observed symptoms (from dist/cfreds, all reproduced and root-caused)

1. **Mangled citations** — report.md cites `-security-0001`,
   `-system-000000000120` (leading dash, human-unreadable).
2. **Report written once, never iterated** — `report-section-block` LLM calls
   exist only in cycle 03 of a 20-cycle session; sections 1–5 were never
   rewritten even though ~30 hypotheses resolved in cycles 4–20.
3. **Appendix excellent, sections 1–5 poor** — appendix blocks are
   `mode: structured` (deterministic SQL → tables); sections 1–5 ran as
   free-narrative LLM blocks from a stale template set.
4. **Contradictory Executive Summary** — claims lateral movement and denies it
   in adjacent sentences.
5. **Empty `Key Findings`** ("insufficient evidence" placeholder) while
   `findings/` holds 100+ findings.
6. **Recommendations sections** contain finding narration (lateral-movement
   evidence), not recommendations; all three subsections are near-identical.
7. **memory/overview.md degraded** — template headings still say
   `Key Findings: none` / `Active Tasks: 初回調査待ち` while ~30 prose lines
   are appended after the template.

## Root causes (code-level)

- **RC1 — capture-group bug in citation validator.**
  `report/writer.py:546` `_EVIDENCE_ID_RE = r"\b(evtx|mft|prefetch)-[a-z0-9-]+\b"`
  with `.findall()` returns only the captured prefix (`evtx`), so the validator
  looks up `evidence_id = 'evtx'`, marks it invalid, and strips the bare token
  `evtx` from the body — turning `evtx-security-0001` into `-security-0001`.
  Real evidence IDs are therefore *never* validated, and hallucinated ones are
  never fully removed. (Symptom 1.)
- **RC2 — findings fed to the narrator can lack citable IDs.** Correlation-rule
  findings (e.g. `windows-corr-logon-then-service-*`) store evidence rows
  projected from the correlation SQL without any `evidence_id` field. The
  narrator prompt demands "cite raw evidence_id only", so the LLM invents
  `evtx-security-0001` (finding ordinal grafted onto the example format).
  (Symptom 1; feeds RC1.)
- **RC3 — stale propagation is rule-declaration-only.**
  `ai/hypothesis_manager.py:624-642` marks sections stale only when the
  resolved hypothesis traces to a rulepack declaration with
  `report_sections:`. LLM-drafted, gap-origin, and follow-up hypotheses (the
  majority) mark nothing, so `_collect_section_requests`
  (`ai/section_refresher.py:50-62`, `needs_refresh = stale or empty`) finds
  nothing to rewrite after the first fill. The iterate-on-report architecture
  exists (stale flag, gap→hypothesis injection works: `gap-8b9254d65e` was
  investigated) but its trigger is too narrow, so resolved verdicts never flow
  back into prose. There is also no final report refresh after the last cycle.
  (Symptoms 2, partly 4/6.)
- **RC4 — two template sets have diverged.** `src/forensia/report_template/`
  (packaged; copied into each case) has table-mode builders
  (`mode: table; builder: overview_key_findings` etc.) for sections 1–5.
  `./templates/` (passed via `--template-dir` for benchmark runs) still has the
  pre-builder narrative comments for sections 1–5, plus the rich structured
  appendix. The cfreds run used `./templates/`, so none of the table-mode
  machinery ran for sections 1–5. This is a Rule 7 conflict: the packaged set
  is more recent; `./templates` must inherit its sections 1–5. (Symptoms 3, 5, 6.)
- **RC5 — narrator key points carry no verdict context.** The "Key points"
  list passed to `section_narrator` mixes confirmed-finding summaries with
  refuted-hypothesis check text, unlabeled. The model blends them into a
  contradictory paragraph. (Symptom 4.)
- **RC6 — overview memory append ignores its own structure.**
  `memory_sync._apply_memory_updates` appends prose lines to the end of
  `overview.md`; the templated sections are never updated, so every LLM
  consumer pays for a noisy, self-contradictory overview. (Symptom 7.)

## Implementation review (2026-06-12, post-implementation)

All six tasks were implemented and reviewed; the review found and fixed the
following issues in the delivered implementation (final state: full suite
green, `scripts/check_imports.py` green):

1. **R5-01 cleanup regex destroyed valid citations** — the delivered
   "(, debris)" cleanup (`\(\s*,\s*[^)]*\)` → delete) removed the *entire*
   citation group, so `（invalid, evtx-valid-…）` lost the valid ID too.
   Replaced with edge-comma trimming (leading/trailing commas inside parens)
   followed by empty-shell removal; regression test added for the
   mixed valid+invalid case
   (`test_validate_section_evidence_ids_keeps_valid_id_sharing_parens_with_invalid`).
2. **Combined template-comment syntax was never parsed (new RC4b, found while
   verifying R5-04)** — `_parse_block_hints` treated
   `<!-- mode: table; builder: X -->` as `mode = "table; builder: x"` with an
   empty `builder`, so **table mode never fired for any template that used the
   packaged syntax**, in both render paths. Parser now expands `;`-combined
   directives (free-text fragments without a colon are dropped); regression
   test `test_parse_block_hints_combined_comment_syntax`.
3. **Table mode missing from the async render path** — the investigate loop
   uses `async _render_section_blocks`, which had no `mode: table` branch (only
   the sync `_render_section_from_request` did), so table blocks would have
   gone through the LLM agent. Branch added; deterministic-render test
   `test_async_render_section_blocks_renders_table_mode_without_llm` (passes
   an unreachable base_url so an LLM regression fails loudly).
4. **`SectionBlockResult` table construction crashed** — both render paths
   built `SectionBlockResult(body=…, evidence_results=[])` without the
   required `iterations`/`status` fields; latent because of (2). Fixed with
   `iterations=0, status="answered"`.
5. **R5-03 final refresh never reached the rendered report** — the delivered
   pass updated DB sections but did not call `render_written_report`, so
   `reports/report.md` kept the stale prose. It also ran after a user
   interrupt (Ctrl-C), spending LLM calls the user asked to stop; now it runs
   only for `status == "completed"` without interrupt, and renders the report
   afterwards.
6. **R5-06 routing keywords misfiled facts** — `'investigat' → Active Tasks`
   sent the dominant check-output shape ("The investigation found …") to the
   task list, and keyword-less facts ("A password reset occurred …") still
   piled up after the template. Routing now defaults facts to
   `## Key Findings`; only imperative task verbs (`task:`, `todo:`,
   `investigate/verify/check/review/correlate/confirm` at line start) go to
   Active Tasks; entries are bullet-normalized; the Active Tasks seed
   placeholders (`初回調査待ち` / `Awaiting initial investigation`) are cleared
   like `- none`. The delivered `task:\b` regex could never match (no word
   boundary after `:`); fixed. Overview dedup in `memory_sync` scanned only
   the last 20 lines, which misses mid-file inserts — now scans the whole
   overview.
7. **R5-04 was claimed but not executed** — CONTRIBUTING.md asserted
   `./templates` sections 1–5 are a copy of `report_template/` while the files
   were untouched. The copy has now actually been made (verified by diff).
8. **Outline prompt example taught the fabricated ID format** — the
   section-outline example used `evtx-security-0001` (4-digit), the exact
   shape the model hallucinated; examples now use realistic 12-digit IDs.

## TODO

(empty — R5-01..06 done, see DONE; next candidates live in DEFER)

- [x] **R5-01: Fix the evidence-id citation validator (RC1).**
  - Change `_EVIDENCE_ID_RE` to a non-capturing group
    (`(?:evtx|mft|prefetch)`) so `findall` yields full IDs; validate the full
    ID against its table; when stripping an invalid ID, also clean up the
    leftover empty citation shell (`（）`, `()`, `（, ...）` comma debris).
  - Files: `src/forensia/report/writer.py` (`_validate_section_evidence_ids`),
    `tests/test_writer_rq_regressions.py`.
  - Success criteria: a body citing one real evtx ID and one fabricated
    `evtx-security-0001` keeps the real citation untouched and removes the
    fabricated one *entirely* (no `-security-0001` residue, no empty parens);
    gaps list names the removed full ID.
  - Verify: `uv run pytest tests/test_writer_rq_regressions.py -q`.

- [x] **R5-02: Guarantee citable evidence IDs on findings, or mark them uncitable (RC2).**
  - In `rules/engine.py`, correlation/aggregation finding evidence rows must
    carry the underlying `evidence_id`(s) (e.g. project the source events'
    evidence_id into the correlated row). Where an ID genuinely cannot exist,
    the prompt assembly (`ai/prompts.py` narrate messages /
    `report/keypoints.py:_resolve_evidence_results`) must tag the row
    `citable: false` so the narrator is told to state facts without citing
    rather than improvise IDs.
  - Files: `src/forensia/rules/engine.py`, `src/forensia/report/keypoints.py`,
    `src/forensia/ai/prompts.py`, tests in `tests/test_rules_and_profiles.py`
    (engine) and `tests/test_review_regressions.py` (prompt).
  - Success criteria: every evidence row passed into
    `build_paragraph_narrate_messages` either contains a DB-resolvable
    `evidence_id` or an explicit uncitable marker; engine test asserts a
    correlation finding's evidence rows include source evidence_ids.

- [x] **R5-03: Generalize stale propagation + final refresh pass (RC3).**
  - In `_resolve_hypothesis` (`ai/hypothesis_manager.py`), mark stale the union
    of: rule-declared `report_sections` (current behavior), the section owning
    `target_keypoint_id` (via `REPORT_KEYPOINTS`), and
    `_guess_related_sections(description)`. Origin (rule/draft/gap) must not
    matter.
  - Cost control: `_collect_section_requests` already coalesces (a section is
    rewritten at most once per report phase regardless of how many resolutions
    marked it); keep that, and add a `report_sections.update_count` cap
    (config, default e.g. 5) so a section cannot be rewritten unboundedly.
  - Add a final report refresh in `investigate()` after the loop terminates
    (before `llm_logger.write_summary()`), so the last render reflects every
    resolution from the final cycles.
  - Files: `src/forensia/ai/hypothesis_manager.py`,
    `src/forensia/ai/investigator.py`, `src/forensia/ai/section_refresher.py`,
    `tests/test_hypothesis_similarity.py` or new
    `tests/test_stale_propagation.py`.
  - Success criteria: unit test — resolving a draft-origin hypothesis with a
    `target_keypoint_id` marks its owning section stale; unit test — a
    gap-origin hypothesis resolution marks the section that emitted the gap
    stale (closes the gap→hypothesis→report loop); loop test — final refresh
    runs once after termination.

- [x] **R5-04: Re-unify the two template sets (RC4, Rule 7 conflict).**
  - Declare `src/forensia/report_template/` the single source of truth for
    sections 1–5. Update `./templates/1..5_*.md` to the table-mode versions
    (verbatim copy). `./templates/6_appendix.md` stays as the benchmark's
    case-specific question list (templates are per-case user content; Rule 16
    allows benchmark-named *templates/fixtures*, not code).
  - Add a doctor/CI check or a note in CONTRIBUTING.md stating that
    `./templates` sections 1–5 must track the packaged set.
  - Files: `templates/*.md`, `CONTRIBUTING.md`.
  - Success criteria: diff between `templates/[1-5]_*.md` and
    `src/forensia/report_template/[1-5]_*.md` is empty; a fresh report run
    renders Evidence Scope / Key Findings / Chronological Events as tables
    from builders, with narrative limited to Executive Summary, Gap
    Assessment, Recommendation Basis.

- [x] **R5-05: Verdict-labeled key points for narrative blocks (RC5).**
  - Wherever narrator key points / reusable facts are assembled
    (`ai/section_blocks._load_reusable_section_facts`, the keypoints path in
    `ai/section_agent._write_block_body`), carry the source verdict/status and
    render each item as `[confirmed] …` / `[refuted] …` / `[finding,
    confidence=0.5] …`. Extend the narrator RULES: refuted items may only be
    mentioned as ruled-out, and confirmed/refuted items must not be blended
    into one claim.
  - Files: `src/forensia/ai/section_blocks.py`, `src/forensia/ai/prompts.py`,
    `tests/test_review_regressions.py`.
  - Success criteria: prompt-assembly test shows labels present; a fact
    sourced from a refuted hypothesis never appears unlabeled in narrator
    input.

- [x] **R5-06: Structured overview memory updates (RC6).**
  - `memory.append_overview` (or `_apply_memory_updates`) inserts new items
    under the matching template heading (`## Key Findings` by default),
    replacing the `- none` placeholder, instead of appending after the
    template. Clear the `初回調査待ち` seed task once the first cycle runs.
  - Files: `src/forensia/core/memory.py`, `src/forensia/ai/memory_sync.py`,
    `tests/test_memory_and_ingest.py`.
  - Success criteria: after two `_apply_memory_updates` calls, `overview.md`
    has items under `## Key Findings`, no `- none` placeholder, and no prose
    lines after the last template section.

## DEFER

- **R5-07: Narrative recommendation blocks fed from gaps.** Subsumed by R5-04
  (`recommendations_action_plan` table builder derives from gaps/unresolved
  hypotheses). Revisit only if a narrative recommendations block survives
  R5-04.
- **R5-08: Finish the section_agent/section_blocks split.** Remove the 60+
  re-exported underscore names in `ai/section_agent.py:76-145`; make
  `section_blocks` the canonical module with a public API. Mechanical but
  wide-blast-radius; do after R5-01..06 land.
- **R5-09: Split `report/probes.py` (2,230 lines).** It mixes claim extraction,
  quality refresh, table-block builders, and section persistence. Target:
  `report/claims.py`, `report/table_blocks.py` (move
  `_TABLE_BLOCK_BUILDERS` next to the builders), keep probes as facade.
- **R5-10: Deterministic fact-pack for narrative blocks.** Mid-term: narrative
  blocks should receive a machine-selected, pre-vetted fact list (top findings
  by verdict+severity with real evidence_ids + structured observations) rather
  than raw finding dumps, making the LLM a pure prose renderer (Rule 5
  boundary). Design after R5-02/R5-05 show how far labeling alone gets.

## DONE

- Analysis of dist/cfreds session-89dae1d15b9a: per-cycle LLM call counts,
  template provenance, citation-mangling reproduction, prompt-input inspection
  (`03-report-section-block-1_overview-executive-summary-03.json`), stale-flag
  trace. Root causes RC1–RC6 documented above.
