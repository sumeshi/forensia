# forensia

![forensia-logo](https://gist.githubusercontent.com/sumeshi/c2f430d352ae763273faadf9616a29e5/raw/afaaa9317a3170fc22b17e0a833632b0018acd12/forensia.svg)

**Your local AI assistant for weekend forensic work.**

forensia is an experimental harness for digital forensic investigations with small local LLMs. It organizes acquired evidence, generates and tests hypotheses, and continuously updates a report so investigators can review the findings and decide what to investigate next. The current artifact support covers Windows EVTX, MFT, Prefetch, and Registry data.

The project explores how architecture can make a small model useful for sustained investigation on modest local hardware. The model proposes hypotheses, verification approaches, and explanations. The harness executes searches, calculates priorities, checks evidence, and records state transitions. Results become the basis for the next question, with unresolved work carried into subsequent cycles.

The intended setting is an isolated investigation environment where sensitive incident data must stay local. Models around 4B–8B parameters motivate the design: each request receives a narrow task and a selected context, while durable investigation state is maintained outside the model.

Three principles guide the work:

1. **Fight alone** — run offline with a local model and locally available dependencies.
2. **Do not over-expect from the LLM** — ask it to propose and interpret; validate execution, evidence references, and conclusions in code.
3. **Spend time like water** — revisit hypotheses and update reports as evidence accumulates, within explicit budgets and with a recorded reason for stopping.

forensia runs through a CLI and produces Markdown/HTML reports. Markdown files provide investigation instructions, reference knowledge, and report specifications. It operates on artifacts already acquired from a system; evidence acquisition and live response are outside its scope. Investigation quality with small models remains an experimental question, evaluated separately from software correctness.

[Quick start](#quick-start) · [Commands](#commands) · [Markdown inputs](#markdown-inputs) · [Architecture](#architecture) · [Development](#development) · [Evaluation](#evaluation)

## Quick start

### Install and configure

Use Python **3.14 or later**. Artifact parsers include native dependencies; wheel availability on your OS is a separate requirement from the CLI being terminal-only. The LLM server runs separately and determines GPU requirements.

For current development:

```bash
git clone https://github.com/sumeshi/forensia.git
cd forensia
uv sync --dev
cp .env.example .env
```

For a published release, use `pip install forensia` or `uv tool install forensia`. A published release may differ from the source checkout described here.

Set the endpoint and the model actually loaded by your OpenAI-compatible server:

```dotenv
LLM_BASE_URL=http://127.0.0.1:8080
LLM_MODEL=your-loaded-model-id
FORENSIA_OUTPUT_LANGUAGE=ja
```

`LLM_BASE_URL` is the server root, **without `/v1`**: the client appends `/v1/chat/completions`. Set `LLM_API_KEY` when authentication is needed. Command options `--llm-base-url` and `--model` override the environment. `.env` is loaded for local configuration; keep it private.

Run with acquired artifacts in `./input`:

```bash
uv run forensia investigate ./case001 ./input --profile windows-basic
```

After installing the command globally, omit `uv run`. Without both an endpoint and model, `investigate` runs the deterministic evidence stages and skips the LLM investigation. A configured but unavailable server enters bounded outage recovery; it is not treated as an unconfigured model.

With a local server and dependencies/model files already installed, investigation and report generation can run offline. A remote endpoint receives case-derived prompt content. Treat input artifacts, case directories, reports, memory, and AI logs as sensitive; use copies of acquired evidence and review conclusions against their sources. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

### Runtime budgets

The configuration owner is [config.py](src/forensia/config.py); [.env.example](.env.example) is an editable example, not the program defaults. Size budgets to the actual model/server capacity.

| Setting | Default and meaning |
|---|---|
| `LLM_MAX_TOKENS` | `4096`; maximum completion tokens |
| `LLM_CONTEXT_WINDOW_TOKENS` | `0`; unknown capacity until configured, with provider rejection still possible |
| `LLM_TEMPERATURE` | `0.0` |
| `LLM_REASONING_RESERVE_TOKENS` | `0`; reserved capacity for reasoning |
| `FORENSIA_OUTPUT_LANGUAGE` | `ja`; `ja` or `en` |
| `FORENSIA_PROMPT_BUDGET_TOKENS` | `0` selects the automatic default of `12000` |
| `FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS` | `0` derives twice the prompt token budget in characters |
| `FORENSIA_MEMORY_MAX_BYTES` | `0` derives a threshold between 4 KiB and 64 KiB from the prompt budget |
| `FORENSIA_REPORT_MAX_QUERIES_PER_SECTION` | `3`; query budget per report block |
| `FORENSIA_REPORT_MARKDOWN_MAX_ROWS` | `200`; preview row limit, not an evidence-completeness measure |
| `LLM_OUTAGE_WALL_CLOCK_BUDGET_S` | `28800`; maximum outage recovery wait |
| `LLM_OUTAGE_PROBE_INTERVAL_S` | `60`; recovery probe interval |

Character and token estimates guide context selection; they are not measured provider usage. Runtime telemetry distinguishes reported usage, estimates, and unavailable values.

## Commands

```bash
# Start a new case, or ingest and investigate additional input.
forensia investigate ./case001 ./input --profile windows-basic

# Resume using the existing case and its admitted work.
forensia investigate ./case001 --max-iter 50

# Stage additional artifacts; then normalize/analyze them on investigation.
forensia add ./case001 ./new-input
forensia investigate ./case001

# Render existing report sections without LLM calls.
forensia report ./case001

# Refill report sections using the LLM, then render.
forensia report ./case001 --write

# Inspect the actual option contract.
forensia investigate --help
forensia report --help
```

`report --output <path>` chooses an HTML output path; the Markdown report stays under `case001/reports/report.md`. `investigate --report-only` skips investigation and renders the existing report. A report job does not settle hypotheses or declare the investigation complete.

| Investigation option | Default / behavior |
|---|---|
| `--profile` | `windows-basic`; rule selection |
| `--max-iter` | `20` investigation cycles |
| `--max-queries-per-hypothesis` | `5` queries per selected hypothesis |
| `--no-progress-limit` | `3` cycles without semantic progress |
| `--report-every-n-cycles` | `3`; periodic section refresh |
| `--report-max-queries-per-section` | `0` uses the environment setting |
| `--max-llm-calls` | `0` disables the session call cap; set a positive cap when wanted |
| `--auto-rulepacks / --no-auto-rulepacks` | Enabled; add packs eligible for observed artifact families |
| `--timezone` | An IANA name, such as `America/New_York`; overrides the case manifest |
| `--forensia-md`, `--report-spec`, `--knowledge` | Explicit Markdown inputs described below |
| `--template-dir` | Existing report-directory input; mutually exclusive with `--report-spec` |
| `--rerun` | Destructive reset of current case tables and generated runtime outputs, then re-normalization from retained raw records |

Ordinary resume preserves case state. Ctrl-C during the investigation requests a stop at the engine's next handling boundary; it may wait for the current operation. The session records its terminal reason, and later `investigate` resumes from durable work.

`--rerun` is a fresh investigation within a compatible case: it clears investigation/report state and input-adoption receipts, while retaining raw records, memory, and AI logs. Use a new case directory for an isolated experiment. Unsupported schema versions are rejected, not migrated; `--rerun` cannot upgrade them.

## Markdown inputs

These inputs have different roles. Operator instructions, reference knowledge, and report requirements never become Evidence or bypass the host's execution and settlement checks.

### FORENSIA.md: investigation policy

Place `FORENSIA.md` in the case root, or pass `--forensia-md <path>` when starting or resuming a case. The engine does not search parent directories or the evidence directory for instructions.

```markdown
# Investigation policy

## Objective
Determine whether remote access was followed by unauthorized execution.

## Scope
Use the supplied artifacts and retain uncertainty about missing telemetry.

## Priority
Correlate remote logons with subsequent process activity before expanding scope.

## Constraints
Separate observed activity from interpretations about intent.
```

The entire body guides gap identification, hypothesis drafting, and query planning. The first paragraph under an English `Objective` heading (or `Scope` when Objective is absent) also supplies the existing objective-admission input. Other headings remain guidance. Editing the file does not withdraw admitted work, rewrite a Spec, or change a verdict.

At adoption, the body, SHA-256, source, and receiving roles are saved in a `forensia-md` Trace step. An implicit resume reuses the recorded policy, even when the file changes or disappears, and surfaces the difference. Explicitly adopt an edit with:

```bash
forensia investigate ./case001 --forensia-md ./case001/FORENSIA.md
```

The adopted policy is fixed for that session. A first adoption or explicit reload exceeding half the configured system-prompt character budget is rejected with a reason. The fixed role/output schema and Evidence/Assessment/Sufficiency/Settlement gates continue to apply. See [case_policy.py](src/forensia/ai/investigation/case_policy.py).

### REPORT.md: report specification

Place `REPORT.md` in the case root, or pass `--report-spec <path>` to `investigate` or `report --write`. This uses the existing section, Claim, and renderer pipeline.

```markdown
---
instructions: |
  Write for incident responders. Cite evidence references, distinguish
  observations from interpretation, and state material limitations.
---
# Overview

## Assessment
Explain what the evidence supports and which interpretations remain open.

# Gaps

## Unresolved work
<!-- mode: table; builder: gaps_unresolved -->

## Follow-up
Describe the next evidence needed to resolve each material uncertainty.
```

Each `#` heading defines a section; `##` headings define blocks. Optional frontmatter `instructions` applies to every section in the file. Supported metadata also includes `type`, `title`, `description`, `tags`, and `timestamp`. Use `FORENSIA_OUTPUT_LANGUAGE` for the runtime language setting.

A file must have at least one `#` section, no prose before the first section, and no headings that normalize to the same slug. Section keys are based on heading order and text, so renaming/reordering headings changes their identity within the report revision. For deterministic blocks, the existing parser accepts `evidence_keypoints`, `mode`, `builder`, `answer_id`, `answer_spec`, and `question` hints; definitions live in [template_parsing.py](src/forensia/report/sections/template_parsing.py) and the [bundled templates](src/forensia/report/templates/).

Input priority on first adoption or explicit reload is: explicit `--report-spec`, explicit `--template-dir`, case-root `REPORT.md`, then case-local packaged templates. Explicit report inputs require an LLM-backed writing run. To adopt an edited specification:

```bash
forensia report ./case001 --write --report-spec ./case001/REPORT.md
```

Implicit resume uses the normalized sections recorded in the `report-input` Trace step and reports file changes. Plain `report` renders the adopted sections. Older sections remain stored but are excluded from the active report after an explicit reload. Changing report requirements does not resolve investigation work.

The current directory-based input also remains available:

```bash
forensia templates-export ./my-templates
forensia report ./case001 --write --template-dir ./my-templates
```

Its numbered Markdown files define sections; `_formats/report.yaml` controls deterministic wording and preview limits. Input `case001/REPORT.md` and generated `case001/reports/report.md` are separate files; output guards reject overwriting the input. See [report_input.py](src/forensia/report/sections/report_input.py).

### Knowledge: local investigation guidance

Pass a directory with `--knowledge`; [knowledge.sample/](knowledge.sample/) contains examples. Only Markdown with `type: knowledge` frontmatter is indexed.

```markdown
---
type: knowledge
title: Remote access review
description: Correlating logons with subsequent activity.
tags: [windows, logon, rdp]
---
# Remote access review

## Correlation
Compare host, account, source address, and time before connecting records.
```

```bash
forensia investigate ./case001 --knowledge ./knowledge.sample
```

Selection is deterministic: tags and query terms narrow documents, then relevant `##` sections are chosen within the prompt budget. There is no extra LLM routing call. Keep one topic per file and include `description` and `tags`. When a file has `##` sections, put essential context in its description or sections; its opening paragraph is not injected alongside them.

Knowledge is reference material, not evidence or tool permission. Schema cards, SQL recipes, phase playbooks, and these snippets are disclosed according to current work and capabilities. The current Knowledge index is reset per invocation, but bodies are read lazily from disk; Knowledge does **not yet have the recorded-revision resume contract** of FORENSIA.md and REPORT.md. Keep the folder unchanged during a reproducibility experiment. See [external.py](src/forensia/knowledge/external.py) and [retrieval.py](src/forensia/knowledge/retrieval.py).

## Architecture

The investigation follows a repeated sequence: normalize artifacts, detect findings, propose and select hypotheses, retrieve evidence, assess it, and record the result. Reports are refreshed during the investigation, and admitted gaps feed subsequent cycles.

Three boundaries support this loop:

- **Evidence-bound verification:** observations, interpretations, and report claims have distinct roles. A model's proposed verdict passes through evidence assessment, sufficiency checks, and a settlement gate before it changes a hypothesis's state.
- **Structured memory:** Case State holds the current investigation, Trace State records how it progressed, and Working State supplies the context for the current model request.
- **Auditability:** evidence references and execution receipts connect report claims, hypotheses, observations, and their sources so a person can inspect the grounds for a conclusion.

| Responsibility | Model | Harness |
|---|---|---|
| Investigation direction | Propose hypotheses, missing information, and verification approaches | Admit work, calculate priority, check prerequisites and available capabilities |
| Evidence retrieval | Propose a bounded query or request additional scoped context | Validate and execute the action; record results, limits, and provenance |
| Interpretation | Explain observations and propose a verdict | Assess declared conditions, aggregate eligible support and contradictions, gate the state transition |
| Reporting | Write explanatory passages and identify unanswered questions | Generate structured answers/tables, retain evidence references, validate publication, admit follow-up work |

The CLI calls [pipeline.run_investigation](src/forensia/pipeline.py) for case creation/resume, ingest, normalization, rules, investigation, and report rendering. One process owns writes to each case. The [investigation loop](src/forensia/ai/investigation/investigator.py) coordinates work selection and individual bounded attempts; session handling records execution status and budgets. Report writing uses the same Case/Trace and verification owners.

```mermaid
flowchart TD
    I[Acquired artifacts] --> N[Ingest and normalize]
    N --> C[(Case DuckDB)]
    C --> R[Rules and Findings]
    R --> W[Work admission and selection]
    W --> P[Bounded plan and query]
    P --> V[Retrieval evaluation]
    V --> A[Evidence assessment]
    A --> S[Sufficiency and Settlement]
    S --> C
    C --> O[Report sections and Claims]
    O -->|Investigation requests| W
    P -. receipts .-> T[(Trace DuckDB)]
    S -. judgment trail .-> T
    C -. scoped projection .-> X[Model context]
    T -. prior attempts .-> X
    X --> P
```

### Case, Trace, and Working State

Case State answers **what is known and unresolved**. Trace State answers **what was attempted and why the current state was reached**. Working State answers **what this model request needs to see**. These are responsibility boundaries within the same application.

Case and Trace are stored in DuckDB. Working State combines a selected projection of their records with scoped Markdown notes and relevant reference material; it has no authority to settle a hypothesis or declare the case complete.

| State | What it owns |
|---|---|
| `db/case.duckdb` | Normalized evidence, sources/Coverage, Findings, Hypotheses and VerificationSpec, assessed evidence links, relations, objective, Gaps/Tasks, report sections and Claims |
| `db/trace.duckdb` | Session lifecycle, investigation steps, hypothesis reasoning, retrieval/LLM telemetry, input-adoption receipts, and bounded recent progress |
| `memory/` | Scoped working Markdown and context cards; not the authority for evidence, verdicts, or completion |
| `ai_logs/` | Inspectable LLM inputs/outputs; previous reasoning is a lead or explanation, never proof |
| `reports/` | Generated Markdown/HTML, briefs, structured answers, and diagnostic exports |

CaseDB attaches Trace to the Case connection and exposes its tables through connection-local views. Preserve both databases together. Trace includes updated lifecycle rows and idempotent step writes, and progress is bounded; it is not a fully append-only event store or a complete historical replay engine. The authoritative DDL and table placement are in [schema.py](src/forensia/db/schema.py), with opening/version checks in [database.py](src/forensia/db/database.py).

Evidence is an observed normalized record. A Finding is a derived signal; a Hypothesis is an interpretation to test; a Claim is an assertion in the report; a Gap describes unresolved information and a Task the associated work. Persisting these objects does not give them equal evidentiary weight. Entity memory cards organize observed names and references; they do not establish a case-wide multi-host identity graph.

### Verification and lifecycle

| Boundary | Decision and owner |
|---|---|
| VerificationSpec | One admitted verification contract. Rule/LLM declarations are normalized once; readers use the stored Spec. [verification.py](src/forensia/core/verification.py) |
| Plan/execute | The model proposes typed `sql.query` or scoped `memory.read_more` actions. The host validates action, paths, read-only SQL, table references, and query bounds. [planner.py](src/forensia/ai/investigation/planner.py), [sql_templates.py](src/forensia/ai/prompts/sql_templates.py) |
| RetrievalEvaluation | Whether that attempt was valid, observable, partial, empty, or unavailable; it does not assign evidentiary support. [retrieval_telemetry.py](src/forensia/ai/retrieval_telemetry.py) |
| Evidence Assessment | Match observations to evaluable Spec conditions and record supporting/contradictory/contextual roles with grounds. Unsupported conditions are not satisfied by a fluent explanation. [assessment.py](src/forensia/ai/checking/assessment.py) |
| Evidence Sufficiency | Aggregate current assessed links, Coverage, independent derivation roots, and contradictions. Multiple queries over the same observation do not create independent support. [sufficiency.py](src/forensia/ai/checking/sufficiency.py) |
| Settlement | Gate the checker's proposed verdict against those results; the runner persists the accepted transition. [settlement.py](src/forensia/ai/checking/settlement.py) |

The model uses role-specific structured responses through an OpenAI-compatible chat endpoint. Native tool calling, arbitrary shell, and Python execution are not part of the action space. Prompt/schema definitions live in [ai/prompts/](src/forensia/ai/prompts/) and [ai/llm/schemas.py](src/forensia/ai/llm/schemas.py); their exact fields are not duplicated here.

Coverage separates absent, partial, failed, unsupported, and available telemetry. Parser success or zero rows alone does not prove completeness. Empty-result refutation needs an explicit refute condition and a certified observable scope; the present certification is conservative and centered on direct case-wide EVTX event-ID lookups. Registry observations remain partial when parser/plugin completeness is unproven. Registry hives and companion logs retain dataset-level contributors rather than assigning uncertain observations to an invented host or single source.

Evidence links retain source/content/Spec fingerprints and assessment grounds. Source replacement, content changes, or a changed Spec can make historical support ineligible and reopen dependent work. Old links remain traceable. See [invalidation.py](src/forensia/evidence/invalidation.py) and [content_identity.py](src/forensia/evidence/content_identity.py).

Selection, stop classification, and reopening share the read-side judgment in [work_judgment.py](src/forensia/ai/investigation/work_judgment.py); [work_state.py](src/forensia/ai/investigation/work_state.py) owns the durable transitions. The investigation agenda is derived from existing Hypothesis/Gap/Task state. Unresolved work with no runnable action needs a blocker and retry condition, not a successful completion label. Semantic progress is a change in work, observations, contradictions, or source/Coverage state, not growth in report prose.

Session lifecycle records a terminal reason before fallible final projections and retains ownership through the closing report pass. Expired leases are reconciled at startup. Execution status and budgets govern whether the session continues; evidence and unresolved work govern what the investigation can conclude.

### Working context

Each attempt gets a deterministic work projection from Case/Trace: current Spec, assessed support, contradictions, unmet requirements, and prior attempts. Memory visibility is scoped to shared material and the current hypothesis; `read_more` enforces the same boundary. Schema/recipe/playbook disclosure is a projection of eligibility, not a new permission system.

Some Markdown can be regenerated from the DB; authored notes and condensed overview prose cannot all be reconstructed. Current compaction includes in-place reduction with explicit loss labels. Preserve the case's memory when retaining authored context. A compact summary never replaces authoritative Case/Trace state. Knowledge selection uses the files available to the invocation, with the revision limitations described in [Markdown inputs](#knowledge-local-investigation-guidance).

### Reports and audit trail

Report blocks use deterministic answers/tables where available and LLM narration where interpretation is needed. Sections retain evidence references and Claims, with quality checks and publication validation applied before rendering. `draft`, `ai_exhausted`, and `human_reviewed` are section workflow states, distinct from hypothesis verdicts and publication readiness. Report gaps can request new work only through admission; writing or completing a section cannot settle an investigation hypothesis.

Review follows references from a report Claim to its cited Evidence, Finding, or Hypothesis. Hypothesis evidence links retain assessment grounds; Trace steps record the plans, retrieval outcomes, and judgment history. Prior model reasoning provides context for an attempt, while the observations and their provenance provide the basis for checking its conclusion.

Typical case layout:

```text
case001/
├── FORENSIA.md            # optional operator investigation policy
├── REPORT.md              # optional report specification input
├── manifest.yaml          # case metadata and timezone
├── allowlist.yaml         # rule-scoped suppression
├── raw/                   # parsed JSONL; retain original acquired artifacts separately
├── db/
│   ├── case.duckdb         # current evidence and case state
│   └── trace.duckdb        # sessions, receipts, reasoning, telemetry
├── memory/                # scoped working Markdown, including authored material
├── ai_logs/               # LLM input/output diagnostics
├── findings/              # finding detail exports
├── report_template/       # seeded templates and format settings
└── reports/               # report.md, report.html, structured/debug outputs
```

![Example generated report](https://github.com/user-attachments/assets/c6d61b5e-16e2-4e73-82e2-bde4b29fac99)

## Rules and extension points

The default [windows-basic profile](src/forensia/knowledge/profiles/windows-basic.yaml) selects Windows, Registry, Prefetch, and filesystem packs. Profiles select rules; rules describe detections and investigation hints. Applicable packs can also be selected from observed artifact families. [Rule models](src/forensia/knowledge/rules/models.py) own the accepted YAML fields, and [rulepacks/](src/forensia/knowledge/rulepacks/) contains executable examples.

Rule hypotheses declare `confirm_when`, `refute_when`, and optional `evidence_requirements`; admission converts them to VerificationSpec. Correlation, follow-up questions, and bounded fallback searches belong in declarations. Event IDs, schema cards, recipes, artifact capabilities, sufficiency policy, structured questions, and verdict vocabulary live in [_schema/](src/forensia/knowledge/rulepacks/_schema/). Suppression in case `allowlist.yaml` matches a rule ID and evidence-row fields after finding generation; it retains the finding and its evidence.

Prefer the smallest existing extension point:

| Change | Owner |
|---|---|
| Artifact family | [ArtifactAdapter registry](src/forensia/evidence/artifacts.py), parser/normalizer, current DB schema, Coverage, and source replacement path |
| Detection or rule selection | Rulepack YAML and [profiles](src/forensia/knowledge/profiles/) |
| Structured question | [question_routing.yaml](src/forensia/knowledge/rulepacks/_schema/question_routing.yaml); add a specialized [answer builder](src/forensia/report/answers/answer_registry.py) only when generic SQL is insufficient |
| Report structure | REPORT.md and the existing section parser; reuse registered [keypoints](src/forensia/report/answers/keypoint_catalog.py) |
| Deterministic report table | [table_registry.py](src/forensia/report/answers/table_registry.py) and [report_tables.yaml](src/forensia/knowledge/rulepacks/_schema/report_tables.yaml) |
| Report quality check | [quality_gates.py](src/forensia/report/sections/quality_gates.py); a side-effect-free check with a reason and confidence cap |

[tests/test_extension_points.py](tests/test_extension_points.py) provides executable examples. These are in-process registration seams, not a plugin loader. Keep case-specific answers and identifiers out of generic Python, and preserve evidence references across every extension.

## Development

### Where to work

| Location | Responsibility |
|---|---|
| [pipeline.py](src/forensia/pipeline.py), [cli/](src/forensia/cli/) | Stage assembly and command/display adaptation |
| [core/](src/forensia/core/), [db/](src/forensia/db/) | Case/session/verification primitives, storage contracts, and state access |
| [evidence/](src/forensia/evidence/) | Artifact admission, parsing, normalization, identity, invalidation |
| [knowledge/](src/forensia/knowledge/) | Declarative rules/catalogs, Coverage, and Knowledge selection |
| [ai/investigation/](src/forensia/ai/investigation/), [ai/hypotheses/](src/forensia/ai/hypotheses/) | Work selection, lifecycle, planning, and hypothesis execution |
| [ai/checking/](src/forensia/ai/checking/), [ai/llm/](src/forensia/ai/llm/) | Verification gates and bounded model transport |
| [ai/sections/](src/forensia/ai/sections/), [report/](src/forensia/report/) | Report block execution, deterministic answers, Claims, publication checks, rendering |

Identify the existing writer before adding state. Extend that owner rather than adding another agenda, planner, cache, or status model. When alternatives preserve the same invariants and deliver comparable quality, prefer fewer independent states, synchronization paths, and model calls. [scripts/check_imports.py](scripts/check_imports.py) enforces dependency direction. For incompatible persisted changes, update consumers and the current schema version together; there is no automatic migration/backfill path or alias policy. Preserve old case data and re-ingest original artifacts into a new directory when needed.

### Verification

From a development checkout:

```bash
uv run pytest tests/ -q
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run python scripts/check_imports.py
uv run forensia doctor
```

`doctor` and `templates-export` are callable maintenance commands hidden from the top-level help. Doctor runs schema coverage, generated-playbook drift, import boundaries, verdict taxonomy, template contracts, report-validation checks, lint, and a test subset. It does **not** replace the full pytest run. Repository scripts and tests are needed for its complete development checks.

Keep pytest offline and use disposable cases. Mock the model/provider boundary, then exercise real storage, CLI behavior, and generated outputs. Retain tests for Evidence/provenance, Assessment/Sufficiency/Settlement, bounded execution, admitted work, termination, and resume. Give each invariant a primary test owner. Remove tests for retired APIs and avoid copying constants, SQL strings, internal counters, or prose into assertions merely to freeze implementation details. Live-model quality/performance experiments belong outside pytest.

When changing declarations, run [audit_schema_coverage.py](scripts/audit_schema_coverage.py). [regenerate_playbook.py](scripts/regenerate_playbook.py) regenerates marked playbook sections from YAML; `--check` detects drift. [cycle_summary.py](scripts/cycle_summary.py) reads recent progress from Trace, so older pruned cycles may not appear.

This README owns current usage, architecture, extension, and development guidance. Link to executable schemas and source owners instead of maintaining duplicate table catalogs or per-file prose maps. Keep design proposals and pending tasks separate from current capability claims, and use git for historical implementation notes. Update the affected README section with a behavior change. PRs should state the concrete change, reason, and checks; sanitized reproductions belong in issues. The project accepts intentional breaking changes and does not retain obsolete paths for tests or old documentation.

## Evaluation

The experiment asks whether a simpler harness helps a weak local model reach defensible conclusions within its call/token/time budget. Deterministic tests check software contracts; investigation quality and performance require separate measurements.

The public [CFReDS Data Leakage Case](https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html) is one evaluation source. [BENCHMARK.md](BENCHMARK.md) holds the selected questions and reference answers as evaluation material, separate from product instructions. The repository does not distribute the images, extracted evidence, or generated cases. Exclude expected answers from the model's Knowledge and report inputs.

For a meaningful comparison, fix source content, code/model revision, endpoint settings, prompts/Knowledge/report specification, and budgets. Record supported conclusions and missed questions, false positives/negatives, unresolved work, invalid/repeated attempts, hypothesis diversity, context duplication, call/token/time cost, and resume behavior. Compare against a simpler configuration and separate correctness fixes from model-quality changes. Repeat runs when model variance could explain the difference.

The existing offline diagnostic script can be run against a **copy** of a completed case:

```bash
uv run python scripts/eval_run.py ./case-copy --output ./evaluation.json
```

Its metrics are heuristics, not a complete scorer: some read Markdown Memory and older report JSON exports; `confirmed_while_benign_rate` is currently a placeholder returning zero with a note, not a measured false-positive rate. A metric missing its input or annotation cannot establish quality. Updating evaluation to current Case/Trace outputs and running a controlled local-model comparison remain pending.

## License

[MIT](LICENSE).
