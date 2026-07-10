# Rules / Profiles / Allowlist

Detection rules, profile selection, suppression via allowlist, and the declarative layer specification.

---

## 1. Rulepack

A rulepack is a YAML definition under `src/forensia/rulepacks/windows/` (or similar). The Pydantic models in `src/forensia/rules/models.py` enforce the schema with `extra="forbid"`, so unknown fields are rejected at load time.

### 1.1 Detection part (required)

| Field | Role |
|---|---|
| `id` | Stable rule identifier |
| `title` | Human-facing title |
| `severity` | Default severity for findings |
| `confidence` | Default confidence for findings |
| `query` | Read-only SQL against normalized evidence |
| `finding.title` / `finding.summary` | Templates rendered from row fields |
| `tags` | Classification tags |
| `attack` | ATT&CK mapping (full-form: `[{tactic, technique_id, technique_name}]`) |

One row of a rule query becomes one finding. The source row is stored as structured evidence.

### 1.2 Hypothesis declaration (optional, drives the hypothesis loop)

If a rule also seeds the LLM-driven hypothesis loop, declare the following. The Python side consumes these generically (kill-chain knowledge is not hardcoded in Python).

- `hypotheses[]`: Hypothesis templates instantiated when the rule fires
  - `id`: Stable id within the rule
  - `segment`: kill-chain segment (`persistence`, `lateral-movement`, etc.)
  - `description`: Hypothesis sentence with `{field}` placeholders (bound to query row columns)
  - `required_entities`: Entity names required for confirmation
  - `confirm_when`: Correlation criteria such as `{co_observed_event_ids: [...], same_host: bool, within_minutes: int}`. `HypothesisProgressTracker` uses it to judge auto-confirm
  - `refute_when`: Refutation criteria such as `{zero_rows: true}`
  - `follow_up_questions`: Questions automatically spawned on confirmation
  - `report_sections`: Section keys to mark stale on resolution
- `correlate_with[]`: A set of event IDs the planner is nudged to "also look at". `{event_ids: [...], rationale: str}`
- `fallback_search[]`: Phases executed in declared order when the primary SQL returns 0 rows. No LLM involved. Allowed phases:
  - `keyword_in_raw_json` (LIKE escaped)
  - `related_event_ids` (alternative event surface)
  - `artifact_table` (another normalized table, whitelisted in `engine.py`)

### 1.3 Example

```yaml
id: windows-security-4625-failed-logon
title: Failed account logon attempt
severity: medium
confidence: 0.6
required_fields: [target_user, src_ip]
tags: [windows, security, credential-access]
attack:
  - tactic: credential-access
    technique_id: T1110
    technique_name: Brute Force
query: |
  SELECT evidence_id, timestamp, computer, target_user, src_ip, logon_type, failure_reason
  FROM evtx_events
  WHERE event_id = 4625
finding:
  title: 'Failed logon for {target_user}'
  summary: '{target_user} failed to log on to {computer} from {src_ip}.'
hypotheses:
  - id: brute_force_attempt
    segment: credential-access
    description: Repeated 4625 from {src_ip} targeting {target_user} suggests brute-force
    required_entities: [src_ip, target_user]
    confirm_when:
      co_observed_event_ids: [4625, 4624]
      same_host: true
      within_minutes: 30
    refute_when:
      zero_rows: true
    follow_up_questions:
      - Did the brute force succeed? Look for 4624 from {src_ip} for {target_user}
    report_sections: [3_technical]
correlate_with:
  - event_ids: [4624, 4771]
    rationale: 'co-observed success / Kerberos pre-auth failure'
fallback_search:
  - phase: related_event_ids
    event_ids: [4776]
```

---

## 2. Profile

A profile is a rule selection policy. It lives under `src/forensia/profiles/`.

| Field | Role |
|---|---|
| `name` | Profile name |
| `rulepacks` | Target directories / paths under the rulepack root |
| `rule_ids` | Optional allowlist of specific rule IDs |

A profile is selection metadata. It does not duplicate rule logic.

### What should remain stable

- Treat rule IDs as persistent external identifiers
- A profile means "which rules are active", not "how to run them"
- Keep rule queries read-only / evidence-oriented
- Finding templates are row-driven, and each finding preserves evidence traceability
- Write package-bundled rule metadata and finding text in English

If you need to change execution semantics rather than selection semantics, that is a rule engine change, not a profile format change.

---

## 3. Allowlist and suppression model

`allowlist.yaml` is conceptually adjacent to rules but does not select rules.

- The profile decides which rules run
- The rules generate candidate findings
- The allowlist determines `suppressed` via a rule_id-scoped field match

The current match model:
- One `rule_id`
- One or more field predicates under `when`
- Values are taken from the first structured evidence row of the target finding

This is a post-generation presentation / triage control, not a pre-filter.

---

## 4. Declarative layer (`_schema/`)

`src/forensia/rulepacks/_schema/` is not a rule directory; it is where schemas and DFIR knowledge shared by rules and prompts live. The loader skips it during enumeration.

| File | Consumer | Role |
|---|---|---|
| `evtx_events.yaml` / `mft_entries.yaml` / `mft_timeline.yaml` / `prefetch_executions.yaml` / `prefetch_timeline.yaml` / `findings.yaml` | `_load_schema_hints()` via `prompts._build_schema_guidance()` | Schema cards for DB tables. `core_columns` (short subset for the planner) + `column_descriptions` (one-line descriptions) + `columns` (for the SQL validator) + `json_field_extractors` (raw_json fallback) |
| `event_ids.yaml` / `logon_types.yaml` | `prompts._dfir_playbook()` | DFIR explanations of Event IDs / Logon Types |
| `app_catalog.yaml` / `artifact_inference.yaml` | `prompts._dfir_playbook()` | Prefetch / MFT / Registry / File → application inference. Intentionally omitted in planning phases and injected only in interpretation phases |
| `false_positive_rules.yaml` | rule engine + `prompts._dfir_playbook()` | Known FPs. Referenced only in interpretation-phase prompts |
| `dfir_ioc_catalog.yaml` | `prompts._dfir_playbook()` | Auxiliary IOC dictionary for anti-forensics / cloud sync / email / Recycle Bin, etc. |
| `finding_themes.yaml` | `report/finding_themes.py` | Finding theme definitions (classification keywords / rank / title / summary) used by the overview and HTML key-findings grouping |
| `benign_auth.yaml` | `report/benign_auth.py` | Benign local-authentication policy (patterns that keep normal logons out of findings emphasis) |
| `query_templates.yaml` | `ai/prompts/sql_templates.py` | SQL query template catalog offered to the planner/composer |
| `question_routing.yaml` | `questions.py` + `section_agent.py` + `prompts.build_section_agent_*` + `prompts.build_structured_classify_messages` | The source of truth for QuestionSpecs. Declares `expected_answer_shape` per `question_type` / `answer_spec` (consumed by the code-side `_format_structured_answer`), `evidence_chain` (deterministically tried by `_execute_evidence_chain` when the primary returns 0 rows), required/render fields, and status rules |
| `question_routing_eval.yaml` | `scripts/audit_schema_coverage.py --strict` | A mutation corpus for QuestionSpec routing. Audits whether headings / body / language changes still resolve to a stable `answer_spec` |
| `verdict_taxonomy.yaml` | `core/verdicts.py` | Verdict value whitelist and cross-layer mapping |
| `playbook/*.md` | `prompts._dfir_playbook(phase)` | Phase-specific (`broad_plan` / `hypothesis_plan` / `check` / `report_section` / `section_agent_plan` / `section_agent_check`) playbook bodies. Tagged with `<CRITICAL_RULES>` / `<FORBIDDEN_PATTERNS>` / `<SCHEMA_CONSTRAINTS>` etc. |

### 4.1 What DB table schema YAML declares

- `table`: Table name (e.g. `evtx_events`)
- `core_columns`: Short list the planner LLM sees. Keep it at 13 or fewer
- `column_descriptions`: One-line description for each `core_columns`
- `columns`: Full column list (used by `validate_select_sql` to reject SELECT / WHERE on undeclared columns)
- `json_field_extractors` (optional): DuckDB JSON extraction expressions to pull from raw_json when a column is NULL
- `notes` (optional): Hints such as timestomp caveats or Prefetch's `no_host_column`

To add a new investigable table, place `_schema/<table>.yaml` and, as needed, update `_LEGACY_ALLOWED_TABLES` / `get_allowed_tables()` and the SQL template allowlist in `sql_schema.py`. The YAML is consumed automatically by `_load_schema_hints()`.

### 4.2 Playbook auto-regeneration

`playbook/*.md` is regenerated by `scripts/regenerate_playbook.py` within `<!-- AUTO-FROM: <yaml-path> -->` ... `<!-- /AUTO-FROM -->` markers. Do not hand-edit inside the markers; edit the source YAML and regenerate.

### 4.3 Allowlist skip

Files with a `kind:` prefix such as `kind: allowlist_services` are not rules; the loader skips them (the suppression logic consumes them).

---

## 5. File placement conventions

- Package defaults live under `src/forensia/report_template/` / `profiles/` / `rulepacks/`
- Treat case-local `report_template/` as an override input copied at initialization
- Currently, case-local copies of profiles and rulepacks are not depended upon (they are resolved from the package tree)
