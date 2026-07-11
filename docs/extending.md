# Extending forensia

Use this page to find the narrowest supported extension point. Prefer YAML or
Markdown declarations; use a Python registry only when deterministic behavior
cannot be expressed as data.

## Extension inventory

| Scenario | Files normally touched | Registration |
|---|---|---|
| Artifact type | `ingest/<kind>.py`, `normalize/<kind>.py`, schema/migration, `ingest/artifacts.py`, test | `register_artifact_adapter(...)` once |
| Detection rule/rulepack | `rulepacks/<pack>/*.yaml`; optionally profile YAML and `pack.yaml` | Automatic YAML discovery |
| Structured question | `_schema/question_routing.yaml`; custom deterministic builder only when generic SQL is insufficient | Generic: none; custom: `register_structured_answer_builder(...)` once |
| Report section/block | `report_template/<n>_<name>.md`; optional resolver module and registration | `register_report_keypoint(...)` once when a new resolver is needed |
| Table block | Builder function, `_schema/report_tables.yaml`, template hint | `register_table_block(...)` once |
| Quality gate | One check function and its focused test | `register_quality_check(...)` once |

An artifact type exceeds three files because parsing, normalization, and the
database schema are deliberately separate contracts. Combining them would hide
migrations or make parsers depend on DuckDB. The adapter registry still keeps
runtime dispatch to one registration point.

## Add an artifact type

1. Put raw parsing in `src/forensia/ingest/<kind>.py`. Produce traceable JSONL
   rows with `source_file` and `evidence_id`.
2. Put set-based DuckDB loading in `src/forensia/normalize/<kind>.py`.
3. Add its table/schema card and a `CaseDB` migration when an existing table
   changes.
4. Implement `ArtifactAdapter` in `ingest/artifacts.py` (or a plugin module) and
   call `register_artifact_adapter(AdapterClass)` once.
5. Test detection, ingest metadata, differential normalization, and replacement
   of an already ingested source.

## Add a detection rule or rulepack

Add a `Rule` YAML document under `src/forensia/rulepacks/<pack>/`. Loader
discovery is automatic; no Python registration is required. Add the pack to a
profile only when it must be opt-in. Run:

```bash
forensia doctor
```

The schema coverage audit validates Event IDs, question types, and catalog
placeholders.

## Add a structured question

Add an entry to `rulepacks/_schema/question_routing.yaml`. Use
`builder_policy: generic` plus an `evidence_chain` whenever SQL and declarative
status rules are sufficient. That path requires no Python edit.

For specialized deterministic aggregation, implement a builder with the
`StructuredAnswerBuilder` signature and register it once:

```python
register_structured_answer_builder("answer_spec", build_answer)
```

Do not add a new `if answer_spec == ...` branch.

## Add a report section or block

Add `report_template/<n>_<section>.md`. Templates are discovered by filename.
Use block comments such as:

```markdown
## Example
<!-- evidence_keypoints: example_activity -->
```

Reuse an existing keypoint when possible. Otherwise implement an
`EvidenceResolver` and call
`register_report_keypoint(name, description, resolver, aliases=(...))` once.
Test template parsing and resolver registration without invoking an LLM.

## Add a table builder

Implement a function `builder(db) -> list[dict]`, register it with
`register_table_block(...)`, add its editable caption/empty text to
`rulepacks/_schema/report_tables.yaml`, and reference it from a template:

```markdown
<!-- mode: table; builder: example_table -->
```

The renderer returns `None` for unknown builders so the caller can choose its
normal fallback; registered builders must render deterministically.

## Add a quality gate

Write a side-effect-free `QualityCheck` receiving `(body, GateContext)` and
returning `(gap_note, confidence_cap)`. Register it once with
`register_quality_check(check)` or place it before a specific existing check.
Keep section-specific activation in template `behaviors`, not section-key
branches. Add a test proving both the gap and confidence cap.

## Verification

Every extension should run:

```bash
timeout 300 env UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/ -q
env UV_CACHE_DIR=/tmp/uv-cache uv run ruff check src/ tests/ scripts/
env UV_CACHE_DIR=/tmp/uv-cache uv run python scripts/check_imports.py
uv run forensia doctor
```

`tests/test_extension_points.py` contains minimal executable examples for each
recipe.
