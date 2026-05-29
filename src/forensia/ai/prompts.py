from __future__ import annotations

import json
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from forensia.config import get_llm_settings
from forensia.core.session import ENTITY_TYPE_ALIASES, Hypothesis, PlannedQuery
from forensia.ai.sql_schema import build_investigation_framework, _load_app_catalog, _load_fp_reduction_guidance

# Module-level time range cache, set at investigation start by investigator.py
_CASE_TIME_RANGE: dict[str, str] = {}

def set_case_time_range(tr: dict[str, str]) -> None:
    _CASE_TIME_RANGE.clear()
    _CASE_TIME_RANGE.update(tr)

def _estimate_message_tokens(text: str) -> int:
    """Rough token estimation: ~4 chars per token for English+JSON."""
    return len(text) // 4


def _trim_dynamic_content(
    messages: list[dict[str, str]],
    *,
    max_total_tokens: int = 28000,
    system_weight: float = 0.5,
) -> list[dict[str, str]]:
    """Trim dynamic (user) message content if total estimated tokens exceed budget.
    
    Strategy: keep system messages intact (they contain the playbook),
    trim user message content progressively.
    """
    total_est = sum(_estimate_message_tokens(m.get("content", "")) for m in messages)
    if total_est <= max_total_tokens:
        return messages
    trimmed = list(messages)
    for msg in trimmed:
        content = msg.get("content", "")
        est = _estimate_message_tokens(content)
        if est > max_total_tokens * system_weight:
            # Trim user/dynamic content — keep first 60%, drop middle 20%, keep last 20%
            mid = len(content) // 2
            quarter = len(content) // 4
            head = content[:mid + quarter]
            tail = content[mid - quarter:]
            dedup = head + "\n...[content trimmed for budget; see full trace in db]...\n" + tail
            msg["content"] = dedup
            total_est = sum(_estimate_message_tokens(m.get("content", "")) for m in trimmed)
            if total_est <= max_total_tokens:
                break
    return trimmed


def _assemble_messages_with_budget(
    builder_func: Callable[..., list[dict[str, str]]],
    *args,
    max_tokens: int = 28000,
    **kwargs,
) -> list[dict[str, str]]:
    """Build messages via builder, then trim if budget exceeded.
    
    Preserves system prompt (playbook) while trimming user/dynamic content.
    Usage: messages = _assemble_messages_with_budget(build_broad_plan_messages, ..., max_tokens=28000)
    """
    messages = builder_func(*args, **kwargs)
    return _trim_dynamic_content(messages, max_total_tokens=max_tokens)


def _time_range_guidance() -> str:
    """Return time-range constraint guidance if the case has one, otherwise empty string."""
    if _CASE_TIME_RANGE.get("earliest") and _CASE_TIME_RANGE.get("latest"):
        return (
            f"\n## Case Time Range\n"
            f"Earliest event: {_CASE_TIME_RANGE['earliest']}\n"
            f"Latest event: {_CASE_TIME_RANGE['latest']}\n"
            "IMPORTANT: Do NOT use datetime('now') or CURRENT_TIMESTAMP — they refer to the current system time, not the case time. "
            "All WHERE clauses on timestamp columns must use values within this range.\n"
        )
    return ""


@dataclass(frozen=True, slots=True)
class RuleContext:
    rule_id: str
    correlate_event_ids: list[int]
    confirm_when: dict[str, Any]
    refute_when: dict[str, Any]


@lru_cache(maxsize=1)
def _get_cached_rules() -> list[Any]:
    """Load and cache all rules at module level to avoid repeated file I/O."""
    from forensia.rules.loader import load_rules_from_dir
    from pathlib import Path
    rules_path = Path(__file__).parent.parent / "rulepacks"
    return load_rules_from_dir(rules_path)


def resolve_rule_context(hypothesis: Hypothesis | None) -> RuleContext | None:
    """Resolve rule context for a hypothesis by looking up source rule declarations.
    
    If the hypothesis was generated from a rule finding, return the rule's
    correlate_with, confirm_when, and refute_when declarations.
    Merges multiple source_rule_ids into a single RuleContext.
    """
    if hypothesis is None or not hasattr(hypothesis, 'source_rule_ids'):
        return None
    source_rule_ids = getattr(hypothesis, 'source_rule_ids', [])
    if not source_rule_ids:
        return None
    
    rules = _get_cached_rules()
    merged_correlate_ids: set[int] = set()
    merged_confirm_when: dict[str, Any] = {}
    merged_refute_when: dict[str, Any] = {}
    found_rule_id = source_rule_ids[0]
    
    for rule_id in source_rule_ids:
        for rule in rules:
            if rule.id == rule_id:
                for corr in rule.correlate_with:
                    merged_correlate_ids.update(corr.event_ids)
                if rule.hypotheses:
                    confirm = rule.hypotheses[0].confirm_when or {}
                    refute = rule.hypotheses[0].refute_when or {}
                    # Merge shallow dicts, first rule takes precedence for conflicts
                    if confirm and not merged_confirm_when:
                        merged_confirm_when = dict(confirm)
                    if refute and not merged_refute_when:
                        merged_refute_when = dict(refute)
                break
    
    return RuleContext(
        rule_id=found_rule_id,
        correlate_event_ids=sorted(merged_correlate_ids),
        confirm_when=merged_confirm_when,
        refute_when=merged_refute_when,
    )


@lru_cache(maxsize=1)
def _load_schema_hints() -> dict[str, dict[str, Any]]:
    """Load schema hints from rulepacks/_schema/*.yaml for planner guidance.
    
    Cached at module level to avoid repeated file I/O.
    """
    import yaml
    from pathlib import Path
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    hints: dict[str, dict[str, Any]] = {}
    if not schema_dir.exists():
        return hints
    for path in schema_dir.glob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data, dict):
                table_name = data.get("table")
                if table_name:
                    hints[str(table_name)] = data
        except Exception:
            continue
    return hints


@lru_cache(maxsize=1)
def _load_schema_notes() -> str:
    """Load schema notes from evtx_events.yaml and prefetch_executions.yaml for section agent."""
    import yaml
    from pathlib import Path
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    notes: list[str] = []
    
    evtx_path = schema_dir / "evtx_events.yaml"
    if evtx_path.exists():
        try:
            data = yaml.safe_load(evtx_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                evtx_notes = data.get("notes", {})
                if isinstance(evtx_notes, dict):
                    for key, note in evtx_notes.items():
                        if isinstance(note, str):
                            notes.append(f"- evtx_events.{key}: {note}")
                extractors = data.get("json_field_extractors", {})
                if isinstance(extractors, dict):
                    for field, expr in list(extractors.items())[:5]:
                        notes.append(f"- If {field.lower()} column is NULL, use {expr}")
        except Exception:
            pass
    
    prefetch_path = schema_dir / "prefetch_executions.yaml"
    if prefetch_path.exists():
        try:
            data = yaml.safe_load(prefetch_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                prefetch_notes = data.get("notes", {})
                if isinstance(prefetch_notes, dict):
                    for key, note in prefetch_notes.items():
                        if isinstance(note, str):
                            notes.append(f"- prefetch_executions.{key}: {note}")
        except Exception:
            pass
    
    return "\n".join(notes)


@lru_cache(maxsize=1)
def _load_dfir_yamls() -> dict[str, Any]:
    """Load all DFIR YAML schemas from _schema/ directory with caching."""
    import yaml
    from pathlib import Path

    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"

    def _load_yaml(name: str) -> dict:
        path = schema_dir / name
        if not path.exists():
            return {}
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    return {
        "evtx_events": _load_yaml("evtx_events.yaml"),
        "logon_types": _load_yaml("logon_types.yaml"),
        "event_ids": _load_yaml("event_ids.yaml"),
        "app_catalog": _load_yaml("app_catalog.yaml"),
        "fp_rules": _load_yaml("false_positive_rules.yaml"),
        "artifact_inference": _load_yaml("artifact_inference.yaml"),
    }


def _render_event_narrative(events_data: dict) -> str:
    parts: list[str] = []
    for eid_str, info in sorted(events_data.items(), key=lambda x: int(x[0]) if isinstance(x[0], str) and x[0].isdigit() else 0):
        if isinstance(info, dict):
            title = info.get("title", "")
            allowed = info.get("allowed_claims", [])
            disallowed = info.get("disallowed_without_extra", [])
            required = info.get("required_fields", [])
            keywords = info.get("keywords_for_string_search", [])
            line_parts = [f"Event {eid_str} ({title})"]
            if required:
                line_parts.append(f" always query: {', '.join(required)}")
            if allowed:
                line_parts.append(f" you may claim: {'; '.join(allowed)}")
            if disallowed:
                line_parts.append(f" DO NOT claim without extra evidence: {'; '.join(disallowed)}")
            if keywords:
                line_parts.append(f" string-search keywords: {', '.join(keywords)}")
            parts.append(" - " + ". ".join(line_parts) + ".")
    return "\n".join(parts)


def _render_logon_narrative(logon_types_data: dict) -> str:
    parts: list[str] = []
    for lt, info in sorted(logon_types_data.items(), key=lambda x: x[1].get("priority", 99) if isinstance(x[1], dict) else 99):
        if isinstance(info, dict):
            parts.append(
                f" - LogonType {lt}: {info.get('name', '')} — {info.get('description', '')} (priority {info.get('priority', '')})"
            )
    return "\n".join(parts)


def _render_priority_narrative(priority_events: list) -> str:
    parts: list[str] = []
    for pe in priority_events:
        if isinstance(pe, dict):
            eids = pe.get("event_ids", [])
            reason = pe.get("reason", "")
            parts.append(f" - First check events {eids}: {reason}")
    return "\n".join(parts)


def _render_schema_narrative(schema_notes: dict) -> str:
    parts: list[str] = []
    for key, note in sorted(schema_notes.items()):
        if isinstance(note, str):
            parts.append(f" - {key}: {note}")
    return "\n".join(parts)


def _render_fp_narrative(fp_guidance: dict) -> str:
    parts: list[str] = []
    if isinstance(fp_guidance, dict):
        for key, items in fp_guidance.items():
            if isinstance(items, list):
                parts.append(f" {key}: {'; '.join(str(i) for i in items)}")
    return "\n".join(parts)


def _render_extractor_narrative(extractors: dict) -> str:
    parts: list[str] = []
    if isinstance(extractors, dict):
        for field, expr in extractors.items():
            parts.append(f" - If {field.lower()} column is NULL/empty, use {expr} to extract from raw_json")
    return "\n".join(parts)


def _render_app_catalog_narrative(app_mappings: dict) -> str:
    parts: list[str] = []
    if isinstance(app_mappings, dict):
        for exe, info in app_mappings.items():
            if isinstance(info, dict):
                parts.append(f" - {exe}: {info.get('category', '?')} — {info.get('description', '')}")
    return "\n".join(parts)


def _render_artifact_inference_narrative(artifact_data: dict) -> str:
    parts: list[str] = []
    for artifact_type, entries in artifact_data.items():
        if isinstance(entries, list):
            parts.append(f"## {artifact_type.replace('_', ' ').title()}")
            for entry in entries:
                if isinstance(entry, dict):
                    pattern = entry.get("pattern", "")
                    app = entry.get("app_name", "")
                    category = entry.get("app_category", "")
                    notes = entry.get("notes", "")
                    line_parts = [f" - {pattern} → {app} ({category})"]
                    if notes:
                        line_parts.append(f": {notes}")
                    parts.append("".join(line_parts))
    return "\n".join(parts)


@lru_cache(maxsize=8)
def _dfir_playbook(phase: str) -> str:
    """Generate DFIR investigator playbook narrative for the given phase.

    Phase is one of: 'broad_plan', 'hypothesis_plan', 'check', 'report_section',
    'section_agent_plan', 'section_agent_check'.
    Returns a narrative string (5-10k chars) optimized for weak LLMs.
    """
    from pathlib import Path

    yamls = _load_dfir_yamls()

    events_data = yamls["event_ids"].get("events", {}) if isinstance(yamls["event_ids"], dict) else {}
    logon_types_data = yamls["logon_types"].get("types", {}) if isinstance(yamls["logon_types"], dict) else {}
    priority_events = yamls["logon_types"].get("priority_events", []) if isinstance(yamls["logon_types"], dict) else []
    schema_notes = yamls["evtx_events"].get("notes", {}) if isinstance(yamls["evtx_events"], dict) else {}
    fp_guidance = yamls["fp_rules"].get("reduction_guidance", {}) if isinstance(yamls["fp_rules"], dict) else {}
    extractors = yamls["evtx_events"].get("json_field_extractors", {}) if isinstance(yamls["evtx_events"], dict) else {}
    app_mappings = yamls["app_catalog"].get("mappings", {}) if isinstance(yamls["app_catalog"], dict) else {}
    artifact_data = yamls["artifact_inference"] if isinstance(yamls["artifact_inference"], dict) else {}

    event_narrative = _render_event_narrative(events_data)
    logon_narrative = _render_logon_narrative(logon_types_data)
    priority_narrative = _render_priority_narrative(priority_events)
    schema_narrative = _render_schema_narrative(schema_notes)
    fp_narrative = _render_fp_narrative(fp_guidance)
    extractor_narrative = _render_extractor_narrative(extractors)
    app_narrative = _render_app_catalog_narrative(app_mappings)
    artifact_narrative = _render_artifact_inference_narrative(artifact_data)

    # Phase-aware sections. Planning phases (broad_plan / hypothesis_plan) don't
    # need evidence-interpretation references; cutting them saves ~25% of the
    # system prompt for those calls.
    planning_phases = {"broad_plan", "hypothesis_plan"}
    interpretation_phases = {"check", "report_section", "section_agent_check"}
    include_fp = phase in interpretation_phases
    include_app_catalog = phase not in planning_phases  # planners don't interpret process names
    include_artifact_inference = phase in interpretation_phases

    sections = [
        "<DFIR_PLAYBOOK>",
        "You are a DFIR analyst. Follow these investigation principles.",
        "",
        "## Event ID Reference",
        event_narrative or "No event ID reference available.",
        "",
        "## Logon Type Reference",
        logon_narrative or "No logon type reference available.",
        "",
        "## Priority Investigation Order",
        priority_narrative or "No priority order specified.",
        "",
        "## Schema Notes & Column Guidance",
        schema_narrative or "No schema notes available.",
        "",
        "## JSON Field Extractors (when columns are NULL)",
        extractor_narrative or "No extractors available.",
    ]
    if include_fp:
        sections.extend([
            "",
            "## False-Positive Reduction Guidance",
            fp_narrative or "No FP reduction guidance.",
        ])
    if include_app_catalog:
        sections.extend([
            "",
            "## Application Catalog (process categorization)",
            app_narrative or "No app catalog available.",
        ])
    if include_artifact_inference:
        sections.extend([
            "",
            "## Artifact-to-Application Inference",
            artifact_narrative or "No artifact inference data available.",
        ])
    base_playbook = "\n".join(sections) + "\n"
    # Phase-specific playbook loaded from external MD file
    playbook_dir = Path(__file__).parent.parent / "rulepacks" / "_schema" / "playbook"
    phase_file = playbook_dir / f"{phase}.md"
    phase_narrative = ""
    if phase_file.exists():
        try:
            phase_narrative = phase_file.read_text(encoding="utf-8")
        except Exception:
            pass
    return base_playbook + phase_narrative


def _load_event_id_hints() -> dict[int, dict[str, Any]]:
    """Load event ID hints from _schema/event_ids.yaml keyed by integer event ID."""
    import yaml
    from pathlib import Path

    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    events: dict[int, dict[str, Any]] = {}
    raw_events = data.get("events") if isinstance(data, dict) else {}
    if not isinstance(raw_events, dict):
        return {}
    for key, value in raw_events.items():
        try:
            event_id = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            events[event_id] = value
    return events


def _lang_instruction() -> str:
    output = str(get_llm_settings()["output_language"])
    return f"All string values must be written in {output}. JSON keys and enum values (verdict, status, entity_type) remain in English."


def _output_language() -> str:
    return str(get_llm_settings()["output_language"]).lower()


def _mandatory_missing_checks_guidance() -> str:
    return """
Mandatory missing_checks:
   - If a logon is confirmed → add: 'Other host logons from the same src_ip', 'Presence of 4688/4104 within 15 minutes after logon'
   - If process execution is confirmed → add: 'Confirm parent process name', 'Check whether the executing user aligns with normal duties'
   - If service/task creation is confirmed → add: 'Path of the executable behind the service', 'Presence of 7036 (service start)'
   - If Defender disable is confirmed → add: 'Presence of 4688/4104 immediately afterward', 'Correlation with 1116 (malware detection)'
   - If account-related: add: 'Owner organization confirmation', 'User interview required'
"""


_RULE_INSTANCE_SUFFIX = re.compile(r"-(\d{4,})$")


def _rule_pattern(finding_id: str) -> str:
    """Collapse '...-0001' / '...-0042' suffix to '-*' so per-instance findings group."""
    if not finding_id:
        return ""
    return _RULE_INSTANCE_SUFFIX.sub("-*", finding_id)


def _slim_findings(items: list[dict[str, Any]], max_findings: int) -> list[dict[str, Any]]:
    """Compact a list of findings for prompt injection.

    Findings sharing the same rule pattern (e.g. windows-security-4648-...-0001..0015)
    collapse into a single summary row with `count` and a sample. This avoids dumping
    the same alert N times when one rule fires repeatedly.
    """
    fields = ("finding_id", "title", "severity", "confidence", "status", "summary")
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for item in items:
        pattern = _rule_pattern(str(item.get("finding_id") or ""))
        key = pattern or str(item.get("finding_id") or "")
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(item)

    slimmed: list[dict[str, Any]] = []
    for key in order:
        bucket = grouped[key]
        first = bucket[0]
        row = {field: first.get(field) for field in fields}
        if len(bucket) > 1:
            row["finding_id"] = key
            row["count"] = len(bucket)
            row["sample_finding_id"] = first.get("finding_id")
            last = bucket[-1]
            if str(last.get("finding_id")) != str(first.get("finding_id")):
                row["last_finding_id"] = last.get("finding_id")
        slimmed.append(row)
        if len(slimmed) >= max_findings:
            break
    return slimmed


def _slim_hypothesis_dump(hypothesis: Any) -> dict[str, Any]:
    """Drop null / empty-collection fields when serializing a Hypothesis for prompts.

    The full Pydantic dump includes a lot of None / [] / '' fields that cost tokens
    without carrying signal for the planner LLM. This trims them.
    """
    if hypothesis is None:
        return {}
    raw = hypothesis.model_dump() if hasattr(hypothesis, "model_dump") else dict(hypothesis)
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if value is None:
            continue
        if isinstance(value, (list, dict, str)) and len(value) == 0:
            continue
        out[key] = value
    return out


def _truncate_context_sections(context_sections: dict[str, str], max_chars: int = 1500) -> dict[str, str]:
    """Trim each section body to max_chars to fit within LLM token budget."""
    trimmed: dict[str, str] = {}
    for section_key, body in context_sections.items():
        text = str(body or "").strip()
        if not text:
            continue
        trimmed[str(section_key)] = text[:max_chars]
    return trimmed


def _slim_report_brief_for_section(report_brief: dict, section_key: str) -> dict:
    """Strip top_findings/hypotheses; keep only structural fields."""
    if not report_brief:
        return {}
    if section_key == "1_overview":
        return report_brief
    return {
        "time_range": report_brief.get("time_range"),
        "source_timezone": report_brief.get("source_timezone"),
        "investigation_objective": report_brief.get("investigation_objective"),
    }


def _summarize_context_sections(context_sections: dict[str, str]) -> dict[str, str]:
    """Return {section_key: first-line 120-char prefix} instead of full body."""
    summary: dict[str, str] = {}
    for key, body in context_sections.items():
        text = str(body or "").strip()
        if not text:
            continue
        first_line = text.split("\n", 1)[0].strip()[:120]
        summary[str(key)] = first_line
    return summary


_SQL_COOKBOOK = """
<SQL_COOKBOOK>
Copy and adapt these templates rather than inventing SQL from scratch.

# 1. Enumerate occurrences of one or more event IDs
SELECT event_id, timestamp, computer, user_name, target_user, raw_json
FROM evtx_events
WHERE event_id IN (4624, 4625)
ORDER BY timestamp
LIMIT 200;

# 2. Filter by time window
SELECT event_id, timestamp, computer
FROM evtx_events
WHERE event_id = 7045
  AND timestamp BETWEEN '2015-03-22 00:00:00' AND '2015-03-25 23:59:59'
ORDER BY timestamp;

# 3. Per-user logon summary
SELECT user_name, logon_type, COUNT(*) AS n, MIN(timestamp) AS first, MAX(timestamp) AS last
FROM evtx_events
WHERE event_id = 4624
GROUP BY 1, 2
ORDER BY n DESC;

# 4. Fall back to raw_json when a column is NULL
SELECT timestamp, COALESCE(user_name, json_extract(raw_json, '$.TargetUserName')) AS user
FROM evtx_events
WHERE event_id = 4720
ORDER BY timestamp;

# 5. Find file activity by path pattern (MFT)
SELECT file_path, file_name, si_modified, is_deleted
FROM mft_entries
WHERE LOWER(file_path) LIKE '%/desktop/%'
  AND extension IN ('docx', 'xlsx', 'pptx', 'doc', 'ppt', 'xls')
ORDER BY si_modified DESC
LIMIT 100;

# 6. Recent application executions (Prefetch)
SELECT executable_name, exec_count, last_exec_time
FROM prefetch_executions
WHERE LOWER(executable_name) IN ('eraser.exe', 'ccleaner.exe', 'ccsetup.exe', 'bleachbit.exe')
ORDER BY last_exec_time DESC;
</SQL_COOKBOOK>
"""


def _format_schema_card(table_hints: dict[str, Any]) -> str:
    """Format a table's schema card (columns, descriptions, notes) for LLM prompt injection."""
    table_name = table_hints.get("table", "?")
    core = table_hints.get("core_columns") or []
    descs = table_hints.get("column_descriptions") or {}
    notes = table_hints.get("notes") or {}
    full_cols = table_hints.get("columns") or []
    lines = [f"## Table `{table_name}`"]
    if core:
        lines.append("Primary columns (use these first):")
        for col in core:
            desc = descs.get(col)
            if desc:
                lines.append(f"  - `{col}` — {desc}")
            else:
                lines.append(f"  - `{col}`")
    elif full_cols:
        lines.append(f"Columns: {full_cols}")
    if notes:
        for key, note in notes.items():
            lines.append(f"  note ({key}): {note}")
    return "\n".join(lines)


def _build_schema_guidance(table_name: str = "evtx_events") -> str:
    """Build the schema_card section of planner prompts.

    Shows curated `core_columns` + descriptions for the LLM; the full
    `columns` list is consumed silently by validate_select_sql elsewhere.
    Surfaces ALL known tables (evtx_events, mft_entries, mft_timeline,
    prefetch_executions, findings) so the planner can JOIN/UNION across them.
    """
    schema_hints = _load_schema_hints()
    if not schema_hints:
        return ""
    primary = schema_hints.get(table_name, {})
    if not primary:
        return ""
    # Only surface entries that look like real DB tables (have a column list).
    db_tables = {name: h for name, h in schema_hints.items() if h.get("columns") or h.get("core_columns")}
    extractors = primary.get("json_field_extractors", {})
    blocks = ["<SCHEMA_CARDS>"]
    # Primary table first, then any other known tables in stable order.
    ordering = [table_name] + sorted(name for name in db_tables if name != table_name)
    for name in ordering:
        hints = db_tables.get(name)
        if hints:
            blocks.append(_format_schema_card(hints))
    if extractors:
        blocks.append(
            "For fields missing from the column list, use these JSON extractors instead of guessing: "
            + ", ".join(f"{k} → {v}" for k, v in extractors.items())
        )
    blocks.append("</SCHEMA_CARDS>")
    return "\n".join(blocks) + "\n" + _SQL_COOKBOOK


def _collect_event_ids(evidence_results: list[dict[str, Any]]) -> list[int]:
    event_ids: list[int] = []
    seen: set[int] = set()
    for result in evidence_results:
        for row in (result.get("sample_rows") or []) + (result.get("head_rows") or []) + (result.get("tail_rows") or []):
            if not isinstance(row, dict):
                continue
            value = row.get("event_id")
            try:
                event_id = int(value)
            except (TypeError, ValueError):
                continue
            if event_id in seen:
                continue
            seen.add(event_id)
            event_ids.append(event_id)
    return event_ids


def _build_event_id_guidance(evidence_results: list[dict[str, Any]]) -> str:
    """Build per-event-ID claim guidance for the report writer based on observed evidence."""
    event_hints = _load_event_id_hints()
    if not event_hints:
        return ""
    parts: list[str] = []
    for event_id in _collect_event_ids(evidence_results):
        hint = event_hints.get(event_id)
        if not hint:
            continue
        allowed_claims = hint.get("allowed_claims") or []
        disallowed = hint.get("disallowed_without_extra") or []
        required_fields = hint.get("required_fields") or []
        parts.append(
            f"Event ID {event_id} ({hint.get('title', 'unknown')}): required_fields={required_fields}, "
            f"allowed_claims={allowed_claims}, disallowed_without_extra={disallowed}. "
        )
    return "".join(parts)


def _collect_source_verdicts(evidence_results: list[dict[str, Any]]) -> list[str]:
    verdicts: list[str] = []
    seen: set[str] = set()
    for result in evidence_results:
        verdict = str(result.get("source_verdict") or "").strip().lower()
        if not verdict or verdict in seen:
            continue
        seen.add(verdict)
        verdicts.append(verdict)
    return verdicts


def _format_evidence_coverage(report_brief: dict[str, Any] | None) -> str:
    """Format evidence coverage summary per section for overview injection."""
    if not report_brief:
        return ""
    coverage = report_brief.get("evidence_coverage")
    if not isinstance(coverage, dict):
        return ""
    sections = coverage.get("sections")
    if not isinstance(sections, dict) or not sections:
        return ""
    lines: list[str] = ["Evidence coverage summary:"]
    for section_key, items in sections.items():
        if not isinstance(items, list):
            continue
        compact = ", ".join(
            f"{row.get('source')} (rows={row.get('rows')}, used={row.get('used_in_answer')})"
            for row in items[:6]
            if isinstance(row, dict)
        )
        if compact:
            lines.append(f"- {section_key}: {compact}")
    return "\n".join(lines)


def _slim_history(items: list[dict[str, Any]], max_items: int = 10) -> list[dict[str, Any]]:
    """Project history items to only the fields needed for broad planning context."""
    slimmed: list[dict[str, Any]] = []
    for item in items[:max_items]:
        slimmed.append({
            "query_id": item.get("query_id"),
            "hypothesis_id": item.get("hypothesis_id"),
            "verdict": item.get("verdict"),
            "rationale": item.get("summary"),
        })
    return slimmed


def build_broad_plan_messages(
    overview_md: str,
    extra_context_md: str,
    iteration: int,
    findings_snapshot: list[dict[str, Any]],
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
    history: list[dict[str, Any]],
    observed_keypoints: list[str] | None = None,
    uncovered_keypoints: list[dict[str, Any]] | None = None,
    max_findings: int = 10,
    max_resolved: int = 20,
) -> list[dict[str, str]]:
    """Build system+user messages for the broad-planning phase.

    Injects DFIR playbook, time-range guidance, and example outputs. Sends
    investigation state (findings, hypotheses, history) as user context."""

    findings = _slim_findings(findings_snapshot, max_findings)
    recent_resolved = resolved_hypotheses[-max_resolved:]
    slimmed_history = _slim_history(history, 10)
    uncovered_guidance = ""
    if uncovered_keypoints:
        uncovered_guidance = f"REQUIRED — The following uncovered keypoints MUST get hypothesis coverage in this cycle: {[kp.get('name') or kp.get('description', '') for kp in uncovered_keypoints[:5]]}\n"

    EXAMPLE_BROAD_PLAN = '''
<EXAMPLE verdict="broad_plan">
Input: unresolved findings show suspicious service creation on HOST-A. Active hypotheses empty. Kill chain shows no lateral movement covered.
Output: {"hypotheses": [{"id": "<assigned by system>", "description": "RDP lateral movement used to deploy malicious service on HOST-A", "required_entities": ["src_ip", "computer", "target_user", "service_name"], "source_rule_ids": ["windows-system-7045-service-install"]}], "stop": false, "stop_reason": ""}
</EXAMPLE>
<EXAMPLE verdict="broad_plan_antiforensic">
Input: observed keypoints show log clearing events (104) and antiforensic tool artifacts. No hypothesis covers defense evasion.
Output: {"read_more": ["memory/facts.md"], "hypotheses": [{"id": "<assigned by system>", "description": "Antiforensic tool execution (CCleaner/Eraser) to cover tracks after compromise", "required_entities": ["computer", "file_path", "process_name"], "source_rule_ids": ["ioc_user_data_files"]}], "stop": false, "stop_reason": ""}
</EXAMPLE>
<EXAMPLE verdict="broad_plan_cloud">
Input: observed keypoints include cloud sync artifacts (Google Drive, OneDrive). No hypothesis covers data exfiltration via cloud.
Output: {"read_more": ["memory/keypoints/KP-020.md"], "hypotheses": [{"id": "<assigned by system>", "description": "Cloud sync service (Google Drive/OneDrive) used for data exfiltration from the workstation", "required_entities": ["computer", "file_path", "process_name"], "source_rule_ids": ["ioc_email_ost_files"]}], "stop": false, "stop_reason": ""}
</EXAMPLE>
'''

    system = (
        f"{_dfir_playbook('broad_plan')}\n"
        f"{_time_range_guidance()}"
        f"{uncovered_guidance}"
        "<TASK>You are a DFIR investigator running broad planning. Propose NEW hypotheses only.</TASK>\n"
        "<INPUT_SCHEMA>overview_md, unresolved_findings, observed_keypoints, active_hypotheses, resolved_hypotheses, recent_history</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "hypothesis_quality: Must satisfy ALL: Falsifiable, Specific, Non-redundant, Evidence-grounded.\n"
        "hypothesis_output_schema: Each hypothesis MUST include required_entities, confirm_when, refute_when.\n"
        "prohibited_phrases: 'unknown', 'cannot confirm', 'insufficient evidence'.\n"
        "confirm_when_rule: co_observed_event_ids entries must be either integer event IDs (e.g. 4624, 7045) OR finding_ids (format: 'windows-xxx-yyyy-xxxx-xxxx'). "
        "Integer event IDs are preferred. Do NOT include keypoint names, free text, or quoted-string numbers — they will be dropped by validation.\n"
        "dedup_critical: NEVER re-state an existing active or resolved hypothesis using synonyms or different wording. "
        "例: 'lateral movement via RDP' と 'RDP remote access used for lateral movement' は THE SAME。 "
        "active_hypotheses と resolved_hypotheses を熟読してから新規提案する。\n"
        "semantic_dedup: 同じ (actor, action, target) triple は重複扱い。 "
        "例: 'Service creation used for persistence' と 'Persistence via service installation' は同じ。\n"
        "coverage_rule: REQUIRED — uncovered_keypoints が空でなければ、TOP 3 をカバーする仮説を「ちょうど 1 つ」生成する。 "
        "全 uncovered が既存仮説でカバーされているなら stop=true。\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "hypotheses": [{"id": "H-123", "description": "...", "required_entities": ["src_ip", "computer"], "confirm_when": {"co_observed_event_ids": [4624, 7045]}, "refute_when": {"zero_rows": true}}],\n'
        '  "stop": false,\n'
        '  "stop_reason": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        f"{EXAMPLE_BROAD_PLAN}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Current investigation state:\n"
        f"plan_cycle: {iteration}\n"
        f"overview_md:\n{overview_md}\n\n"
        f"extra_context_md:\n{extra_context_md}\n\n"
        f"unresolved_findings: {findings}\n"
        f"observed_keypoints: {observed_keypoints or []}\n"
        f"uncovered_keypoints: {uncovered_keypoints or []}\n"
        f"active_hypotheses: {[_slim_hypothesis_dump(item) for item in active_hypotheses]}\n"
        f"resolved_hypotheses: {[_slim_hypothesis_dump(item) for item in recent_resolved]}\n"
        f"recent_history: {slimmed_history}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_hypothesis_plan_messages(
    overview_md: str,
    extra_context_md: str,
    iteration: int,
    hypothesis: Hypothesis,
    finding_candidates: list[dict[str, Any]],
    hypothesis_history: list[dict[str, Any]],
    query_templates: list[dict[str, Any]],
    query_index: int = 1,
    max_queries: int = 5,
) -> list[dict[str, str]]:
    """Build messages for hypothesis-specific query planning.

    Includes schema guidance, convergence notes near the last allowed query,
    and structured summaries of already-executed queries to avoid repeats."""

    executed_query_summaries = [
        {
            "query_id": item.get("query_id"),
            "template_id": item.get("template_id"),
            "params": item.get("params"),
            "purpose": item.get("purpose"),
            "verdict": item.get("verdict"),
        }
        for item in hypothesis_history
        if item.get("query_id")
    ]
    queries_remaining = max_queries - query_index + 1
    if queries_remaining <= 1:
        convergence_note = (
            f"IMPORTANT: This is query {query_index} of {max_queries} — your LAST allowed query for this hypothesis. "
            "You must either propose one final decisive query that can definitively confirm or refute the hypothesis, "
            "or set needs_more=false with a stop_reason explaining why the hypothesis cannot be resolved further. "
            "Do not propose an exploratory query that is likely to return inconclusive results."
        )
    else:
        convergence_note = (
            f"This is query {query_index} of {max_queries} ({queries_remaining} queries remaining for this hypothesis). "
            "Prioritize queries that can directly confirm or refute the hypothesis over broad exploratory ones."
        )
    
    schema_guidance = _build_schema_guidance("evtx_events")

    EXAMPLE_HYPOTHESIS_PLAN = '''
<EXAMPLE verdict="hypothesis_plan">
Input: hypothesis='RDP used to HOST-B by admin'. Query history empty. Templates available for logon queries.
Output: {"read_more": [], "hypothesis": {"id": "H-5", "description": "RDP used to HOST-B by admin"}, "query": {"query_id": "Q-5a", "hypothesis_id": "H-5", "purpose": "Find RDP logons to HOST-B by admin", "template_id": "logon-by-user", "params": {"computer": "HOST-B", "user": "admin", "logon_type": "10"}}, "needs_more": true, "stop_reason": ""}
</EXAMPLE>
'''

    system = (
        f"{_dfir_playbook('hypothesis_plan')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR investigator. Propose exactly one read-only query to test the current hypothesis.</TASK>\n"
        "<INPUT_SCHEMA>hypothesis, related_findings, hypothesis_history, query_templates</INPUT_SCHEMA>\n"
        f"Memory context: facts.md, tasks.md, memory/details/fact-NNN.md paths.\n"
        f"Already-executed queries for this hypothesis (DO NOT repeat any — template_id+params must differ): {executed_query_summaries}\n"
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        "<RULES>\n"
        "convergence: On last query, propose decisive test. Do not output exploratory queries.\n"
        "query_required: MUST provide ONE of (a) template_id + params for a template in query_templates, OR (b) raw SELECT sql string. Never leave both blank — that aborts the investigation.\n"
        "template_preference: Use template_id only when an entry in query_templates fits exactly. Otherwise emit raw SELECT sql against the allowed tables (evtx_events, mft_entries, mft_timeline, prefetch_executions, findings).\n"
        "sql_rules: Read-only SELECT only. Use the schema_card columns. Reference WHERE timestamp within the case time range.\n"
        "</RULES>\n"
        f"{convergence_note}\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "read_more": [],\n'
        '  "hypothesis": {"id": "H-123", "description": "...", "required_entities": [], "confirm_when": {}, "refute_when": {}},\n'
        '  "query": {"query_id": "Q-123", "hypothesis_id": "H-123", "purpose": "...", "template_id": "..." | null, "params": {}, "sql": "SELECT ... | null"},\n'
        '  "needs_more": true|false,\n'
        '  "stop_reason": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        '<EXAMPLE verdict="raw_sql_fallback">\n'
        'Input: hypothesis is about event_id 104 log clearing. No template_id covers it.\n'
        'Output: {"read_more": [], "hypothesis": {"id": "H-002", "description": "..."}, "query": {"query_id": "Q-002-1", "hypothesis_id": "H-002", "purpose": "Enumerate all log-clear events", "template_id": null, "params": {}, "sql": "SELECT timestamp, computer, channel, raw_json FROM evtx_events WHERE event_id = 104 ORDER BY timestamp"}, "needs_more": false, "stop_reason": ""}\n'
        '</EXAMPLE>\n'
        f"{EXAMPLE_HYPOTHESIS_PLAN}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Current hypothesis-planning state:\n"
        f"plan_cycle: {iteration}\n"
        f"queries_remaining: {queries_remaining}\n"
        f"overview_md:\n{overview_md}\n\n"
        f"extra_context_md:\n{extra_context_md}\n\n"
        f"hypothesis: {_slim_hypothesis_dump(hypothesis)}\n"
        f"related_findings: {finding_candidates}\n"
        f"hypothesis_history: {hypothesis_history}\n"
        f"query_templates: {query_templates}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_query_intent_messages(
    hypothesis,
    recent_history: list[dict],
    finding_candidates: list[dict],
    active_hypotheses: list[Hypothesis],
    time_range: dict,
    schema_context: str,
    extra_context_md: str = "",
) -> list[dict[str, str]]:
    """Build messages for the query_intent_planner phase.
    
    Decides WHAT data to fetch for this hypothesis, not HOW.
    Uses read_more expansion for memory context.
    """
    system = (
        f"{_dfir_playbook('hypothesis_plan')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a query_intent_planner. Decide WHAT data to fetch for the given hypothesis. Do NOT write SQL.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"hypothesis: {hypothesis.model_dump() if hasattr(hypothesis, 'model_dump') else hypothesis}\n"
        f"recent_history: {json.dumps(recent_history, ensure_ascii=False, default=str)}\n"
        f"time_range: {json.dumps(time_range, ensure_ascii=False, default=str)}\n"
        f"schema: {schema_context}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "read_more": ["list of memory paths for additional context, or empty list"],\n'
        '  "intent": "string — one sentence describing what data to retrieve",\n'
        '  "target_table": "evtx_events | mft_entries | mft_timeline | prefetch_executions",\n'
        '  "filters_required": ["list of column-level filters needed"],\n'
        '  "time_window": "string describing time bounds",\n'
        '  "expected_row_shape": "string describing expected columns"\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"hypothesis.description: {hypothesis.description}\n"
        f"hypothesis.required_entities: {getattr(hypothesis, 'required_entities', [])}\n"
        f"active_hypotheses: {[h.model_dump() if hasattr(h, 'model_dump') else dict(h) for h in active_hypotheses]}\n"
        f"extra_context:\n{extra_context_md}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_sql_composer_messages(
    intent: dict,
    table_schema_card: str,
    template_catalog: list[dict],
    time_range: dict,
) -> list[dict[str, str]]:
    """Build messages for the sql_composer phase.
    
    Produces a valid DuckDB SELECT statement that satisfies `intent`.
    Idempotent — no read_more cycle needed.
    """
    system = (
        f"{_dfir_playbook('hypothesis_plan')}\n"
        "<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent. Output template_id or raw SQL.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"intent: {json.dumps(intent, ensure_ascii=False)}\n"
        f"table_schema: {table_schema_card}\n"
        f"template_catalog: {json.dumps(template_catalog[:10], ensure_ascii=False)}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "template_id": "string | null — if a template matches",\n'
        '  "sql": "string | null — raw SQL if no template matches",\n'
        '  "params": {"key": "value"},\n'
        '  "purpose": "string — why this query answers the hypothesis"\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = json.dumps({"intent": intent}, ensure_ascii=False, default=str)
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _check_strictness_note(query_index: int, max_queries: int) -> str:
    queries_remaining = max_queries - query_index
    if queries_remaining == 0:
        return (
            f"CONVERGENCE REQUIRED: This is query {query_index} of {max_queries} — the FINAL check for this hypothesis. "
            "You must commit to a definitive verdict now. "
            "If any evidence leans one way, use 'confirmed' or 'refuted'. "
            "Reserve 'inconclusive' only when the result is genuinely ambiguous AND no further query could resolve it. "
            "Do not output 'newlead' on the final query — new leads will not be pursued at this stage."
        )
    elif queries_remaining == 1:
        return (
            f"This is query {query_index} of {max_queries} — one query remains after this. "
            "Be willing to lean toward a verdict if the evidence is suggestive but not conclusive. "
            "Use 'newlead' only if you have identified a genuinely distinct attack surface not yet investigated."
        )
    return (
        f"This is query {query_index} of {max_queries} ({queries_remaining} checks remaining). "
        "Apply standard evidentiary rigor."
    )


def _check_evidence_id_guidance(observed_evidence_ids: list[str] | None) -> str:
    if not observed_evidence_ids:
        return ""
    return (
        f"The following evidence_ids are valid for this query: {observed_evidence_ids[:50]}. "
        "Only reference evidence_ids from this list in your output. "
    )


def _check_zero_evidence_note(result_summary: dict) -> str:
    if int(result_summary.get("row_count") or 0) != 0:
        return ""
    return (
        "IMPORTANT: The query result contains 0 rows — 'confirmed' verdict is forbidden. "
        "Use 'refuted' if the hypothesis is clearly disproven, or 'inconclusive' if the result is ambiguous. "
    )


def _check_entity_constraint() -> str:
    entity_type_list = list(ENTITY_TYPE_ALIASES.keys())
    return (
        f"When adding entities, entity_type must be one of: {entity_type_list}. "
        "Do not emit placeholder values ('n/a', 'unknown', empty string) as entity names or types. "
    )


def _check_rule_verdict_guidance(rule_context: RuleContext | None) -> str:
    if not rule_context:
        return ""
    confirm_conditions = rule_context.confirm_when or {}
    refute_conditions = rule_context.refute_when or {}
    return (
        f"Rule-based verdict criteria (from {rule_context.rule_id}): "
        f"Confirm when: {confirm_conditions}. "
        f"Refute when: {refute_conditions}. "
        "If rule criteria are met, use them as the primary verdict basis. "
    )


def _check_fallback_guidance(fallback_info: dict | None) -> str:
    if not fallback_info:
        return ""
    phase = fallback_info.get("phase", "")
    source_rule = fallback_info.get("source_rule_id", "")
    event_ids = fallback_info.get("event_ids") or []
    keywords = fallback_info.get("keywords") or []
    return (
        f"IMPORTANT: This result was obtained via fallback_search phase '{phase}' "
        f"from rule '{source_rule}'. "
        "The primary query returned 0 rows, but this fallback phase found relevant evidence. "
        f"{f'Event IDs from the query were {event_ids}. ' if event_ids else ''}"
        f"{f'String-search keywords used were {keywords}. ' if keywords else ''}"
        "Use this context when determining verdict and rationale. "
    )


def _check_example_block(rule_context: RuleContext | None, fallback_info: dict | None, zero_evidence: bool) -> str:
    EXAMPLE_CONFIRMED = '''
<EXAMPLE verdict="confirmed">
Input: hypothesis requires entities {src_ip, computer, target_user} to confirm lateral movement.
Query returned rows showing src_ip='192.168.10.50', computer='HOST-B', target_user='admin' all in the same rows.
Output: {"query_id": "Q123", "verdict": "confirmed", "rationale": "All required entities co-observed in results. src_ip 192.168.10.50 accessed HOST-B with admin account.", "finding_updates": [{"finding_id": "F456", "new_status": "accepted", "confidence_delta": 0.2}], "memory_updates": {"facts": [{"fact_type": "lateral_movement", "fact_key": "source_ip->host", "fact_value": "192.168.10.50->HOST-B", "evidence_ids": ["E789"]}]}}
</EXAMPLE>
'''
    EXAMPLE_REFUTED_ZERO = '''
<EXAMPLE verdict="refuted">
Input: hypothesis suggests admin account was created for attacker persistence.
Query returned 0 rows, no 4720 (user creation) events for 'admin' found.
Output: {"query_id": "Q124", "verdict": "refuted", "rationale": "Zero rows for admin account creation. The account may be pre-existing or the log was cleared.", "finding_updates": [], "memory_updates": {"refuted_hypotheses": [{"hypothesis_id": "H99", "reason": "No creation evidence found"}]}}
</EXAMPLE>
'''
    EXAMPLE_INCONCLUSIVE = '''
<EXAMPLE verdict="inconclusive">
Input: hypothesis requires {src_ip, computer} for lateral movement. Query returned 1 row with computer='HOST-B' but no src_ip.
Output: {"query_id": "Q125", "verdict": "inconclusive", "rationale": "Missing src_ip in observed row. Need query to identify source IP of logon events to HOST-B.", "finding_updates": [], "memory_updates": {}}
</EXAMPLE>
'''
    return f"{EXAMPLE_CONFIRMED}{EXAMPLE_REFUTED_ZERO}{EXAMPLE_INCONCLUSIVE}"


def build_check_messages(
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    overview_md: str,
    memory_context_md: str,
    query_index: int = 1,
    max_queries: int = 5,
    observed_evidence_ids: list[str] | None = None,
    rule_context: RuleContext | None = None,
    fallback_info: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Build full check-phase messages for evaluating a query result.

    Injects verdict taxonomy rules, entity constraints, zero-evidence
    guardrails, and rule-based criteria."""
    str_fallback = _check_fallback_guidance(fallback_info)
    zero_evidence = int(result_summary.get("row_count") or 0) == 0
    system = (
        f"{_dfir_playbook('check')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR review analyst. Evaluate SQL results against hypothesis and output structured findings.</TASK>\n"
        "<INPUT_SCHEMA>SQL result summary, hypothesis with required_entities, finding candidates, evidence_ids list</INPUT_SCHEMA>\n"
        "<RULES>\n"
        f"evidence_ids: {_check_evidence_id_guidance(observed_evidence_ids) or 'none available'}\n"
        f"zero_evidence: {_check_zero_evidence_note(result_summary)}\n"
        f"{_check_entity_constraint()}\n"
        f"rule_based: {_check_rule_verdict_guidance(rule_context)}\n"
        f"fallback: {str_fallback}\n"
        "</RULES>\n"
        "<MEMORY_RULES>\n"
        "facts: always include observed evidence_ids from the current query result. Do not emit speculative or unconfirmed items into memory_updates.facts. If you cannot cite observed evidence_ids, omit the fact.\n"
        "finding_updates format: finding_id, new_status (accepted or suppressed), confidence_delta\n"
        "suspicious_evidence format: evidence_id, reason, confidence (0.0-1.0)\n"
        "entities require entity_type and role.\n"
        "</MEMORY_RULES>\n"
        f"{_load_fp_reduction_guidance()}{_mandatory_missing_checks_guidance()}"
        "<VERDICT_RULES>\n"
        "confirmed — required_entities co-observed in same rows, OR >= 50% of confirm_when.co_observed_event_ids present with matching temporal order. In DFIR, evidence presence SUFFICES for confirmation — you do not need smoking-gun causation proof. Confidence >= 0.6.\n"
        "refuted — zero rows after a fair search, or observed entities clearly contradict hypothesis. Confidence < 0.3.\n"
        "inconclusive — USE ONLY when the result is genuinely ambiguous AND no further query could resolve it. NEVER output 'inconclusive' for zero-row results that could instead be 'refuted'. Each hypothesis may have at most 2 inconclusive verdicts before the system treats further inconclusives as refuted. MUST list missing entity types in rationale.\n"
        "newlead — genuinely new attack surface or actor. Name the specific entity.\n"
        "Prohibited phrases: 'direct causation not proven', 'full attack chain not visible', 'requires further investigation', 'cannot be determined', 'insufficient evidence'. State exactly what entity is missing.\n"
        "</VERDICT_RULES>\n"
        f"{_check_strictness_note(query_index, max_queries)}\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "query_id": "Q-123",\n'
        '  "verdict": "confirmed",\n'
        '  "finding_updates": [{"finding_id": "F-456", "new_status": "accepted", "confidence_delta": 0.2}],\n'
        '  "suspicious_evidence": [{"evidence_id": "E-789", "reason": "encoded command line", "confidence": 0.9}],\n'
        '  "new_hypotheses": [],\n'
        '  "memory_updates": {"facts": [{"fact_type": "lateral_movement", "fact_key": "src_ip->host", "fact_value": "192.168.1.1->HOST-A", "evidence_ids": ["E-789"]}],\n'
        '  "report_text": "RDP logon observed from external IP to HOST-A",\n'
        '  "missing_checks": [],\n'
        '  "notes": ""\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        f"{_check_example_block(rule_context, fallback_info, zero_evidence)}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        "Evaluate the following query result.\n"
        f"overview_md:\n{overview_md}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"planned_query: {planned_query.model_dump()}\n"
        f"hypothesis: {_slim_hypothesis_dump(hypothesis) if hypothesis else None}\n"
        f"finding_candidates: {finding_candidates}\n"
        f"result_summary: {result_summary}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_check_verdict_messages(
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    rule_context: RuleContext | None = None,
    fallback_info: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Build verdict-only check messages as the first phase of phased checking.

    Narrowly focuses on verdict determination (confirmed/refuted/inconclusive/newlead)
    without memory-update or suspicious-evidence extraction."""

    zero_evidence = int(result_summary.get("row_count") or 0) == 0
    rule_verdict_guidance = ""
    if rule_context:
        confirm = rule_context.confirm_when or {}
        refute = rule_context.refute_when or {}
        rule_verdict_guidance = f"Rule-based verdict criteria (from {rule_context.rule_id}): Confirm when: {confirm}. Refute when: {refute}. "

    system = (
        f"{_dfir_playbook('check')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR review analyst. Determine verdict based on SQL results.</TASK>\n"
        "<INPUT_SCHEMA>SQL result summary, hypothesis, rule_context</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "confirmed: required_entities co-observed, OR >= 50% of confirm_when.co_observed_event_ids present with matching temporal order. Evidence presence is enough for confirmation.\n"
        "refuted: zero rows after a fair search, or entities contradict hypothesis.\n"
        "inconclusive: USE SPARINGLY — at most 2 per hypothesis. Name the missing entity.\n"
        f"{rule_verdict_guidance}\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"query_id\": \"Q-123\", \"verdict\": \"confirmed|refuted|inconclusive|newlead\", \"rationale\": \"explanation\"}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"planned_query: {planned_query.model_dump()}\n"
        f"hypothesis: {_slim_hypothesis_dump(hypothesis) if hypothesis else None}\n"
        f"result_summary: {result_summary}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_check_memory_updates_messages(
    verdict: str,
    result_summary: dict[str, Any],
    finding_candidates: list[dict[str, Any]],
    overview_md: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for durable memory extraction (facts, timeline, entities) after a verdict."""

    system = (
        "<TASK>You are a DFIR review analyst. Extract durable memory updates based on verdict.</TASK>\n"
        "<INPUT_SCHEMA>verdict, SQL result, finding candidates</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts: Include evidence_ids; for co-observed entities, facts, timestamps.\n"
        "timeline: Include evidence_ids; central attack timestamps.\n"
        "tasks: Unresolved questions with kind (internal_db_check/external_lookup/human_decision).\n"
        "entities: entity_type + name + role; include evidence_ids.\n"
        "refuted_hypotheses/resolved_gaps: When hypothesis disproven or gap resolved.\n"
        "Only output items you can cite with evidence_ids.\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"memory_updates\": {\"facts\": [...], \"timeline\": [...], \"tasks\": [...], \"entities\": [...], \"refuted_hypotheses\": [...], \"resolved_gaps\": [...]}}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"verdict: {verdict}\n"
        f"result_summary: {result_summary}\n"
        f"finding_candidates: {finding_candidates}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_check_suspicious_evidence_messages(
    result_summary: dict[str, Any],
) -> list[dict[str, str]]:
    """Build messages for suspicious-evidence identification and report-text generation."""

    system = (
        "<TASK>You are a DFIR review analyst. Identify suspicious evidence from SQL results.</TASK>\n"
        "<INPUT_SCHEMA>SQL result rows (sample_rows)</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "suspicious_evidence: List evidence_ids with reason and confidence (0.0-1.0).\n"
        "reason: Why this evidence is suspicious (encoded command, unusual time, external IP, etc.).\n"
        "report_text: Brief summary sentence in output language.\n"
        "</RULES>\n"
        "<OUTPUT_SCHEMA>{\"suspicious_evidence\": [{\"evidence_id\": \"E-123\", \"reason\": \"...\", \"confidence\": 0.9}], \"report_text\": \"...\"}\n"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = f"sample_rows: {result_summary.get('sample_rows') or []}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_column_selection_messages(
    headers: list[str],
    section_key: str,
    template_body: str,
) -> list[dict[str, str]]:
    """Build messages asking LLM to select analytically relevant columns from a query result set."""

    system = (
        "You are a DFIR analyst. "
        "Given a list of column names from query results and the report section context, "
        "select only the columns that are analytically relevant for this section. "
        "Drop: internal row IDs, empty/null-only fields, columns redundant with another column, "
        "and any field that a reader of this section would not care about. "
        "Output JSON only: {\"columns\": [\"col_a\", \"col_b\", ...]}"
    )
    user = (
        f"section_key: {section_key}\n\n"
        f"template_context (first 600 chars):\n{template_body[:600]}\n\n"
        f"available_columns: {headers}\n\n"
        "Return only the column names worth including in the evidence table."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_verdict_review_messages(
    hypothesis,
    planned_query,
    result_summary: dict,
    time_range: dict,
    strictness_note: str = "",
) -> list[dict[str, str]]:
    """role: verdict_reviewer.
    Goal: classify the SQL result vs hypothesis as confirmed/refuted/inconclusive.
    Output JSON: {verdict, rationale, confidence}
    """
    system = (
        f"{_dfir_playbook('check')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a verdict_reviewer. Classify the SQL result against the hypothesis as confirmed, refuted, or inconclusive.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "confirmed | refuted | inconclusive",\n'
        '  "rationale": "string — concise reason (< 200 chars)",\n'
        '  "confidence": 0.0-1.0\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"query: {planned_query.sql if hasattr(planned_query, 'sql') else planned_query}\n"
        f"result_summary: {json.dumps(result_summary, ensure_ascii=False)}\n"
        f"{strictness_note}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_finding_extractor_messages(
    hypothesis, result_rows: list[dict], verdict: str, rationale: str
) -> list[dict[str, str]]:
    """role: finding_extractor.
    Goal: extract finding entries IFF verdict == confirmed.
    Called only when verdict is confirmed.
    """
    system = (
        "<TASK>You are a finding_extractor. Extract findings from the confirmed query results. Only output findings if the evidence clearly supports a specific security event.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "findings": [{"title": "string", "severity": "low|medium|high|critical", "evidence_ids": ["str"]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
        f"result_rows: {json.dumps(result_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_memory_updater_messages(
    hypothesis, verdict: str, rationale: str
) -> list[dict[str, str]]:
    """role: memory_updater.
    Goal: propose durable memory writes (facts.md additions).
    """
    system = (
        "<TASK>You are a memory_updater. Propose durable fact updates based on the investigation result.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "memory_updates": [{"path": "facts.md | timeline.md | entities/*.md", "content": "string"}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _rows_to_markdown_table(rows: list[dict[str, Any]], max_rows: int = 30) -> str:
    if not rows:
        return ""
    keys = list(rows[0].keys())
    header = "| " + " | ".join(keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    data_lines = []
    for row in rows[:max_rows]:
        cells = [str(row.get(k, "")).replace("|", "\\|").replace("\n", " ") for k in keys]
        data_lines.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, separator, *data_lines])


def _section_verification_block(verification_notes: list[str] | None) -> str:
    return f"verification_notes_from_prior_subsections: {verification_notes or []}\n\n"


def _section_evidence_block(raw_evidence_rows: list[dict] | None) -> str:
    if not raw_evidence_rows:
        return ""
    return (
        "You are also given normalized evidence summaries derived from row-level evidence. "
        "Treat them as reference only; do not paste raw tables or raw field dumps into the narrative body. "
        "Use them to write a short, normalized one-line summary of each relevant observation. "
        "If the section needs an appendix-style evidence note, place it in a dedicated Raw Evidence subsection with concise summaries only, never with NULL/None-heavy raw rows. "
    )


def _section_coverage_block(report_brief: dict) -> str:
    return _format_evidence_coverage(report_brief)


def _format_outline(outline: list[dict]) -> str:
    if not outline:
        return ""
    lines = ["<PRIOR_BLOCKS_IN_THIS_SECTION>"]
    for entry in outline:
        heading = entry.get("heading", "")
        summary = entry.get("summary", "")
        lines.append(f"  - **{heading}:** {summary}")
    lines.append("</PRIOR_BLOCKS_IN_THIS_SECTION>")
    return "\n".join(lines)


def _section_context_block(context_sections: dict[str, str], current_section_outline: list[dict]) -> str:
    trimmed_context = _summarize_context_sections(context_sections)
    lines = [f"previous_sections: {trimmed_context}\n"]
    if current_section_outline:
        lines.append("<PRIOR_BLOCKS_IN_THIS_SECTION>")
        for entry in current_section_outline:
            heading = entry.get("heading", "")
            summary = entry.get("summary", "")
            lines.append(f"  - **{heading}:** {summary}")
        lines.append("</PRIOR_BLOCKS_IN_THIS_SECTION>")
    return "\n".join(lines)


def build_report_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    context_sections: dict[str, str],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    section_heading: str = "",
    current_section_outline: list[dict] | None = None,
    verification_notes: list[str] | None = None,
    raw_evidence_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Build messages for report section writing with evidence and template context."""

    insufficient_evidence_placeholder = (
        "【調査不足: 理由】"
        if _output_language().startswith("ja")
        else "[INSUFFICIENT EVIDENCE: reason]"
    )
    coverage_guidance = _section_coverage_block(report_brief or {})
    if str(section_meta.get("section") or "").strip() == "1_overview" and coverage_guidance:
        coverage_guidance = (
            "Use the following evidence coverage summary as the canonical Evidence Scope. "
            "Do not invent sources that are not listed.\n"
            f"{coverage_guidance}\n"
        )
    evidence_for_prompt: list[dict[str, Any]] = [result for result in evidence_results if str(result.get("kind") or "rows") == "rows"]
    if not evidence_for_prompt:
        evidence_for_prompt = evidence_results
    if raw_evidence_rows:
        evidence_for_prompt = [
            {k: v for k, v in result.items() if k != "sample_rows"}
            for result in evidence_results
        ]
    EXAMPLE_REPORT_SECTION = '''
<EXAMPLE verdict="report_section">
Input: section_meta={'section': '3_technical'}, template_body='## Process Execution\\nLook for suspicious processes.', evidence_results=[{'sample_rows': [{'evidence_id': 'E1', 'process_name': 'powershell.exe', 'command_line': '-enc ...'}]}]
Output: "## Process Execution\\n\\nOne suspicious process was observed: powershell.exe with encoded command line (evidence_id: E1)."
</EXAMPLE>
'''

    app_catalog = _load_app_catalog()
    app_cat_compact = ", ".join(
        f"{exe}={info.get('category', '?')}"
        for exe, info in app_catalog.get("mappings", {}).items()
    ) or "see investigation framework"
    event_guidance = _build_event_id_guidance(evidence_results)
    source_verdicts = _collect_source_verdicts(evidence_results)
    strength_guidance = ""
    if source_verdicts and all(verdict != "confirmed" for verdict in source_verdicts):
        strength_guidance = (
            "source_verdict guidance: Every supplied evidence result is below confirmed. "
            "Use cautious language only; avoid 'confirmed', 'executed', 'compromised', 'attack succeeded', or equivalent strong assertions unless additional evidence explicitly supports them.\n"
        )

    system = (
        f"{_dfir_playbook('report_section')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR report writer. Fill the provided Markdown section template using only supplied evidence.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, evidence_results, previous_sections, template_body</INPUT_SCHEMA>\n"
        "<RULES>\n"
        "confidence_matrix: confidence >= 0.8 => 'confirmed'/'observed'; confidence >= 0.5 and < 0.8 => 'strongly suggests'; confidence < 0.5 => 'requires further investigation'.\n"
        "Do not use 'confirmed' for findings or conclusions below 0.8 confidence.\n"
        "Match wording to confidence: use cautious language for low-confidence items.\n"
        f"no_invented_facts: Write placeholder only for unsupported claims. Placeholder: {insufficient_evidence_placeholder}\n"
        "no_causation: Correlation is not proof of causation.\n"
        "confirmed_hypotheses: Reflect in appropriate sections; refuted_hypotheses only in 'Discarded Hypotheses' subsection.\n"
        "Recommended actions must scale with evidence strength.\n"
        f"app_categories: {app_cat_compact}\n"
        f"{_format_artifact_inference()}"
        f"{event_guidance}"
        f"{strength_guidance}"
        "</RULES>\n"
    )
    evidence_guidance = _section_evidence_block(raw_evidence_rows)
    if evidence_guidance:
        system += f"{evidence_guidance}\n"
    if coverage_guidance:
        system += f"{coverage_guidance}\n"
    system += f"{EXAMPLE_REPORT_SECTION}"
    system += f"Output Markdown only (no fences). {_lang_instruction()}"
    raw_block = ""
    if raw_evidence_rows:
        table_md = _rows_to_markdown_table(raw_evidence_rows)
        raw_block = f"\nnormalized_evidence_rows (summaries only; do not mirror raw tables):\n{table_md}\n"
    user = (
        f"section_meta: {section_meta}\n\n"
        f"current_subsection: {section_heading or '(full section)'}\n\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief or {}, str(section_meta.get('section') or ''))}\n\n"
        f"{_section_context_block(context_sections, current_section_outline or [])}"
        f"{_section_verification_block(verification_notes)}"
        f"evidence_coverage: {report_brief.get('evidence_coverage') if isinstance(report_brief, dict) else {}}\n\n"
        f"evidence_results: {evidence_for_prompt}\n"
        f"{raw_block}\n"
        "Complete only this current template block by replacing placeholders and comments with evidence-based content. "
        "If verification_notes indicate contradiction, explicitly state what evidence refutes the claim and why.\n\n"
        f"{template_body}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _load_question_routing_raw() -> dict[str, Any]:
    """Load raw question-routing schema from _schema/question_routing.yaml."""
    import yaml
    from pathlib import Path
    routing_path = Path(__file__).resolve().parent.parent / "rulepacks" / "_schema" / "question_routing.yaml"
    try:
        raw = yaml.safe_load(routing_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    except Exception:
        pass
    return {}


def _format_artifact_inference() -> str:
    return (
        "\nKnown artifact-to-application inferences:\n"
        "- *.ost, *.pst files → Microsoft Outlook (almost certainly — no other app uses .ost)\n"
        "- %LocalAppData%/Google/Drive/sync_config.db → Google Drive\n"
        "- %LocalAppData%/Google/Drive/snapshot.db → Google Drive\n"
        "- %LocalAppData%/Apple Computer/iCloud/ → Apple iCloud\n"
        "- %LocalAppData%/Microsoft/OneDrive/ → Microsoft OneDrive\n"
        "- %AppData%/Dropbox/config.dbx → Dropbox\n"
        "- Eraser.exe → Eraser antiforensic tool\n"
        "- ccsetup*.exe → CCleaner\n"
        "- bleachbit.exe → BleachBit\n"
        "- privazer*.exe → PrivaZer\n"
        "- sdelete.exe → SDelete\n"
        "- chrome.exe → Google Chrome\n"
        "- iexplore.exe → Microsoft Internet Explorer\n"
        "- firefox.exe → Mozilla Firefox\n"
        "- msedge.exe → Microsoft Edge\n"
    )


def build_benchmark_section_messages(
    section_meta: dict[str, Any],
    evidence_results: list[dict[str, Any]],
    template_body: str,
    report_brief: dict[str, Any] | None = None,
    block_heading: str = "",
    raw_evidence_rows: list[dict[str, Any]] | None = None,
    verification_notes: list[str] | None = None,
    benchmark_id: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for benchmark appendix blocks with structured JSON output schema.

    Injects question-routing expected answer shape and artifact-inference guidance.
    Benchmark blocks output structured JSON instead of free-form Markdown."""

    raw_evidence_rows = raw_evidence_rows or []
    evidence_for_prompt = [result for result in evidence_results if str(result.get("kind") or "rows") == "rows"]
    if not evidence_for_prompt:
        evidence_for_prompt = evidence_results
    summary_lines = []
    for row in raw_evidence_rows:
        summary = str(row.get("summary") or "").strip()
        if summary:
            summary_lines.append(f"- {summary}")
    block_id = str(benchmark_id or "").strip()
    if not block_id:
        block_id = str(section_meta.get("id") or "").strip()

    # QA3-9: Inject expected_answer_shape from question_routing
    shape_guidance = ""
    block_cf = block_heading.casefold()
    qr_raw = _load_question_routing_raw()
    for qtype in qr_raw.get("question_types", []):
        if isinstance(qtype, dict) and any(kw in block_cf for kw in qtype.get("keywords", [])):
            shape = qtype.get("expected_answer_shape")
            if shape:
                shape_guidance = (
                    f"<OUTPUT_FORMAT_GUIDANCE>\n"
                    f"Expected answer shape: {shape.get('format', 'list')}\n"
                    f"Fields to include: {shape.get('fields', [])}\n"
                    f"Style: {shape.get('style', 'list')}\n"
                    f"Note: {shape.get('note', '')}\n"
                    f"</OUTPUT_FORMAT_GUIDANCE>\n"
                )
            break

    system = (
        f"{_dfir_playbook('report_section')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a benchmark answer writer for a DFIR appendix block.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, block_heading, template_body, evidence_results, raw_evidence_rows</INPUT_SCHEMA>\n"
        f"<BENCHMARK_ID>The id field of your output MUST be exactly: {block_id}</BENCHMARK_ID>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  \"id\": \"<copy BENCHMARK_ID verbatim>\",\n'
        '  \"status\": \"answered|partial|not_found|not_searched|insufficient_evidence|wrong_query\",\n'
        '  \"answer\": [\"concise normalized statements\" OR {\"field\": \"value\", ...}],\n'
        '  \"missing_reason\": [\"why evidence is missing or incomplete\"],\n'
        '  \"queries_run\": [\"keypoint or SQL query identifiers actually used\"]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Return exactly one JSON object.\n"
        "Do not return markdown, code fences, or prose outside JSON.\n"
        "Output JSON only.\n"
        "Keep answer items short and normalized; no NULL/None-heavy dumps.\n"
        "When OUTPUT_FORMAT_GUIDANCE indicates Style: table, return answer as a list of JSON objects, each keyed by the declared fields (one row per object). Otherwise return answer as a list of short strings.\n"
        "Do not pre-format answer items as Markdown tables or pipe-separated rows; emit objects and the writer renders the table.\n"
        "If evidence is incomplete, status must be partial or insufficient_evidence, and missing_reason must explain what is missing.\n"
        "If no relevant search ran, use not_searched.\n"
        "If the relevant search returned zero rows after search, use not_found.\n"
        "queries_run should list only the concrete keypoint/template/sql identifiers that were actually executed.\n"
        "Never infer that a generic file extension or shortcut name alone answers the question; use wrong_query or insufficient_evidence when evidence is only tangential.\n"
        f"{_format_artifact_inference()}"
        "</RULES>\n"
    )
    if shape_guidance:
        system += f"{shape_guidance}\n"
    user = (
        f"section_meta: {section_meta}\n\n"
        f"block_heading: {block_heading}\n\n"
        f"benchmark_id: {block_id}\n\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief or {}, str(section_meta.get('section') or ''))}\n\n"
        f"verification_notes: {verification_notes or []}\n\n"
        f"evidence_results: {evidence_for_prompt}\n\n"
        f"normalized_evidence_rows:\n" + ("\n".join(summary_lines) if summary_lines else "- none") + "\n\n"
        f"template_body:\n{template_body}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def build_benchmark_classify_messages(
    question: str,
    block_heading: str,
    evidence_rows: list[dict],
    expected_shape: dict | None,
) -> list[dict[str, str]]:
    """role: benchmark_classifier.
    Goal: decide answer status and pick which evidence_rows answer the question.
    Output: {status, picked_row_ids, rationale}
    """
    system = (
        "<TASK>You are a benchmark_classifier. Decide the answer status and pick which evidence rows answer the question. "
        "Do NOT write narrative.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "status": "answered | partial | not_found | not_searched | wrong_query",\n'
        '  "picked_row_ids": ["list of evidence row identifiers"],\n'
        '  "rationale": "string"\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"question: {question}\n"
        f"block_heading: {block_heading}\n"
        f"evidence_rows: {json.dumps(evidence_rows[:20], default=str, ensure_ascii=False)}\n"
        f"expected_shape: {json.dumps(expected_shape or {}, ensure_ascii=False)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _filter_prior_runs_by_heading(prior_runs: list[dict[str, Any]], block_heading: str, limit: int = 6) -> list[dict[str, Any]]:
    """Filter prior runs by block_heading match."""
    heading_matches = [run for run in prior_runs if str(run.get("block_heading") or "") == str(block_heading)]
    return heading_matches[-limit:]


def build_section_agent_plan_messages(
    *,
    section_key: str,
    section_title: str,
    block_heading: str,
    template_body: str,
    report_brief: dict[str, Any],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    findings_snapshot: list[dict[str, Any]],
    keypoint_catalog: list[dict[str, str]],
    query_template_catalog: list[dict[str, Any]],
    prior_runs: list[dict[str, Any]],
    reusable_facts: list[dict[str, Any]],
    reusable_evidence: list[dict[str, Any]],
    memory_context_md: str = "",
) -> list[dict[str, str]]:
    """Build messages for the section agent's plan phase — decide next evidence action.

    Supports action types: sql, template, keypoint, facts, write. Includes
    error-recovery logic to switch to keypoint after repeated SQL failures."""

    schema_guidance = _build_schema_guidance("evtx_events")

    EXAMPLE_SECTION_PLAN = '''
<EXAMPLE verdict="section_plan">
Input: block_heading='Logon Summary', template_body='## Logon Summary\\nList all logons.', reusable_facts empty, query_template_catalog has logon templates.
Output: {"action": "sql", "purpose": "Find all logon events", "sql": "SELECT evidence_id, computer, user_name, src_ip, logon_type, timestamp FROM evtx_events WHERE event_id IN (4624, 4625)"}
</EXAMPLE>
'''
    EXAMPLE_SECTION_PLAN_TEMPLATE = '''
<EXAMPLE verdict="section_plan_template">
Input: block_heading='Service Creation', template_body='## Service Creation\\nFind malicious services.', template_id available, params extractable.
Output: {"action": "template", "template_id": "service-creation", "params": {"computer": "HOST-A"}}
</EXAMPLE>
'''

    schema_notes = _load_schema_notes()
    schema_notes_block = f"<SCHEMA_NOTES>\n{schema_notes}\n</SCHEMA_NOTES>\n" if schema_notes else ""

    system = (
        f"{_dfir_playbook('section_agent_plan')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR section-planning agent. Decide next evidence-gathering action for report block.</TASK>\n"
        "<INPUT_SCHEMA>section_key, block_heading, template_block, structured_memory_context, findings_snapshot, keypoint_catalog, query_template_catalog, prior_runs</INPUT_SCHEMA>\n"
        f"{schema_notes_block}"
        "<TIME_RULES>\nIMPORTANT: The case data may be from a DIFFERENT YEAR than the current date. "
        "DO NOT use datetime('now') or CURRENT_TIMESTAMP in SQL queries — these refer to the current system time, not the case time. "
        "If a time filter is needed, use a broad time range that covers the case data window.\n</TIME_RULES>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "action": "sql|template|keypoint|facts|write",\n'
        '  "sql": "SELECT ...", '
        '  "template_id": "template-name", '
        '  "params": {"key": "value"},\n'
        '  "enough_to_write": true|false\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts_first: Reuse reusable_section_facts if they already answer the block question.\n"
        "keypoint_preferred: Use keypoint when it matches the block topic.\n"
        "template_preferred: Use template_id+params instead of raw sql.\n"
        "error_recovery: If the prior runs show two consecutive zero-row OR query_error results, the next action must be keypoint (not sql/template). "
        "Immediately after a query_error, do NOT retry SQL — switch to keypoint or template action.\n"
        "stop_early: Set action=write when enough evidence exists.\n"
        "</RULES>\n"
        f"{build_investigation_framework()}"
        f"{schema_guidance}"
        f"{EXAMPLE_SECTION_PLAN}{EXAMPLE_SECTION_PLAN_TEMPLATE}"
        "Output JSON only. "
        f"{_lang_instruction()} "
    )
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief, section_key)}\n\n"
        f"previous_sections: {_truncate_context_sections(context_sections)}\n\n"
        f"current_section_outline: {_format_outline(current_section_outline or [])}\n\n"
        f"findings_snapshot: {findings_snapshot[:10]}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"keypoint_catalog: {keypoint_catalog}\n\n"
        f"query_template_catalog: {query_template_catalog}\n\n"
        f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_section_agent_check_messages(
    *,
    section_key: str,
    section_title: str,
    block_heading: str,
    template_body: str,
    collected_results: list[dict[str, Any]],
    latest_result: dict[str, Any],
    prior_runs: list[dict[str, Any]],
    reusable_facts: list[dict[str, Any]],
    reusable_evidence: list[dict[str, Any]],
    memory_context_md: str = "",
) -> list[dict[str, str]]:
    """Build messages for the section agent's check phase — verify evidence sufficiency.

    Injects contradiction-history context and status taxonomy
    (answered/partial/not_found/not_searched/insufficient_evidence/wrong_query)."""

    contradicted_history = [run for run in prior_runs if run.get("verdict") in {"block_contradicted", "refuted"}]
    EXAMPLE_SECTION_CHECK = '''
<EXAMPLE verdict="section_check">
Input: collected_results has 3 rows with process_name='powershell.exe', template_body='## Suspicious Processes\\nList suspicious processes.'.
Output: {"verdict": "block_supported", "status": "answered", "rationale": "Evidence shows powershell.exe execution. Block can be written.", "fact_updates": []}
</EXAMPLE>
'''
    EXAMPLE_SECTION_CHECK_REFUTED = '''
<EXAMPLE verdict="section_check_contradicted">
Input: collected_results empty, template_body='## Malicious Services\\nList malicious services.'. prior runs show queries returned nothing.
Output: {"verdict": "block_contradicted", "status": "not_found", "rationale": "No service-related evidence found in collected results.", "missing_questions": ["Query for event_id 4697/7045 returned 0 rows earlier"]}
</EXAMPLE>
'''
    system = (
        f"{_dfir_playbook('section_agent_check')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a DFIR section-check agent. Judge if collected evidence suffices to write the report block.</TASK>\n"
        "<INPUT_SCHEMA>collected_results, latest_result, reusable_section_facts, reusable_section_evidence, structured_memory_context, template_block</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "block_supported|block_needs_more|block_contradicted",\n'
        '  "status": "answered|partial|not_found|not_searched|insufficient_evidence|wrong_query",\n'
        '  "rationale": "explanation string",\n'
        '  "missing_questions": [],\n'
        '  "fact_updates": [{"fact_type": "string", "fact_key": "string", "fact_value": "any", "confidence": 0.9}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "block_supported: Evidence answers the block question; ready to write.\n"
        "block_needs_more: More evidence needed; another query may help.\n"
        "block_contradicted: Evidence contradicts the template claim; explain contradiction.\n"
        "status rules: answered when evidence supports the block, partial when some evidence exists but not enough, not_found only after an appropriate search has been run and returned zero rows repeatedly, not_searched when the matching query/keypoint was never executed, wrong_query when the search hit the wrong artifact family, insufficient_evidence for other unresolved cases.\n"
        "Never use not_found unless the relevant search has actually run.\n"
        "</RULES>\n"
    )
    if contradicted_history:
        system += "PREVIOUSLY CONTRADICTED ATTEMPTS ARE SHOWN ABOVE - avoid the same contradiction. "
    system += f"{EXAMPLE_SECTION_CHECK}{EXAMPLE_SECTION_CHECK_REFUTED}Output JSON only. {_lang_instruction()} "
    user = (
        f"section_key: {section_key}\n"
        f"section_title: {section_title}\n"
        f"block_heading: {block_heading}\n\n"
        f"template_block:\n{template_body}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"latest_result: {latest_result}\n\n"
        f"collected_results: {collected_results}\n\n"
    )
    if contradicted_history:
        user += f"contradicted_attempts_previous_iterations: {contradicted_history}\n\n"
    user += f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_section_outline_messages(
    template_body: str,
    relevant_evidence: list[dict],
    time_range: dict,
    section_meta: dict,
) -> list[dict[str, str]]:
    """role: section_outliner.
    Goal: assign each evidence item to ONE paragraph; produce outline JSON.
    """
    system = (
        f"{_dfir_playbook('report_section')}\n"
        f"{_time_range_guidance()}"
        "<TASK>You are a section_outliner. Assign evidence items to template paragraphs. Do NOT write narrative text.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"template_body: {template_body}\n"
        f"time_range: {time_range}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "outline": [{"heading": "str", "key_points": ["str"], "evidence_ids": ["str"]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    evidence_summary = "\n".join(
        f"- {e.get('evidence_id', '?')}: {e.get('summary', str(e)[:100])}"
        for e in (relevant_evidence or [])
    )
    user = (
        f"section_meta: {json.dumps(section_meta, ensure_ascii=False)}\n"
        f"available_evidence:\n{evidence_summary or 'No evidence available.'}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_paragraph_narrate_messages(
    heading: str,
    key_points: list[str],
    evidence_rows: list[dict],
    template_body: str,
    language: str = "en",
) -> list[dict[str, str]]:
    """role: section_narrator.
    Goal: write ONE markdown paragraph for the given heading using the evidence.
    NO access to other sections, NO full report_brief, NO findings list.
    """
    system = (
        "<TASK>You are a section_narrator. Write one markdown paragraph for the given heading using the supplied evidence. "
        "Cite evidence_ids inline. Keep the paragraph factual and concise.</TASK>\n"
        f"Language: {language}\n"
        "<OUTPUT_SCHEMA>Return a single markdown paragraph string.</OUTPUT_SCHEMA>"
    )
    user = (
        f"Heading: {heading}\n"
        f"Key points: {json.dumps(key_points, ensure_ascii=False)}\n"
        f"Template body context: {template_body[:500]}\n"
        f"Evidence rows: {json.dumps(evidence_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_gap_identifier_messages(
    observed_keypoints: list[dict],
    uncovered_keypoints: list[dict],
    active_hypotheses_slim: list[dict],
) -> list[dict[str, str]]:
    """role: gap_identifier.
    Goal: identify which uncovered_keypoints lack active hypothesis coverage.
    """
    system = (
        "<TASK>You are a gap_identifier. Identify which uncovered keypoints lack active hypothesis coverage.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "gap_areas": [{"keypoint_id": "str", "why_uncovered": "str", "required_entities": ["str"]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"observed_keypoints: {json.dumps(observed_keypoints[:10], ensure_ascii=False)}\n"
        f"uncovered_keypoints: {json.dumps(uncovered_keypoints[:10], ensure_ascii=False)}\n"
        f"active_hypotheses: {json.dumps(active_hypotheses_slim, ensure_ascii=False)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_hypothesis_drafter_messages(
    gap_area: dict,
    available_rules: list[dict],
) -> list[dict[str, str]]:
    """role: hypothesis_drafter.
    Goal: draft ONE hypothesis targeting the given gap_area.
    """
    system = (
        "<TASK>You are a hypothesis_drafter. Draft ONE hypothesis targeting the given gap_area.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "hypothesis": {"description": "str", "required_entities": ["str"], "source_rule_ids": ["str"], "confirm_when": "str"}\n'
        "}\n"
        "</OUTPUT_SCHEMA>"
    )
    user = (
        f"gap_area: {json.dumps(gap_area, ensure_ascii=False)}\n"
        f"available_rules: {json.dumps(available_rules[:5], ensure_ascii=False)}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
