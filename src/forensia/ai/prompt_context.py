"""Shared prompt-context helpers: token budgets, slimming, schema cards."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from forensia.ai.sql_schema import (
    _build_live_schema_guidance,
)
from forensia.config import get_llm_settings
from forensia.knowledge import (
    load_event_id_hints,
    load_schema_hints,
)

if TYPE_CHECKING:
    from forensia.db.database import CaseDB


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
    trim user message content progressively by descending size.
    """
    total_est = sum(_estimate_message_tokens(m.get("content", "")) for m in messages)
    if total_est <= max_total_tokens:
        return messages
    trimmed = list(messages)
    non_system_indices = [i for i, m in enumerate(trimmed) if m.get("role") != "system"]
    non_system_indices.sort(
        key=lambda i: _estimate_message_tokens(trimmed[i].get("content", "")),
        reverse=True,
    )
    for idx in non_system_indices:
        content = trimmed[idx].get("content", "")
        if not content:
            continue
        length = len(content)
        head_len = int(length * 0.6)
        tail_start = int(length * 0.8)
        head = content[:head_len]
        tail = content[tail_start:]
        dedup = (
            head + "\n...[content trimmed for budget; see full trace in db]...\n" + tail
        )
        trimmed[idx]["content"] = dedup
        total_est = sum(_estimate_message_tokens(m.get("content", "")) for m in trimmed)
        if total_est <= max_total_tokens:
            break
    return trimmed


def _assemble_messages_with_budget(
    builder_func: Callable[
        ..., list[dict[str, str]] | tuple[list[dict[str, str]], dict]
    ],
    *args,
    max_tokens: int = 28000,
    **kwargs,
) -> list[dict[str, str]]:
    """Build messages via builder, then trim if budget exceeded.

    Preserves system prompt (playbook) while trimming user/dynamic content.
    Usage: messages = _assemble_messages_with_budget(build_broad_plan_messages, ..., max_tokens=28000)
    """
    result = builder_func(*args, **kwargs)
    if isinstance(result, tuple):
        messages = result[0]
    else:
        messages = result
    return _trim_dynamic_content(messages, max_total_tokens=max_tokens)


def _time_range_guidance(time_range: dict[str, str] | None = None) -> str:
    """Return time-range constraint guidance if the case has one, otherwise empty string."""
    if time_range and time_range.get("earliest") and time_range.get("latest"):
        return (
            f"\n## Case Time Range\n"
            f"Earliest event: {time_range['earliest']}\n"
            f"Latest event: {time_range['latest']}\n"
            "IMPORTANT: Do NOT use datetime('now') or CURRENT_TIMESTAMP — they refer to the current system time, not the case time. "
            "All WHERE clauses on timestamp columns must use values within this range.\n"
        )
    return ""


def _case_profile_guidance(profile_str: str | None = None) -> str:
    """Return case evidence-availability profile guidance as an XML block, or empty string."""
    if not profile_str:
        return ""
    return (
        f"<CASE_EVIDENCE_PROFILE>\n"
        f"{profile_str}\n"
        f"</CASE_EVIDENCE_PROFILE>\n"
        f"<RULES>\n"
        f"confirm_when.co_observed_event_ids MUST be chosen from available_event_ids. "
        f"If the behavior you want to test has no available event source, design the hypothesis around mft_entries / mft_timeline / prefetch_executions instead.\n"
        f"Prefer hypotheses that name concrete observed entities (users, hosts, executables, file paths) from the case profile over generic patterns.\n"
        f"</RULES>"
    )


_load_schema_hints = load_schema_hints


def _enforce_system_budget(system_str: str, budget_chars: int = 24000) -> str:
    """Trim system message to fit budget by removing lower-priority sections.

    Applies after the playbook is already budget-constrained; drops additional
    content (schema cards, cookbook, framework) that was appended after the
    playbook. Uses section headers as markers for deterministic removal in
    priority order (last = first to drop).
    """
    if len(system_str) <= budget_chars:
        return system_str

    # Sections appended after the playbook, in priority order (last = first to drop)
    # Priority: schema > fp_guidance > event_ids > logon_types (highest = last to drop)
    sections_to_drop = [
        "<INVESTIGATION_FRAMEWORK>",
        "<SCHEMA_GUIDANCE>",
        "## IOC Catalog",
        "## Artifact-to-Application",
        "## Application Catalog",
        "## Logon Type Reference",
        "## Priority Investigation Order",
        "## Event ID Reference",
        "## False-Positive",
        "## JSON Field Extractors",
        "## Schema Notes",
    ]

    text = system_str
    for marker in sections_to_drop:
        if len(text) <= budget_chars:
            break
        # Remove section from marker to next ## or end
        pattern = re.compile(rf"\n{re.escape(marker)}.*?(?=\n##|\Z)", re.DOTALL)
        text = pattern.sub("", text)
        text = re.sub(r"\n{3,}", "\n\n", text.strip())

    return text


_load_event_id_hints = load_event_id_hints


def _lang_instruction() -> str:
    output = str(get_llm_settings()["output_language"])
    return (
        f"Write every natural-language sentence in {output}. "
        "Keep evidence IDs, file paths, SQL, JSON keys, and enum values (verdict, status, entity_type) unchanged."
    )


_RULE_INSTANCE_SUFFIX = re.compile(r"-(\d{4,})$")


def _truncate_context_sections(
    context_sections: dict[str, str], max_chars: int = 1500
) -> dict[str, str]:
    """Trim each section body to max_chars to fit within LLM token budget."""
    trimmed: dict[str, str] = {}
    for section_key, body in context_sections.items():
        text = str(body or "").strip()
        if not text:
            continue
        trimmed[str(section_key)] = text[:max_chars]
    return trimmed


def _slim_brief_items(
    items: Any, fields: tuple[str, ...], limit: int
) -> list[dict[str, Any]]:
    """Keep report_brief lists useful for section synthesis without flooding prompts."""
    if not isinstance(items, list):
        return []
    slim: list[dict[str, Any]] = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        projected = {
            field: item.get(field)
            for field in fields
            if item.get(field) not in (None, "", [])
        }
        if projected:
            slim.append(projected)
    return slim


def _slim_report_brief_for_section(report_brief: dict, section_key: str) -> dict:
    """Return case-level report context scoped to the current section."""
    if not report_brief:
        return {}
    if section_key == "1_overview":
        return report_brief
    family = str(section_key or "").split("_", 1)[0]
    brief = {
        "time_range": report_brief.get("time_range"),
        "source_timezone": report_brief.get("source_timezone"),
        "investigation_objective": report_brief.get("investigation_objective"),
    }
    finding_fields = (
        "finding_id",
        "title",
        "summary",
        "severity",
        "confidence",
        "evidence_ids",
    )
    hypothesis_fields = (
        "hypothesis_id",
        "description",
        "status",
        "verdict",
        "summary",
        "required_entities",
        "confirm_when",
    )
    if family in {"2", "3", "5"}:
        brief["top_findings"] = _slim_brief_items(
            report_brief.get("top_findings"), finding_fields, 8
        )
        brief["confirmed_hypotheses"] = _slim_brief_items(
            report_brief.get("confirmed_hypotheses"), hypothesis_fields, 6
        )
        brief["refuted_hypotheses"] = _slim_brief_items(
            report_brief.get("refuted_hypotheses"), hypothesis_fields, 4
        )
    if family in {"4", "5"}:
        brief["active_hypotheses"] = _slim_brief_items(
            report_brief.get("active_hypotheses"), hypothesis_fields, 8
        )
    return brief


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
These are reference SQL snippets to copy and adapt. They are NOT templates — do not put their headings into the `template_id` field. To use a real template, pick a `template_id` value from `template_catalog`.

-- Enumerate occurrences of one or more event IDs --
SELECT event_id, timestamp, computer, user_name, target_user, raw_json
FROM evtx_events
WHERE event_id IN (4624, 4625)
ORDER BY timestamp
LIMIT 200;

-- Filter by time window --
SELECT event_id, timestamp, computer
FROM evtx_events
WHERE event_id = 7045
  AND timestamp BETWEEN '2024-05-14 00:00:00' AND '2024-05-17 23:59:59'
ORDER BY timestamp;

-- Per-user logon summary --
SELECT user_name, logon_type, COUNT(*) AS n, MIN(timestamp) AS first, MAX(timestamp) AS last
FROM evtx_events
WHERE event_id = 4624
GROUP BY 1, 2
ORDER BY n DESC;

-- Fall back to raw_json when a column is NULL (use json_extract_string for VARCHAR-typed cols) --
SELECT timestamp, COALESCE(user_name, json_extract_string(raw_json, '$.TargetUserName')) AS user
FROM evtx_events
WHERE event_id = 4720
ORDER BY timestamp;

-- Find file activity by path pattern (MFT) --
SELECT file_path, file_name, si_modified, is_deleted
FROM mft_entries
WHERE LOWER(file_path) LIKE '%/desktop/%'
  AND extension IN ('docx', 'xlsx', 'pptx', 'doc', 'ppt', 'xls')
ORDER BY si_modified DESC
LIMIT 100;

-- Recent application executions (Prefetch) --
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


def _build_schema_guidance(
    table_name: str = "evtx_events", db: CaseDB | None = None
) -> str:
    schema_hints = _load_schema_hints()
    if not schema_hints:
        return ""
    primary = schema_hints.get(table_name, {})
    if not primary:
        return ""
    db_tables = {
        name: h
        for name, h in schema_hints.items()
        if h.get("columns") or h.get("core_columns")
    }
    extractors = primary.get("json_field_extractors", {})
    blocks = ["<SCHEMA_CARDS>"]
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
    live = _build_live_schema_guidance(db)
    if live:
        blocks.append(live)
    return "\n".join(blocks) + "\n" + _SQL_COOKBOOK


def _collect_event_ids(evidence_results: list[dict[str, Any]]) -> list[int]:
    event_ids: list[int] = []
    seen: set[int] = set()
    for result in evidence_results:
        for row in (
            (result.get("sample_rows") or [])
            + (result.get("head_rows") or [])
            + (result.get("tail_rows") or [])
        ):
            if not isinstance(row, dict):
                continue
            value = row.get("event_id")
            try:
                event_id = int(value)
            except TypeError, ValueError:
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


def _rows_to_markdown_table(rows: list[dict[str, Any]], max_rows: int = 30) -> str:
    if not rows:
        return ""
    keys = list(rows[0].keys())
    header = "| " + " | ".join(keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    data_lines = []
    for row in rows[:max_rows]:
        cells = [
            str(row.get(k, "")).replace("|", "\\|").replace("\n", " ") for k in keys
        ]
        data_lines.append("| " + " | ".join(cells) + " |")
    return "\n".join([header, separator, *data_lines])


def _format_evidence_row(e: dict[str, Any]) -> str:
    evid = e.get("evidence_id") or e.get("id") or "?"
    if "summary" in e:
        return f"- {evid}: {e['summary'][:300]}"
    keys = [
        k
        for k in (
            "event_id",
            "timestamp",
            "computer",
            "target_user",
            "src_ip",
            "process_name",
            "file_path",
            "file_name",
        )
        if k in e
    ]
    parts = ", ".join(f"{k}={e[k]}" for k in keys[:8])
    return f"- {evid}: {parts}"

