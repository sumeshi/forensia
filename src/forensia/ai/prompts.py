from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from forensia.ai.schemas import (
    FINDING_EXTRACTOR_SCHEMA,
    MEMORY_UPDATER_SCHEMA,
    PARAGRAPH_NARRATE_SCHEMA,
    SECTION_AGENT_CHECK_SCHEMA,
    SECTION_AGENT_PLAN_SCHEMA,
    SECTION_OUTLINE_SCHEMA,
    SQL_SELF_CHECK_SCHEMA,
    VERDICT_REVIEW_SCHEMA,
    benchmark_classify_schema,
    gap_identifier_schema,
    hypothesis_drafter_schema,
    structured_classify_schema,
)
from forensia.ai.sql_schema import (
    _build_live_schema_guidance,
    _load_app_catalog,
    build_investigation_framework,
)
from forensia.config import get_llm_settings
from forensia.core.session import Hypothesis
from forensia.knowledge import (
    load_benign_context_rules,
    load_dfir_yamls,
    load_event_id_hints,
    load_question_routing_raw,
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


@dataclass(frozen=True, slots=True)
class RuleContext:
    rule_id: str
    correlate_event_ids: list[int]
    confirm_when: dict[str, Any]
    refute_when: dict[str, Any]


@lru_cache(maxsize=1)
def _get_cached_rules() -> list[Any]:
    """Load and cache all rules at module level to avoid repeated file I/O."""
    from pathlib import Path

    from forensia.rules.loader import load_rules_from_dir

    rules_path = Path(__file__).parent.parent / "rulepacks"
    return load_rules_from_dir(rules_path)


def resolve_rule_context(hypothesis: Hypothesis | None) -> RuleContext | None:
    """Resolve rule context for a hypothesis by looking up source rule declarations.

    If the hypothesis was generated from a rule finding, return the rule's
    correlate_with, confirm_when, and refute_when declarations.
    Merges multiple source_rule_ids into a single RuleContext.
    """
    if hypothesis is None or not hasattr(hypothesis, "source_rule_ids"):
        return None
    source_rule_ids = getattr(hypothesis, "source_rule_ids", [])
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


_load_schema_hints = load_schema_hints


@lru_cache(maxsize=1)
def _load_schema_notes() -> str:
    """Load schema notes from evtx_events.yaml and prefetch_executions.yaml for section agent."""
    from pathlib import Path

    import yaml

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


_load_dfir_yamls = load_dfir_yamls


def _render_event_narrative(events_data: dict) -> str:
    parts: list[str] = []
    for eid_str, info in sorted(
        events_data.items(),
        key=lambda x: int(x[0]) if isinstance(x[0], str) and x[0].isdigit() else 0,
    ):
        if isinstance(info, dict):
            title = info.get("title", "")
            allowed = info.get("allowed_claims", [])
            disallowed = info.get("disallowed_without_extra", [])
            required = info.get("required_fields", [])
            keywords = info.get("keywords_for_string_search", [])
            channels = info.get("channels", [])
            line_parts = [f"Event {eid_str} ({title})"]
            if channels:
                line_parts.append(
                    f" ONLY meaningful on channel(s): {', '.join(str(c) for c in channels)} — the same ID on other channels is unrelated"
                )
            if required:
                line_parts.append(f" always query: {', '.join(required)}")
            if allowed:
                line_parts.append(f" you may claim: {'; '.join(allowed)}")
            if disallowed:
                line_parts.append(
                    f" DO NOT claim without extra evidence: {'; '.join(disallowed)}"
                )
            if keywords:
                line_parts.append(f" string-search keywords: {', '.join(keywords)}")
            parts.append(" - " + ". ".join(line_parts) + ".")
    return "\n".join(parts)


def _render_logon_narrative(logon_types_data: dict) -> str:
    parts: list[str] = []
    for lt, info in sorted(
        logon_types_data.items(),
        key=lambda x: x[1].get("priority", 99) if isinstance(x[1], dict) else 99,
    ):
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
            parts.append(
                f" - If {field.lower()} column is NULL/empty, use {expr} to extract from raw_json"
            )
    return "\n".join(parts)


def _render_app_catalog_narrative(app_mappings: dict) -> str:
    parts: list[str] = []
    if isinstance(app_mappings, dict):
        for exe, info in app_mappings.items():
            if isinstance(info, dict):
                parts.append(
                    f" - {exe}: {info.get('category', '?')} — {info.get('description', '')}"
                )
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


def _render_ioc_catalog_narrative(ioc_data: dict) -> str:
    parts: list[str] = []
    if not isinstance(ioc_data, dict):
        return ""

    tools = ioc_data.get("antiforensic_tools") or []
    if isinstance(tools, list) and tools:
        parts.append("## Antiforensic Tools")
        for item in tools:
            if not isinstance(item, dict):
                continue
            names = ", ".join(
                str(v) for v in item.get("exe_patterns") or [] if str(v).strip()
            )
            prefetch = ", ".join(
                str(v) for v in item.get("prefetch_names") or [] if str(v).strip()
            )
            line = f" - {item.get('name', '?')}: exe_patterns=[{names}]"
            if prefetch:
                line += f"; prefetch=[{prefetch}]"
            parts.append(line)

    for section, label, key in (
        ("cloud_sync_artifacts", "Cloud Sync Artifacts", "service"),
        ("email_artifacts", "Email Artifacts", "client"),
        ("browser_artifacts", "Browser Artifacts", "name"),
        ("lolbins", "LOLBins", "name"),
    ):
        entries = ioc_data.get(section) or []
        if not isinstance(entries, list) or not entries:
            continue
        parts.append(f"## {label}")
        for item in entries:
            if not isinstance(item, dict):
                continue
            patterns = item.get("exe_patterns") or []
            suspicious_args = item.get("suspicious_args") or []
            details = []
            if patterns:
                details.append("exe=" + ", ".join(str(v) for v in patterns))
            if suspicious_args:
                details.append("args=" + ", ".join(str(v) for v in suspicious_args))
            parts.append(f" - {item.get(key, '?')}: {'; '.join(details)}")
    return "\n".join(parts)


_PLAYBOOK_SECTION_DROP_ORDER = [
    "ioc",
    "app",
    "artifact",
    "extractor",
    "fp",
    "logon",
    "schema",
    "events",
]


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
    sections_to_drop = [
        "<INVESTIGATION_FRAMEWORK>",
        "<SCHEMA_GUIDANCE>",
        "## IOC Catalog",
        "## Artifact-to-Application",
        "## JSON Field Extractors",
        "## Application Catalog",
        "## False-Positive",
        "## Schema Notes",
        "## Logon Type Reference",
        "## Event ID Reference",
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


def _dfir_playbook(
    phase: str,
    *,
    event_ids: set[int] | None = None,
    tables: set[str] | None = None,
) -> str:
    """Generate DFIR investigator playbook narrative for the given phase.

    Phase is one of: 'broad_plan', 'hypothesis_plan', 'check', 'report_section',
    'section_agent_plan', 'section_agent_check'.

    Parameters
    ----------
    event_ids : optional set of ints
        If provided, only those event IDs (union of case-present + hypothesis-referenced)
        are rendered in the Event ID Reference section, capped at 40.
        When None, all known event IDs are included.
    tables : optional set of table names
        If provided, the app/artifact/IOC sections are included only if a relevant
        table is present in the case. None means include all (current behavior).

    Returns a narrative string optimized for weak LLMs.
    """
    from pathlib import Path

    from forensia.config import get_system_prompt_budget_chars

    yamls = _load_dfir_yamls()

    events_data = (
        yamls["event_ids"].get("events", {})
        if isinstance(yamls["event_ids"], dict)
        else {}
    )
    logon_types_data = (
        yamls["logon_types"].get("types", {})
        if isinstance(yamls["logon_types"], dict)
        else {}
    )
    priority_events = (
        yamls["logon_types"].get("priority_events", [])
        if isinstance(yamls["logon_types"], dict)
        else []
    )
    schema_notes = (
        yamls["evtx_events"].get("notes", {})
        if isinstance(yamls["evtx_events"], dict)
        else {}
    )
    fp_guidance = (
        yamls["fp_rules"].get("reduction_guidance", {})
        if isinstance(yamls["fp_rules"], dict)
        else {}
    )
    extractors = (
        yamls["evtx_events"].get("json_field_extractors", {})
        if isinstance(yamls["evtx_events"], dict)
        else {}
    )
    app_mappings = (
        yamls["app_catalog"].get("mappings", {})
        if isinstance(yamls["app_catalog"], dict)
        else {}
    )
    artifact_data = (
        yamls["artifact_inference"]
        if isinstance(yamls["artifact_inference"], dict)
        else {}
    )
    ioc_data = (
        yamls["dfir_ioc_catalog"] if isinstance(yamls["dfir_ioc_catalog"], dict) else {}
    )

    # -- Event-ID narrative filtering --
    if event_ids is not None and isinstance(events_data, dict):

        def _eid_sort_key(k: Any) -> int:
            if isinstance(k, str) and k.isdigit():
                return int(k)
            if isinstance(k, (int, float)):
                return int(k)
            return 0

        filtered: dict[str | int, Any] = {}
        for eid_key in sorted(events_data, key=_eid_sort_key):
            eid_val = int(eid_key) if isinstance(eid_key, str) else int(eid_key)
            if eid_val in event_ids:
                filtered[eid_key] = events_data[eid_key]
                if len(filtered) >= 40:
                    break
        events_data = filtered

    event_narrative = _render_event_narrative(events_data)
    logon_narrative = _render_logon_narrative(logon_types_data)
    priority_narrative = _render_priority_narrative(priority_events)
    schema_narrative = _render_schema_narrative(schema_notes)
    fp_narrative = _render_fp_narrative(fp_guidance)
    extractor_narrative = _render_extractor_narrative(extractors)
    app_narrative = _render_app_catalog_narrative(app_mappings)
    artifact_narrative = _render_artifact_inference_narrative(artifact_data)
    ioc_narrative = _render_ioc_catalog_narrative(ioc_data)

    # Phase-aware sections. Planning phases (broad_plan / hypothesis_plan) don't
    # need evidence-interpretation references; cutting them saves ~25% of the
    # system prompt for those calls.
    planning_phases = {"broad_plan", "hypothesis_plan"}
    interpretation_phases = {"check", "report_section", "section_agent_check"}
    include_fp = phase in interpretation_phases
    include_app_catalog = phase not in planning_phases
    include_artifact_inference = phase in interpretation_phases
    include_ioc_catalog = phase in (interpretation_phases | {"section_agent_plan"})

    # -- Table-scoped gating --
    has_mft_or_prefetch = tables is None or bool(
        tables
        & {"mft_entries", "mft_timeline", "prefetch_executions", "prefetch_timeline"}
    )
    has_evtx = tables is None or "evtx_events" in tables
    if tables is not None:
        include_app_catalog = include_app_catalog and has_evtx
        include_artifact_inference = include_artifact_inference and has_mft_or_prefetch
        include_ioc_catalog = include_ioc_catalog and has_mft_or_prefetch

    # Build section entries as (key, rendered_text) for budget enforcement
    section_entries: list[tuple[str, str]] = [
        (
            "preamble",
            "<DFIR_PLAYBOOK>\nYou are a DFIR analyst. Follow these investigation principles.",
        ),
        (
            "events",
            f"## Event ID Reference\n{event_narrative or 'No event ID reference available.'}",
        ),
        (
            "logon",
            f"## Logon Type Reference\n{logon_narrative or 'No logon type reference available.'}",
        ),
        (
            "priority",
            f"## Priority Investigation Order\n{priority_narrative or 'No priority order specified.'}",
        ),
        (
            "schema",
            f"## Schema Notes & Column Guidance\n{schema_narrative or 'No schema notes available.'}",
        ),
        (
            "extractor",
            f"## JSON Field Extractors (when columns are NULL)\n{extractor_narrative or 'No extractors available.'}",
        ),
    ]
    if include_fp:
        section_entries.append(
            (
                "fp",
                f"## False-Positive Reduction Guidance\n{fp_narrative or 'No FP reduction guidance.'}",
            )
        )
    if include_app_catalog:
        section_entries.append(
            (
                "app",
                f"## Application Catalog (process categorization)\n{app_narrative or 'No app catalog available.'}",
            )
        )
    if include_artifact_inference:
        section_entries.append(
            (
                "artifact",
                f"## Artifact-to-Application Inference\n{artifact_narrative or 'No artifact inference data available.'}",
            )
        )
    if include_ioc_catalog:
        section_entries.append(
            ("ioc", f"## IOC Catalog\n{ioc_narrative or 'No IOC catalog available.'}")
        )

    base_playbook = "\n".join(text for _, text in section_entries) + "\n"

    # -- Budget enforcement --
    budget = get_system_prompt_budget_chars()
    dropped: list[str] = []

    # Step 1: if the Event ID Reference alone busts the budget (no case profile
    # supplied, so no event-id filtering happened), shrink it to the events the
    # declarative priority list marks as most important instead of letting the
    # serial drop loop discard every guidance section just to remove this one.
    if (
        len(base_playbook) > budget
        and event_ids is None
        and isinstance(events_data, dict)
    ):
        priority_ids: list[int] = []
        for entry in priority_events or []:
            for eid in entry.get("event_ids", []) if isinstance(entry, dict) else []:
                try:
                    eid_int = int(eid)
                except TypeError, ValueError:
                    continue
                if eid_int not in priority_ids:
                    priority_ids.append(eid_int)
        if priority_ids:
            trimmed = {
                key: value
                for key, value in events_data.items()
                if (int(key) if isinstance(key, str) and key.isdigit() else key)
                in priority_ids
            }
            if trimmed and len(trimmed) < len(events_data):
                trimmed_narrative = _render_event_narrative(trimmed)
                section_entries = [
                    (
                        k,
                        f"## Event ID Reference (priority events only; full list omitted for budget)\n{trimmed_narrative}",
                    )
                    if k == "events"
                    else (k, v)
                    for k, v in section_entries
                ]
                base_playbook = "\n".join(text for _, text in section_entries) + "\n"
                dropped.append("events:truncated-to-priority")

    # Step 2: drop whole sections in priority order until under budget.
    if len(base_playbook) > budget:
        for key in _PLAYBOOK_SECTION_DROP_ORDER:
            if len(base_playbook) <= budget:
                break
            section_entries = [(k, v) for k, v in section_entries if k != key]
            base_playbook = "\n".join(text for _, text in section_entries) + "\n"
            dropped.append(key)
        if dropped:
            logging.info(
                "[_dfir_playbook] phase=%s budget=%d exceeded (%d chars), dropped: %s",
                phase,
                budget,
                len(base_playbook),
                dropped,
            )

    # -- Phase-specific playbook loaded from external MD file --
    playbook_dir = Path(__file__).parent.parent / "rulepacks" / "_schema" / "playbook"
    phase_file = playbook_dir / f"{phase}.md"
    phase_narrative = ""
    if phase_file.exists():
        try:
            phase_narrative = phase_file.read_text(encoding="utf-8")
        except Exception:
            pass
    phase_narrative = re.sub(
        r"\n?<!-- AUTO-FROM: (?:event_ids|app_catalog)\.yaml -->.*?<!-- END-AUTO -->\n?",
        "\n",
        phase_narrative,
        flags=re.DOTALL,
    )
    result = base_playbook + phase_narrative

    # -- Telemetry --
    section_sizes = {k: len(v) for k, v in section_entries}
    logging.debug(
        "[_dfir_playbook] phase=%s total=%d chars, sections=%s, dropped=%s",
        phase,
        len(result),
        section_sizes,
        dropped,
    )
    return result


_load_event_id_hints = load_event_id_hints


_load_benign_context_rules = load_benign_context_rules


def _lang_instruction() -> str:
    output = str(get_llm_settings()["output_language"])
    return (
        f"Write every natural-language sentence in {output}. "
        "Keep evidence IDs, file paths, SQL, JSON keys, and enum values (verdict, status, entity_type) unchanged."
    )


def _output_language() -> str:
    return str(get_llm_settings()["output_language"]).lower()


_RULE_INSTANCE_SUFFIX = re.compile(r"-(\d{4,})$")


def _rule_pattern(finding_id: str) -> str:
    """Collapse '...-0001' / '...-0042' suffix to '-*' so per-instance findings group."""
    if not finding_id:
        return ""
    return _RULE_INSTANCE_SUFFIX.sub("-*", finding_id)


def _slim_findings(
    items: list[dict[str, Any]], max_findings: int
) -> list[dict[str, Any]]:
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
    raw = (
        hypothesis.model_dump()
        if hasattr(hypothesis, "model_dump")
        else dict(hypothesis)
    )
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if value is None:
            continue
        if isinstance(value, (list, dict, str)) and len(value) == 0:
            continue
        out[key] = value
    return out


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
  AND timestamp BETWEEN '2015-03-22 00:00:00' AND '2015-03-25 23:59:59'
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


def _slim_history(
    items: list[dict[str, Any]], max_items: int = 10
) -> list[dict[str, Any]]:
    """Project history items to only the fields needed for broad planning context."""
    slimmed: list[dict[str, Any]] = []
    for item in items[:max_items]:
        slimmed.append(
            {
                "query_id": item.get("query_id"),
                "hypothesis_id": item.get("hypothesis_id"),
                "verdict": item.get("verdict"),
                "rationale": item.get("summary"),
            }
        )
    return slimmed


def build_query_intent_messages(
    hypothesis,
    recent_history: list[dict],
    active_hypotheses: list[Hypothesis],
    time_range: dict[str, str] | None = None,
    schema_context: str = "",
    extra_context_md: str = "",
    prior_check_feedback: str = "",
    case_profile: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for the query_intent_planner phase.

    Decides WHAT data to fetch for this hypothesis, not HOW.
    Uses read_more expansion for memory context.
    """
    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if (
        _pb_ids is not None
        and hasattr(hypothesis, "confirm_when")
        and isinstance(hypothesis.confirm_when, dict)
    ):
        extra = hypothesis.confirm_when.get("co_observed_event_ids", [])
        if extra:
            _pb_ids.update(int(e) for e in extra if e is not None)
    system = (
        f"{_dfir_playbook('hypothesis_plan', event_ids=_pb_ids)}\n"
        f"{_time_range_guidance(time_range)}"
        f"{_case_profile_guidance(case_profile)}"
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
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "If EXECUTION_ERROR is present, you MUST change the query — at minimum change the table list, the WHERE clause, or eliminate the failing JOIN. Never repeat the same SQL that caused an execution error.\n"
        "If prior_check_feedback names specific missing event_ids or evidence types, the new SQL MUST include those event_ids or evidence types. Never ignore prior check feedback.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis.description: {hypothesis.description}\n"
        f"hypothesis.required_entities: {getattr(hypothesis, 'required_entities', [])}\n"
        f"active_hypotheses: {[h.model_dump() if hasattr(h, 'model_dump') else dict(h) for h in active_hypotheses]}\n"
        f"extra_context:\n{extra_context_md}\n"
        f"prior_check_feedback:\n{prior_check_feedback or '(no prior checks)'}\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_sql_composer_messages(
    intent: dict,
    table_schema_card: str = "",
    template_catalog: list[dict] | None = None,
    time_range: dict[str, str] | None = None,
    prior_check_feedback: str = "",
) -> list[dict[str, str]]:
    """Build messages for the sql_composer phase.

    Produces a valid DuckDB SELECT statement that satisfies `intent`.
    Idempotent — no read_more cycle needed.
    """
    from forensia.ai.case_profile import get_profile_event_ids

    system = (
        f"{_dfir_playbook('hypothesis_plan', event_ids=get_profile_event_ids())}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a sql_composer. Write a DuckDB SQL query that satisfies the given intent. Output template_id or raw SQL.</TASK>\n"
        "<INPUT_SCHEMA>\n"
        f"intent: {json.dumps(intent, ensure_ascii=False, default=str)}\n"
        f"table_schema: {table_schema_card}\n"
        f"template_catalog: {json.dumps(template_catalog[:10], ensure_ascii=False, default=str)}\n"
        "</INPUT_SCHEMA>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "template_id": "string OR null. MUST be either (a) JSON null, or (b) an exact template_id from template_catalog. NEVER the literal string \\"null\\".",\n'
        '  "sql": "string | null — raw SELECT if no template_id matches. Use SQL_COOKBOOK snippets as reference style.",\n'
        '  "params": {"key": "value"},\n'
        '  "purpose": "string — why this query answers the hypothesis"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Exactly ONE of template_id or sql MUST be non-null. The other MUST be null.\n"
        "template_id MUST be an exact match to a template_catalog entry (use null otherwise).\n"
        "Target dialect is DuckDB. Do NOT use SQLite syntax (datetime('now', ...), strftime via SQLite quirks) or MySQL/Postgres syntax (DATE_SUB, INTERVAL ... MINUTE keyword form, NOW()). "
        "For relative time windows on historical evidence, anchor to a literal TIMESTAMP within the case time range, not the current system clock: "
        "`WHERE ts BETWEEN TIMESTAMP '2024-01-15 10:00:00' AND TIMESTAMP '2024-01-15 10:15:00'`. "
        "For interval arithmetic use `ts + INTERVAL 15 MINUTE` or `ts - INTERVAL '15' MINUTE` (DuckDB form), never `DATE_SUB(...)`.\n"
        "Only `evtx_events` carries `computer` / `user_name` columns. `mft_entries`, `mft_timeline`, `prefetch_executions`, and `prefetch_timeline` are single-host filesystem/prefetch artifacts with NO host column. "
        "Do NOT write `JOIN mft_entries m ON e.computer = m.computer` or any host/user equality JOIN across evtx and mft/prefetch — it fails at bind time. "
        "When the intent calls for 'correlate evtx with mft/prefetch', either (a) issue two separate SELECTs and let the verdict step merge them, or (b) JOIN by `file_path` string match against `process_name` / `command_line` / `message`, optionally narrowed by a timestamp BETWEEN window. Only columns listed under each table's SCHEMA_CARD block exist; never invent columns from the table alias.\n"
        "When raw SQL is used: ensure all COALESCE arguments have the same data type. Use json_extract_string (returns VARCHAR) when COALESCE-ing with a VARCHAR column, never json_extract (returns JSON).\n"
        "Never put a VARCHAR-returning function (json_extract_string) and an INTEGER column in the same COALESCE without explicit CAST. "
        "Use: COALESCE(CAST(json_extract_string(json, '$.x') AS BIGINT), int_col) for integer unification, "
        "or COALESCE(CAST(json_extract_string(json, '$.x') AS VARCHAR), CAST(int_col AS VARCHAR)) for string unification.\n"
        "If EXECUTION_ERROR is present, you MUST change the query — at minimum change the table list, the WHERE clause, or eliminate the failing JOIN. Never repeat the same SQL that caused an execution error.\n"
        "If prior_check_feedback names specific missing event_ids or evidence types, the new SQL MUST include those event_ids or evidence types. Never ignore prior check feedback.\n"
        "</RULES>"
    )
    user = json.dumps(
        {
            "intent": intent,
            "prior_check_feedback": prior_check_feedback or "(no prior checks)",
        },
        ensure_ascii=False,
        default=str,
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_sql_self_check_messages(
    intent: dict[str, Any],
    schema_card: str,
) -> tuple[list[dict[str, str]], dict]:
    system = (
        "<TASK>You are a SQL schema validator. Check whether the intent can be expressed as valid SQL against the given schema.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "target_table_exists": true,\n'
        '  "required_columns_present": ["col1", "col2"],\n'
        '  "missing_columns": [],\n'
        '  "join_keys": [{"left_table": "...", "left_col": "...", "right_table": "...", "right_col": "..."}],\n'
        '  "time_column": "timestamp | si_modified | exec_time | ...",\n'
        '  "ready_to_compose": true,\n'
        '  "blockers": "string — empty if ready_to_compose=true, else what is missing"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Check that all columns referenced in the intent exist in the schema card.\n"
        "If JOIN is needed, verify the join key columns exist in both tables.\n"
        "If ready_to_compose is false, describe what's blocking in the blockers field.\n"
        "</RULES>\n"
    )
    user = (
        f"intent: {json.dumps(intent, ensure_ascii=False, default=str)}\n"
        f"schema_card:\n{schema_card}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SQL_SELF_CHECK_SCHEMA


def build_verdict_review_messages(
    hypothesis,
    planned_query,
    result_summary: dict,
    time_range: dict[str, str] | None = None,
    strictness_note: str = "",
    fallback_info: dict | None = None,
    benign_annotations: dict[int, list[str]] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: verdict_reviewer.
    Goal: classify the SQL result vs hypothesis as confirmed/refuted/inconclusive.
    Output JSON: {verdict, rationale, confidence}
    """
    fallback_notice = ""
    if fallback_info:
        phase = fallback_info.get("phase", "unknown")
        fallback_notice = (
            "\nFALLBACK_NOTICE: the rows below were NOT returned by the planned query; "
            f"they come from a fallback search ({phase}). They may belong to a different "
            "event family. You may NOT answer 'confirmed' for the original hypothesis "
            "from fallback rows; choose 'newlead' if they suggest a different lead, "
            "otherwise 'inconclusive'.\n"
        )

    benign_notes_block = ""
    if benign_annotations:
        benign_rules = _load_benign_context_rules()
        rule_notes = {
            r["id"]: r.get("note", "") for r in benign_rules if isinstance(r, dict)
        }
        benign_lines: list[str] = []
        for row_idx in sorted(benign_annotations.keys())[:3]:
            rule_ids = benign_annotations[row_idx]
            notes = [rule_notes.get(rid, rid) for rid in rule_ids]
            benign_lines.append(f"  Row {row_idx}: {'; '.join(notes)}")
        if benign_lines:
            benign_notes_block = (
                "\nBenign-context notes for relevant evidence rows:\n"
                + "\n".join(benign_lines)
                + "\n"
            )

    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if _pb_ids is not None:
        if hasattr(hypothesis, "confirm_when") and isinstance(
            hypothesis.confirm_when, dict
        ):
            extra = hypothesis.confirm_when.get("co_observed_event_ids", [])
            if extra:
                _pb_ids.update(int(e) for e in extra if e is not None)
        for row in (result_summary or {}).get("sample_rows") or []:
            if not isinstance(row, dict):
                continue
            ev = row.get("event_id")
            if ev is not None:
                try:
                    _pb_ids.add(int(ev))
                except TypeError, ValueError:
                    pass

    system = (
        f"{_dfir_playbook('check', event_ids=_pb_ids)}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a verdict_reviewer. Classify the SQL result against the hypothesis as confirmed, refuted, or inconclusive.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "verdict": "confirmed | refuted | inconclusive",\n'
        '  "rationale": "string — concise reason (< 200 chars)",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "missing_questions": ["specific event_id, table, or evidence type that would resolve the hypothesis (required when verdict=inconclusive, MUST be non-empty in that case)"]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        f"{fallback_notice}"
        "When verdict=inconclusive, missing_questions MUST contain at least 1 specific item naming the missing evidence (e.g. 'event_id 4663', 'mft_entries WHERE file_path LIKE %.docx%', 'browser executable in prefetch_executions'). Do NOT leave it empty.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"query: {planned_query.sql if hasattr(planned_query, 'sql') else planned_query}\n"
        f"result_summary: {json.dumps(result_summary, ensure_ascii=False, default=str)}\n"
        f"{strictness_note}"
        f"{benign_notes_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], VERDICT_REVIEW_SCHEMA


def build_finding_extractor_messages(
    hypothesis,
    result_rows: list[dict],
    verdict: str,
    rationale: str,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: finding_extractor.
    Goal: extract finding entries IFF verdict == confirmed.
    Called only when verdict is confirmed.
    """
    system = (
        "<TASK>You are a finding_extractor. Extract findings from the confirmed query results. Only output findings if the evidence clearly supports a specific security event.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "findings": [{"title": "string", "severity": "low|medium|high|critical", "evidence_ids": ["str"], "claim_type": "observation|interpretation"}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Each finding MUST be labeled claim_type.\n"
        "observation: states only what the rows show (who/what/when/where).\n"
        "interpretation: states what it might mean (attack, staging, exfiltration...).\n"
        "An interpretation MUST reference at least one observation finding in its text.\n"
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
        f"result_rows: {json.dumps(result_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], FINDING_EXTRACTOR_SCHEMA


def build_memory_updater_messages(
    hypothesis,
    verdict: str,
    rationale: str,
    time_range: dict[str, str] | None = None,
    result_summary: dict | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: memory_updater.
    Goal: propose durable memory writes (facts, timeline anchors, entity cards, etc.).
    """
    evidence_block = ""
    if result_summary:
        evidence_block = (
            f"\nevidence_rows: {json.dumps(result_summary.get('sample_rows') or [], default=str, ensure_ascii=False)[:3000]}\n"
            f"observed_evidence_ids: {result_summary.get('evidence_ids')}\n"
        )

    system = (
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a memory_updater. Propose durable memory writes based on the investigation result.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "memory_updates": {\n'
        '    "facts": [{"text": "string", "evidence_ids": ["evtx-...", "mft-..."], "claim_type": "observation|interpretation"}],\n'
        '    "timeline": [{"timestamp": "ISO 8601", "description": "string", "evidence_ids": ["..."]}],\n'
        '    "tasks": [{"text": "string", "kind": "followup | verification | gap"}],\n'
        '    "overview": ["short single-line summary"],\n'
        '    "refuted_hypotheses": [{"hypothesis_id": "H-001", "description": "...", "reason": "..."}],\n'
        '    "resolved_gaps": [{"text": "string", "evidence_ids": ["..."]}],\n'
        '    "entities": [{"entity_type": "user | host | ip | process | service | file | registry | group | machine_account", "name": "string — the entity identifier", "role": "attacker | victim | actor_candidate | observed_user | suspicious_user | newly_created_user | machine_account | unknown", "notes": "1-2 sentences explaining why this entity matters in the case"}]\n'
        "  },\n"
        '  "new_hypotheses": [{"description": "...", "required_entities": ["..."]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Omit any sub-key whose array would be empty — never emit empty arrays. Every fact/timeline/resolved_gap entry MUST cite at least one evidence_id observed in the SQL result; entries without evidence_ids are dropped.\n"
        "Each fact MUST be labeled claim_type.\n"
        "observation: states only what the rows show (who/what/when/where).\n"
        "interpretation: states what it might mean (attack, staging, exfiltration...).\n"
        "An interpretation MUST reference at least one observation fact in its text.\n"
        "ALWAYS register an `entities` entry for every distinct user, host, IP, process, or service that the verdict rationale attributes a role to — this is what populates the Top Entities panel. Use the entity_type / role enums above; freeform values are dropped.\n"
        "Use ONLY evidence_ids from observed_evidence_ids. Use ONLY entity names that literally appear as values in evidence_rows (user_name, target_user, computer, src_ip, process_name, service_name, executable_name, file_name, file_path). Never invent descriptive names like 'Source IP Address'.\n"
        "Examples (entity shapes only):\n"
        '  {"entity_type": "user", "name": "alice", "role": "victim", "notes": "Lost session token after 4624 logon from 10.0.0.5 at 03:14 UTC."}\n'
        '  {"entity_type": "host", "name": "WIN10-DC01", "role": "actor_candidate", "notes": "Source of repeated 4625 failures then a successful 4624 logon within 5 minutes."}\n'
        '  {"entity_type": "ip", "name": "10.0.0.5", "role": "attacker", "notes": "Originating IP for 30+ failed Kerberos pre-auth attempts (4771)."}\n'
        "</RULES>"
    )
    user = (
        f"hypothesis: {hypothesis.description if hasattr(hypothesis, 'description') else hypothesis}\n"
        f"verdict: {verdict}\n"
        f"rationale: {rationale}\n"
        f"{evidence_block}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], MEMORY_UPDATER_SCHEMA


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


def _section_context_block(
    context_sections: dict[str, str], current_section_outline: list[dict]
) -> str:
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
    time_range: dict[str, str] | None = None,
    structured_digest: str | None = None,
) -> list[dict[str, str]]:
    """Build messages for report section writing with evidence and template context."""

    placeholder = "[INSUFFICIENT EVIDENCE: reason]"
    cov = _section_coverage_block(report_brief or {})
    if cov and str(section_meta.get("section") or "").strip() == "1_overview":
        cov = f"Use the following evidence coverage summary as the canonical Evidence Scope. Do not invent sources that are not listed.\n{cov}\n"
    evidence = [
        r for r in evidence_results if str(r.get("kind") or "rows") != "rows"
    ] or evidence_results
    sv = _collect_source_verdicts(evidence_results)
    strength = ""
    if sv and all(v != "confirmed" for v in sv):
        strength = "source_verdict guidance: Every supplied evidence result is below confirmed. Use cautious language only; avoid 'confirmed', 'executed', 'compromised', 'attack succeeded', or equivalent strong assertions unless additional evidence explicitly supports them.\n"
    app_cat = (
        ", ".join(
            f"{e}={i.get('category', '?')}"
            for e, i in _load_app_catalog().get("mappings", {}).items()
        )
        or "see investigation framework"
    )

    from forensia.ai.case_profile import get_profile_event_ids

    _pb_ids: set[int] | None = get_profile_event_ids()
    if _pb_ids is not None:
        collected = _collect_event_ids(evidence_results)
        if collected:
            _pb_ids.update(collected)
    exec_rules = ""
    if structured_digest:
        exec_rules = (
            "Write what the evidence shows, not instructions to the reader.\n"
            "Lead with the 2-3 strongest observations (with dates and counts) from "
            "STRUCTURED_OBSERVATIONS and confirmed findings. One sentence on open questions.\n"
            'Do not use phrases like "should be verified", "needs confirmation", "requires verification" more than once.\n'
        )
    digest_block = f"\n{structured_digest}\n" if structured_digest else ""
    system = (
        f"{_dfir_playbook('report_section', event_ids=_pb_ids)}\n{_time_range_guidance(time_range)}"
        "<TASK>You are a DFIR report writer. Fill the provided Markdown section template using only supplied evidence.</TASK>\n"
        "<INPUT_SCHEMA>section_meta, evidence_results, previous_sections, template_body</INPUT_SCHEMA>\n"
        "<RULES>\nconfidence_matrix: confidence >= 0.8 => 'confirmed'/'observed'; confidence >= 0.5 => 'strongly suggests'; confidence < 0.5 => 'requires further investigation'.\n"
        "Do not use 'confirmed' for findings or conclusions below 0.8 confidence.\n"
        "Match wording to confidence: use cautious language for low-confidence items.\n"
        f"no_invented_facts: Write placeholder for unsupported claims: {placeholder}\n"
        "no_causation: Correlation is not proof of causation.\n"
        "confirmed_hypotheses: Reflect in appropriate sections; refuted_hypotheses only in 'Discarded Hypotheses' subsection.\n"
        "Recommended actions must scale with evidence strength.\n"
        f"app_categories: {app_cat}\n{_format_artifact_inference()}{_build_event_id_guidance(evidence_results)}{strength}{exec_rules}</RULES>\n"
        f"{_section_evidence_block(raw_evidence_rows)}{cov or ''}"
        f"{digest_block}"
        "<EXAMPLE verdict=\"report_section\">\nInput: section_meta={'section': '3_technical'}, evidence_results=[{'sample_rows': [{'evidence_id': 'E1', 'process_name': 'powershell.exe'}]}]\nOutput: \"## Process Execution\\n\\nOne suspicious process was observed: powershell.exe (evidence_id: E1).\"\n</EXAMPLE>\n"
        f"Output Markdown only (no fences). {_lang_instruction()}"
    )
    raw_block = ""
    if raw_evidence_rows:
        raw_block = f"\nnormalized_evidence_rows (summaries only; do not mirror raw tables):\n{_rows_to_markdown_table(raw_evidence_rows)}\n"
    user = (
        f"section_meta: {section_meta}\ncurrent_subsection: {section_heading or '(full section)'}\n"
        f"report_brief: {_slim_report_brief_for_section(report_brief or {}, str(section_meta.get('section') or ''))}\n"
        f"{_section_context_block(context_sections, current_section_outline or [])}"
        f"{_section_verification_block(verification_notes)}"
        f"evidence_results: {evidence}\n{raw_block}\n"
        "Complete only this current template block by replacing placeholders with evidence-based content.\n"
        f"{template_body}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


_load_question_routing_raw = load_question_routing_raw


def _format_artifact_inference() -> str:
    """Generate artifact inference text from YAML schema files."""
    yamls = _load_dfir_yamls()
    artifact_inference = yamls.get("artifact_inference", {})
    if not isinstance(artifact_inference, dict):
        return "\nKnown artifact-to-application inferences:\n- (no artifact inference data loaded)\n"
    lines = ["\nKnown artifact-to-application inferences:"]
    for artifact_type, entries in artifact_inference.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pattern = entry.get("pattern", "")
            app = entry.get("app_name", "")
            if pattern and app:
                notes = entry.get("notes", "")
                line = f"- {pattern} → {app}"
                if notes:
                    line += f" — {notes}"
                lines.append(line)
    if len(lines) == 1:
        lines.append("- (no artifact inference data loaded)")
    return "\n".join(lines) + "\n"


def build_benchmark_classify_messages(
    question: str,
    block_heading: str,
    evidence_rows: list[dict],
    expected_shape: dict | None,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: benchmark_classifier.
    Goal: decide answer status and pick which evidence_rows answer the question.
    Output: {status, picked_row_indices, rationale}
    """
    schema = benchmark_classify_schema(len(evidence_rows))
    system = (
        "<TASK>You are a benchmark_classifier. Decide the answer status and pick which evidence rows answer the question. "
        "Do NOT write narrative.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "status": "answered | partial | not_found | not_searched | wrong_query",\n'
        '  "picked_row_indices": [0-based row indices into evidence_rows (e.g. [0, 2, 5]). Each value MUST be an integer between 0 and len(evidence_rows)-1],\n'
        '  "rationale": "string"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Output picked_row_indices as integer array indices (0-based). Never invent identifiers or use placeholders like 'evidence_rows[0]'.\n"
        "</RULES>"
    )
    user = (
        f"question: {question}\n"
        f"block_heading: {block_heading}\n"
        f"evidence_rows: {json.dumps(evidence_rows[:20], default=str, ensure_ascii=False)}\n"
        f"expected_shape: {json.dumps(expected_shape or {}, ensure_ascii=False, default=str)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], schema


def build_structured_classify_messages(
    question: str,
    block_heading: str,
    evidence_rows: list[dict],
    expected_shape: dict | None,
    time_range: dict[str, str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: structured_classifier.
    Goal: decide answer status and pick which evidence_rows answer a reusable QuestionSpec.
    Output: {status, picked_row_indices, rationale}
    """
    schema = structured_classify_schema(len(evidence_rows))
    system = (
        "<TASK>You are a structured_classifier. Decide the answer status and pick which evidence rows answer the question. "
        "Do NOT write narrative.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "status": "answered | partial | not_found | not_searched | wrong_query",\n'
        '  "picked_row_indices": [0-based row indices into evidence_rows (e.g. [0, 2, 5]). Each value MUST be an integer between 0 and len(evidence_rows)-1],\n'
        '  "rationale": "string"\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Output picked_row_indices as integer array indices (0-based). Never invent identifiers or use placeholders like 'evidence_rows[0]'.\n"
        "Use expected_shape only as a contract for judging completeness; do not create rows or values that are not in evidence_rows.\n"
        "</RULES>"
    )
    user = (
        f"question: {question}\n"
        f"block_heading: {block_heading}\n"
        f"evidence_rows: {json.dumps(evidence_rows[:20], default=str, ensure_ascii=False)}\n"
        f"expected_shape: {json.dumps(expected_shape or {}, ensure_ascii=False, default=str)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], schema


def _filter_prior_runs_by_heading(
    prior_runs: list[dict[str, Any]], block_heading: str, limit: int = 6
) -> list[dict[str, Any]]:
    """Filter prior runs by block_heading match."""
    heading_matches = [
        run
        for run in prior_runs
        if str(run.get("block_heading") or "") == str(block_heading)
    ]
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
    time_range: dict[str, str] | None = None,
    evidence_keypoints: list[str] | None = None,
    prior_section_keypoints: list[str] | None = None,
    question_spec: dict[str, Any] | None = None,
    db: CaseDB | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """Build messages for the section agent's plan phase — decide next evidence action.

    Supports action types: sql, template, keypoint, facts, write. Includes
    error-recovery logic to switch to keypoint after repeated SQL failures."""

    schema_guidance = _build_schema_guidance("evtx_events", db=db)

    EXAMPLE_SECTION_PLAN = """
<EXAMPLE verdict="section_plan">
Input: block_heading='Logon Summary', template_body='## Logon Summary\\nList all logons.', reusable_facts empty, query_template_catalog has logon templates.
Output: {"action": "sql", "purpose": "Find all logon events", "sql": "SELECT evidence_id, computer, user_name, src_ip, logon_type, timestamp FROM evtx_events WHERE event_id IN (4624, 4625)"}
</EXAMPLE>
"""
    EXAMPLE_SECTION_PLAN_TEMPLATE = """
<EXAMPLE verdict="section_plan_template">
Input: block_heading='Service Creation', template_body='## Service Creation\\nFind malicious services.', template_id available, params extractable.
Output: {"action": "template", "template_id": "service-creation", "params": {"computer": "HOST-A"}}
</EXAMPLE>
"""
    EXAMPLE_SECTION_PLAN_KEYPOINT = """
<EXAMPLE verdict="section_plan_keypoint">
Input: block_heading='Endpoint identity' with template hint evidence_keypoints=[overview_hosts]. The keypoint_catalog includes {"name": "overview_hosts", "description": "Distinct hosts observed in evidence"}.
Output: {"action": "keypoint", "keypoint": "overview_hosts", "purpose": "List hosts observed in evidence"}
</EXAMPLE>
"""

    schema_notes = _load_schema_notes()
    schema_notes_block = (
        f"<SCHEMA_NOTES>\n{schema_notes}\n</SCHEMA_NOTES>\n" if schema_notes else ""
    )

    from forensia.ai.case_profile import get_profile_event_ids

    _sa_ev = get_profile_event_ids()
    _sa_tables: set[str] | None = None
    if db is not None:
        try:
            _rows = db.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='main'"
            ).fetchall()
            _sa_tables = {str(r[0]) for r in _rows if r[0]}
        except Exception:
            pass
    system = (
        f"{_dfir_playbook('section_agent_plan', event_ids=_sa_ev, tables=_sa_tables)}\n"
        f"{_time_range_guidance(time_range)}"
        "<TASK>You are a DFIR section-planning agent. Decide next evidence-gathering action for report block.</TASK>\n"
        "<INPUT_SCHEMA>section_key, block_heading, template_block, structured_memory_context, findings_snapshot, keypoint_catalog, query_template_catalog, prior_runs</INPUT_SCHEMA>\n"
        f"{schema_notes_block}"
        "<TIME_RULES>\nIMPORTANT: The case data may be from a DIFFERENT YEAR than the current date. "
        "DO NOT use datetime('now') or CURRENT_TIMESTAMP in SQL queries — these refer to the current system time, not the case time. "
        "If a time filter is needed, use a broad time range that covers the case data window.\n</TIME_RULES>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "action": "sql|template|keypoint|facts|write",\n'
        '  "keypoint": "exact keypoint name when action=keypoint, else null",\n'
        '  "sql": "SELECT ...", '
        '  "template_id": "template-name", '
        '  "params": {"key": "value"},\n'
        '  "enough_to_write": true|false\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "facts_first: Reuse reusable_section_facts if they already answer the block question.\n"
        "question_spec_first: If semantic_question_spec is present, satisfy that contract before following wording quirks in the template.\n"
        "keypoint_preferred: Use keypoint when it matches the block topic.\n"
        "template_preferred: Use template_id+params instead of raw sql.\n"
        "error_recovery: If the prior runs show two consecutive zero-row OR query_error results, the next action must be keypoint (not sql/template). "
        "Immediately after a query_error, do NOT retry SQL — switch to keypoint or template action.\n"
        "stop_early: Set action=write when enough evidence exists.\n"
        "If template_evidence_keypoints is non-empty and action=keypoint is appropriate, prefer those names verbatim.\n"
        "Avoid re-using keypoints already used by other sections (listed in prior_section_keypoints_in_this_report). Choose different evidence for this section.\n"
        "</RULES>\n"
        f"{build_investigation_framework(db)}"
        f"{schema_guidance}"
        f"{EXAMPLE_SECTION_PLAN}{EXAMPLE_SECTION_PLAN_TEMPLATE}{EXAMPLE_SECTION_PLAN_KEYPOINT}"
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
        f"template_evidence_keypoints: {evidence_keypoints or []}\n\n"
        f"semantic_question_spec: {question_spec or {}}\n\n"
        f"prior_section_keypoints_in_this_report: {prior_section_keypoints or []}\n\n"
        f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_AGENT_PLAN_SCHEMA


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
    time_range: dict[str, str] | None = None,
    question_spec: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """Build messages for the section agent's check phase — verify evidence sufficiency.

    Injects contradiction-history context and status taxonomy
    (answered/partial/not_found/not_searched/insufficient_evidence/wrong_query)."""

    contradicted_history = [
        run
        for run in prior_runs
        if run.get("verdict") in {"block_contradicted", "refuted"}
    ]
    EXAMPLE_SECTION_CHECK = """
<EXAMPLE verdict="section_check">
Input: collected_results has 3 rows with process_name='powershell.exe', template_body='## Suspicious Processes\\nList suspicious processes.'.
Output: {"verdict": "block_supported", "status": "answered", "rationale": "Evidence shows powershell.exe execution. Block can be written.", "fact_updates": []}
</EXAMPLE>
"""
    EXAMPLE_SECTION_CHECK_REFUTED = """
<EXAMPLE verdict="section_check_contradicted">
Input: collected_results empty, template_body='## Malicious Services\\nList malicious services.'. prior runs show queries returned nothing.
Output: {"verdict": "block_contradicted", "status": "not_found", "rationale": "No service-related evidence found in collected results.", "missing_questions": ["Query for event_id 4697/7045 returned 0 rows earlier"]}
</EXAMPLE>
"""
    from forensia.ai.case_profile import get_profile_event_ids

    _sac_ids: set[int] | None = get_profile_event_ids()
    if _sac_ids is not None:
        for result in (collected_results or []) + [latest_result]:
            if not isinstance(result, dict):
                continue
            for row in result.get("sample_rows") or []:
                if not isinstance(row, dict):
                    continue
                ev = row.get("event_id")
                if ev is not None:
                    try:
                        _sac_ids.add(int(ev))
                    except TypeError, ValueError:
                        pass
    system = (
        f"{_dfir_playbook('section_agent_check', event_ids=_sac_ids)}\n"
        f"{_time_range_guidance(time_range)}"
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
        "If semantic_question_spec is present, judge sufficiency against its required_fields, required_sources, render_columns, and status_rules.\n"
        "block_needs_more: More evidence needed; another query may help.\n"
        "block_contradicted: Evidence contradicts the template claim; explain contradiction.\n"
        "status rules: answered when evidence supports the block, partial when some evidence exists but not enough, not_found only after an appropriate search has been run and returned zero rows repeatedly, not_searched when the matching query/keypoint was never executed, wrong_query when the search hit the wrong artifact family, insufficient_evidence for other unresolved cases.\n"
        "Never use not_found unless the relevant search has actually run.\n"
        "block_supported requires at least 2 DIFFERENT KINDS of evidence (different event_id families, different keypoint sources). If all evidence is the same type (e.g. all 4648 findings), verdict should be 'partial' or 'needs_more', not 'block_supported'.\n"
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
        f"semantic_question_spec: {question_spec or {}}\n\n"
        f"structured_memory_context:\n{memory_context_md}\n\n"
        f"reusable_section_facts: {reusable_facts[:12]}\n\n"
        f"reusable_section_evidence: {reusable_evidence[:20]}\n\n"
        f"latest_result: {latest_result}\n\n"
        f"collected_results: {collected_results}\n\n"
    )
    if contradicted_history:
        user += f"contradicted_attempts_previous_iterations: {contradicted_history}\n\n"
    user += f"prior_runs: {_filter_prior_runs_by_heading(prior_runs, block_heading)}\n"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_AGENT_CHECK_SCHEMA


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


def build_section_outline_messages(
    template_body: str,
    relevant_evidence: list[dict],
    time_range: dict[str, str] | None = None,
    section_meta: dict | None = None,
    prior_section_keypoints: list[str] | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: section_outliner.
    Goal: assign each evidence item to ONE paragraph; produce outline JSON.
    """
    system = (
        "<TASK>You are a section_outliner. Decide what concrete claims this section should make based on the supplied evidence rows, and assign supporting evidence IDs to each claim. Do NOT write narrative prose — only output the outline JSON.</TASK>\n"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "outline": [{\n'
        '    "heading": "exact heading from template (verbatim)",\n'
        "    \"key_points\": [\"concrete claims, each grounded in 1-3 specific evidence rows. Each claim should name an actor/action/target/timestamp where possible. NO meta-statements like 'Summary of findings' or 'List of activity'\"],\n"
        '    "evidence_ids": ["actual evidence_id strings copied from the evidence_rows above (e.g. evtx-security-000000000122). NOT keypoint names. NOT finding_ids."]\n'
        "  }]\n"
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "When 5+ evidence rows share the same pattern (same event_id, same finding_id prefix), summarize them as ONE key_point referencing 1-2 representative evidence_ids, not all of them.\n"
        "Each key_point MUST be a falsifiable claim, not a topic label.\n"
        "If the evidence is insufficient to make a substantive claim, return an empty outline list.\n"
        "If prior_section_keypoints is non-empty, avoid re-using those same keypoints for this section — choose different evidence.\n"
        "If evidence_id is '?' (unknown), do NOT include it in evidence_ids array — only reference evidence with real identifiers.\n"
        "Do not use raw internal IDs (gap-*, H-*, KP-*) in prose. Use human-readable descriptions instead.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input evidence rows: [{"evidence_id": "evtx-security-000000000122", "summary": "4648 logon WIN-D9->informant 2015-03-22 14:33:54"}, {"evidence_id": "evtx-security-000000000152", "summary": "4648 logon WIN-D9->informant 2015-03-22 14:34:28"}]\n'
        'Output: {"outline": [{"heading": "Executive Summary", "key_points": ["Two explicit-credential logon attempts (4648) from WIN-D9RGPJQ68G8$ targeting informant were observed within 60 seconds on 2015-03-22"], "evidence_ids": ["evtx-security-000000000122"]}]}\n'
        "</EXAMPLE>\n"
        "Output JSON only. "
    )
    evidence_summary = "\n".join(
        _format_evidence_row(e) for e in (relevant_evidence or [])[:30]
    )
    user = (
        f"section_meta: {json.dumps(section_meta, ensure_ascii=False, default=str)}\n"
        f"available_evidence:\n{evidence_summary or 'No evidence available.'}\n"
        f"prior_section_keypoints: {prior_section_keypoints or []}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_OUTLINE_SCHEMA


def build_paragraph_narrate_messages(
    heading: str,
    key_points: list[str],
    evidence_rows: list[dict],
    template_body: str,
    language: str = "en",
    structured_digest: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    settings = get_llm_settings()
    language = str(settings.get("output_language", language))
    """role: section_narrator.
    Goal: write ONE markdown paragraph for the given heading using the evidence.
    NO access to other sections, NO full report_brief, NO findings list.
    """
    digest_block = f"\n{structured_digest}\n" if structured_digest else ""
    exec_summary_rules = ""
    if structured_digest:
        exec_summary_rules = (
            "Write what the evidence shows, not instructions to the reader.\n"
            "Lead with the 2-3 strongest observations (with dates and counts) from "
            "STRUCTURED_OBSERVATIONS and confirmed findings. One sentence on open questions.\n"
            'Do not use phrases like "should be verified", "needs confirmation", "requires verification" more than once.\n'
        )
    system = (
        "<TASK>You are a section_narrator. Write one markdown paragraph for the given heading using the supplied evidence. "
        "Cite evidence_ids inline. Keep the paragraph factual and concise.</TASK>\n"
        f"Language: {language}\n"
        '<OUTPUT_SCHEMA>Return exactly one JSON object: {"body": "single markdown paragraph"}.</OUTPUT_SCHEMA>\n'
        "<RULES>\n"
        "The response MUST be valid JSON and MUST contain the key `body`. Do not return a bare string.\n"
        "Citation count: cite AT MOST 2-3 representative evidence_ids per paragraph. If many similar findings exist (same event_id pattern), state the count and cite 1-2 examples.\n"
        "Citation format: cite raw `evidence_id` strings only (e.g. evtx-security-000000000122). Do NOT cite `finding_id` (e.g. windows-security-4648-logon-explicit-creds-0001) — those are finding labels, not evidence references. If the input shows a finding_id without an evidence_id, OMIT the citation entirely instead of using the finding_id.\n"
        "No KP-NNNN identifiers. Do not use raw internal IDs (gap-*, H-*, KP-*) in prose. Use human-readable descriptions instead.\n"
        "No meta-statements: write what was observed, not what was reviewed. Avoid 'investigation covered', 'scope included', 'comprehensive review of' style phrasing.\n"
        "Do NOT write `## {heading}` in your output — the heading is prepended by the renderer. Only write paragraph content below the heading.\n"
        "If the status is not_searched or not_found, this function should not be called. If you see such a status, output nothing.\n"
        "Key points may be prefixed with verdict labels: [confirmed], [refuted], [finding, confidence=N]. Refuted items may only be mentioned as ruled-out. Confirmed and refuted items must not be blended into one claim.\n"
        'If a row has `"citable": false`, do NOT invent an evidence_id for it. State the factual claim without a citation token.\n'
        f"{exec_summary_rules}"
        "</RULES>\n"
        f"{digest_block}"
        "<EXAMPLE_GOOD>\n"
        "Eight explicit-credential logon attempts (4648) targeting informant, admin11, and temporary were observed from INFORMANT-PC$ between 14:33 and 15:55 on 2015-03-22 (evtx-security-000000000122, evtx-security-000000000152). All attempts succeeded and produced no subsequent 4624 from the same src_ip, suggesting localhost credential injection rather than network-reused access.\n"
        "</EXAMPLE_GOOD>\n"
        "<EXAMPLE_BAD>\n"
        "The investigation revealed multiple high-severity findings related to logon attempts using explicit credentials (windows-security-4648-logon-explicit-creds-0001, ..., 0011).\n"
        "</EXAMPLE_BAD>\n"
        "<EXAMPLE_JSON>\n"
        '{"body":"Eight explicit-credential logon attempts targeting informant and admin11 were observed from INFORMANT-PC$ on 2015-03-22 (evtx-security-000000000122, evtx-security-000000000152)."}\n'
        "</EXAMPLE_JSON>"
    )
    user = (
        f"Heading: {heading}\n"
        f"Key points: {json.dumps(key_points, ensure_ascii=False, default=str)}\n"
        f"Template body context: {template_body[:500]}\n"
        f"Evidence rows: {json.dumps(evidence_rows[:10], default=str, ensure_ascii=False)}\n"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], PARAGRAPH_NARRATE_SCHEMA


def build_gap_identifier_messages(
    observed_keypoints: list[dict],
    uncovered_keypoints: list[dict],
    active_hypotheses_slim: list[dict],
    time_range: dict[str, str] | None = None,
    status_callback: Callable[[str], None] | None = None,
    case_profile: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: gap_identifier.
    Goal: identify which uncovered_keypoints lack active hypothesis coverage.
    """
    slim_observed = [
        {
            "keypoint": kp.get("keypoint") or kp.get("name", ""),
            "row_count": kp.get("row_count", 0),
        }
        for kp in (observed_keypoints or [])
    ]
    available_keypoint_names = [
        kp.get("name") or kp.get("keypoint", "")
        for kp in (observed_keypoints + uncovered_keypoints)[:80]
        if kp.get("name") or kp.get("keypoint")
    ]
    if not available_keypoint_names and (observed_keypoints or uncovered_keypoints):
        logging.warning(
            "gap_identifier: available_keypoint_names empty — check key names: observed has 'keypoint' vs prompt expects 'name'"
        )
    schema = gap_identifier_schema(available_keypoint_names)
    system = (
        "<TASK>You are a gap_identifier. From available_keypoints, pick the ones that lack active hypothesis coverage.</TASK>\n"
        f"{_case_profile_guidance(case_profile)}"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "gap_areas": [{"keypoint_id": "EXACT name from available_keypoints", "why_uncovered": "str", "required_entities": ["snake_case column names"]}]\n'
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "keypoint_id MUST be exact substring match of an entry in available_keypoints. Inventing names will make the agent fail to resolve them.\n"
        "required_entities MUST be snake_case DB column identifiers (e.g. src_ip, target_user, computer, logon_type). NEVER natural language phrases.\n"
        "If active hypotheses already cover all available keypoints, return an empty gap_areas list.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input observed_keypoints=[{name: "overview_hosts"}], uncovered_keypoints=[{name: "account_bruteforce_clusters"}], active_hypotheses=[].\n'
        'Output: {"gap_areas": [{"keypoint_id": "account_bruteforce_clusters", "why_uncovered": "no hypothesis targets 4625 clusters yet", "required_entities": ["src_ip", "target_user"]}]}\n'
        "</EXAMPLE>"
    )
    user = (
        f"available_keypoints: {json.dumps([{'name': kp.get('name') or kp.get('keypoint'), 'description': kp.get('description', '')[:80]} for kp in (observed_keypoints + uncovered_keypoints)[:80]], ensure_ascii=False, default=str)}\n"
        f"observed_keypoints: {json.dumps(slim_observed, ensure_ascii=False, default=str)}\n"
        f"uncovered_keypoints: {json.dumps(uncovered_keypoints, ensure_ascii=False, default=str)}\n"
        f"active_hypotheses: {json.dumps(active_hypotheses_slim, ensure_ascii=False, default=str)}\n"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    total_chars = sum(len(m["content"]) for m in messages)
    if status_callback:
        status_callback(
            f"[gap_identifier] prompt size: {total_chars} chars / ~{total_chars // 4} tokens"
        )
    return messages, schema


def build_hypothesis_drafter_messages(
    gap_area: dict,
    available_rules: list[dict],
    time_range: dict[str, str] | None = None,
    status_callback: Callable[[str], None] | None = None,
    case_profile: str | None = None,
) -> tuple[list[dict[str, str]], dict]:
    """role: hypothesis_drafter.
    Goal: draft ONE hypothesis targeting the given gap_area.
    """
    schema = hypothesis_drafter_schema()
    system = (
        "<TASK>You are a hypothesis_drafter. Draft ONE falsifiable hypothesis targeting the given gap_area.</TASK>\n"
        f"{_case_profile_guidance(case_profile)}"
        "<OUTPUT_SCHEMA>\n"
        "{\n"
        '  "hypothesis": {\n'
        '    "description": "str (one investigative claim that can be confirmed or refuted by SQL evidence)",\n'
        '    "required_entities": ["snake_case column names such as src_ip, target_user, computer, logon_type, process_name, file_path"],\n'
        '    "source_rule_ids": ["rule_id from available_rules if any aligns, else empty list"],\n'
        '    "confirm_when": {"co_observed_event_ids": [int, ...], "same_host": bool, "within_minutes": int},\n'
        '    "refute_when": {"zero_rows": true}\n'
        "  }\n"
        "}\n"
        "</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "confirm_when MUST be a JSON object (not a string). Use co_observed_event_ids as a list of integer Windows event IDs (e.g. [4624, 4625, 4768]).\n"
        "required_entities MUST be column-like identifiers (snake_case), not natural language phrases. Example: src_ip, target_user, computer.\n"
        "confirm_when.co_observed_event_ids MUST be event IDs commonly logged by DEFAULT Windows audit policy. Avoid event IDs that require non-default auditing such as:\n"
        "  - 4663 (Object Access) — requires explicit SACL / Object Access auditing\n"
        "  - 5140/5145 (file share access) — requires File Share auditing\n"
        "  - 4658 / 4660 — Object Access subcategory\n"
        "If the hypothesis fundamentally needs these IDs, state in the description that it is only testable when corresponding audit policy is enabled.\n"
        "event_id semantics:\n"
        "  - 4624/4625 = logon success/failure\n"
        "  - 4648 = explicit credential logon attempt\n"
        "  - 4688 = process creation (NOT 'browser activity' — for browser look at mft_entries / prefetch_executions)\n"
        "  - 4697 / 7045 = service installation\n"
        "  - 4698 = scheduled task creation\n"
        "  - 1102 / 104 = log clearing\n"
        "For browser usage, file activity, or process artifact analysis, prefer mft_entries + prefetch_executions tables over event IDs.\n"
        "Output JSON only.\n"
        "</RULES>\n"
        "<EXAMPLE>\n"
        'Input gap_area: {"keypoint_id": "account_bruteforce_clusters", "required_entities": ["src_ip", "target_user"]}\n'
        'Output: {"hypothesis": {"description": "Repeated 4625 failures from a single src_ip targeting one or more users indicate brute-force attempts that may have been followed by a successful 4624 logon.", "required_entities": ["src_ip", "target_user", "computer"], "source_rule_ids": ["windows-security-4625-failed-logon"], "confirm_when": {"co_observed_event_ids": [4625, 4624], "same_host": true, "within_minutes": 30}, "refute_when": {"zero_rows": true}}}\n'
        "</EXAMPLE>\n"
        "<EXAMPLE_GOOD>\n"
        'Input: gap_area={"keypoint_id": "host_execution_activity", "required_entities": ["computer", "process_name"]}\n'
        'Output: {"hypothesis": {"description": "Unauthorized execution of LOLBAS binaries (powershell.exe, mshta.exe) on informant-PC indicates initial code execution.", "required_entities": ["computer", "process_name", "command_line"], "source_rule_ids": ["windows-security-4688-suspicious-tools"], "confirm_when": {"co_observed_event_ids": [4688, 4624], "same_host": true, "within_minutes": 5}, "refute_when": {"zero_rows": true}}}\n'
        "</EXAMPLE_GOOD>\n"
        "<EXAMPLE_BAD>\n"
        'Output: {"hypothesis": {"description": "...", "required_entities": ["user_identity", "computer_name", "logon_type", "credential_usage"]}}\n'
        "Reason: required_entities must be snake_case column-like names (target_user, computer, logon_type), not natural language. NEVER use natural language for required_entities.\n"
        "</EXAMPLE_BAD>\n"
        "<EXAMPLE_BAD>\n"
        'Output: {"hypothesis": {"description": "Logon (4624) followed by file access (4663) or browser activity (4688)...", "confirm_when": {"co_observed_event_ids": [4624, 4663, 4688]}}}\n'
        'Reason: 4663 requires Object Access auditing (rarely enabled), and 4688 is process creation not "browser activity". Better: split into two hypotheses — one tested via 4624 + mft_entries WHERE file_path LIKE patterns, another via 4624 + prefetch_executions filtered to browser executable names.\n'
        "</EXAMPLE_BAD>\n"
    )
    # T-09: Slim each rule to essential fields only
    slim_rules: list[dict[str, Any]] = []
    for rule in available_rules[:5]:
        if not isinstance(rule, dict):
            continue
        slim_hypotheses: list[dict[str, Any]] = []
        for h in rule.get("hypotheses") or []:
            if isinstance(h, dict):
                slim_hypotheses.append(
                    {
                        "description": h.get("description", ""),
                        "confirm_when": h.get("confirm_when"),
                    }
                )
        slim_rules.append(
            {
                "id": rule.get("id", ""),
                "title": rule.get("title", ""),
                "tags": rule.get("tags", []),
                "hypotheses": slim_hypotheses,
            }
        )
    user = (
        f"gap_area: {json.dumps(gap_area, ensure_ascii=False, default=str)}\n"
        f"available_rules: {json.dumps(slim_rules, ensure_ascii=False, default=str)}\n"
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    total_chars = sum(len(m["content"]) for m in messages)
    if status_callback:
        status_callback(
            f"[hypothesis_drafter] prompt size: {total_chars} chars / ~{total_chars // 4} tokens"
        )
    return messages, schema


SECTION_REVIEW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["pass", "rewrite"]},
        "problems": {"type": "array", "items": {"type": "string"}},
        "guidance": {"type": "string"},
    },
    "required": ["verdict", "problems", "guidance"],
}


def build_section_review_messages(
    heading: str,
    body: str,
    digest: str | None,
    deterministic_problems: list[str],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    system = (
        "<TASK>You are a section_reviewer. Evaluate the narrative paragraph for the given heading. "
        "Check: does it state what happened, who/when, and what remains open? Does it cite at most 2-3 "
        "representative evidence IDs (not enumerate findings)? Is it factual, concise, and self-contained? "
        "Output verdict 'pass' if acceptable, 'rewrite' if needs improvement, with specific guidance.</TASK>\n"
        '<OUTPUT_SCHEMA>{"verdict": "pass"|"rewrite", "problems": ["..."], "guidance": "..."}</OUTPUT_SCHEMA>\n'
        "<RULES>\n"
        "- Executive Summary must state what happened, who/when, and what remains open in ≤2 paragraphs\n"
        "- At most 3 representative evidence IDs per paragraph\n"
        "- Must not enumerate findings or list finding_ids\n"
        "- Must not contain internal IDs (gap-*, H-*, KP-*)\n"
        "- Must not contain pseudo-citations like (some_label)\n"
        "- If body is the insufficient-evidence placeholder but digest has data, always rewrite\n"
        "</RULES>\n"
    )
    digest_block = f"\nSection table digest:\n{digest}\n" if digest else ""
    problems_block = (
        f"\nDeterministic problems found:\n{chr(10).join('- ' + p for p in deterministic_problems)}\n"
        if deterministic_problems
        else ""
    )
    user = f"Heading: {heading}\n\nBody:\n{body}\n{digest_block}{problems_block}"
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ], SECTION_REVIEW_SCHEMA
