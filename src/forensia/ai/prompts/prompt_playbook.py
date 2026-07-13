"""DFIR playbook assembly and knowledge-catalog narrative rendering."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from forensia.core.session import Hypothesis
from forensia.knowledge.catalog import (
    load_dfir_yamls,
    load_event_class_definitions,
    load_question_routing_raw,
)
from forensia.knowledge.resources import rulepacks_dir, schema_dir
from forensia.report.sections.section_taxonomy import (
    SECTION_KEY_PLAYBOOK_MAP as _SECTION_KEY_MAP,
)

if TYPE_CHECKING:
    pass


@dataclass(frozen=True, slots=True)
class RuleContext:
    rule_id: str
    correlate_event_ids: list[int]
    confirm_when: dict[str, Any]
    refute_when: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _PlaybookCatalog:
    events_data: dict[str | int, Any]
    logon_types_data: dict[str | int, Any]
    priority_events: list[Any]
    schema_notes: dict[str, Any]
    fp_guidance: dict[str, Any]
    extractors: dict[str, Any]
    app_mappings: dict[str, Any]
    artifact_data: dict[str, Any]
    ioc_data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _PlaybookBudgetResult:
    section_entries: list[tuple[str, str]]
    base_playbook: str
    pre_budget_chars: int
    dropped: list[str]


@lru_cache(maxsize=1)
def _get_cached_rules() -> list[Any]:
    """Load and cache all rules at module level to avoid repeated file I/O."""

    from forensia.knowledge.rules.loader import load_rules_from_dir

    rules_path = rulepacks_dir()
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


@lru_cache(maxsize=1)
def _load_schema_notes() -> str:
    """Load schema notes from evtx_events.yaml and prefetch_executions.yaml for section agent."""

    import yaml

    schema_root = schema_dir()
    notes: list[str] = []

    evtx_path = schema_root / "evtx_events.yaml"
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

    prefetch_path = schema_root / "prefetch_executions.yaml"
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
    "ioc",  # first to drop — auxiliary catalog
    "app",  # application catalog — interpretation aid
    "artifact",  # artifact inference — interpretation aid
    "logon",  # logon types — lowest-priority core section
    "events",  # event IDs
    "priority",  # priority investigation order
    "fp",  # false-positive guidance
    "extractor",  # JSON extractors
    "schema",  # schema notes — highest priority, last to drop
]

# Mapping from internal section keys to user-facing keys used by the
# ``sections`` parameter of ``_dfir_playbook``.  Callers pass a set of
# user-facing keys; only sections whose mapped key is in the set are
# rendered.  The ``preamble`` key is always included.
# _SECTION_KEY_MAP: canonical definition moved to report/section_taxonomy.py
# Re-exported via the import at the top of this file.

# Entity columns whose presence signals that file/executable interpretation
# aids (app catalog, artifact inference, IOC catalog) are worth including.
_CATALOG_ENTITY_COLUMNS = frozenset(
    {
        "process_name",
        "executable_name",
        "file_path",
        "file_name",
        "command_line",
        "service_name",
        "extension",
    }
)


@lru_cache(maxsize=1)
def _auth_event_ids() -> frozenset[int]:
    """Event IDs of authentication-related classes from event_ids.yaml."""
    ids: set[int] = set()
    for class_name, class_def in load_event_class_definitions().items():
        name = class_name.lower()
        if "logon" in name or "auth" in name or "credential" in name:
            for eid in class_def.get("event_ids") or []:
                try:
                    ids.add(int(eid))
                except TypeError, ValueError:
                    continue
    return frozenset(ids)


def _sections_for_hypothesis(
    hypothesis: Any, sample_rows: list[dict[str, Any]] | None = None
) -> set[str] | None:
    """Deterministically pick playbook sections relevant to one hypothesis.

    Selection signals (all code-side, no LLM):
    - confirm_when.co_observed_event_ids → logon_types only when they
      intersect the auth event classes.
    - required_entities / sample-row columns → catalog sections only when
      file/executable columns are involved.

    Returns None (= render all sections) when the hypothesis carries no
    usable signal, so behaviour degrades to the full playbook.
    """
    event_ids: set[int] = set()
    confirm_when = getattr(hypothesis, "confirm_when", None)
    if isinstance(confirm_when, dict):
        for eid in confirm_when.get("co_observed_event_ids") or []:
            try:
                event_ids.add(int(eid))
            except TypeError, ValueError:
                continue
    entities = {
        str(e).strip().lower()
        for e in (getattr(hypothesis, "required_entities", None) or [])
        if e
    }
    row_columns: set[str] = set()
    for row in sample_rows or []:
        if isinstance(row, dict):
            row_columns.update(k for k, v in row.items() if v not in (None, ""))
    if not event_ids and not entities and not row_columns:
        return None
    sections = {"schema", "event_ids", "fp_guidance"}
    if event_ids & _auth_event_ids():
        sections.add("logon_types")
    if (entities | row_columns) & _CATALOG_ENTITY_COLUMNS:
        sections.update({"app_catalog", "artifact_inference", "ioc_catalog"})
    return sections


def _playbook_eid_sort_key(key: Any) -> int:
    if isinstance(key, str) and key.isdigit():
        return int(key)
    if isinstance(key, (int, float)):
        return int(key)
    return 0


def _filter_playbook_events(
    events_data: dict[str | int, Any], event_ids: set[int] | None
) -> dict[str | int, Any]:
    if event_ids is None or not isinstance(events_data, dict):
        return events_data
    filtered: dict[str | int, Any] = {}
    for eid_key in sorted(events_data, key=_playbook_eid_sort_key):
        eid_val = int(eid_key) if isinstance(eid_key, str) else int(eid_key)
        if eid_val in event_ids:
            filtered[eid_key] = events_data[eid_key]
            if len(filtered) >= 40:
                break
    return filtered


def _load_playbook_catalog(event_ids: set[int] | None) -> _PlaybookCatalog:
    yamls = _load_dfir_yamls()
    events_data = (
        yamls["event_ids"].get("events", {})
        if isinstance(yamls["event_ids"], dict)
        else {}
    )
    events_data = _filter_playbook_events(events_data, event_ids)
    return _PlaybookCatalog(
        events_data=events_data,
        logon_types_data=(
            yamls["logon_types"].get("types", {})
            if isinstance(yamls["logon_types"], dict)
            else {}
        ),
        priority_events=(
            yamls["logon_types"].get("priority_events", [])
            if isinstance(yamls["logon_types"], dict)
            else []
        ),
        schema_notes=(
            yamls["evtx_events"].get("notes", {})
            if isinstance(yamls["evtx_events"], dict)
            else {}
        ),
        fp_guidance=(
            yamls["fp_rules"].get("reduction_guidance", {})
            if isinstance(yamls["fp_rules"], dict)
            else {}
        ),
        extractors=(
            yamls["evtx_events"].get("json_field_extractors", {})
            if isinstance(yamls["evtx_events"], dict)
            else {}
        ),
        app_mappings=(
            yamls["app_catalog"].get("mappings", {})
            if isinstance(yamls["app_catalog"], dict)
            else {}
        ),
        artifact_data=(
            yamls["artifact_inference"]
            if isinstance(yamls["artifact_inference"], dict)
            else {}
        ),
        ioc_data=(
            yamls["dfir_ioc_catalog"]
            if isinstance(yamls["dfir_ioc_catalog"], dict)
            else {}
        ),
    )


def _playbook_include_flags(
    phase: str, tables: set[str] | None
) -> tuple[bool, bool, bool, bool]:
    planning_phases = {"broad_plan", "hypothesis_plan"}
    interpretation_phases = {"check", "report_section", "section_agent_check"}
    include_fp = phase in interpretation_phases
    include_app_catalog = phase not in planning_phases
    include_artifact_inference = phase in interpretation_phases
    include_ioc_catalog = phase in (interpretation_phases | {"section_agent_plan"})

    has_mft_or_prefetch = tables is None or bool(
        tables
        & {"mft_entries", "mft_timeline", "prefetch_executions", "prefetch_timeline"}
    )
    has_evtx = tables is None or "evtx_events" in tables
    if tables is not None:
        include_app_catalog = include_app_catalog and has_evtx
        include_artifact_inference = include_artifact_inference and has_mft_or_prefetch
        include_ioc_catalog = include_ioc_catalog and has_mft_or_prefetch
    return (
        include_fp,
        include_app_catalog,
        include_artifact_inference,
        include_ioc_catalog,
    )


def _build_playbook_section_entries(
    catalog: _PlaybookCatalog, phase: str, tables: set[str] | None
) -> list[tuple[str, str]]:
    event_narrative = _render_event_narrative(catalog.events_data)
    logon_narrative = _render_logon_narrative(catalog.logon_types_data)
    priority_narrative = _render_priority_narrative(catalog.priority_events)
    schema_narrative = _render_schema_narrative(catalog.schema_notes)
    fp_narrative = _render_fp_narrative(catalog.fp_guidance)
    extractor_narrative = _render_extractor_narrative(catalog.extractors)
    app_narrative = _render_app_catalog_narrative(catalog.app_mappings)
    artifact_narrative = _render_artifact_inference_narrative(catalog.artifact_data)
    ioc_narrative = _render_ioc_catalog_narrative(catalog.ioc_data)
    include_fp, include_app, include_artifact, include_ioc = _playbook_include_flags(
        phase, tables
    )

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
    if include_app:
        section_entries.append(
            (
                "app",
                f"## Application Catalog (process categorization)\n{app_narrative or 'No app catalog available.'}",
            )
        )
    if include_artifact:
        section_entries.append(
            (
                "artifact",
                f"## Artifact-to-Application Inference\n{artifact_narrative or 'No artifact inference data available.'}",
            )
        )
    if include_ioc:
        section_entries.append(
            ("ioc", f"## IOC Catalog\n{ioc_narrative or 'No IOC catalog available.'}")
        )
    return section_entries


def _filter_playbook_sections(
    section_entries: list[tuple[str, str]], sections: set[str] | None
) -> list[tuple[str, str]]:
    if sections is None:
        return section_entries
    return [
        (key, text)
        for key, text in section_entries
        if key == "preamble" or _SECTION_KEY_MAP.get(key, key) in sections
    ]


def _join_playbook_entries(section_entries: list[tuple[str, str]]) -> str:
    return "\n".join(text for _, text in section_entries) + "\n"


def _priority_event_ids(priority_events: list[Any]) -> list[int]:
    priority_ids: list[int] = []
    for entry in priority_events or []:
        for eid in entry.get("event_ids", []) if isinstance(entry, dict) else []:
            try:
                eid_int = int(eid)
            except TypeError, ValueError:
                continue
            if eid_int not in priority_ids:
                priority_ids.append(eid_int)
    return priority_ids


def _truncate_events_to_priority(
    section_entries: list[tuple[str, str]], catalog: _PlaybookCatalog
) -> tuple[list[tuple[str, str]], bool]:
    priority_ids = _priority_event_ids(catalog.priority_events)
    if not priority_ids:
        return section_entries, False
    trimmed = {
        key: value
        for key, value in catalog.events_data.items()
        if (int(key) if isinstance(key, str) and key.isdigit() else key) in priority_ids
    }
    if not trimmed or len(trimmed) >= len(catalog.events_data):
        return section_entries, False
    trimmed_narrative = _render_event_narrative(trimmed)
    return [
        (
            key,
            "## Event ID Reference (priority events only; full list omitted for budget)\n"
            + trimmed_narrative,
        )
        if key == "events"
        else (key, value)
        for key, value in section_entries
    ], True


def _apply_playbook_budget(
    *,
    section_entries: list[tuple[str, str]],
    catalog: _PlaybookCatalog,
    event_ids: set[int] | None,
    phase: str,
    budget: int,
) -> _PlaybookBudgetResult:
    base_playbook = _join_playbook_entries(section_entries)
    pre_budget_chars = len(base_playbook)
    dropped: list[str] = []

    if (
        len(base_playbook) > budget
        and event_ids is None
        and isinstance(catalog.events_data, dict)
    ):
        section_entries, did_trim = _truncate_events_to_priority(
            section_entries, catalog
        )
        if did_trim:
            base_playbook = _join_playbook_entries(section_entries)
            dropped.append("events:truncated-to-priority")

    if len(base_playbook) > budget:
        for key in _PLAYBOOK_SECTION_DROP_ORDER:
            if len(base_playbook) <= budget:
                break
            section_entries = [(k, v) for k, v in section_entries if k != key]
            base_playbook = _join_playbook_entries(section_entries)
            dropped.append(key)
        if dropped:
            logging.info(
                "[_dfir_playbook] phase=%s budget=%d exceeded (%d chars), dropped: %s",
                phase,
                budget,
                len(base_playbook),
                dropped,
            )

    return _PlaybookBudgetResult(
        section_entries=section_entries,
        base_playbook=base_playbook,
        pre_budget_chars=pre_budget_chars,
        dropped=dropped,
    )


def _load_phase_playbook(phase: str) -> str:

    playbook_dir = schema_dir() / "playbook"
    phase_file = playbook_dir / f"{phase}.md"
    phase_narrative = ""
    if phase_file.exists():
        try:
            phase_narrative = phase_file.read_text(encoding="utf-8")
        except Exception:
            pass
    return re.sub(
        r"\n?<!-- AUTO-FROM: (?:event_ids|app_catalog)\.yaml -->.*?<!-- END-AUTO -->\n?",
        "\n",
        phase_narrative,
        flags=re.DOTALL,
    )


def _log_playbook_telemetry(
    *,
    phase: str,
    sections: set[str] | None,
    budget_result: _PlaybookBudgetResult,
    result: str,
) -> None:
    section_sizes = {k: len(v) for k, v in budget_result.section_entries}
    if sections is not None:
        logging.debug(
            "[_dfir_playbook] phase=%s sections=%s pre_budget=%d post_budget=%d total=%d dropped=%s",
            phase,
            sorted(sections),
            budget_result.pre_budget_chars,
            len(budget_result.base_playbook),
            len(result),
            budget_result.dropped,
        )
    else:
        logging.debug(
            "[_dfir_playbook] phase=%s total=%d chars, sections=%s, dropped=%s",
            phase,
            len(result),
            section_sizes,
            budget_result.dropped,
        )


def _dfir_playbook(
    phase: str,
    *,
    event_ids: set[int] | None = None,
    tables: set[str] | None = None,
    sections: set[str] | None = None,
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
    sections : optional set of str
        If provided, only sections whose mapped key is in this set are included.
        Valid keys: 'event_ids', 'logon_types', 'fp_guidance', 'schema',
        'app_catalog', 'artifact_inference', 'ioc_catalog'.
        When None, all sections are included (backward compatible).

    Returns a narrative string optimized for weak LLMs.
    """
    from forensia.config import get_system_prompt_budget_chars

    catalog = _load_playbook_catalog(event_ids)
    section_entries = _build_playbook_section_entries(catalog, phase, tables)
    section_entries = _filter_playbook_sections(section_entries, sections)
    budget_result = _apply_playbook_budget(
        section_entries=section_entries,
        catalog=catalog,
        event_ids=event_ids,
        phase=phase,
        budget=get_system_prompt_budget_chars(),
    )
    result = budget_result.base_playbook + _load_phase_playbook(phase)
    _log_playbook_telemetry(
        phase=phase,
        sections=sections,
        budget_result=budget_result,
        result=result,
    )
    return result


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


PLAYBOOK_SECTION_DROP_ORDER = _PLAYBOOK_SECTION_DROP_ORDER
dfir_playbook = _dfir_playbook
load_dfir_yamls_cached = _load_dfir_yamls
render_event_narrative = _render_event_narrative
sections_for_hypothesis = _sections_for_hypothesis
