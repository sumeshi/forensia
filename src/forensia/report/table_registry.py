"""Registry and rendering of report table blocks."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.db.database import CaseDB
from forensia.report.finding_themes import (
    _build_key_findings_table,
    _build_recommendations_table,
)
from forensia.report.gap_tables import (
    _build_evidence_gaps_table,
    _build_gaps_confirmed_table,
    _build_gaps_unresolved_table,
    _build_gaps_untestable_table,
)
from forensia.report.markdown import (
    _markdown_table,
    render_rows_template,
)
from forensia.report.summary_rows import (
    _account_summary_rows,
    _antiforensic_rows,
    _count_table,
    _execution_rows,
    _file_artifact_rows,
    _host_summary_rows,
    _network_summary_rows,
    _timeline_phase_rows,
    _timeline_rows,
)


def _build_evidence_scope_table(db: CaseDB) -> list[dict[str, Any]]:
    return _count_table(db)


def _build_systems_observed_table(db: CaseDB) -> list[dict[str, Any]]:
    return _host_summary_rows(db, 5)


def _build_timeline_phase_table(db: CaseDB) -> list[dict[str, Any]]:
    return _timeline_phase_rows(db)


def _build_timeline_chronological_table(db: CaseDB) -> list[dict[str, Any]]:
    return _timeline_rows(db)


def _build_accounts_table(db: CaseDB) -> list[dict[str, Any]]:
    return _account_summary_rows(db)


def _build_execution_table(db: CaseDB) -> list[dict[str, Any]]:
    return _execution_rows(db)


def _build_file_artifacts_table(db: CaseDB) -> list[dict[str, Any]]:
    return _file_artifact_rows(db)


def _build_antiforensic_table(db: CaseDB) -> list[dict[str, Any]]:
    return _antiforensic_rows(db)


def _build_network_table(db: CaseDB) -> list[dict[str, Any]]:
    return _network_summary_rows(db)


_TABLE_BLOCK_BUILDERS: dict[str, Callable[[CaseDB], list[dict[str, Any]]]] = {
    "overview_evidence_scope": _build_evidence_scope_table,
    "overview_systems_observed": _build_systems_observed_table,
    "overview_key_findings": _build_key_findings_table,
    "timeline_phase_summary": _build_timeline_phase_table,
    "timeline_chronological": _build_timeline_chronological_table,
    "technical_accounts": _build_accounts_table,
    "technical_execution": _build_execution_table,
    "technical_files": _build_file_artifacts_table,
    "technical_antiforensic": _build_antiforensic_table,
    "technical_network": _build_network_table,
    "gaps_unresolved": _build_gaps_unresolved_table,
    "gaps_untestable": _build_gaps_untestable_table,
    "gaps_confirmed": _build_gaps_confirmed_table,
    "gaps_evidence": _build_evidence_gaps_table,
    "recommendations_action_plan": _build_recommendations_table,
}

_TABLE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "overview_evidence_scope": [
        ("metric", "Metric"),
        ("value", "Value"),
        ("scope", "Scope"),
    ],
    "overview_systems_observed": [
        ("host", "Host"),
        ("events", "EVTX rows"),
        ("first_seen", "First seen"),
        ("last_seen", "Last seen"),
    ],
    "overview_key_findings": [
        ("finding", "Finding"),
        ("severity", "Severity"),
        ("confidence", "Confidence"),
        ("why_it_matters", "Why it matters"),
    ],
    "timeline_phase_summary": [
        ("date", "Date"),
        ("phase", "Observed activity"),
        ("interpretation", "Interpretation"),
        ("window", "Event window"),
    ],
    "timeline_chronological": [
        ("time", "Time"),
        ("host", "Host"),
        ("activity", "Activity"),
        ("subject", "Subject"),
        ("artifact", "Artifact"),
        ("evidence_id", "Ref"),
    ],
    "technical_accounts": [
        ("account", "Account"),
        ("computer", "Host"),
        ("logons", "4624"),
        ("failed_logons", "4625"),
        ("explicit_credential_events", "4648"),
        ("first_seen", "First seen"),
        ("last_seen", "Last seen"),
    ],
    "technical_execution": [
        ("executable_name", "Executable"),
        ("exec_count", "Exec count"),
        ("last_exec_time", "Last execution"),
        ("evidence_id", "Ref"),
    ],
    "technical_files": [
        ("timestamp", "Timestamp"),
        ("file_name", "File"),
        ("file_path", "Path"),
        ("evidence_id", "Ref"),
    ],
    "technical_antiforensic": [
        ("type", "Type"),
        ("timestamp", "Timestamp"),
        ("artifact", "Artifact"),
        ("context", "Context"),
        ("computer", "Host"),
        ("evidence_id", "Ref"),
    ],
    "technical_network": [
        ("area", "Area"),
        ("observed_rows", "Rows with IP"),
        ("external_src_rows", "External source rows"),
        ("external_dst_rows", "External destination rows"),
        ("interpretation", "Interpretation"),
    ],
    "gaps_unresolved": [
        ("hypothesis", "Hypothesis"),
        ("state", "State"),
        ("reasoning", "Reasoning rows"),
        ("latest", "Latest rationale"),
        ("needed", "Needed evidence"),
    ],
    "gaps_untestable": [
        ("hypothesis", "Hypothesis"),
        ("missing_telemetry", "Missing telemetry"),
        ("rationale", "Rationale"),
        ("next_step", "Next step"),
    ],
    "gaps_confirmed": [
        ("hypothesis", "Hypothesis"),
        ("verdict", "Verdict"),
        ("basis", "Basis"),
        ("benign_context", "Benign context"),
        ("summary", "Summary"),
    ],
    "gaps_evidence": [
        ("gap", "Gap"),
        ("why_it_matters", "Why it matters"),
        ("next_step", "Next step"),
    ],
    "recommendations_action_plan": [
        ("priority", "Priority"),
        ("action", "Action"),
        ("rationale", "Rationale"),
        ("evidence_or_gap", "Evidence/Gap"),
    ],
}


def _table_block_columns(
    builder_name: str, rows: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """Return column definitions for a table builder, with dynamic adjustments."""
    base = _TABLE_COLUMNS.get(builder_name, [("key", "Key"), ("value", "Value")])
    if builder_name == "overview_systems_observed" and any("note" in r for r in rows):
        return [
            ("host", "Host"),
            ("note", "Note"),
            ("events", "EVTX rows"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
        ]
    return base


@lru_cache(maxsize=1)
def _load_table_captions() -> dict[str, dict[str, str]]:
    """Load per-builder caption/empty templates from rulepacks/_schema/report_tables.yaml."""
    import yaml

    path = (
        Path(__file__).resolve().parent.parent
        / "rulepacks"
        / "_schema"
        / "report_tables.yaml"
    )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    tables = data.get("tables") if isinstance(data, dict) else None
    if not isinstance(tables, dict):
        return {}
    return {
        str(name): {str(k): str(v) for k, v in spec.items() if isinstance(v, str)}
        for name, spec in tables.items()
        if isinstance(spec, dict)
    }


def render_table_block(
    db: CaseDB, builder_name: str, *, max_rows: int | None = None
) -> str | None:
    """Render a `mode: table` block deterministically: caption paragraph + table.

    ``max_rows`` controls the number of table rows shown in the Markdown output.
    ``0`` means unlimited. When *None*, the value is read from the per-builder
    ``max_rows:`` key in *report_tables.yaml*; if absent, defaults to ``0``
    (unlimited).

    Returns None when the builder name is unknown (caller falls back to the
    LLM agent). Empty result sets render the declared ``empty`` text instead of
    a bare empty table.
    """
    builder_fn = _TABLE_BLOCK_BUILDERS.get(builder_name)
    if builder_fn is None:
        return None
    rows = builder_fn(db)
    spec = _load_table_captions().get(builder_name) or {}
    if not rows:
        return str(spec.get("empty") or "").strip() or "_No rows available._"
    if max_rows is None:
        try:
            max_rows = int(spec.get("max_rows") or 0)
        except TypeError, ValueError:
            max_rows = 0
    caption = render_rows_template(str(spec.get("caption") or "").strip(), rows).strip()
    table = _markdown_table(
        rows, _table_block_columns(builder_name, rows), max_rows=max_rows
    )
    return f"{caption}\n\n{table}" if caption else table


def _collect_flat_evidence_rows(
    evidence_results: list[dict[str, Any]],
    max_rows: int = 80,
    min_filled_cols: float = 0.5,
) -> list[dict[str, Any]]:
    """Collect unique, non-sparse evidence rows from evidence results, filtering by minimum filled-column ratio."""
    seen: set[str] = set()
    flat: list[dict[str, Any]] = []
    for result in evidence_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        for row in result.get("sample_rows") or []:
            if not isinstance(row, dict):
                continue
            non_empty = 0
            total = 0
            for value in row.values():
                total += 1
                if value is None:
                    continue
                text = str(value).strip()
                if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
                    continue
                non_empty += 1
            if total and (non_empty / total) < min_filled_cols:
                continue
            key = json.dumps(row, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            flat.append(row)
            if len(flat) >= max_rows:
                return flat
    return flat


def _row_to_summary_line(row: dict[str, Any]) -> str:
    """Convert a single evidence row dict into a compact one-line summary string."""
    if not row:
        return "no fields"
    preferred_fields = (
        "timestamp",
        "event_id",
        "record_id",
        "computer",
        "user_name",
        "target_user",
        "subject_user",
        "process_name",
        "service_name",
        "file_path",
        "file_name",
        "src_ip",
        "dst_ip",
        "message",
        "description",
        "command_line",
        "evidence_id",
    )
    parts: list[str] = []
    remaining_keys = [key for key in row.keys() if key not in preferred_fields]
    for key in preferred_fields:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
            continue
        if key == "timestamp":
            parts.append(text)
        elif key in {"message", "description"} and len(text) > 120:
            parts.append(text[:117].rstrip() + "...")
        else:
            parts.append(f"{key}={text}")
    if not parts:
        for key in remaining_keys:
            value = row.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
                continue
            parts.append(f"{key}={text}")
            if len(parts) >= 4:
                break
    return " ".join(parts) if parts else "no usable summary"


def _summarize_flat_evidence_rows(
    rows: list[dict[str, Any]], max_rows: int = 30
) -> list[dict[str, Any]]:
    summarized: list[dict[str, Any]] = []
    for row in rows[:max_rows]:
        summarized.append({"summary": _row_to_summary_line(row)})
    return summarized

