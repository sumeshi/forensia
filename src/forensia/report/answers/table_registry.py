"""Registry and rendering of report table blocks."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from forensia.core.log import log as _log
from forensia.db.database import CaseDB
from forensia.knowledge.resources import schema_dir
from forensia.report.answers.gap_tables import (
    _build_evidence_gaps_table,
    _build_gaps_confirmed_table,
    _build_gaps_unresolved_table,
    _build_gaps_untestable_table,
)
from forensia.report.answers.summary_rows import (
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
from forensia.report.finding_themes import (
    _build_key_findings_table,
    _build_recommendations_table,
)
from forensia.report.render.markdown import (
    _markdown_table,
    render_rows_template,
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


@dataclass(frozen=True)
class TableSpec:
    """One entry in the unified TABLE_BLOCKS registry."""

    builder: Callable[[CaseDB], list[dict[str, Any]]]
    columns: tuple[tuple[str, str], ...] | None  # None = use default
    optional_keys: tuple[str, ...] = ("evidence_id",)
    source_tables: tuple[str, ...] = ()
    source_families: tuple[str, ...] = ()
    query_description: str = ""


def source_receipt_metadata(db: CaseDB, spec: TableSpec) -> dict[str, object]:
    """Return canonical table recipe and current evidence source receipt metadata."""
    rows = (
        db.execute(
            """
            SELECT source_id, artifact_family, ingest_status, parser_name,
                   parser_version, row_count, channel, CAST(hosts AS VARCHAR),
                   volume_id, CAST(min_time AS VARCHAR), CAST(max_time AS VARCHAR),
                   error_code
            FROM evidence_sources
            WHERE artifact_family IN (SELECT UNNEST(?))
            ORDER BY source_id
            """,
            [list(spec.source_families)],
        ).fetchall()
        if spec.source_families
        else []
    )
    encoded = json.dumps(
        rows, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")
    )
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return {
        "source_tables": list(spec.source_tables),
        "source_families": list(spec.source_families),
        "query_description": spec.query_description,
        "source_ids": [str(row[0]) for row in rows],
        "source_receipt_sha256": digest,
    }


@dataclass
class TableValidationError:
    """Structured validation error for a table builder output."""

    builder_name: str
    error_type: (
        str  # "missing_required", "all_empty", "unknown_keys", "schema_mismatch"
    )
    message: str
    details: str | None = None


def _validate_table_output(
    builder_name: str,
    rows: list[dict[str, Any]],
    columns: list[tuple[str, str]],
    optional_keys: tuple[str, ...] = (),
) -> list[TableValidationError]:
    """Validate builder output against declared column schema.

    Returns a list of validation errors (empty if valid).
    """
    errors: list[TableValidationError] = []
    if not rows:
        return errors

    col_keys = {k for k, _ in columns}
    row_keys = {k for row in rows for k in row}
    unknown_keys = row_keys - col_keys

    if unknown_keys:
        errors.append(
            TableValidationError(
                builder_name=builder_name,
                error_type="unknown_keys",
                message=f"Builder produced keys not in schema: {sorted(unknown_keys)}",
                details=f"Schema keys: {sorted(col_keys)}",
            )
        )

    # Requiredness is a schema property, never inferred from a display label.
    required_cols = [(k, label) for k, label in columns if k not in optional_keys]
    for col_key, col_label in required_cols:
        all_empty = all(
            row.get(col_key) in (None, "", "-", "None", "null", "N/A") for row in rows
        )
        if all_empty:
            errors.append(
                TableValidationError(
                    builder_name=builder_name,
                    error_type="all_empty",
                    message=f"Required column '{col_label}' ({col_key}) is empty in all {len(rows)} rows",
                    details="Builder may not be producing the correct key names",
                )
            )

    return errors


TABLE_BLOCKS: dict[str, TableSpec] = {
    "overview_evidence_scope": TableSpec(
        builder=_build_evidence_scope_table,
        columns=(
            ("metric", "Metric"),
            ("value", "Value"),
            ("scope", "Scope"),
        ),
        source_tables=(
            "evidence_sources",
            "evidence_coverage",
            "evtx_events",
            "mft_entries",
            "prefetch_executions",
            "registry_artifacts",
        ),
        source_families=("evtx", "mft", "prefetch", "registry"),
        query_description="normalized row counts by artifact family, source receipt counts and rows/status, capability coverage, and distinct EVTX channels",
    ),
    "overview_systems_observed": TableSpec(
        builder=_build_systems_observed_table,
        columns=(
            ("host", "Host"),
            ("events", "EVTX rows"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
        ),
        source_tables=("evtx_events",),
        source_families=("evtx",),
        query_description="non-empty computers grouped case-insensitively, ordered by event count, limited to 5",
    ),
    "overview_key_findings": TableSpec(
        builder=_build_key_findings_table,
        columns=(
            ("finding", "Finding"),
            ("severity", "Severity"),
            ("confidence", "Confidence"),
            ("why_it_matters", "Why it matters"),
            ("reference", "Ref"),
        ),
        optional_keys=("reference",),
        source_tables=("findings",),
        query_description="current report key findings",
    ),
    "timeline_phase_summary": TableSpec(
        builder=_build_timeline_phase_table,
        columns=(
            ("date", "Date"),
            ("phase", "Observed activity"),
            ("interpretation", "Interpretation"),
            ("window", "Event window"),
        ),
        source_tables=("evtx_events", "prefetch_executions"),
        source_families=("evtx", "prefetch"),
        query_description="phase summary derived from the bounded chronological activity rows",
    ),
    "timeline_chronological": TableSpec(
        builder=_build_timeline_chronological_table,
        columns=(
            ("time", "Time"),
            ("host", "Host"),
            ("activity", "Activity"),
            ("subject", "Subject"),
            ("artifact", "Artifact"),
            ("evidence_id", "Ref"),
        ),
        source_tables=("evtx_events", "prefetch_executions"),
        source_families=("evtx", "prefetch"),
        query_description="event-context-filtered EVTX rows (up to 80) and notable Prefetch executions (up to 12), ordered by time",
    ),
    "technical_accounts": TableSpec(
        builder=_build_accounts_table,
        columns=(
            ("account", "Account"),
            ("computer", "Host"),
            ("logons", "4624"),
            ("failed_logons", "4625"),
            ("explicit_credential_events", "4648"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
            ("evidence_id", "Evidence ID"),
        ),
        source_tables=("evtx_events",),
        source_families=("evtx",),
        query_description="context-valid events 4624, 4625, and 4648 grouped by account and host; top 10",
    ),
    "technical_execution": TableSpec(
        builder=_build_execution_table,
        columns=(
            ("executable", "Executable"),
            ("execution_count", "Execution count"),
            ("last_execution", "Last execution"),
            ("evidence_id", "Ref"),
        ),
        source_tables=("prefetch_executions",),
        source_families=("prefetch",),
        query_description="deterministic execution summary from Prefetch rows",
    ),
    "technical_files": TableSpec(
        builder=_build_file_artifacts_table,
        columns=(
            ("timestamp", "Timestamp"),
            ("file_name", "File"),
            ("file_path", "Path"),
            ("evidence_id", "Ref"),
        ),
        source_tables=("mft_entries",),
        source_families=("mft",),
        query_description="deterministic file artifact rows from normalized MFT entries",
    ),
    "technical_antiforensic": TableSpec(
        builder=_build_antiforensic_table,
        columns=(
            ("type", "Type"),
            ("timestamp", "Timestamp"),
            ("artifact", "Artifact"),
            ("context", "Context"),
            ("computer", "Host"),
            ("evidence_id", "Ref"),
        ),
        source_tables=("findings", "evtx_events", "prefetch_executions", "mft_entries"),
        source_families=("evtx", "prefetch", "mft"),
        query_description="deterministic anti-forensic observations and linked findings",
    ),
    "technical_network": TableSpec(
        builder=_build_network_table,
        columns=(
            ("area", "Area"),
            ("ip_address", "IP address"),
            ("outbound_rows", "Outbound rows"),
            ("inbound_rows", "Inbound rows"),
            ("interpretation", "Interpretation"),
        ),
        source_tables=("evtx_events",),
        source_families=("evtx",),
        query_description="normalized network activity grouped by area and IP address",
    ),
    "gaps_unresolved": TableSpec(
        builder=_build_gaps_unresolved_table,
        columns=(
            ("hypothesis_id", "Hypothesis ID"),
            ("hypothesis", "Hypothesis"),
            ("status", "State"),
            ("evidence_rows", "Linked evidence"),
            ("missing_rationale", "Missing rationale"),
            ("next_step", "Next step"),
            ("task_id", "Task / admission state"),
            ("gap_id", "Gap / admission state"),
        ),
        source_tables=("hypotheses", "investigation_tasks", "report_gaps"),
        query_description="unresolved hypotheses joined to their admitted open/in-progress Tasks and linked Gaps",
    ),
    "gaps_untestable": TableSpec(
        builder=_build_gaps_untestable_table,
        columns=(
            ("hypothesis_id", "Hypothesis ID"),
            ("hypothesis", "Hypothesis"),
            ("missing_telemetry", "Missing telemetry"),
            ("rationale", "Rationale"),
            ("next_step", "Next step"),
            ("task_id", "Task / admission state"),
            ("gap_id", "Gap / admission state"),
        ),
        source_tables=("hypotheses", "investigation_tasks", "report_gaps"),
        query_description="untestable hypotheses joined to their admitted open/in-progress Tasks and linked Gaps",
    ),
    "gaps_confirmed": TableSpec(
        builder=_build_gaps_confirmed_table,
        columns=(
            ("hypothesis", "Hypothesis"),
            ("verdict", "Verdict"),
            ("evidence_basis", "Basis"),
            ("related_context", "Related context"),
            ("summary", "Summary"),
        ),
        source_tables=("hypotheses", "hypothesis_evidence", "claims"),
        query_description="settled confirmed hypotheses with linked evidence and related context",
    ),
    "gaps_evidence": TableSpec(
        builder=_build_evidence_gaps_table,
        columns=(
            ("gap", "Gap"),
            ("why_it_matters", "Why it matters"),
            ("next_step", "Next step"),
        ),
        source_tables=("report_gaps", "investigation_tasks"),
        query_description="admitted evidence gaps and their linked Tasks",
    ),
    "recommendations_action_plan": TableSpec(
        builder=_build_recommendations_table,
        columns=(
            ("priority", "Priority"),
            ("action", "Action"),
            ("rationale", "Rationale"),
            ("evidence_or_gap", "Evidence/Gap"),
            ("validation", "Validation criterion"),
        ),
        source_tables=("report_gaps", "investigation_tasks", "hypotheses"),
        query_description="recommendations derived from current unresolved work",
    ),
}


def register_table_block(
    name: str,
    builder: Callable[[CaseDB], list[dict[str, Any]]],
    columns: tuple[tuple[str, str], ...] | None = None,
    *,
    replace: bool = False,
) -> None:
    """Register a deterministic ``mode: table`` block renderer."""
    normalized = str(name).strip()
    if not normalized:
        raise ValueError("table block name must not be empty")
    if normalized in TABLE_BLOCKS and not replace:
        raise ValueError(f"table block already registered: {normalized}")
    TABLE_BLOCKS[normalized] = TableSpec(builder=builder, columns=columns)


def _table_block_columns(
    builder_name: str, rows: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """Return column definitions for a table builder, with dynamic adjustments."""
    spec = TABLE_BLOCKS.get(builder_name)
    base = (
        list(spec.columns)
        if spec and spec.columns
        else [("key", "Key"), ("value", "Value")]
    )
    if builder_name == "overview_systems_observed" and any("note" in r for r in rows):
        base = [
            ("host", "Host"),
            ("note", "Note"),
            ("events", "EVTX rows"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
        ]
    from forensia.config import get_llm_settings

    language = str(get_llm_settings().get("output_language", "ja")).casefold()
    localized = (_load_table_captions().get(builder_name) or {}).get(
        f"columns_{language}"
    )
    if isinstance(localized, dict):
        base = [(key, str(localized.get(key) or label)) for key, label in base]
    return base


@lru_cache(maxsize=1)
def _load_table_captions() -> dict[str, dict[str, Any]]:
    """Load per-builder caption/empty templates from data/schema/report_tables.yaml."""
    import yaml

    path = schema_dir() / "report_tables.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    tables = data.get("tables") if isinstance(data, dict) else None
    if not isinstance(tables, dict):
        return {}
    return {
        str(name): {str(k): v for k, v in spec.items()}
        for name, spec in tables.items()
        if isinstance(spec, dict)
    }


def render_table_block(
    db: CaseDB,
    builder_name: str,
    *,
    max_rows: int | None = None,
    rows: list[dict[str, Any]] | None = None,
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
    table_spec = TABLE_BLOCKS.get(builder_name)
    builder_fn = table_spec.builder if table_spec else None
    if builder_fn is None:
        return None
    rows = builder_fn(db) if rows is None else rows
    caption_spec = _load_table_captions().get(builder_name) or {}
    from forensia.config import get_llm_settings

    language = str(get_llm_settings().get("output_language", "ja")).casefold()
    if not rows:
        empty = caption_spec.get(f"empty_{language}") or caption_spec.get("empty")
        return str(empty or "").strip() or "_No rows available._"
    if max_rows is None:
        try:
            max_rows = int(caption_spec.get("max_rows") or 0)
        except TypeError, ValueError:
            max_rows = 0
    columns = _table_block_columns(builder_name, rows)
    validation_errors = _validate_table_output(
        builder_name,
        rows,
        columns,
        optional_keys=table_spec.optional_keys,
    )
    if validation_errors:
        for error in validation_errors:
            _log(
                "VALIDATION",
                f"table_schema: {error.message}",
                level="error",
            )
    caption_template = caption_spec.get(f"caption_{language}") or caption_spec.get(
        "caption"
    )
    caption = render_rows_template(str(caption_template or "").strip(), rows).strip()
    table = _markdown_table(rows, columns, max_rows=max_rows)
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
        "first_event",
        "last_event",
        "event_count",
        "evidence_count",
        "_source_keypoint",
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
        "representative_evidence_ids",
        "evidence_distribution",
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


collect_flat_evidence_rows = _collect_flat_evidence_rows
summarize_flat_evidence_rows = _summarize_flat_evidence_rows
