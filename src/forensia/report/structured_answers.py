from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.core.case import Case, detect_epochs
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.knowledge import (
    catalog_artifact_names,
    catalog_entries,
    catalog_exe_globs,
    catalog_file_patterns,
    catalog_marker,
    catalog_marker_map,
    catalog_values,
    exe_glob_sql,
    expand_catalog_sql_placeholders,
)
from forensia.knowledge import (
    load_event_class_definitions as _load_event_class_definitions,
)
from forensia.questions import (
    evaluate_question_spec_status,
    extract_time_qualifiers,
    project_rows_for_question_spec,
    question_spec_for_answer_spec,
)
from forensia.report.keypoints import _report_keypoint_rows, _sql_like_any
from forensia.report.markdown import (
    _HUMAN_REPORT_HIDDEN_COLUMNS,
    _build_host_note,
    _is_human_report_hidden_column,
    _local_time_from_utc,
    render_rows_template,
)

__all__ = [
    "_add_local_time_columns",
    "_answer_columns",
    "_benchmark_block_id",
    "_benchmark_answers_path",
    "_build_antiforensic_activity",
    "_build_application_execution_history",
    "_build_browser_usage",
    "_build_cloud_service_traces",
    "_build_daily_session_activity",
    "_build_daily_session_timeline",
    "_build_daily_session_timeline_rows",
    "_build_desktop_rename_candidates",
    "_build_generic_question_spec_answer",
    "_build_host_identity",
    "_build_last_human_logon",
    "_build_last_shutdown_event",
    "_build_generic_question_spec_answer",
    "_coerce_answer_items",
    "_coerce_string_list",
    "_collect_answer_evidence_ids",
    "_dedupe_dict_rows",
    "_feed_structured_to_timeline",
    "_human_user_predicate",
    "_is_human_report_hidden_column",
    "_load_benchmark_answers",
    "_load_interpretation_templates",
    "_load_structured_answers",
    "_local_time_from_utc",
    "_lower_blob",
    "_meaningful_missing_reason_items",
    "_normalize_benchmark_answer",
    "_normalize_structured_answer",
    "_persist_benchmark_answer",
    "_persist_structured_answer",
    "_prefetch_executable_from_filename",
    "_render_answer_block",
    "_render_answer_cell",
    "_render_benchmark_answer_markdown",
    "_render_interpretation_template",
    "_render_structured_answer_markdown",
    "_safe_answer_filename",
    "_structured_answer",
    "_structured_answer_interpretation",
    "_structured_answers_path",
    "_structured_block_id",
    "_structured_rows",
    "_text",
    "_TIMESTAMP_COLUMN_SUFFIXES",
    "_HUMAN_REPORT_HIDDEN_COLUMNS",
    "_MISSING_REASON_NOOP_VALUES",
    "_STRUCTURED_ANSWER_BUILDERS",
    "STRUCTURED_MARKDOWN_MAX_CELL_CHARS",
    "STRUCTURED_MARKDOWN_MAX_LIST_ITEMS",
    "STRUCTURED_MARKDOWN_MAX_ROWS",
    "StructuredAnswerBuilder",
    "UNIVERSAL_QUESTION_SPECS",
    "build_structured_answer",
    "ensure_universal_question_probes",
]


def _structured_block_id(block_heading: str) -> str:
    match = re.match(r"\s*(\d+)", str(block_heading or ""))
    if match:
        return f"Q{match.group(1)}"
    return "Q0"


def _benchmark_block_id(block_heading: str) -> str:
    return _structured_block_id(block_heading)


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _coerce_answer_items(value: Any) -> list[Any]:
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                if any(str(v).strip() for v in item.values()):
                    out.append(item)
            else:
                text = str(item).strip()
                if text:
                    out.append(text)
        return out
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _answer_columns(items: list[Any], preferred: Any = None) -> list[str]:
    columns = _coerce_string_list(preferred)
    seen = set(columns)
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in item.keys():
            key_text = str(key)
            if key_text not in seen:
                seen.add(key_text)
                columns.append(key_text)
    return columns


def _normalize_benchmark_answer(
    answer: dict[str, Any],
    *,
    section_key: str,
    block_heading: str,
    status: str,
) -> dict[str, Any]:
    normalized_id = str(
        answer.get("id") or _structured_block_id(block_heading)
    ).strip() or _structured_block_id(block_heading)
    normalized_status = (
        str(answer.get("status") or status or "insufficient_evidence").strip().lower()
    )
    from forensia.core.verdicts import assert_valid_verdict

    try:
        assert_valid_verdict(normalized_status, "structured_status")
    except ValueError:
        normalized_status = status or "insufficient_evidence"
        try:
            assert_valid_verdict(normalized_status, "structured_status")
        except ValueError:
            normalized_status = "insufficient_evidence"
    normalized_answer = _coerce_answer_items(answer.get("answer"))
    normalized_missing = _coerce_string_list(answer.get("missing_reason"))
    normalized_queries = _coerce_string_list(answer.get("queries_run"))
    normalized_columns = _answer_columns(normalized_answer, answer.get("columns"))
    normalized: dict[str, Any] = {
        "id": normalized_id,
        "status": normalized_status,
        "answer": normalized_answer,
        "missing_reason": normalized_missing,
        "queries_run": normalized_queries,
    }
    if normalized_columns:
        normalized["columns"] = normalized_columns
    for key in ("source", "csv_path", "json_path", "answer_spec"):
        value = str(answer.get(key) or "").strip()
        if value:
            normalized[key] = value
    return normalized


def _normalize_structured_answer(
    answer: dict[str, Any],
    *,
    section_key: str,
    block_heading: str,
    status: str,
) -> dict[str, Any]:
    return _normalize_benchmark_answer(
        answer,
        section_key=section_key,
        block_heading=block_heading,
        status=status,
    )


def _structured_answers_path(case: Case) -> Path:
    return case.reports_dir / "structured" / "answers.json"


def _load_structured_answers(case: Case) -> list[dict[str, Any]]:
    path = _structured_answers_path(case)
    if not path.exists():
        return []
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _safe_answer_filename(answer_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(answer_id or "answer")).strip("._")
    return safe or "answer"


def _write_structured_answer_csv(case: Case, answer: dict[str, Any]) -> str:
    items = [item for item in answer.get("answer") or [] if isinstance(item, dict)]
    columns = _answer_columns(items, answer.get("columns"))
    if not columns:
        return ""
    path = (
        case.reports_dir
        / "structured"
        / f"{_safe_answer_filename(str(answer.get('id') or 'answer'))}.csv"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in items:
            row = {}
            for key in columns:
                value = item.get(key, "")
                if isinstance(value, (list, tuple)):
                    row[key] = "; ".join(
                        str(part) for part in value if str(part).strip()
                    )
                elif isinstance(value, dict):
                    row[key] = json.dumps(
                        value, ensure_ascii=False, default=str, sort_keys=True
                    )
                else:
                    row[key] = "" if value is None else str(value)
            writer.writerow(row)
    return f"structured/{path.name}"


def _persist_structured_answer(case: Case, answer: dict[str, Any]) -> None:
    path = _structured_answers_path(case)
    path.parent.mkdir(parents=True, exist_ok=True)
    answer["json_path"] = "structured/answers.json"
    csv_path = _write_structured_answer_csv(case, answer)
    if csv_path:
        answer["csv_path"] = csv_path
    answers = _load_structured_answers(case)
    answers = [
        item
        for item in answers
        if str(item.get("id") or "") != str(answer.get("id") or "")
    ]
    answers.append(answer)
    answers.sort(key=lambda item: str(item.get("id") or ""))
    path.write_text(
        json.dumps(answers, ensure_ascii=False, default=str, indent=2), encoding="utf-8"
    )


def _resolve_max_rows() -> int:
    """Return STRUCTURED_MARKDOWN_MAX_ROWS from config."""
    from forensia.config import settings

    return max(1, settings.structured_markdown_max_rows)


STRUCTURED_MARKDOWN_MAX_ROWS = _resolve_max_rows()
STRUCTURED_MARKDOWN_MAX_LIST_ITEMS = 5
STRUCTURED_MARKDOWN_MAX_CELL_CHARS = 240


def _render_answer_cell(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        parts = [str(part).strip() for part in value if str(part).strip()]
        extra = max(len(parts) - STRUCTURED_MARKDOWN_MAX_LIST_ITEMS, 0)
        value = "; ".join(parts[:STRUCTURED_MARKDOWN_MAX_LIST_ITEMS])
        if extra:
            value = f"{value}; ... (+{extra} more)" if value else f"... (+{extra} more)"
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    text = (
        str(value if value is not None else "")
        .replace("|", "\\|")
        .replace("\n", " ")
        .strip()
    )
    if len(text) > STRUCTURED_MARKDOWN_MAX_CELL_CHARS:
        return (
            text[: STRUCTURED_MARKDOWN_MAX_CELL_CHARS - 15].rstrip()
            + " ... [truncated]"
        )
    return text


def _render_answer_block(
    items: list[Any],
    columns: Any = None,
    *,
    max_rows: int | None = None,
) -> list[str]:
    if max_rows is None:
        max_rows = _resolve_max_rows()
    if not items:
        return ["- no answer"]
    dicts = [item for item in items if isinstance(item, dict)]
    if dicts and len(dicts) == len(items):
        keys = [
            key
            for key in _answer_columns(dicts, columns)
            if not _is_human_report_hidden_column(key)
        ]
        if not keys:
            return ["- no answer"]
        header = "| " + " | ".join(keys) + " |"
        divider = "| " + " | ".join(["---"] * len(keys)) + " |"
        preview = dicts[:max_rows] if max_rows > 0 else dicts
        body_rows = [
            "| " + " | ".join(_render_answer_cell(item.get(key)) for key in keys) + " |"
            for item in preview
        ]
        lines = [header, divider, *body_rows]
        if len(dicts) > len(preview):
            lines.extend(
                [
                    "",
                    f"_Showing {len(preview)} of {len(dicts)} rows. Full data is available in the structured JSON/CSV export._",
                ]
            )
        return lines
    return [
        f"- {str(item).strip()}"
        for item in items
        if not isinstance(item, dict) and str(item).strip()
    ]


_MISSING_REASON_NOOP_VALUES = frozenset({"none", "n/a", "na", "-", "not applicable"})


def _meaningful_missing_reason_items(value: Any) -> list[str]:
    return [
        item
        for item in _coerce_string_list(value)
        if item.strip().lower() not in _MISSING_REASON_NOOP_VALUES
    ]


@lru_cache(maxsize=1)
def _load_interpretation_templates() -> dict[str, str]:
    import yaml

    path = (
        Path(__file__).resolve().parent.parent
        / "rulepacks"
        / "_schema"
        / "question_routing.yaml"
    )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    templates: dict[str, str] = {}
    if not isinstance(data, dict):
        return templates
    question_types = data.get("question_types")
    if not isinstance(question_types, list):
        return templates
    for entry in question_types:
        if not isinstance(entry, dict):
            continue
        spec_key = entry.get("answer_spec") or entry.get("name")
        if not isinstance(spec_key, str):
            continue
        template = entry.get("interpretation_template")
        if isinstance(template, str) and template.strip():
            templates[spec_key] = template.strip()
    return templates


def _render_interpretation_template(template: str, answer: dict[str, Any]) -> str:
    rows = [item for item in list(answer.get("answer") or []) if isinstance(item, dict)]
    return render_rows_template(template, rows)


def _structured_answer_interpretation(
    answer: dict[str, Any], block_heading: str, tz_name: str | None = None
) -> str:
    rows = [item for item in list(answer.get("answer") or []) if isinstance(item, dict)]
    status = str(answer.get("status") or "").strip().lower()
    tz_basis = ""
    if tz_name and tz_name != "UTC":
        tz_basis = f" (timezone: {tz_name})"
    elif tz_name == "UTC":
        tz_basis = " (UTC, timezone undetermined)"
    if not rows:
        base = (
            "No rows directly matching this question were found. Before concluding 'not found', verify that the ingested logs and time range are sufficient."
            if status == "not_found"
            else "Insufficient rows were retrieved for this question. Review the missing reason in the table and determine whether additional evidence exists."
        )
        return base + tz_basis

    row_count = len(rows)
    answer_spec = answer.get("answer_spec") or answer.get("id", "")
    templates = _load_interpretation_templates()
    template = templates.get(answer_spec)
    if template:
        return _render_interpretation_template(template, answer) + tz_basis
    return f"This question has {row_count} rows of structured evidence. The table supports the answer, but evaluate conclusions by correlating time, host, user, and related artifacts.{tz_basis}"


def _render_structured_answer_markdown(
    answer: dict[str, Any], block_heading: str, tz_name: str | None = None
) -> str:
    answer_block = _render_answer_block(
        list(answer.get("answer") or []), answer.get("columns")
    )
    interpretation = _structured_answer_interpretation(
        answer, block_heading, tz_name=tz_name
    )
    missing_lines = [
        f"- {item}"
        for item in _meaningful_missing_reason_items(answer.get("missing_reason"))
    ]
    query_lines = [
        f"- {item}" for item in _coerce_string_list(answer.get("queries_run"))
    ]
    data_lines = (
        [f"- JSON: {answer.get('json_path')}"] if answer.get("json_path") else []
    )
    if answer.get("csv_path"):
        data_lines.append(f"- CSV: {answer.get('csv_path')}")
    if not data_lines:
        data_lines = ["- none"]
    if not query_lines:
        query_lines = ["- none"]
    lines = [
        f"## {block_heading}",
        "",
        f"**ID:** {str(answer.get('id') or _structured_block_id(block_heading))}",
        f"**Status:** {str(answer.get('status') or 'insufficient_evidence')}",
        "",
        "### Interpretation",
        interpretation,
        "",
        "### Answer",
        *answer_block,
        "",
    ]
    status = str(answer.get("status") or "").strip().lower()
    if status != "answered" or missing_lines:
        lines.append("### Missing Reason")
        lines.extend(missing_lines if missing_lines else ["- none"])
        lines.append("")
    lines.extend(
        [
            "### Queries Run",
            *query_lines,
            "",
            "### Structured Data",
            *data_lines,
        ]
    )
    return "\n".join(lines).strip() + "\n"


def _benchmark_answers_path(case: Case) -> Path:
    return _structured_answers_path(case)


def _load_benchmark_answers(case: Case) -> list[dict[str, Any]]:
    return _load_structured_answers(case)


def _persist_benchmark_answer(case: Case, answer: dict[str, Any]) -> None:
    _persist_structured_answer(case, answer)


def _render_benchmark_answer_markdown(
    answer: dict[str, Any], block_heading: str, tz_name: str | None = None
) -> str:
    return _render_structured_answer_markdown(answer, block_heading, tz_name=tz_name)


def _structured_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return [normalize_value(row) for row in _report_keypoint_rows(db, query)]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower_blob(row: dict[str, Any]) -> str:
    return " ".join(
        _text(value).casefold() for value in row.values() if value is not None
    )


def _catalog_path_patterns(section: str) -> tuple[str, ...]:
    patterns: list[str] = []
    for entry in catalog_entries(section):
        for raw in catalog_values(
            entry, "paths", "mft_patterns", "version_sources", "registry"
        ):
            marker = catalog_marker(raw)
            if not marker:
                continue
            patterns.append(f"%{marker}%")
            if "/" in marker:
                backslash_marker = marker.replace("/", "\\")
                patterns.append(f"%{backslash_marker}%")
    return tuple(dict.fromkeys(pattern for pattern in patterns if pattern))


def _like_sql(column: str, patterns: tuple[str, ...] | list[str]) -> str:
    return _sql_like_any(column, *patterns) if patterns else "FALSE"


def _dedupe_dict_rows(
    rows: list[dict[str, Any]], keys: tuple[str, ...]
) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        fingerprint = tuple(_text(row.get(key)).casefold() for key in keys)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(row)
    return out


_TIMESTAMP_COLUMN_SUFFIXES = ("_time", "_Time", "timestamp", "Timestamp")


def _add_local_time_columns(
    rows: list[dict[str, Any]], columns: list[str], case: Case
) -> tuple[list[dict[str, Any]], list[str]]:
    tz_name = getattr(case, "source_timezone", "UTC")
    if tz_name == "UTC":
        return rows, columns
    local_columns: list[str] = []
    ts_cols = [
        c
        for c in columns
        if any(c.endswith(s) or c == s for s in _TIMESTAMP_COLUMN_SUFFIXES)
        or c
        in ("date", "logon_time", "shutdown_time", "last_exec_time", "artifact_time")
    ]
    for col in ts_cols:
        local_col = f"{col}_local"
        if local_col not in columns:
            local_columns.append(local_col)
    if not local_columns:
        return rows, columns
    for row in rows:
        for col in ts_cols:
            local_col = f"{col}_local"
            val = row.get(col)
            if isinstance(val, str) and val:
                local_val = _local_time_from_utc(val, tz_name)
                if local_val:
                    row[local_col] = local_val
    return rows, columns + local_columns


def _structured_answer(
    case: Case,
    *,
    answer_id: str,
    section_key: str,
    block_heading: str,
    rows: list[dict[str, Any]],
    columns: list[str],
    queries_run: list[str],
    status: str | None = None,
    missing_reason: list[str] | None = None,
    source: str = "deterministic_sql",
) -> dict[str, Any]:
    rows, columns = _add_local_time_columns(rows, columns, case)
    resolved_status = status or ("answered" if rows else "not_found")
    answer = _normalize_structured_answer(
        {
            "id": answer_id,
            "status": resolved_status,
            "answer": rows,
            "columns": columns,
            "missing_reason": missing_reason
            or ([] if rows else ["No matching structured database rows were found."]),
            "queries_run": queries_run,
            "source": source,
        },
        section_key=section_key,
        block_heading=block_heading,
        status=resolved_status,
    )
    _persist_structured_answer(case, answer)
    return answer


def _prefetch_executable_from_filename(file_name: Any) -> str:
    name = _text(file_name)
    if not name:
        return ""
    upper = name.upper()
    if upper.endswith(".PF"):
        name = name[:-3]
    return re.sub(r"-[A-Fa-f0-9]{8}$", "", name)


def _human_user_predicate(column: str = "target_user") -> str:
    return f"""
        {column} IS NOT NULL
        AND TRIM({column}) <> ''
        AND {column} NOT LIKE '%$'
        AND UPPER({column}) NOT IN ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
        AND UPPER({column}) NOT LIKE 'DWM-%'
        AND UPPER({column}) NOT LIKE 'UMFD-%'
    """


# ── Builder functions for deterministic structured answers ──────────────────


def _build_host_identity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        WITH raw AS (
          SELECT
              computer,
              COUNT(*) AS evidence_count,
              MIN(timestamp) AS first_seen,
              MAX(timestamp) AS last_seen
          FROM evtx_events
          WHERE computer IS NOT NULL AND TRIM(computer) <> ''
          GROUP BY computer
        )
        SELECT
            ARG_MAX(computer, evidence_count) AS host_id,
            SUM(evidence_count) AS evidence_count,
            MIN(first_seen) AS first_seen,
            MAX(last_seen) AS last_seen
        FROM raw
        GROUP BY UPPER(TRIM(computer))
        ORDER BY evidence_count DESC, host_id
        """,
    )
    rows = _dedupe_dict_rows(rows, ("host_id",))
    try:
        epochs = detect_epochs(db)
        for row in rows:
            host_key = str(row.get("host_id") or "").strip().upper()
            host_epochs = epochs.get(host_key) or []
            if host_epochs:
                row["note"] = _build_host_note(host_epochs)
    except Exception:
        pass
    columns = (
        ["host_id", "note", "evidence_count", "first_seen", "last_seen"]
        if any("note" in r for r in rows)
        else ["host_id", "evidence_count", "first_seen", "last_seen"]
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=columns,
        queries_run=["structured:host_identity:evtx_distinct_hosts"],
    )


def _build_last_human_logon(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    interactive_rows = _structured_rows(
        db,
        f"""
        SELECT
            timestamp AS logon_time,
            computer,
            target_user AS user_name,
            logon_type,
            process_name,
            src_ip,
            evidence_id
        FROM evtx_events
        WHERE event_id = 4624
          AND {_human_user_predicate("target_user")}
          AND CAST(COALESCE(logon_type, '') AS VARCHAR) IN ('2', '7', '10', '11')
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    if interactive_rows:
        rows = interactive_rows
        status = "answered"
        missing: list[str] = []
        label = "structured:last_human_logon:last_interactive_user_logon"
    else:
        rows = _structured_rows(
            db,
            f"""
            SELECT
                timestamp AS logon_time,
                computer,
                target_user AS user_name,
                logon_type,
                process_name,
                src_ip,
                evidence_id
            FROM evtx_events
            WHERE event_id = 4624
              AND {_human_user_predicate("target_user")}
            ORDER BY timestamp DESC
            LIMIT 1
            """,
        )
        status = "partial" if rows else "not_found"
        missing = [] if rows else ["No human-user 4624 logon events were found."]
        if rows:
            missing = [
                "No interactive logon type was found; returned the latest human-user 4624 logon event."
            ]
        label = "structured:last_human_logon:last_human_user_logon_fallback"
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "logon_time",
            "computer",
            "user_name",
            "logon_type",
            "process_name",
            "src_ip",
            "evidence_id",
        ],
        queries_run=[label],
        status=status,
        missing_reason=missing,
    )


def _build_last_shutdown_event(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            timestamp AS shutdown_time,
            event_id,
            computer,
            evidence_id,
            message
        FROM evtx_events
        WHERE (event_id = 1074)
           OR (event_id IN (6006, 6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["shutdown_time", "event_id", "computer", "evidence_id", "message"],
        queries_run=["structured:last_shutdown_event:1074_6006_6008"],
    )


def _build_application_execution_history(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            executable_name,
            SUM(exec_count) AS exec_count,
            MAX(last_exec_time) AS last_exec_time,
            COUNT(*) AS prefetch_records,
            MIN(COALESCE(
              (SELECT MIN(x.executable_path)
               FROM (SELECT UNNEST(TRY_CAST(filenames AS VARCHAR[])) AS executable_path) x
               WHERE x.executable_path LIKE '%' || UPPER(executable_name)),
              source_file
            )) AS executable_path,
            MIN(source_file) AS prefetch_file
        FROM prefetch_executions
        WHERE executable_name IS NOT NULL AND TRIM(executable_name) <> ''
        GROUP BY executable_name
        ORDER BY last_exec_time DESC NULLS LAST
        LIMIT 200
        """,
    )
    if rows:
        return _structured_answer(
            case,
            answer_id=answer_id,
            section_key=section_key,
            block_heading=block_heading,
            rows=rows,
            columns=[
                "executable_name",
                "exec_count",
                "last_exec_time",
                "prefetch_records",
                "executable_path",
                "prefetch_file",
            ],
            queries_run=[
                "structured:application_execution_history:prefetch_executions"
            ],
        )

    mft_rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(extension, '')) = 'pf'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.pf'
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 200
        """,
    )
    rows = [
        {
            "executable_name": _prefetch_executable_from_filename(row.get("file_name")),
            "exec_count": "",
            "last_exec_time": "",
            "prefetch_records": "",
            "executable_path": row.get("file_path"),
            "prefetch_file": row.get("file_name"),
            "artifact_time": row.get("artifact_time"),
            "artifact_path": row.get("file_path"),
            "evidence_id": row.get("evidence_id"),
        }
        for row in mft_rows
    ]
    rows = [row for row in rows if _text(row.get("executable_name"))]
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "executable_name",
            "exec_count",
            "last_exec_time",
            "prefetch_records",
            "executable_path",
            "prefetch_file",
            "artifact_time",
            "artifact_path",
            "evidence_id",
        ],
        queries_run=[
            "structured:application_execution_history:mft_prefetch_file_fallback"
        ],
        status="partial" if rows else "not_found",
        missing_reason=[]
        if not rows
        else [
            "prefetch_executions was empty; returned MFT Prefetch files without execution counts."
        ],
    )


def _build_daily_session_activity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            SUM(CASE WHEN event_id IN (6005, 4608) THEN 1 ELSE 0 END) AS startup,
            SUM(CASE WHEN event_id = 4624 THEN 1 ELSE 0 END) AS logons,
            SUM(CASE WHEN event_id IN (4634, 4647) THEN 1 ELSE 0 END) AS logoff,
            SUM(CASE WHEN event_id IN (1074, 6006, 6008) THEN 1 ELSE 0 END) AS shutdown
        FROM evtx_events
        WHERE timestamp IS NOT NULL
          AND (
            event_id IN (4608, 4624, 4634, 4647, 1074)
            OR (event_id IN (6005, 6006, 6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
          )
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["date", "startup", "logons", "logoff", "shutdown"],
        queries_run=["structured:daily_session_activity:startup_logon_logoff_shutdown"],
    )


def _build_daily_session_timeline_rows(
    db: CaseDB,
    qualifiers: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    classes = _load_event_class_definitions()
    startup_ids = tuple(classes.get("startup", {}).get("event_ids", [6005, 12]))
    shutdown_ids = tuple(classes.get("shutdown", {}).get("event_ids", [6006, 13, 1074]))
    logon_ids = tuple(classes.get("logon", {}).get("event_ids", [4624]))
    logon_types = tuple(classes.get("logon", {}).get("logon_types", [2, 10, 11]))
    logoff_ids = tuple(classes.get("logoff", {}).get("event_ids", [4634, 4647]))

    all_event_ids = sorted(set(startup_ids + shutdown_ids + logon_ids + logoff_ids))
    if not all_event_ids:
        return []

    id_list = ", ".join(str(eid) for eid in all_event_ids)
    startup_list = ", ".join(str(e) for e in startup_ids)
    shutdown_list = ", ".join(str(e) for e in shutdown_ids)
    logon_id_list = ", ".join(str(eid) for eid in logon_ids)
    logon_type_list = ", ".join(str(lt) for lt in logon_types)
    logoff_list = ", ".join(str(e) for e in logoff_ids)

    hour_filter = ""
    qual = qualifiers or {}
    hour_from = qual.get("hour_from")
    hour_to = qual.get("hour_to")
    if hour_from and hour_to:
        hour_filter = (
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) >= '{hour_from}'\n"
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) <= '{hour_to}'\n"
        )

    sql = f"""
    WITH sessions AS (
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            timestamp,
            event_id,
            logon_type,
            target_user
        FROM evtx_events
        WHERE event_id IN ({id_list})
          AND timestamp IS NOT NULL
{hour_filter}
    ),
    daily_agg AS (
        SELECT
            date,
            MIN(CASE WHEN event_id IN ({startup_list}) THEN timestamp END) AS first_startup,
            MIN(CASE WHEN event_id IN ({logon_id_list}) AND logon_type IN ({logon_type_list}) THEN timestamp END) AS first_logon,
            MAX(CASE WHEN event_id IN ({logoff_list}) THEN timestamp END) AS last_logoff,
            MAX(CASE WHEN event_id IN ({shutdown_list}) THEN timestamp END) AS last_shutdown
        FROM sessions
        GROUP BY date
    ),
    daily_logon_users AS (
        SELECT
            date,
            LIST(DISTINCT target_user) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS logon_users_raw,
            COUNT(*) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS interactive_logon_count
        FROM sessions
        WHERE event_id IN ({logon_id_list})
          AND logon_type IN ({logon_type_list})
        GROUP BY date
    )
    SELECT
        d.date,
        d.first_startup,
        d.first_logon,
        d.last_logoff,
        d.last_shutdown,
        CASE
            WHEN LEN(u.logon_users_raw) > 5
            THEN u.logon_users_raw[1:5]
            ELSE u.logon_users_raw
        END AS logon_users,
        u.interactive_logon_count
    FROM daily_agg d
    LEFT JOIN daily_logon_users u ON d.date = u.date
    ORDER BY d.date

    """

    try:
        rows = fetch_records(db, sql)
    except Exception:
        return []

    result: list[dict[str, Any]] = []
    for row in rows:
        entry: dict[str, Any] = {
            "date": str(row.get("date") or ""),
            "first_startup": str(row.get("first_startup") or ""),
            "first_logon": str(row.get("first_logon") or ""),
            "last_logoff": str(row.get("last_logoff") or ""),
            "last_shutdown": str(row.get("last_shutdown") or ""),
            "logon_users": "",
            "interactive_logon_count": int(row.get("interactive_logon_count") or 0),
        }
        raw_users = row.get("logon_users")
        if isinstance(raw_users, list):
            entry["logon_users"] = ", ".join(str(u) for u in raw_users if u)
        result.append(entry)
    return result


def _build_daily_session_timeline(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    qualifiers = extract_time_qualifiers(block_heading)
    rows = _build_daily_session_timeline_rows(db, qualifiers)
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "date",
            "first_startup",
            "first_logon",
            "last_logoff",
            "last_shutdown",
            "logon_users",
            "interactive_logon_count",
        ],
        queries_run=["structured:daily_session_timeline:per_day_session_timeline"],
    )


@lru_cache(maxsize=1)
def _browser_markers() -> dict[str, tuple[str, ...]]:
    return catalog_marker_map(
        "browser_artifacts",
        "name",
        "exe_patterns",
        "paths",
        "version_sources",
    )


def _browser_name_for_row(row: dict[str, Any]) -> str:
    text = _lower_blob(row).replace("\\", "/")
    for name, markers in _browser_markers().items():
        if any(marker.replace("\\", "/") in text for marker in markers):
            return name
    return ""


def _build_browser_usage(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    browser_exe_sql = exe_glob_sql(
        "executable_name", catalog_exe_globs("browser_artifacts")
    )
    browser_file_sql = exe_glob_sql("file_name", catalog_exe_globs("browser_artifacts"))
    browser_path_sql = _like_sql(
        "file_path", _catalog_path_patterns("browser_artifacts")
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE {browser_exe_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    mft_rows = _structured_rows(
        db,
        f"""
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE {browser_file_sql}
           OR {browser_path_sql}
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 100
        """,
    )
    grouped: dict[str, dict[str, Any]] = {}

    def group_for(browser_name: str) -> dict[str, Any]:
        return grouped.setdefault(
            browser_name,
            {
                "browser_name": browser_name,
                "prefetch_records": 0,
                "total_exec_count": 0,
                "last_exec_time": "",
                "mft_artifacts": 0,
                "first_artifact_time": "",
                "last_artifact_time": "",
                "sample_paths": [],
                "evidence_ids": [],
            },
        )

    def append_unique(values: list[Any], value: Any, limit: int) -> None:
        text = _text(value)
        if text and text not in values and len(values) < limit:
            values.append(text)

    def max_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return (
            max(left_text, right_text)
            if left_text and right_text
            else (left_text or right_text)
        )

    def min_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return (
            min(left_text, right_text)
            if left_text and right_text
            else (left_text or right_text)
        )

    for row in prefetch_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["prefetch_records"] = int(item.get("prefetch_records") or 0) + 1
        try:
            item["total_exec_count"] = int(item.get("total_exec_count") or 0) + int(
                row.get("exec_count") or 0
            )
        except TypeError, ValueError:
            pass
        item["last_exec_time"] = max_text_time(
            item.get("last_exec_time"), row.get("last_exec_time")
        )
        append_unique(
            item["sample_paths"],
            row.get("source_file") or row.get("executable_name"),
            10,
        )
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    for row in mft_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["mft_artifacts"] = int(item.get("mft_artifacts") or 0) + 1
        item["first_artifact_time"] = min_text_time(
            item.get("first_artifact_time"), row.get("artifact_time")
        )
        item["last_artifact_time"] = max_text_time(
            item.get("last_artifact_time"), row.get("artifact_time")
        )
        append_unique(
            item["sample_paths"], row.get("file_path") or row.get("file_name"), 10
        )
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    rows = sorted(
        grouped.values(), key=lambda item: str(item.get("browser_name") or "")
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "browser_name",
            "prefetch_records",
            "total_exec_count",
            "last_exec_time",
            "mft_artifacts",
            "first_artifact_time",
            "last_artifact_time",
            "sample_paths",
            "evidence_ids",
        ],
        queries_run=[
            "structured:browser_usage:browser_prefetch",
            "structured:browser_usage:browser_mft_artifacts",
        ],
    )


def _recent_lnk_base_name(file_name: Any) -> str:
    text = _text(file_name)
    if text.lower().endswith(".lnk"):
        text = text[:-4]
    return text.strip()


def _recent_lnk_tokens(file_name: Any) -> set[str]:
    base = _recent_lnk_base_name(file_name).lower()
    base = re.sub(r"\.[a-z0-9]{1,8}$", "", base)
    tokens = {token for token in re.split(r"[^a-z0-9]+", base) if len(token) >= 3}
    return tokens - {"lnk", "desktop", "templates", "drive"}


def _row_time_text(row: dict[str, Any]) -> str:
    for key in ("fn_created", "si_created", "fn_modified", "si_modified"):
        value = _text(row.get(key))
        if value:
            return value
    return ""


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _infer_recent_lnk_rename_candidates(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for left_index, left in enumerate(rows):
        left_tokens = _recent_lnk_tokens(left.get("file_name"))
        left_time = _parse_iso_datetime(_row_time_text(left))
        if not left_tokens or left_time is None:
            continue
        for right in rows[left_index + 1 :]:
            right_tokens = _recent_lnk_tokens(right.get("file_name"))
            right_time = _parse_iso_datetime(_row_time_text(right))
            if not right_tokens or right_time is None:
                continue
            delta_s = abs((right_time - left_time).total_seconds())
            if delta_s > 120:
                continue
            shared = left_tokens & right_tokens
            if not shared:
                continue
            shorter, longer = (left, right)
            shorter_tokens, longer_tokens = left_tokens, right_tokens
            if len(_recent_lnk_base_name(left.get("file_name"))) > len(
                _recent_lnk_base_name(right.get("file_name"))
            ):
                shorter, longer = right, left
                shorter_tokens, longer_tokens = right_tokens, left_tokens
            if not shorter_tokens <= longer_tokens:
                continue
            candidates.append(
                {
                    "original_name": _recent_lnk_base_name(shorter.get("file_name")),
                    "new_name": _recent_lnk_base_name(longer.get("file_name")),
                    "timestamp": max(_row_time_text(left), _row_time_text(right)),
                    "basis": "Windows Recent LNK files created/modified within 120 seconds with overlapping filename tokens",
                    "source_paths": [
                        _text(shorter.get("file_path")),
                        _text(longer.get("file_path")),
                    ],
                    "evidence_ids": [
                        _text(shorter.get("evidence_id")),
                        _text(longer.get("evidence_id")),
                    ],
                }
            )
    deduped = _dedupe_dict_rows(candidates, ("original_name", "new_name", "timestamp"))
    return sorted(
        deduped, key=lambda row: str(row.get("timestamp") or ""), reverse=True
    )[:50]


def _build_desktop_rename_candidates(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            json_extract_string(raw_json, '$.fn_filename') AS original_name,
            file_name AS new_name,
            file_path,
            si_modified,
            fn_modified,
            evidence_id
        FROM mft_entries
        WHERE (
            LOWER(COALESCE(file_path, '')) LIKE '%/desktop/%'
            OR LOWER(COALESCE(file_path, '')) LIKE '%\\desktop\\%'
        )
          AND json_extract_string(raw_json, '$.fn_filename') IS NOT NULL
          AND json_extract_string(raw_json, '$.fn_filename') != file_name
        ORDER BY COALESCE(fn_modified, si_modified) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    queries_run = ["structured:desktop_rename_candidates:mft_filename_pairs"]
    if not rows:
        recent_rows = _structured_rows(
            db,
            """
            SELECT
                file_name,
                file_path,
                si_created,
                si_modified,
                fn_created,
                fn_modified,
                evidence_id
            FROM mft_entries
            WHERE (
                LOWER(COALESCE(file_path, '')) LIKE '%/windows/recent/%'
                OR LOWER(COALESCE(file_path, '')) LIKE '%\\windows\\recent\\%'
            )
              AND LOWER(COALESCE(file_name, '')) LIKE '%.lnk'
            ORDER BY COALESCE(fn_created, si_created, fn_modified, si_modified) NULLS LAST, file_name
            LIMIT 500
            """,
        )
        rows = _infer_recent_lnk_rename_candidates(recent_rows)
        queries_run.append(
            "structured:desktop_rename_candidates:recent_lnk_temporal_alias_pairs"
        )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "original_name",
            "new_name",
            "timestamp",
            "basis",
            "source_paths",
            "evidence_ids",
        ],
        queries_run=queries_run,
        status="partial" if rows else "not_found",
        missing_reason=[]
        if not rows
        else [
            "MFT filename-pair evidence was not available; returned Recent LNK temporal alias candidates."
        ],
    )


@lru_cache(maxsize=1)
def _cloud_markers() -> dict[str, tuple[str, ...]]:
    return catalog_marker_map(
        "cloud_sync_artifacts",
        "service",
        "exe_patterns",
        "paths",
        "registry",
    )


def _build_cloud_service_traces(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    cloud_path_sql = _like_sql(
        "file_path", _catalog_path_patterns("cloud_sync_artifacts")
    )
    cloud_file_sql = _like_sql(
        "file_name",
        [
            *catalog_file_patterns(
                "cloud_sync_artifacts", "exe_patterns", "paths", "prefetch_names"
            )
        ],
    )
    cloud_prefetch_sql = exe_glob_sql(
        "executable_name", catalog_exe_globs("cloud_sync_artifacts")
    )
    mft_rows = _structured_rows(
        db,
        f"""
        SELECT
            file_name,
            file_path,
            is_deleted,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE {cloud_path_sql}
           OR {cloud_file_sql}
        ORDER BY si_modified DESC NULLS LAST, file_path
        LIMIT 200
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE {cloud_prefetch_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    rows: list[dict[str, Any]] = []
    for service_name, markers in _cloud_markers().items():
        service_mft = [
            row
            for row in mft_rows
            if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)
        ]
        service_prefetch = [
            row
            for row in prefetch_rows
            if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)
        ]
        if not service_mft and not service_prefetch:
            continue
        paths = [
            _text(row.get("file_path"))
            for row in service_mft
            if _text(row.get("file_path"))
        ]
        paths.extend(
            _text(row.get("source_file"))
            for row in service_prefetch
            if _text(row.get("source_file"))
        )
        evidence_ids = [
            _text(row.get("evidence_id"))
            for row in [*service_mft, *service_prefetch]
            if _text(row.get("evidence_id"))
        ]
        rows.append(
            {
                "service_name": service_name,
                "exe_found": "yes"
                if service_prefetch
                or any(
                    ".exe" in _lower_blob(row) or ".pf" in _lower_blob(row)
                    for row in service_mft
                )
                else "no",
                "paths_found": paths[:20],
                "config_found": "yes"
                if any(
                    marker in _lower_blob(row)
                    for row in service_mft
                    for marker in ("config", ".db", "snapshot")
                )
                else "no",
                "evidence_ids": evidence_ids[:20],
            }
        )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "service_name",
            "exe_found",
            "paths_found",
            "config_found",
            "evidence_ids",
        ],
        queries_run=[
            "structured:cloud_service_traces:mft_artifacts",
            "structured:cloud_service_traces:prefetch",
        ],
    )


def _build_antiforensic_activity(
    case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str
) -> dict[str, Any]:
    tool_globs = catalog_exe_globs("antiforensic_tools")
    tool_exe_sql = exe_glob_sql("executable_name", tool_globs)
    tool_file_sql = exe_glob_sql("file_name", tool_globs)
    artifact_name_sql = _like_sql(
        "file_name", catalog_artifact_names("antiforensic_tools")
    )
    prefetch_name_sql = _like_sql(
        "file_name", catalog_file_patterns("antiforensic_tools", "prefetch_names")
    )
    tool_markers = [
        markers[0]
        for markers in catalog_marker_map(
            "antiforensic_tools", "name", "exe_patterns", "artifact_names"
        ).values()
        if markers
    ]
    prefetch_path_sql = _like_sql(
        "file_path", [f"%prefetch%{marker}%" for marker in tool_markers]
    )
    event_rows = _structured_rows(
        db,
        """
        SELECT
            'log_integrity_event' AS evidence_type,
            timestamp,
            event_id,
            channel,
            computer,
            target_user,
            evidence_id,
            message
        FROM evtx_events
        WHERE (event_id IN (1100, 1102) AND LOWER(COALESCE(channel, '')) LIKE '%security%')
           OR (event_id = 104 AND LOWER(COALESCE(channel, '')) LIKE '%eventlog%')
        ORDER BY timestamp DESC NULLS LAST
        LIMIT 100
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        f"""
        SELECT
            'tool_execution' AS evidence_type,
            last_exec_time AS timestamp,
            executable_name AS file_name,
            source_file AS file_path,
            evidence_id
        FROM prefetch_executions
        WHERE {tool_exe_sql}
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        LIMIT 50
        """,
    )
    tool_rows = _structured_rows(
        db,
        f"""
        SELECT
            'tool_or_cleanup_artifact' AS evidence_type,
            file_name,
            file_path,
            is_deleted,
            si_created,
            si_modified,
            evidence_id
        FROM mft_entries
        WHERE (
              {artifact_name_sql}
           OR {prefetch_name_sql}
           OR {prefetch_path_sql}
           OR (
                ({tool_file_sql})
                AND (
                    LOWER(COALESCE(file_path, '')) LIKE '%/download/%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%\\download\\%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%/desktop/%'
                    OR LOWER(COALESCE(file_path, '')) LIKE '%\\desktop\\%'
                )
              )
        )
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'windows/system32/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'windows/syswow64/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'program files/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE 'program files (x86)/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%/lang/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%\\lang\\%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%/logs/%'
          AND LOWER(COALESCE(file_path, '')) NOT LIKE '%\\logs\\%'
        ORDER BY COALESCE(si_modified, si_created) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    rows = event_rows + prefetch_rows + tool_rows
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=[
            "evidence_type",
            "timestamp",
            "event_id",
            "channel",
            "computer",
            "target_user",
            "file_name",
            "file_path",
            "is_deleted",
            "si_created",
            "si_modified",
            "evidence_id",
            "message",
        ],
        queries_run=[
            "structured:antiforensic_activity:event_log_clear_events",
            "structured:antiforensic_activity:prefetch_tool_execution",
            "structured:antiforensic_activity:tool_artifacts",
        ],
    )


def _build_generic_question_spec_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    spec = question_spec_for_answer_spec(answer_spec)
    if spec is None or not spec.evidence_chain:
        return None

    rows: list[dict[str, Any]] = []
    queries_run: list[str] = []
    errors: list[str] = []
    for index, entry in enumerate(spec.evidence_chain, start=1):
        query = str(entry.get("query") or "").strip()
        if not query:
            continue
        query = expand_catalog_sql_placeholders(query)
        source = str(entry.get("source") or f"query_{index}").strip()
        label = f"structured:{spec.semantic_id}:{source}"
        queries_run.append(label)
        try:
            source_rows = _structured_rows(db, query)
        except Exception as exc:
            errors.append(f"{source}: {str(exc)[:120]}")
            continue
        for row in source_rows:
            rows.append({**row, "_question_source": source})

    rows = project_rows_for_question_spec(spec, rows)
    status, reasons = evaluate_question_spec_status(spec, rows, queries_run=queries_run)
    if errors:
        reasons.extend(errors)
        if status == "answered":
            status = "partial"
    columns = list(spec.render_columns)
    if not columns and rows:
        columns = [str(key) for key in rows[0].keys() if not str(key).startswith("_")]
    answer = _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=columns,
        queries_run=queries_run,
        status=status,
        missing_reason=reasons,
        source="question_spec",
    )
    if not answer.get("answer_spec"):
        answer["answer_spec"] = answer_spec
        _persist_structured_answer(case, answer)
    return answer


StructuredAnswerBuilder = Callable[[Case, CaseDB, str, str, str], dict[str, Any]]

_STRUCTURED_ANSWER_BUILDERS: dict[str, StructuredAnswerBuilder] = {
    "host_identity": _build_host_identity,
    "last_human_logon": _build_last_human_logon,
    "last_shutdown_event": _build_last_shutdown_event,
    "application_execution_history": _build_application_execution_history,
    "daily_session_activity": _build_daily_session_activity,
    "daily_session_timeline": _build_daily_session_timeline,
    "browser_usage": _build_browser_usage,
    "desktop_rename_candidates": _build_desktop_rename_candidates,
    "cloud_service_traces": _build_cloud_service_traces,
    "antiforensic_activity": _build_antiforensic_activity,
}


def build_structured_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    normalized_spec = str(answer_spec or "").strip().casefold().replace("-", "_")
    if not normalized_spec:
        return None
    spec = question_spec_for_answer_spec(normalized_spec)
    builder_policy = str(getattr(spec, "builder_policy", "") or "").strip().casefold()
    if builder_policy in {"generic", "question_spec", "declarative"}:
        return _build_generic_question_spec_answer(
            case,
            db,
            answer_spec=normalized_spec,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
        )
    builder = _STRUCTURED_ANSWER_BUILDERS.get(normalized_spec)
    if builder is None:
        return _build_generic_question_spec_answer(
            case,
            db,
            answer_spec=normalized_spec,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
        )
    resolved_id = str(answer_id or normalized_spec).strip() or normalized_spec
    answer = builder(case, db, resolved_id, section_key, block_heading)
    if not answer.get("answer_spec"):
        answer["answer_spec"] = normalized_spec
        _persist_structured_answer(case, answer)
    if spec is not None:
        status, reasons = evaluate_question_spec_status(
            spec,
            [item for item in answer.get("answer") or [] if isinstance(item, dict)],
            queries_run=_coerce_string_list(answer.get("queries_run")),
            fallback_status=str(answer.get("status") or ""),
        )
        if status != answer.get("status") or reasons:
            answer["status"] = status
            missing = _coerce_string_list(answer.get("missing_reason"))
            for reason in reasons:
                if reason and reason not in missing:
                    missing.append(reason)
            answer["missing_reason"] = missing
            _persist_structured_answer(case, answer)
    return answer


UNIVERSAL_QUESTION_SPECS: tuple[str, ...] = (
    "host_identity",
    "last_human_logon",
    "last_shutdown_event",
    "application_execution_history",
    "daily_session_activity",
    "daily_session_timeline",
    "browser_usage",
    "email_data_files",
    "cloud_service_traces",
    "antiforensic_activity",
)


def _collect_answer_evidence_ids(value: Any) -> list[str]:
    found: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            single = item.get("evidence_id")
            if single is not None:
                text = str(single).strip()
                if text:
                    found.append(text)
            many = item.get("evidence_ids")
            if isinstance(many, (list, tuple, set)):
                for part in many:
                    text = str(part).strip()
                    if text:
                        found.append(text)
            elif many is not None:
                text = str(many).strip()
                if text:
                    found.append(text)
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return list(dict.fromkeys(found))


def ensure_universal_question_probes(case: Case, db: CaseDB) -> None:
    try:
        existing = db.execute(
            """
            SELECT COUNT(*)
            FROM section_questions
            WHERE section_key = '__case_probe__'
              AND status = 'case_probe'
            """
        ).fetchone()
        if existing is not None and int(existing[0] or 0) >= len(
            UNIVERSAL_QUESTION_SPECS
        ):
            return
    except Exception:
        return

    now = datetime.now(UTC).replace(tzinfo=None)
    for answer_spec in UNIVERSAL_QUESTION_SPECS:
        spec = question_spec_for_answer_spec(answer_spec)
        if spec is None:
            continue
        try:
            answer = build_structured_answer(
                case,
                db,
                answer_spec=answer_spec,
                answer_id=f"probe_{answer_spec}",
                section_key="__case_probe__",
                block_heading=spec.intent or spec.name,
            )
        except Exception:
            answer = None
        question_id = hashlib.sha1(
            f"__case_probe__\n{answer_spec}".encode()
        ).hexdigest()[:20]
        required_evidence = {
            "required_fields": list(spec.required_fields),
            "required_sources": list(spec.required_sources),
            "keypoints": list(spec.keypoints),
            "render_columns": list(spec.render_columns),
            "status_rules": spec.status_rules,
        }
        db.execute(
            """
            INSERT INTO section_questions (
                question_id, section_key, block_heading, question_text, question_type,
                answer_spec, intent, confidence, matched_rule, required_evidence,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (question_id) DO UPDATE SET
                confidence = excluded.confidence,
                required_evidence = excluded.required_evidence,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                question_id,
                "__case_probe__",
                spec.intent or spec.name,
                spec.intent or spec.name,
                spec.name,
                spec.answer_spec,
                spec.intent,
                1.0,
                spec.name,
                json.dumps(required_evidence, ensure_ascii=False, default=str),
                "case_probe",
                now,
                now,
            ),
        )
        if answer is not None:
            evidence_ids = _collect_answer_evidence_ids(answer.get("answer"))
            fact_value = {
                "status": answer.get("status"),
                "answer": answer.get("answer"),
                "columns": answer.get("columns"),
                "evidence_ids": evidence_ids,
            }
            fact_id = hashlib.sha1(
                f"universal_question:{answer_spec}".encode()
            ).hexdigest()[:20]
            db.execute(
                """
                INSERT INTO section_facts (
                    fact_id, fact_type, fact_key, fact_value, evidence_ids,
                    source_query, source_section, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fact_id) DO UPDATE SET
                    fact_value = excluded.fact_value,
                    evidence_ids = excluded.evidence_ids,
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at
                """,
                (
                    fact_id,
                    "universal_question",
                    answer_spec,
                    json.dumps(fact_value, ensure_ascii=False, default=str),
                    json.dumps(evidence_ids, ensure_ascii=False),
                    f"structured:{answer_spec}",
                    "__case_probe__",
                    0.9 if answer.get("status") == "answered" else 0.5,
                    now,
                    now,
                ),
            )
        if (
            answer is not None
            and answer.get("status") in {"answered", "partial"}
            and spec.timeline
        ):
            _feed_structured_to_timeline(db, answer_spec, answer)


def _feed_structured_to_timeline(
    db: CaseDB, spec_name: str, answer: dict[str, Any]
) -> None:
    answer_rows = [
        item for item in (answer.get("answer") or []) if isinstance(item, dict)
    ]
    if not answer_rows:
        return
    for index, row in enumerate(answer_rows[:3]):
        ts = (
            row.get("timestamp")
            or row.get("logon_time")
            or row.get("shutdown_time")
            or row.get("last_exec_time")
            or row.get("artifact_time")
            or row.get("si_modified")
            or row.get("date")
        )
        if not ts:
            continue
        host = row.get("computer") or row.get("host") or ""
        evidence_id = row.get("evidence_id") or ""
        summary_parts = [
            str(row.get(k) or "")
            for k in (
                "event_id",
                "executable_name",
                "file_name",
                "service_name",
                "target_user",
                "message",
            )
            if row.get(k)
        ]
        summary = " ".join(summary_parts)[:200] or spec_name
        entry_id = f"tl-structured-{spec_name}-{index}"
        db.execute(
            """
            INSERT INTO case_timeline (entry_id, timestamp, source, ref_id, host, summary, evidence_id)
            VALUES (?, ?, 'structured', ?, ?, ?, ?)
            ON CONFLICT (entry_id) DO NOTHING
            """,
            (entry_id, ts, spec_name, host, summary, evidence_id),
        )
