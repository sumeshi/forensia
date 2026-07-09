"""Structured-answer infrastructure: normalize, persist, and render answers."""

from __future__ import annotations

import csv
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.core.textutil import (
    is_local_ingest_path,
    path_basename,
    sanitize_ingest_path,
)
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value
from forensia.knowledge import (
    catalog_entries,
    catalog_marker,
    catalog_values,
)
from forensia.report.evidence_refs import _report_keypoint_rows, _sql_like_any
from forensia.report.markdown import (
    _is_human_report_hidden_column,
    _local_time_from_utc,
    render_rows_template,
)


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


# Shared implementations live in core/textutil so the rules engine can
# sanitize finding evidence without a report-layer import. These aliases
# keep the established local names.
def _is_local_ingest_path(path: Any) -> bool:
    return is_local_ingest_path(_text(path))


def _strip_path_basename(path: Any) -> str:
    return path_basename(_text(path))


def _sanitize_prefetch_path(path: Any) -> str:
    return sanitize_ingest_path(_text(path))


def _human_user_predicate(column: str = "target_user") -> str:
    return f"""
        {column} IS NOT NULL
        AND TRIM({column}) <> ''
        AND {column} NOT LIKE '%$'
        AND UPPER({column}) NOT IN ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
        AND UPPER({column}) NOT LIKE 'DWM-%'
        AND UPPER({column}) NOT LIKE 'UMFD-%'
    """

