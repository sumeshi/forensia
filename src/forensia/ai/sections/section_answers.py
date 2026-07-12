"""Answer extraction and formatting for structured and question blocks."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any

from forensia.ai.sections.section_exec import (
    _is_valid_status,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import catalog_marker_map as _catalog_marker_map
from forensia.knowledge.catalog import catalog_names as _catalog_names
from forensia.knowledge.questions import (
    resolve_question_spec,
)
from forensia.report.answers.answer_builders_host import (
    _build_daily_session_timeline_rows,
)
from forensia.report.answers.answer_store import (
    _normalize_structured_answer,
    _persist_structured_answer,
    _render_structured_answer_markdown,
    _structured_block_id,
)


def _resolve_structured_expected_shape(block_heading: str) -> dict | None:
    """Resolve expected_answer_shape from question_routing.yaml by block_heading keywords."""
    spec, _confidence = resolve_question_spec(block_heading=block_heading)
    return spec.expected_answer_shape if spec is not None else None


def _format_structured_answer(
    classification: dict,
    picked_rows: list[dict],
    expected_shape: dict | None,
    section_key: str,
    block_heading: str,
    status: str,
    case: Case,
    question_id: str = "",
    queries_run: list[str] | None = None,
    evidence_rows: list[dict] | None = None,
    answer_spec: str = "",
) -> str:
    """Pure code. Format a structured answer from picked rows + expected_answer_shape."""
    shape = expected_shape or {}
    fields = shape.get("fields", [])

    answer_data: list[dict] = []
    if fields and picked_rows:
        for row in picked_rows:
            entry = {}
            for field in fields:
                value = row.get(field, row.get(f"normalized_{field}", ""))
                if value is not None and str(value).strip():
                    entry[field] = value
            if entry:
                answer_data.append(entry)

    resolved_id = (
        question_id.strip() if question_id else _structured_block_id(block_heading)
    )
    normalized_status = (
        str(classification.get("status") or status or "insufficient_evidence")
        .strip()
        .lower()
    )
    if not _is_valid_status(normalized_status):
        normalized_status = (
            status if _is_valid_status(status) else "insufficient_evidence"
        )
    # Validate via row indices
    picked_row_indices = classification.get("picked_row_indices") or []
    if isinstance(picked_row_indices, list):
        valid_indices = [
            i
            for i in picked_row_indices
            if isinstance(i, (int, float))
            and evidence_rows
            and 0 <= int(i) < len(evidence_rows)
        ]
    else:
        valid_indices = []
    validated_rows = (
        [evidence_rows[int(i)] for i in valid_indices] if evidence_rows else []
    )
    if not validated_rows and picked_row_indices:
        normalized_status = "wrong_query"
        classification["rationale"] = (
            "no valid evidence rows (picked_row_indices out of range or empty)"
        )
    answer_spec_val = str(answer_spec or "").strip()
    if not answer_spec_val:
        spec, _confidence = resolve_question_spec(block_heading=block_heading)
        answer_spec_val = spec.answer_spec if spec is not None else ""
    normalized_answer = {
        "id": resolved_id,
        "section": section_key,
        "status": normalized_status,
        "answer": answer_data or validated_rows,
        "missing_reason": [str(classification.get("rationale") or "").strip()]
        if classification.get("rationale")
        else [],
        "queries_run": queries_run or [],
        "answer_spec": answer_spec_val,
    }

    answer_items = list(normalized_answer.get("answer") or [])
    if answer_items:
        filtered = []
        for item in answer_items:
            if isinstance(item, dict):
                values = [str(v).strip() for v in item.values() if v is not None]
                if any(values):
                    filtered.append(item)
            elif isinstance(item, str) and item.strip():
                filtered.append(item)
        normalized_answer["answer"] = filtered

    if normalized_answer["status"] in {
        "answered",
        "partial",
    } and not normalized_answer.get("answer"):
        normalized_answer["status"] = "wrong_query"
        reason = str(
            classification.get("rationale") or "answer was empty after filtering"
        ).strip()
        normalized_answer["missing_reason"] = [reason]

    normalized_answer = _normalize_structured_answer(
        normalized_answer,
        section_key=section_key,
        block_heading=block_heading,
        status=normalized_answer["status"],
    )

    _persist_structured_answer(case, normalized_answer)
    return _render_structured_answer_markdown(
        normalized_answer,
        block_heading,
        template_dir=getattr(case, "report_template_dir", None),
    )


def format_question_answer(
    classification: dict,
    picked_rows: list[dict],
    expected_shape: dict | None,
    section_key: str,
    block_heading: str,
    status: str,
    case: Case,
    question_id: str = "",
    queries_run: list[str] | None = None,
    evidence_rows: list[dict] | None = None,
    answer_spec: str = "",
) -> str:
    """Compatibility wrapper for older tests/callers."""
    return _format_structured_answer(
        classification=classification,
        picked_rows=picked_rows,
        expected_shape=expected_shape,
        section_key=section_key,
        block_heading=block_heading,
        status=status,
        case=case,
        question_id=question_id,
        queries_run=queries_run,
        evidence_rows=evidence_rows,
        answer_spec=answer_spec,
    )


@lru_cache(maxsize=1)
def _antiforensic_tool_names() -> tuple[str, ...]:
    """Cleanup-tool names from the IOC catalog (declarative, never hardcoded)."""
    return _catalog_names("antiforensic_tools")


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(value) for value in row.values() if value is not None
    ).casefold()


def _row_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return value
    summary = str(row.get("summary") or "")
    for key in keys:
        match = re.search(rf"\b{re.escape(key)}=([^\s|]+)", summary, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _all_values_empty(item: dict[str, Any]) -> bool:
    return not any(str(value).strip() for value in item.values() if value is not None)


@lru_cache(maxsize=1)
def _application_marker_map() -> dict[str, tuple[str, ...]]:
    markers: dict[str, tuple[str, ...]] = {}
    markers.update(
        _catalog_marker_map(
            "email_artifacts", "client", "exe_patterns", "paths", "data_files"
        )
    )
    markers.update(
        _catalog_marker_map(
            "browser_artifacts",
            "name",
            "exe_patterns",
            "paths",
            "version_sources",
        )
    )
    return markers


@lru_cache(maxsize=1)
def _cloud_service_marker_map() -> dict[str, tuple[str, ...]]:
    return _catalog_marker_map(
        "cloud_sync_artifacts",
        "service",
        "exe_patterns",
        "paths",
        "registry",
    )


def build_daily_session_timeline(
    db: CaseDB,
    qualifiers: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    """Structured answer builder (compatibility shim): delegates to report.answer_registry."""
    return _build_daily_session_timeline_rows(db, qualifiers)


def _extract_daily_table(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    by_date: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        date_value = _row_value(row, "date")
        timestamp = _row_value(row, "timestamp")
        if not date_value and timestamp:
            date_value = str(timestamp)[:10]
        event_id = str(_row_value(row, "event_id") or "").strip()
        if not date_value or not event_id:
            continue
        bucket = by_date.setdefault(
            str(date_value),
            {
                "startup": 0,
                "logons": 0,
                "logoff": 0,
                "shutdown": 0,
                "first_event_time": None,
                "last_event_time": None,
            },
        )
        count = int(row.get("n") or row.get("count") or 1)
        if event_id in {"6005", "4608"}:
            bucket["startup"] += count
        elif event_id == "4624":
            bucket["logons"] += count
        elif event_id in {"4634", "4647"}:
            bucket["logoff"] += count
        elif event_id in {"6006", "6008", "1074", "13"}:
            bucket["shutdown"] += count
        ts = str(timestamp or "")
        if ts:
            if bucket["first_event_time"] is None or ts < bucket["first_event_time"]:
                bucket["first_event_time"] = ts
            if bucket["last_event_time"] is None or ts > bucket["last_event_time"]:
                bucket["last_event_time"] = ts
    return [
        {
            field: (date_value if field == "date" else values.get(field, ""))
            for field in fields
        }
        for date_value, values in sorted(by_date.items())
    ]


def _extract_known_list(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in raw_rows:
        item: dict[str, Any] = {}
        if fields == ["host_id"]:
            host = _row_value(row, "host_id", "computer", "host")
            if host:
                item["host_id"] = host
        elif "executable_name" in fields:
            exe = _row_value(row, "executable_name", "file_name", "process_name")
            if exe:
                item["executable_name"] = exe
            for field in fields:
                if field not in item:
                    value = _row_value(row, field)
                    if value:
                        item[field] = value
        if item and not _all_values_empty(item):
            out.append(item)
    return out


def _extract_name_with_version(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    detected: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        text = _row_text(row)
        for app_name, markers in _application_marker_map().items():
            if any(marker in text for marker in markers):
                item = detected.setdefault(app_name, {field: "" for field in fields})
                if "application_name" in fields:
                    item["application_name"] = app_name
                if "data_files" in fields:
                    data_file = _row_value(row, "file_path", "file_name", "summary")
                    if data_file:
                        existing = str(item.get("data_files") or "")
                        item["data_files"] = (
                            data_file if not existing else f"{existing}; {data_file}"
                        )
                if "version" in fields and not item.get("version"):
                    match = re.search(r"(\d+(?:\.\d+){1,4})", text)
                    if match:
                        item["version"] = match.group(1)
    return [item for item in detected.values() if not _all_values_empty(item)]


def _extract_enumerated_services(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for service_name, markers in _cloud_service_marker_map().items():
        matches = [
            row
            for row in raw_rows
            if any(marker in _row_text(row) for marker in markers)
        ]
        if not matches:
            continue
        item = {field: "" for field in fields}
        if "service_name" in fields:
            item["service_name"] = service_name
        if "exe_found" in fields:
            item["exe_found"] = (
                "yes"
                if any(
                    ".exe" in _row_text(row) or ".pf" in _row_text(row)
                    for row in matches
                )
                else "no"
            )
        if "paths_found" in fields:
            item["paths_found"] = "; ".join(
                str(_row_value(row, "file_path", "summary") or "")
                for row in matches[:3]
            ).strip("; ")
        if "config_found" in fields:
            item["config_found"] = (
                "yes"
                if any(
                    marker in _row_text(row)
                    for row in matches
                    for marker in ("config", ".db", "snapshot")
                )
                else "no"
            )
        rows.append(item)
    return [item for item in rows if not _all_values_empty(item)]


def _extract_pair_list(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        original = _row_value(row, "original_name", "fn_filename")
        new = _row_value(row, "new_name", "file_name")
        if original and new and str(original) != str(new):
            rows.append(
                {
                    field: {
                        "original_name": original,
                        "new_name": new,
                        "timestamp": _row_value(
                            row, "timestamp", "si_modified", "fn_modified"
                        )
                        or "",
                    }.get(field, "")
                    for field in fields
                }
            )
    return rows


def _extract_full_scan(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        text = _row_text(row)
        tool_names = _antiforensic_tool_names()
        tool_markers = tuple(name.casefold() for name in tool_names)
        if not any(
            marker in text
            for marker in (
                *tool_markers,
                "log cleared",
                "event_id=104",
                "event_id=1102",
                "event_id=1100",
            )
        ):
            continue
        item = {field: "" for field in fields}
        if "tool_name" in fields:
            for tool in tool_names:
                if tool.casefold() in text:
                    item["tool_name"] = tool
                    break
            if not item.get("tool_name") and any(
                marker in text for marker in ("104", "1102", "1100")
            ):
                item["tool_name"] = "Windows Event Log"
        if "evidence_type" in fields:
            item["evidence_type"] = "event" if "event_id" in text else "file"
        if "found" in fields:
            item["found"] = "yes"
        if "details" in fields:
            item["details"] = str(
                _row_value(row, "summary", "file_path", "message") or row
            )
        rows.append(item)
    return [item for item in rows if not _all_values_empty(item)]


def extract_answer_by_shape(
    raw_rows: list[dict],
    expected_shape: dict | None,
    shape_format: str,
) -> list[dict]:
    if not raw_rows or not expected_shape:
        return raw_rows or []

    fields = expected_shape.get("fields", [])
    if not fields:
        return raw_rows

    shape_format = str(shape_format or expected_shape.get("format") or "")
    if shape_format == "daily_table":
        return _extract_daily_table(raw_rows, fields)
    if shape_format == "list":
        list_rows = _extract_known_list(raw_rows, fields)
        if list_rows:
            return list_rows
    if shape_format == "name_with_version":
        return _extract_name_with_version(raw_rows, fields)
    if shape_format == "enumerated_services":
        return _extract_enumerated_services(raw_rows, fields)
    if shape_format == "pair_list":
        return _extract_pair_list(raw_rows, fields)
    if shape_format == "full_scan":
        return _extract_full_scan(raw_rows, fields)

    result: list[dict[str, Any]] = []
    for row in raw_rows:
        item = {}
        for f in fields:
            val = row.get(f, row.get(f.lower(), row.get(f.upper(), "")))
            if val is not None and str(val).strip():
                item[f] = val
        if item and not _all_values_empty(item):
            result.append(item)

    return result


def _flatten_sample_rows(
    collected_results: list[dict], *, rows_only: bool = False
) -> list[dict]:
    flat: list[dict] = []
    for r in collected_results:
        if rows_only and str(r.get("kind") or "rows") != "rows":
            continue
        source = r.get("keypoint") or r.get("source_kind") or ""
        for row in r.get("sample_rows") or []:
            if isinstance(row, dict):
                flat.append({**row, "_source_keypoint": source})
    return flat


def is_effectively_empty_body(body: str) -> bool:
    """Return True when narration produced no useful prose beyond a status marker."""
    text = str(body or "").strip()
    if not text:
        return True
    text = re.sub(r"^\*\*Status:\*\*\s*[A-Za-z_]+\s*", "", text).strip()
    text = re.sub(r"^#+\s+.+$", "", text, flags=re.MULTILINE).strip()
    text = re.sub(r"\*Block skipped:[^*]+\*", "", text, flags=re.IGNORECASE).strip()
    return len(text) < 40


def _report_language() -> str:
    try:
        from forensia.config import get_llm_settings

        return str(get_llm_settings().get("output_language", "ja")).strip().lower()
    except Exception:
        return "ja"


def _insufficient_evidence_placeholder() -> str:
    """Neutral reader-facing text for blocks whose evidence status blocks narration.

    Deliberately avoids quality-gate trigger phrases (failure markers,
    open-question markers, hedge words without citations).
    """
    return "No sufficient evidence was collected for this block. Details are tracked in the Investigation Gaps section."


def _compact_narrative_value(value: Any, *, max_chars: int = 90) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value if value is not None else "")
    text = text.replace("\n", " ").strip()
    if text in {"", "-", "None", "null"}:
        return ""
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def _result_source_label(result: dict[str, Any]) -> str:
    for key in ("keypoint", "source_kind", "source_ref", "description"):
        value = _compact_narrative_value(result.get(key), max_chars=64)
        if value:
            if value.lower().startswith("select "):
                return "evidence_query"
            return value
    return "unknown_source"


def _representative_ids(
    collected_results: list[dict[str, Any]], flat_rows: list[dict[str, Any]]
) -> tuple[list[str], list[str]]:
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    seen_evidence: set[str] = set()
    seen_findings: set[str] = set()

    def add_evidence(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in seen_evidence:
            seen_evidence.add(text)
            evidence_ids.append(text)

    def add_finding(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in seen_findings:
            seen_findings.add(text)
            finding_ids.append(text)

    for result in collected_results:
        for evidence_id in result.get("evidence_ids") or []:
            add_evidence(evidence_id)
        for finding_id in result.get("finding_ids") or []:
            add_finding(finding_id)
    for row in flat_rows:
        add_evidence(row.get("evidence_id"))
        add_finding(row.get("finding_id"))
    return evidence_ids[:3], finding_ids[:3]
