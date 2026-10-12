from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from forensia.db.database import CaseDB


def fetch_records(
    db: CaseDB, query: str, params: Sequence[Any] | None = None
) -> list[dict[str, Any]]:
    """Execute a query and return results as a list of dicts (column name → value)."""
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def fetch_bounded_records(
    db: CaseDB, query: str, *, max_rows: int
) -> tuple[list[dict[str, Any]], bool]:
    """Fetch an already bounded query plus one sentinel row."""
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    result = db.execute(query)
    columns = [item[0] for item in result.description]
    fetched = result.fetchmany(max_rows + 1)
    truncated = len(fetched) > max_rows
    return (
        [dict(zip(columns, row, strict=False)) for row in fetched[:max_rows]],
        truncated,
    )


def normalize_value(value: Any) -> Any:
    """Normalize database values: JSON-parse stringified JSON, ISO-format datetimes, recurse into lists/dicts."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_value(item) for key, item in value.items()}
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                return normalize_value(json.loads(stripped))
            except json.JSONDecodeError:
                return value
    return value


def summarize_query_result(
    rows: list[dict[str, Any]], sample_size: int = 10
) -> dict[str, Any]:
    """Summarize SQL query rows for checker and report-section consumers."""
    head_size = min(max(sample_size // 2, 1), sample_size) if sample_size > 0 else 0
    tail_size = max(sample_size - head_size, 0)
    head_rows = rows[:head_size]
    tail_rows = rows[-tail_size:] if tail_size else []
    if tail_rows and head_rows:
        last_head_index = len(head_rows) - 1
        first_tail_index = len(rows) - len(tail_rows)
        if first_tail_index <= last_head_index:
            tail_rows = []
    sample_rows = head_rows + tail_rows
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    finding_ids_by_evidence: dict[str, str] = {}
    for row in sample_rows:
        value = row.get("evidence_id") or row.get("artifact_id")
        normalized = str(value).strip() if value else ""
        if normalized and normalized not in evidence_ids:
            evidence_ids.append(normalized)
        finding = str(row.get("finding_id") or "").strip()
        if finding and finding not in finding_ids:
            finding_ids.append(finding)
        if normalized and finding:
            finding_ids_by_evidence.setdefault(normalized, finding)
    distinct_counts = {
        column: len({row.get(column) for row in rows if row.get(column)})
        for column in ("target_user", "computer", "src_ip", "event_id")
        if any(row.get(column) for row in rows)
    }

    event_id_set: set[int] = set()
    for row in rows:
        try:
            event_id_set.add(int(row.get("event_id")))
        except TypeError, ValueError:
            pass

    return {
        "row_count": len(rows),
        "head_rows": head_rows,
        "tail_rows": tail_rows,
        "sample_rows": sample_rows,
        "distinct_counts": distinct_counts,
        "evidence_ids": evidence_ids,
        "event_id_set": sorted(event_id_set),
        "finding_ids": finding_ids,
        "finding_ids_by_evidence": finding_ids_by_evidence,
    }


def findings_snapshot(
    db: CaseDB, limit: int = 12, *, include_evidence: bool = False
) -> list[dict[str, Any]]:
    """Fetch top findings ordered by confidence for prompts and reports."""
    columns = "finding_id, title, severity, confidence, status, summary"
    if include_evidence:
        columns += ", evidence"
    return fetch_records(
        db,
        f"""
        SELECT {columns}
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
