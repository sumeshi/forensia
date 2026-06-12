"""Bulk and single evidence-record lookup, shared by the report and API layers.

Table routing by id prefix (evtx-/mft-/prefetch-). Returns full record rows
(all columns) plus parsed raw_json merged under a ``raw`` key.
"""
from __future__ import annotations

import json
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


# Prefix-to-table routing: prefetch IDs may live in either table.
_PREFIX_TABLES: dict[str, tuple[str, ...]] = {
    "evtx-": ("evtx_events",),
    "mft-": ("mft_entries",),
    "prefetch-": ("prefetch_executions", "prefetch_timeline"),
}


def _group_by_prefix(ids: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for eid in ids:
        eid_str = str(eid)
        matched = False
        for prefix in _PREFIX_TABLES:
            if eid_str.startswith(prefix):
                groups.setdefault(prefix, []).append(eid_str)
                matched = True
                break
        if not matched:
            groups.setdefault("unknown", []).append(eid_str)
    return groups


def _lookup_table(
    db: CaseDB, table: str, ids: list[str], result: dict[str, dict[str, Any]]
) -> None:
    placeholders = ", ".join("?" for _ in ids)
    rows = fetch_records(
        db, f"SELECT * FROM {table} WHERE evidence_id IN ({placeholders})", tuple(ids)
    )
    for row in rows:
        eid = str(row.get("evidence_id") or "")
        if not eid or eid in result:
            continue
        row["_source"] = table
        raw_val = row.pop("raw_json", None)
        if raw_val is not None:
            if isinstance(raw_val, str):
                try:
                    row["raw"] = json.loads(raw_val)
                except json.JSONDecodeError:
                    row["raw"] = raw_val
            else:
                row["raw"] = raw_val
        result[eid] = row


def fetch_evidence_records(
    db: CaseDB, ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Bulk lookup: return {evidence_id: full_record} for all given IDs.

    Queries evtx_events, mft_entries, prefetch_executions, and
    prefetch_timeline based on the id prefix (evtx-, mft-, prefetch-).
    Full record includes all table columns plus a ``raw`` key with the
    parsed ``raw_json`` (if any).
    """
    result: dict[str, dict[str, Any]] = {}
    grouped = _group_by_prefix(ids)
    for prefix, tables in _PREFIX_TABLES.items():
        group = grouped.get(prefix)
        if not group:
            continue
        for table in tables:
            _lookup_table(db, table, group, result)
    return result


def lookup_evidence_record(
    db: CaseDB, evidence_id: str
) -> dict[str, Any] | None:
    """Single ID lookup via fetch_evidence_records."""
    result = fetch_evidence_records(db, [evidence_id])
    return result.get(evidence_id)
