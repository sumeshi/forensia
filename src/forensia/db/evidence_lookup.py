"""Bulk and single evidence-record lookup, shared by the report and API layers.

Table routing by id prefix (evtx-/mft-/prefetch-/registry-). Returns full record rows
(all columns) plus parsed raw_json merged under a ``raw`` key.
"""

from __future__ import annotations

import json
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value

# Prefix-to-table routing stays on canonical artifact records; derived timeline
# rows share their parent's evidence_id and do not define another record.
_PREFIX_TABLES: dict[str, tuple[str, ...]] = {
    "evtx-": ("evtx_events",),
    "mft-": ("mft_entries",),
    "prefetch-": ("prefetch_executions",),
    "registry-": ("registry_artifacts",),
}


def routed_family(evidence_id: str) -> str | None:
    """Return the routing family ('evtx'/'mft'/'prefetch'/'registry') for an id.

    ``None`` means the id matches no routed prefix and its records cannot be
    looked up here.
    """
    eid = str(evidence_id)
    for prefix in _PREFIX_TABLES:
        if eid.startswith(prefix):
            return prefix.rstrip("-")
    return None


def canonical_record_table(family: str) -> str | None:
    """Return the authoritative record table routed for an artifact family."""
    tables = _PREFIX_TABLES.get(f"{str(family).strip().lower()}-")
    return tables[0] if tables else None


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


def find_missing_evidence_ids(db: CaseDB, evidence_ids: list[str]) -> list[str]:
    """Return the subset of *evidence_ids* that resolve in no routed table.

    Authoritative existence check shared by report finalization and quality
    gates; one UNION query per prefix group.
    """
    if not evidence_ids:
        return []
    groups = _group_by_prefix(evidence_ids)
    missing: list[str] = []
    for prefix, tables in _PREFIX_TABLES.items():
        ids = groups.get(prefix)
        if not ids:
            continue
        id_column = "artifact_id" if prefix == "registry-" else "evidence_id"
        placeholders = ", ".join("?" for _ in ids)
        union_sql = " UNION ".join(
            f"SELECT {id_column} FROM {table} WHERE {id_column} IN ({placeholders})"
            for table in tables
        )
        found = {
            str(row[0])
            for row in db.execute(union_sql, tuple(ids * len(tables))).fetchall()
        }
        missing.extend(eid for eid in ids if eid not in found)
    missing.extend(groups.get("unknown", []))
    return missing


def _lookup_table(
    db: CaseDB,
    table: str,
    ids: list[str],
    result: dict[str, dict[str, Any]],
    *,
    id_column: str = "evidence_id",
) -> None:
    placeholders = ", ".join("?" for _ in ids)
    rows = fetch_records(
        db, f"SELECT * FROM {table} WHERE {id_column} IN ({placeholders})", tuple(ids)
    )
    rows_by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        eid = str(row.get(id_column) or "")
        if not eid:
            continue
        previous = rows_by_id.get(eid)
        if previous is not None:
            if previous != row:
                raise ValueError(
                    f"conflicting rows share evidence ID {eid!r} in {table}"
                )
            continue
        rows_by_id[eid] = dict(row)
        if eid in result:
            continue
        row["_source"] = table
        if id_column != "evidence_id":
            row["evidence_id"] = eid
        if table == "prefetch_executions":
            row["exec_times"] = normalize_value(row.get("exec_times"))
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


def fetch_evidence_records(db: CaseDB, ids: list[str]) -> dict[str, dict[str, Any]]:
    """Bulk lookup: return {evidence_id: full_record} for all given IDs.

    Queries the authoritative record table for each id prefix (evtx-, mft-,
    prefetch-, registry-). Derived timeline rows are not evidence records.
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
            _lookup_table(
                db,
                table,
                group,
                result,
                id_column="artifact_id" if prefix == "registry-" else "evidence_id",
            )
    return result


def lookup_evidence_record(db: CaseDB, evidence_id: str) -> dict[str, Any] | None:
    """Single ID lookup via fetch_evidence_records."""
    result = fetch_evidence_records(db, [evidence_id])
    return result.get(evidence_id)
