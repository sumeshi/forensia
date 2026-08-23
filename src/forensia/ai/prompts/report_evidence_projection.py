"""Deterministic, semantic evidence projection for report LLM prompts.

Persisted query results and their complete evidence-id sets remain authoritative.
This module creates a copy for report prompts, replacing only large opaque ID
arrays with citable representatives and evidence-derived coverage metadata.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from forensia.core.timeutil import parse_epoch_seconds
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records

_LARGE_EVIDENCE_SET = 20
_MAX_REPRESENTATIVES = 10
_MAX_DISTRIBUTION_VALUES = 6

_METADATA_QUERIES: tuple[tuple[str, str, str], ...] = (
    (
        "evtx-",
        "evtx_events",
        "SELECT evidence_id, timestamp, channel AS source_family, computer AS host, "
        "COALESCE(target_user, user_name, subject_user) AS user_name, event_id "
        "FROM evtx_events WHERE evidence_id IN ({placeholders})",
    ),
    (
        "mft-",
        "mft_entries",
        "SELECT evidence_id, COALESCE(si_modified, fn_modified, si_created, fn_created) AS timestamp, "
        "'mft' AS source_family, NULL AS host, NULL AS user_name, extension AS event_id "
        "FROM mft_entries WHERE evidence_id IN ({placeholders})",
    ),
    (
        "prefetch-",
        "prefetch_executions",
        "SELECT evidence_id, last_exec_time AS timestamp, 'prefetch' AS source_family, "
        "NULL AS host, NULL AS user_name, executable_name AS event_id "
        "FROM prefetch_executions WHERE evidence_id IN ({placeholders})",
    ),
    (
        "prefetch-",
        "prefetch_timeline",
        "SELECT evidence_id, exec_time AS timestamp, 'prefetch' AS source_family, "
        "NULL AS host, NULL AS user_name, executable_name AS event_id "
        "FROM prefetch_timeline WHERE evidence_id IN ({placeholders})",
    ),
    (
        "registry-",
        "registry_artifacts",
        "SELECT artifact_id AS evidence_id, timestamp, "
        "COALESCE(plugin, 'registry') AS source_family, NULL AS host, NULL AS user_name, "
        "hive AS event_id FROM registry_artifacts WHERE artifact_id IN ({placeholders})",
    ),
)


def _artifact_family(evidence_id: str) -> str:
    return evidence_id.split("-", 1)[0] if "-" in evidence_id else "unknown"


def _fetch_prompt_metadata(
    db: CaseDB, evidence_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Read only the fields needed for representative selection and coverage."""
    result: dict[str, dict[str, Any]] = {}
    for prefix, table, query in _METADATA_QUERIES:
        ids = [item for item in evidence_ids if item.startswith(prefix)]
        if not ids:
            continue
        placeholders = ", ".join("?" for _ in ids)
        try:
            rows = fetch_records(db, query.format(placeholders=placeholders), tuple(ids))
        except Exception:
            # Older/incomplete cases may not contain every routed table. Other
            # families can still be projected without weakening ID validation.
            continue
        for row in rows:
            evidence_id = str(row.get("evidence_id") or "").strip()
            if not evidence_id or evidence_id in result:
                continue
            result[evidence_id] = {
                "evidence_id": evidence_id,
                "timestamp": row.get("timestamp"),
                "artifact_family": _artifact_family(evidence_id),
                "source_family": row.get("source_family") or table,
                "host": row.get("host"),
                "user": row.get("user_name"),
                "event_family": row.get("event_id"),
            }
    return result


def _value_key(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _timestamp_key(record: dict[str, Any]) -> tuple[int, float, str]:
    parsed = parse_epoch_seconds(record.get("timestamp"))
    return (
        0 if parsed is not None else 1,
        parsed if parsed is not None else 0.0,
        str(record.get("evidence_id") or ""),
    )


def _distribution(
    records: list[dict[str, Any]], field: str
) -> dict[str, Any] | None:
    counts = Counter(
        _value_key(record.get(field))
        for record in records
        if _value_key(record.get(field))
    )
    if not counts:
        return None
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    shown = ordered[:_MAX_DISTRIBUTION_VALUES]
    return {
        "distinct_count": len(ordered),
        "top_values": [{"value": value, "count": count} for value, count in shown],
        "other_count": sum(count for _, count in ordered[len(shown) :]),
    }


def _select_representatives(
    records: list[dict[str, Any]], *, limit: int = _MAX_REPRESENTATIVES
) -> tuple[list[str], dict[str, list[str]]]:
    """Select temporal endpoints and major semantic buckets deterministically."""
    selected: list[str] = []
    reasons: dict[str, list[str]] = {}

    def add(record: dict[str, Any], reason: str) -> None:
        evidence_id = str(record.get("evidence_id") or "").strip()
        if not evidence_id:
            return
        reasons.setdefault(evidence_id, []).append(reason)
        if evidence_id not in selected and len(selected) < limit:
            selected.append(evidence_id)

    timestamped = [
        record for record in records if parse_epoch_seconds(record.get("timestamp")) is not None
    ]
    if timestamped:
        ordered = sorted(timestamped, key=_timestamp_key)
        add(ordered[0], "earliest_timestamp")
        add(ordered[-1], "latest_timestamp")

    for field in ("artifact_family", "source_family", "host", "user", "event_family"):
        buckets: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            value = _value_key(record.get(field))
            if value:
                buckets.setdefault(value, []).append(record)
        ranked = sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0]))
        for value, members in ranked[:2]:
            representative = min(members, key=_timestamp_key)
            add(representative, f"major_{field}:{value}")
            if len(selected) >= limit:
                break
        if len(selected) >= limit:
            break
    return selected, reasons


def project_report_evidence_row(
    row: dict[str, Any], *, db: CaseDB | None
) -> dict[str, Any]:
    """Return a prompt-only copy of one evidence row.

    Small sets are kept byte-for-byte equivalent at the value level. Large
    sets are projected only when their IDs resolve to authoritative records;
    unresolved IDs are never presented as citable representatives.
    """
    projected = dict(row)
    raw_ids = row.get("evidence_ids")
    if not isinstance(raw_ids, list):
        return projected
    evidence_ids = list(dict.fromkeys(str(item).strip() for item in raw_ids if str(item).strip()))
    if len(evidence_ids) <= _LARGE_EVIDENCE_SET:
        return projected

    projected.pop("evidence_ids", None)
    projected["evidence_count"] = len(evidence_ids)
    if db is None:
        projected["representative_evidence_ids"] = []
        projected["citable"] = False
        projected["evidence_projection"] = {
            "complete_set_authority": "persisted evidence row / DuckDB",
            "resolved_evidence_count": 0,
            "unresolved_evidence_count": len(evidence_ids),
            "selection_unavailable": "authoritative evidence metadata was not provided to the report prompt builder",
        }
        return projected

    metadata = _fetch_prompt_metadata(db, evidence_ids)
    records = [metadata[item] for item in sorted(metadata)]
    if not records:
        projected["representative_evidence_ids"] = []
        projected["citable"] = False
        projected["evidence_projection"] = {
            "complete_set_authority": "persisted evidence row / DuckDB",
            "resolved_evidence_count": 0,
            "unresolved_evidence_count": len(evidence_ids),
            "selection_unavailable": "none of the aggregate evidence IDs resolved to authoritative metadata",
        }
        return projected

    representative_ids, reasons = _select_representatives(records)
    if not representative_ids:
        projected["representative_evidence_ids"] = []
        projected["citable"] = False
        projected["evidence_projection"] = {
            "complete_set_authority": "persisted evidence row / DuckDB",
            "resolved_evidence_count": len(records),
            "unresolved_evidence_count": len(evidence_ids) - len(records),
            "selection_unavailable": "resolved evidence lacked usable representative metadata",
        }
        return projected

    representative_records = []
    for evidence_id in representative_ids:
        record = dict(metadata[evidence_id])
        record["selection_reasons"] = reasons.get(evidence_id, [])
        representative_records.append(record)

    projected["representative_evidence_ids"] = representative_ids
    projected["representative_evidence"] = representative_records
    distributions = {
        field: distribution
        for field in (
            "artifact_family",
            "source_family",
            "host",
            "user",
            "event_family",
        )
        if (distribution := _distribution(records, field)) is not None
    }
    if distributions:
        projected["evidence_distribution"] = distributions
    projected["evidence_projection"] = {
        "complete_set_authority": "persisted evidence row / DuckDB",
        "resolved_evidence_count": len(records),
        "unresolved_evidence_count": len(evidence_ids) - len(records),
        "selection_policy": "temporal endpoints plus representatives of major semantic buckets; stable evidence_id tie-break",
    }
    return projected


def project_report_evidence_rows(
    rows: list[dict[str, Any]] | None, *, db: CaseDB | None
) -> list[dict[str, Any]]:
    return [
        project_report_evidence_row(row, db=db) if isinstance(row, dict) else row
        for row in (rows or [])
    ]


def project_report_results(
    results: list[dict[str, Any]] | None, *, db: CaseDB | None
) -> list[dict[str, Any]]:
    """Project nested report result rows and result-level opaque ID sets."""
    projected_results: list[dict[str, Any]] = []
    for result in results or []:
        if not isinstance(result, dict):
            continue
        projected = dict(result)
        for key in ("sample_rows", "head_rows", "tail_rows"):
            value = result.get(key)
            if isinstance(value, list):
                projected[key] = project_report_evidence_rows(value, db=db)
        if isinstance(result.get("evidence_ids"), list):
            container = project_report_evidence_row(
                {"evidence_ids": result["evidence_ids"]}, db=db
            )
            if "representative_evidence_ids" in container:
                projected.pop("evidence_ids", None)
                projected.update(container)
        projected_results.append(projected)
    return projected_results


def project_report_prior_runs(
    runs: list[dict[str, Any]] | None, *, db: CaseDB | None
) -> list[dict[str, Any]]:
    """Project result payloads embedded in section run history."""
    projected_runs: list[dict[str, Any]] = []
    for run in runs or []:
        if not isinstance(run, dict):
            continue
        projected_run = dict(run)
        payload = run.get("payload")
        if isinstance(payload, dict):
            projected_payload = dict(payload)
            result = payload.get("result")
            if isinstance(result, dict):
                projected_payload["result"] = project_report_results(
                    [result], db=db
                )[0]
            projected_run["payload"] = projected_payload
        projected_runs.append(projected_run)
    return projected_runs


def project_report_brief(
    brief: dict[str, Any] | None, *, db: CaseDB | None
) -> dict[str, Any]:
    """Project evidence references nested in the report brief's item lists."""
    projected = dict(brief or {})
    for key in (
        "top_findings",
        "confirmed_hypotheses",
        "refuted_hypotheses",
        "active_hypotheses",
    ):
        items = brief.get(key) if isinstance(brief, dict) else None
        if isinstance(items, list):
            projected[key] = project_report_evidence_rows(items, db=db)
    return projected
