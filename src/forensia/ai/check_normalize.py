"""Normalization and filtering of checker LLM output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensia.core.session import (
    ENTITY_ROLES,
    ENTITY_TYPE_ALIASES,
    Hypothesis,
)
from forensia.core.timeutil import parse_epoch_seconds

VALID_VERDICTS = {"confirmed", "refuted", "inconclusive", "newlead"}
SMALL_CONFIDENCE_DELTA = 0.02
_DURABLE_MEMORY_KEYS = {"facts", "timeline", "resolved_gaps"}
_ENTITY_PLACEHOLDER_VALUES = {"", "-", "n/a", "na", "none", "null", "unknown"}


@dataclass(slots=True)
class CheckResult:
    query_id: str
    verdict: str
    finding_updates: list[dict[str, Any]]
    suspicious_evidence: list[dict[str, Any]]
    new_hypotheses: list[Hypothesis]
    memory_updates: dict[str, Any]
    report_text: str
    new_leads: int
    progress: bool  # True if something meaningfully changed
    raw_response: dict[str, Any]


def _parse_new_hypotheses(items: Any) -> list[Hypothesis]:
    """Parse LLM output into a list of Hypothesis objects, skipping invalid entries."""
    hypotheses: list[Hypothesis] = []
    if not isinstance(items, list):
        return hypotheses
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = dict(item)
        if str(payload.get("verdict") or "") not in {"confirmed", "refuted"}:
            payload["verdict"] = None
        if str(payload.get("status") or "") not in {"active", "confirmed", "refuted"}:
            payload["status"] = "active"
        try:
            hypotheses.append(Hypothesis.model_validate(payload))
        except Exception:
            continue
    return hypotheses


def summarize_query_result(
    rows: list[dict[str, Any]], sample_size: int = 10
) -> dict[str, Any]:
    """Build a structured summary of SQL query rows for LLM consumption.

    Extracts evidence IDs, head/tail sample rows, and distinct counts for key
    columns (target_user, computer, src_ip, event_id).
    """
    evidence_ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        value = row.get("evidence_id")
        if not value:
            continue
        normalized = str(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        evidence_ids.append(normalized)

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
    distinct_counts = {
        column: len({row.get(column) for row in rows if row.get(column)})
        for column in ("target_user", "computer", "src_ip", "event_id")
        if any(row.get(column) for row in rows)
    }

    event_id_set: set[int] = set()
    for row in rows:
        try:
            eid = int(row.get("event_id"))
            event_id_set.add(eid)
        except TypeError, ValueError:
            pass

    return {
        "row_count": len(rows),
        "head_rows": head_rows,
        "tail_rows": tail_rows,
        "sample_rows": sample_rows,
        "distinct_counts": distinct_counts,
        "evidence_ids": evidence_ids[:sample_size],
        "event_id_set": sorted(event_id_set),
    }


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def _normalize_verdict(value: Any) -> str:
    verdict = str(value or "").strip().lower()
    return verdict if verdict in VALID_VERDICTS else "inconclusive"


def _collect_observed_evidence_ids(result_summary: dict[str, Any]) -> set[str]:
    """Collect all evidence IDs from both evidence_ids list and sample_rows."""
    observed: set[str] = set()
    for evidence_id in result_summary.get("evidence_ids") or []:
        normalized = str(evidence_id).strip()
        if normalized:
            observed.add(normalized)
    for row in result_summary.get("sample_rows") or []:
        if not isinstance(row, dict):
            continue
        normalized = str(row.get("evidence_id") or "").strip()
        if normalized:
            observed.add(normalized)
    return observed


def _has_zero_evidence(
    result_summary: dict[str, Any], observed_evidence_ids: set[str]
) -> bool:
    row_count = int(result_summary.get("row_count") or 0)
    sample_rows = result_summary.get("sample_rows") or []
    return row_count == 0 and not observed_evidence_ids and not sample_rows


def _normalize_status(value: Any, fallback: str = "accepted") -> str:
    status = str(value or "").strip().lower()
    return status if status in {"accepted", "suppressed"} else fallback


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except TypeError, ValueError:
        return 0.0


def _parse_timestamp(ts: Any) -> float | None:
    """Parse a timestamp value to Unix epoch seconds (float)."""
    return parse_epoch_seconds(ts)


def _normalize_finding_updates(
    items: Any,
    *,
    allowed_finding_ids: set[str],
    verdict: str,
    zero_evidence: bool,
) -> list[dict[str, Any]]:
    """Normalize and guardrail LLM-proposed finding updates.

    Only updates for allowed finding IDs are kept. Zero-evidence results cannot
    increase confidence. Verdict constraints: confirmed -> positive delta only,
    refuted -> negative delta + suppressed, inconclusive -> clamped small delta.
    """
    normalized: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return normalized

    for item in items:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding_id") or "").strip()
        if not finding_id or finding_id not in allowed_finding_ids:
            continue

        delta = _coerce_float(item.get("confidence_delta"))
        new_status = _normalize_status(item.get("new_status"))

        if zero_evidence and delta > 0:
            delta = 0.0

        if verdict == "confirmed":
            delta = max(0.0, delta)
        elif verdict == "refuted":
            delta = min(0.0, delta)
            new_status = "suppressed"
        else:
            delta = max(-SMALL_CONFIDENCE_DELTA, min(SMALL_CONFIDENCE_DELTA, delta))

        normalized.append(
            {
                "finding_id": finding_id,
                "new_status": new_status,
                "confidence_delta": delta,
            }
        )
    return normalized


def _filter_evidence_references(
    items: Any, observed_evidence_ids: set[str]
) -> list[dict[str, Any]]:
    """Keep only evidence references whose IDs appear in the observed set."""
    filtered: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return filtered

    for item in items:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("evidence_id") or "").strip()
        if not evidence_id or evidence_id not in observed_evidence_ids:
            continue
        payload = dict(item)
        payload["evidence_id"] = evidence_id
        filtered.append(payload)
    return filtered


def _filter_memory_updates(
    updates: Any,
    observed_evidence_ids: set[str],
    sample_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Filter memory updates to only include valid entities and observed evidence.

    Durable memory keys (facts, timeline, resolved_gaps) require non-empty
    evidence_ids. Entity entries are validated against ENTITY_TYPE_ALIASES,
    ENTITY_ROLES, placeholder-value exclusion rules, and literal name presence
    in sample rows.
    """
    entity_name_set: set[str] | None = None
    entity_value_blob = ""
    if sample_rows:
        identity_cols = {
            "user_name",
            "target_user",
            "computer",
            "src_ip",
            "process_name",
            "service_name",
            "executable_name",
            "file_name",
            "file_path",
        }
        entity_name_set = set()
        blob_parts: list[str] = []
        for row in sample_rows:
            if not isinstance(row, dict):
                continue
            for col in identity_cols:
                val = row.get(col)
                if (
                    val
                    and isinstance(val, str)
                    and val.strip().lower() not in _ENTITY_PLACEHOLDER_VALUES
                ):
                    entity_name_set.add(val.strip().casefold())
                    blob_parts.append(val.casefold())
        entity_value_blob = "\n".join(blob_parts)
    if not isinstance(updates, dict):
        return {}

    filtered: dict[str, Any] = {}
    for key, value in updates.items():
        if not isinstance(value, list):
            filtered[key] = value
            continue

        filtered_items: list[Any] = []
        for item in value:
            if not isinstance(item, dict):
                filtered_items.append(item)
                continue
            payload = dict(item)
            if "evidence_ids" in payload:
                payload["evidence_ids"] = [
                    evidence_id
                    for evidence_id in (
                        str(evidence_id).strip()
                        for evidence_id in (payload.get("evidence_ids") or [])
                    )
                    if evidence_id and evidence_id in observed_evidence_ids
                ]
            if key in _DURABLE_MEMORY_KEYS and not payload.get("evidence_ids"):
                continue
            if key == "entities":
                normalized_type = ENTITY_TYPE_ALIASES.get(
                    str(payload.get("entity_type") or "").strip().lower()
                )
                if normalized_type is None:
                    continue
                normalized_name = str(payload.get("name") or "").strip()
                if (
                    not normalized_name
                    or normalized_name.lower() in _ENTITY_PLACEHOLDER_VALUES
                ):
                    continue
                normalized_role = (
                    str(payload.get("role") or "unknown").strip().lower() or "unknown"
                )
                if normalized_role not in ENTITY_ROLES:
                    normalized_role = "unknown"
                payload["entity_type"] = normalized_type
                payload["name"] = normalized_name
                payload["role"] = normalized_role
                if entity_name_set is not None:
                    name_cf = normalized_name.casefold()
                    # Accept exact value matches, or containment within observed
                    # values (e.g. a user name inside a file_path) for names
                    # long enough not to match by accident.
                    if name_cf not in entity_name_set and not (
                        len(name_cf) >= 3 and name_cf in entity_value_blob
                    ):
                        continue
            filtered_items.append(payload)
        filtered[key] = filtered_items
    return filtered


def _validate_extracted_findings(
    items: Any,
    observed_evidence_ids: set[str],
) -> list[dict[str, Any]]:
    """Validate LLM-extracted findings: non-empty title, valid severity, evidence_ids subset."""
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    validated: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return validated
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        severity = str(item.get("severity") or "").strip().lower()
        evidence_ids = item.get("evidence_ids") or []
        if not isinstance(evidence_ids, list):
            evidence_ids = []
        evidence_ids = [str(e).strip() for e in evidence_ids if str(e).strip()]

        if not title:
            continue
        if severity not in VALID_SEVERITIES:
            continue
        if not observed_evidence_ids or not evidence_ids:
            validated.append(
                {"title": title, "severity": severity, "evidence_ids": evidence_ids}
            )
            continue
        if all(eid in observed_evidence_ids for eid in evidence_ids):
            validated.append(
                {"title": title, "severity": severity, "evidence_ids": evidence_ids}
            )
    return validated

