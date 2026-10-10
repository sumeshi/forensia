"""Normalization and filtering of checker LLM output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensia.core.session import Hypothesis
from forensia.core.timeutil import parse_epoch_seconds

VALID_VERDICTS = {"confirmed", "refuted", "inconclusive", "newlead"}
SMALL_CONFIDENCE_DELTA = 0.02


@dataclass(slots=True)
class CheckResult:
    query_id: str
    verdict: str
    finding_updates: list[dict[str, Any]]
    suspicious_evidence: list[dict[str, Any]]
    new_hypotheses: list[Hypothesis]
    report_text: str
    new_leads: int
    progress: bool  # True if something meaningfully changed
    raw_response: dict[str, Any]


def parse_new_hypotheses(items: Any) -> list[Hypothesis]:
    """Parse LLM output into a list of Hypothesis objects, skipping invalid entries."""
    hypotheses: list[Hypothesis] = []
    if not isinstance(items, list):
        return hypotheses
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        payload = dict(item)
        payload.setdefault("id", f"candidate-{index:02d}")
        if str(payload.get("verdict") or "") not in {"confirmed", "refuted"}:
            payload["verdict"] = None
        if str(payload.get("status") or "") not in {"active", "confirmed", "refuted"}:
            payload["status"] = "active"
        try:
            hypotheses.append(Hypothesis.model_validate(payload))
        except Exception:
            continue
    return hypotheses


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


def validate_extracted_findings(
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
        raw_evidence_ids = item.get("evidence_ids")
        if raw_evidence_ids is None:
            evidence_ids = []
        elif not isinstance(raw_evidence_ids, list):
            continue
        else:
            evidence_ids = raw_evidence_ids
        evidence_ids = [str(e).strip() for e in evidence_ids if str(e).strip()]

        if not title:
            continue
        if severity not in VALID_SEVERITIES:
            continue
        if evidence_ids and (
            not observed_evidence_ids
            or not all(eid in observed_evidence_ids for eid in evidence_ids)
        ):
            continue
        validated.append(
            {"title": title, "severity": severity, "evidence_ids": evidence_ids}
        )
    return validated
