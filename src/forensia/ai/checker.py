from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import (
    _load_benign_context_rules,
    build_finding_extractor_messages,
    build_memory_updater_messages,
    build_verdict_review_messages,
    resolve_rule_context,
)
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.timeutil import parse_epoch_seconds
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, ENTITY_TYPE_ALIASES, Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value

VALID_VERDICTS = {"confirmed", "refuted", "inconclusive", "newlead"}
SMALL_CONFIDENCE_DELTA = 0.02
_DURABLE_MEMORY_KEYS = {"facts", "timeline", "resolved_gaps"}
_ENTITY_PLACEHOLDER_VALUES = {"", "-", "n/a", "na", "none", "null", "unknown"}


def annotate_benign_context(
    rows: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[int, list[str]]:
    """Map row_index to matching benign-context rule IDs for each row.

    Each rule must have: id, when.column, when.regex. Returns empty dict when
    no rows match any rule.
    """
    result: dict[int, list[str]] = {}
    for i, row in enumerate(rows):
        matched: list[str] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            when = rule.get("when")
            if not isinstance(when, dict):
                continue
            column = when.get("column")
            regex = when.get("regex")
            if not column or not regex:
                continue
            value = row.get(column)
            if value is None:
                continue
            try:
                if re.search(regex, str(value)):
                    matched.append(str(rule.get("id", "unknown")))
            except re.error:
                continue
        if matched:
            result[i] = matched
    return result


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


def summarize_query_result(rows: list[dict[str, Any]], sample_size: int = 10) -> dict[str, Any]:
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
        except (TypeError, ValueError):
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


def _has_zero_evidence(result_summary: dict[str, Any], observed_evidence_ids: set[str]) -> bool:
    row_count = int(result_summary.get("row_count") or 0)
    sample_rows = result_summary.get("sample_rows") or []
    return row_count == 0 and not observed_evidence_ids and not sample_rows


def _normalize_status(value: Any, fallback: str = "accepted") -> str:
    status = str(value or "").strip().lower()
    return status if status in {"accepted", "suppressed"} else fallback


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parse_timestamp(ts: Any) -> float | None:
    """Parse a timestamp value to Unix epoch seconds (float)."""
    return parse_epoch_seconds(ts)


def _co_observation_satisfied(confirm_when: dict, rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Check if co-observed event IDs satisfy correlation constraints.

    Supports `same_host`, `within_minutes`, and `co_observed_event_ids`.
    Returns (satisfied, reason_string).
    """
    co_ids = confirm_when.get("co_observed_event_ids") or []
    required_ids: set[int] = set()
    for eid in co_ids:
        try:
            required_ids.add(int(eid))
        except (TypeError, ValueError):
            continue
    if not required_ids:
        return (True, "no co_observed_event_ids to verify")

    same_host = bool(confirm_when.get("same_host", False))
    within_minutes: int | None = confirm_when.get("within_minutes")

    # Simple presence check when no correlation constraints
    if not same_host and within_minutes is None:
        observed_ids: set[int] = set()
        for row in rows:
            eid = row.get("event_id")
            if eid is not None:
                try:
                    observed_ids.add(int(eid))
                except (TypeError, ValueError):
                    pass
        if required_ids.issubset(observed_ids):
            return (True, f"all co_observed_event_ids {sorted(required_ids)} present in rows")
        return (False, f"not all co_observed_event_ids found: missing {sorted(required_ids - observed_ids)}")

    # Group rows by computer when same_host
    if same_host:
        host_groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            host = row.get("computer")
            if host is not None and str(host).strip():
                host_groups.setdefault(str(host), []).append(row)
        if not host_groups:
            return (False, "same_host=True but no rows have a 'computer' column")
    else:
        host_groups = {"_all": rows}

    for host, host_rows in host_groups.items():
        host_event_ids: set[int] = set()
        for row in host_rows:
            eid = row.get("event_id")
            if eid is not None:
                try:
                    host_event_ids.add(int(eid))
                except (TypeError, ValueError):
                    pass

        if not required_ids.issubset(host_event_ids):
            continue

        if within_minutes is not None:
            # Sliding window: find ANY window of within_minutes that contains
            # every required event ID. A global min/max span check would fail
            # whenever the result set spans days even though a valid co-observed
            # pair exists somewhere inside it.
            events: list[tuple[float, int]] = []
            for row in host_rows:
                eid = row.get("event_id")
                if eid is not None:
                    try:
                        eid_int = int(eid)
                        if eid_int in required_ids:
                            ts = _parse_timestamp(row.get("timestamp"))
                            if ts is not None:
                                events.append((ts, eid_int))
                    except (TypeError, ValueError):
                        pass

            if not events:
                continue

            events.sort()
            window_seconds = within_minutes * 60
            window_counts: Counter[int] = Counter()
            left = 0
            found = False
            for right in range(len(events)):
                window_counts[events[right][1]] += 1
                while events[right][0] - events[left][0] > window_seconds:
                    window_counts[events[left][1]] -= 1
                    if window_counts[events[left][1]] == 0:
                        del window_counts[events[left][1]]
                    left += 1
                if required_ids.issubset(window_counts.keys()):
                    found = True
                    break
            if found:
                host_label = f" on host={host}" if same_host else ""
                return (True, f"co-observed event_ids {sorted(required_ids)} within {within_minutes}min{host_label}")
        else:
            host_label = f" on host={host}" if same_host else ""
            return (True, f"co-observed event_ids {sorted(required_ids)} present{host_label}")

    parts = [f"co-observation not satisfied: required={sorted(required_ids)}"]
    if same_host:
        parts.append("same_host=True")
    if within_minutes is not None:
        parts.append(f"within_{within_minutes}min")
    return (False, "; ".join(parts))


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


def _filter_evidence_references(items: Any, observed_evidence_ids: set[str]) -> list[dict[str, Any]]:
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
            "user_name", "target_user", "computer", "src_ip",
            "process_name", "service_name", "executable_name",
            "file_name", "file_path",
        }
        entity_name_set = set()
        blob_parts: list[str] = []
        for row in sample_rows:
            if not isinstance(row, dict):
                continue
            for col in identity_cols:
                val = row.get(col)
                if val and isinstance(val, str) and val.strip().lower() not in _ENTITY_PLACEHOLDER_VALUES:
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
                        str(evidence_id).strip() for evidence_id in (payload.get("evidence_ids") or [])
                    )
                    if evidence_id and evidence_id in observed_evidence_ids
                ]
            if key in _DURABLE_MEMORY_KEYS and not payload.get("evidence_ids"):
                continue
            if key == "entities":
                normalized_type = ENTITY_TYPE_ALIASES.get(str(payload.get("entity_type") or "").strip().lower())
                if normalized_type is None:
                    continue
                normalized_name = str(payload.get("name") or "").strip()
                if not normalized_name or normalized_name.lower() in _ENTITY_PLACEHOLDER_VALUES:
                    continue
                normalized_role = str(payload.get("role") or "unknown").strip().lower() or "unknown"
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
                    if name_cf not in entity_name_set and not (len(name_cf) >= 3 and name_cf in entity_value_blob):
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
            validated.append({"title": title, "severity": severity, "evidence_ids": evidence_ids})
            continue
        if all(eid in observed_evidence_ids for eid in evidence_ids):
            validated.append({"title": title, "severity": severity, "evidence_ids": evidence_ids})
    return validated


def _verify_verdict_consistency(
    verdict: str,
    rationale: str,
    hypothesis,
    result_summary: dict[str, Any],
) -> tuple[str, str | None]:
    """Veto confirmed verdicts when cited event IDs don't match observed rows.

    Returns (adjusted_verdict, veto_reason_or_None).
    """
    if verdict != "confirmed":
        return verdict, None

    # -- Check 1: event_id claim vs observed event_ids --
    claimed_event_ids: set[int] = set()
    if hypothesis and hasattr(hypothesis, "confirm_when") and hypothesis.confirm_when:
        co_ids = hypothesis.confirm_when.get("co_observed_event_ids") or []
        for eid in co_ids:
            try:
                claimed_event_ids.add(int(eid))
            except (TypeError, ValueError):
                pass
    # Bare numbers in the rationale are usually counts, years, or row totals,
    # not event-id claims. Treat a number as a claimed event id only when it is
    # framed by "event ..." wording, or when it is a 4-5 digit number that
    # exists in the declared event-id vocabulary (event_ids.yaml).
    from forensia.ai.prompts import _load_event_id_hints

    rationale_lower = rationale.lower()
    framed = {int(m) for m in re.findall(r"event[^0-9]{0,8}(\d{2,5})\b", rationale_lower)}
    bare = {int(m) for m in re.findall(r"\b(\d{4,5})\b", rationale_lower)}
    known_event_ids = set(_load_event_id_hints().keys())
    if known_event_ids:
        rationale_eids = (framed | bare) & known_event_ids
    else:
        rationale_eids = framed
    claimed_event_ids.update(rationale_eids)

    observed_event_ids: set[int] = set()
    for eid in result_summary.get("event_id_set") or []:
        try:
            observed_event_ids.add(int(eid))
        except (TypeError, ValueError):
            pass

    missing_ids = claimed_event_ids - observed_event_ids
    if missing_ids:
        sorted_missing = sorted(missing_ids)
        return (
            "inconclusive",
            f"verdict cited event_ids {sorted_missing} not present in result rows",
        )

    # -- Check 2: required_entities columns are non-NULL in sample rows --
    if hypothesis and hasattr(hypothesis, "required_entities") and hypothesis.required_entities:
        sample_rows = result_summary.get("sample_rows") or []
        if sample_rows:
            all_null = True
            for col in hypothesis.required_entities:
                for row in sample_rows:
                    val = row.get(col)
                    if val not in (None, "", "-", "n/a", "na", "none", "null", "unknown"):
                        all_null = False
                        break
                if not all_null:
                    break
            if all_null:
                return (
                    "inconclusive",
                    f"required_entities columns {hypothesis.required_entities} are NULL/absent in all sample rows",
                )

    # -- Check 3: co-observation correlation constraints (same_host / within_minutes) --
    if hypothesis and hasattr(hypothesis, "confirm_when") and hypothesis.confirm_when:
        cw = hypothesis.confirm_when
        if isinstance(cw, dict) and (cw.get("same_host") or cw.get("within_minutes")):
            sample_rows = result_summary.get("sample_rows") or []
            satisfied, veto_reason = _co_observation_satisfied(cw, sample_rows)
            if not satisfied:
                return ("inconclusive", veto_reason)

    # -- Check 4: Benign context gate --
    # Only rules matching the columns the hypothesis actually reasons about
    # (required_entities) count toward the downgrade: a machine-account
    # subject_user is the normal shape of a human interactive logon and must
    # not veto a hypothesis whose required entities are target_user/computer.
    sample_rows = result_summary.get("sample_rows") or []
    if sample_rows:
        benign_rules = _load_benign_context_rules()
        required_entities = set(getattr(hypothesis, "required_entities", None) or []) if hypothesis else set()
        if required_entities:
            benign_rules = [
                rule for rule in benign_rules
                if isinstance(rule, dict)
                and isinstance(rule.get("when"), dict)
                and rule["when"].get("column") in required_entities
            ]
        if benign_rules:
            benign_annotations = annotate_benign_context(sample_rows, benign_rules)
            if benign_annotations and len(benign_annotations) == len(sample_rows):
                all_rule_ids: set[str] = set()
                for ids in benign_annotations.values():
                    all_rule_ids.update(ids)
                return (
                    "inconclusive",
                    f"all supporting rows match benign-context rules: {sorted(all_rule_ids)}",
                )

    return verdict, None


def _guardrail_check_payload(
    parsed: dict[str, Any],
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    fallback_info: dict | None = None,
) -> dict[str, Any]:
    """Apply safety guardrails to the raw LLM check response.

    Forces inconclusive on zero-evidence confirmed/newlead. Filters finding_updates
    to allowed IDs and enforces verdict-constrained delta signs.
    Caps fallback-sourced verdicts to newlead.
    """
    verdict = _normalize_verdict(parsed.get("verdict"))
    observed_evidence_ids = _collect_observed_evidence_ids(result_summary)
    zero_evidence = _has_zero_evidence(result_summary, observed_evidence_ids)
    if zero_evidence and verdict in {"confirmed", "newlead"}:
        verdict = "inconclusive"

    if fallback_info and verdict == "confirmed":
        verdict = "newlead"
        phase = fallback_info.get("phase", "unknown")
        existing_notes = str(parsed.get("notes") or "")
        veto_note = f"downgraded from confirmed to newlead: rows from fallback search ({phase})"
        if existing_notes:
            veto_note = existing_notes + "; " + veto_note
        parsed["notes"] = veto_note

    allowed_finding_ids = {
        str(item.get("finding_id") or "").strip()
        for item in finding_candidates
        if isinstance(item, dict) and str(item.get("finding_id") or "").strip()
    }

    return {
        "query_id": parsed.get("query_id"),
        "verdict": verdict,
        "finding_updates": _normalize_finding_updates(
            parsed.get("finding_updates"),
            allowed_finding_ids=allowed_finding_ids,
            verdict=verdict,
            zero_evidence=zero_evidence,
        ),
        "suspicious_evidence": _filter_evidence_references(
            parsed.get("suspicious_evidence"),
            observed_evidence_ids,
        ),
        "new_hypotheses": parsed.get("new_hypotheses"),
        "memory_updates": _filter_memory_updates(
            parsed.get("memory_updates"),
            observed_evidence_ids,
            sample_rows=result_summary.get("sample_rows"),
        ),
        "report_text": parsed.get("report_text") or "",
        "extracted_findings": _validate_extracted_findings(
            parsed.get("extracted_findings"),
            observed_evidence_ids,
        ),
    }


def _upsert_ai_review(
    db: CaseDB,
    finding_id: str,
    verdict: str,
    report_text: str,
    missing_checks: list[str],
    confidence_adjustment: float,
    notes: str,
    raw_response: dict[str, Any],
    ) -> None:
    """Replace the ai_review record for a finding with a new one (delete + insert)."""
    db.execute("DELETE FROM ai_reviews WHERE finding_id = ?", (finding_id,))
    review_id = f"review-{finding_id}"
    db.execute(
        """
        INSERT INTO ai_reviews (
            review_id, finding_id, verdict, report_text, missing_checks,
            confidence_adjustment, notes, raw_response, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            review_id,
            finding_id,
            verdict,
            report_text,
            json.dumps(missing_checks, ensure_ascii=False),
            confidence_adjustment,
            notes,
            json.dumps(raw_response, ensure_ascii=False, default=str),
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )


def _record_hypothesis_assessment(
    db: CaseDB,
    hypothesis: Hypothesis | None,
    planned_query: PlannedQuery,
    verdict: str,
    report_text: str,
    raw_response: dict[str, Any],
) -> None:
    """Record a hypothesis/query assessment as an ai_review entry."""
    finding_id = f"hypothesis:{hypothesis.id}" if hypothesis else f"query:{planned_query.query_id}"
    missing_checks = raw_response.get("missing_checks") or []
    notes = str(raw_response.get("notes") or "")
    _upsert_ai_review(
        db=db,
        finding_id=finding_id,
        verdict=verdict,
        report_text=report_text,
        missing_checks=missing_checks if isinstance(missing_checks, list) else [],
        confidence_adjustment=0.0,
        notes=notes,
        raw_response=raw_response,
    )


def _insert_investigation_finding(
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    result_summary: dict[str, Any],
    report_text: str,
) -> str:
    """Insert a new investigation finding for a newlead verdict.

    Returns the generated finding_id.
    """
    finding_id = f"{session_id}-{planned_query.query_id}-finding"
    language = str(get_llm_settings()["output_language"]).lower()
    prefix = "Investigation"
    title = f"{prefix}: {planned_query.purpose}"
    summary = report_text
    evidence = [normalize_value(row) for row in result_summary.get("sample_rows", [])]
    missing_checks = []
    now = datetime.now(UTC).replace(tzinfo=None)
    db.execute(
        """
        INSERT INTO findings (
            finding_id, rule_id, title, summary, severity, confidence,
            status, tags, attack, evidence, ai_summary, missing_checks, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding_id,
            "investigation",
            title,
            summary,
            "medium",
            0.75,
            "accepted",
            json.dumps(["investigation", planned_query.query_id], ensure_ascii=False),
            json.dumps([], ensure_ascii=False),
            json.dumps(evidence, ensure_ascii=False, default=str),
            report_text,
            json.dumps(missing_checks, ensure_ascii=False, default=str),
            now,
        ),
    )
    return finding_id


def apply_check_result(
    case: Case,
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    check_result: CheckResult,
) -> tuple[int, bool]:
    """Apply a CheckResult to the case DB: update findings, insert new-lead findings.

    Returns (new_lead_count, progress_flag) where progress_flag is True if any
    meaningful state change occurred (new leads, significant confidence delta,
    new hypotheses).
    """
    new_leads = 0
    significant_delta = False
    missing_checks = check_result.raw_response.get("missing_checks") or []
    notes = str(check_result.raw_response.get("notes") or "")

    _record_hypothesis_assessment(
        db=db,
        hypothesis=hypothesis,
        planned_query=planned_query,
        verdict=check_result.verdict,
        report_text=check_result.report_text,
        raw_response=check_result.raw_response,
    )

    for item in check_result.finding_updates:
        finding_id = item.get("finding_id")
        if not finding_id:
            continue
        current = db.execute(
            "SELECT confidence, missing_checks FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if current is None:
            continue
        new_status = item.get("new_status") or "accepted"
        delta = float(item.get("confidence_delta") or 0.0)
        new_confidence = _clamp_confidence(float(current[0]) + delta)
        db.execute(
            """
            UPDATE findings
            SET status = ?, confidence = ?, ai_summary = ?, missing_checks = ?
            WHERE finding_id = ?
            """,
            (
                new_status,
                new_confidence,
                check_result.report_text,
                json.dumps(missing_checks, ensure_ascii=False),
                finding_id,
            ),
        )
        _upsert_ai_review(
            db=db,
            finding_id=finding_id,
            verdict=check_result.verdict,
            report_text=check_result.report_text,
            missing_checks=missing_checks if isinstance(missing_checks, list) else [],
            confidence_adjustment=delta,
            notes=notes,
            raw_response=check_result.raw_response,
        )
        if abs(delta) >= 0.05:
            significant_delta = True

    # T-04: Persist finding_extractor output (extracted_findings) when verdict is confirmed
    if check_result.verdict == "confirmed" and hypothesis:
        extracted = check_result.raw_response.get("extracted_findings") or []
        normalized_evidence_rows = [
            normalize_value(row) for row in result_summary.get("sample_rows", [])
        ]
        observed_evidence_ids = _collect_observed_evidence_ids(result_summary)
        for i, entry in enumerate(extracted):
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title") or "").strip()
            severity = str(entry.get("severity") or "medium").strip().lower()
            evidence_ids = entry.get("evidence_ids") or []
            if not isinstance(evidence_ids, list):
                evidence_ids = []
            evidence_ids = [str(e).strip() for e in evidence_ids if str(e).strip()]
            if not title:
                continue
            if evidence_ids and observed_evidence_ids:
                if not all(eid in observed_evidence_ids for eid in evidence_ids):
                    continue
            finding_id = f"{session_id}-{planned_query.query_id}-ext-{i:02d}"
            existing = db.execute(
                "SELECT finding_id FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if existing:
                continue
            # Dedup by normalized title + evidence_id set
            existing_by_content = db.execute(
                """
                SELECT finding_id, title, evidence FROM findings
                WHERE rule_id = 'hypothesis-extraction' AND title = ?
                """,
                (title,),
            ).fetchone()
            if existing_by_content:
                try:
                    existing_evidence_ids = set()
                    existing_evidence = json.loads(existing_by_content[2] or "[]")
                    for ev_row in existing_evidence if isinstance(existing_evidence, list) else []:
                        if isinstance(ev_row, dict):
                            eid = str(ev_row.get("evidence_id") or "").strip()
                            if eid:
                                existing_evidence_ids.add(eid)
                    if existing_evidence_ids and set(evidence_ids) == existing_evidence_ids:
                        continue
                except Exception:
                    pass

            db.execute(
                """
                INSERT INTO findings (
                    finding_id, rule_id, title, summary, severity, confidence,
                    status, tags, attack, evidence, ai_summary, missing_checks, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    "hypothesis-extraction",
                    title,
                    entry.get("summary") or check_result.report_text,
                    severity,
                    0.7,
                    "accepted",
                    json.dumps(["investigation", hypothesis.id], ensure_ascii=False),
                    json.dumps([], ensure_ascii=False),
                    json.dumps(normalized_evidence_rows, ensure_ascii=False, default=str),
                    check_result.report_text,
                    json.dumps([], ensure_ascii=False),
                    datetime.now(UTC).replace(tzinfo=None),
                ),
            )

    if check_result.verdict == "newlead":
        finding_id = _insert_investigation_finding(
            db=db,
            session_id=session_id,
            planned_query=planned_query,
            result_summary=result_summary,
            report_text=check_result.report_text,
        )
        _upsert_ai_review(
            db=db,
            finding_id=finding_id,
            verdict="newlead",
            report_text=check_result.report_text,
            missing_checks=missing_checks if isinstance(missing_checks, list) else [],
            confidence_adjustment=0.0,
            notes=notes,
            raw_response=check_result.raw_response,
        )
        new_leads += 1

    progress = new_leads > 0 or significant_delta or len(check_result.new_hypotheses) > 0
    return new_leads, progress


def check_query_result(
    case: Case,
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    memory: MemoryManager,
    base_url: str,
    model: str,
    overview_md: str | None = None,
    memory_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    time_range: dict[str, str] | None = None,
    fallback_info: dict | None = None,
    audit_callback: Callable[[str, list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> CheckResult:
    """Run the LLM-based query result check: verdict + memory + suspicious evidence.

    Uses phased checking (separate LLM calls for verdict, memory, and
    suspicious evidence). Applies guardrails via _guardrail_check_payload
    and persists results via apply_check_result.
    """
    overview_md = overview_md if overview_md is not None else memory.load_overview()
    memory_context_md = memory_context_md if memory_context_md is not None else memory.load_compact_context(
        memory.investigation_context_files(
            hypothesis.id if hypothesis else None,
            include_overview=False,
        ),
        max_bytes=max(1024, memory.max_bytes // 2),
    )
    observed_evidence_ids = list(_collect_observed_evidence_ids(result_summary))
    rule_context = resolve_rule_context(hypothesis)

    benign_rules = _load_benign_context_rules()
    benign_annotations = (
        annotate_benign_context(result_summary.get("sample_rows") or [], benign_rules)
        if benign_rules
        else None
    )

    # Step 1: verdict_reviewer — classify result against hypothesis
    verdict_messages, verdict_schema = build_verdict_review_messages(
        hypothesis=hypothesis,
        planned_query=planned_query,
        result_summary=result_summary,
        time_range=time_range or {},
        fallback_info=fallback_info,
        benign_annotations=benign_annotations,
    )
    verdict_parsed = request_llm_json(
        messages=verdict_messages,
        model=model,
        base_url=base_url,
        json_schema=verdict_schema,
        status_callback=status_callback,
        audit_callback=(lambda msgs, out, parsed, _p="check-verdict": audit_callback(_p, msgs, out, parsed)) if audit_callback else None,
    )
    verdict = _normalize_verdict(verdict_parsed.get("verdict"))

    # T-01: Deterministic claim–evidence consistency gate
    veto_verdict, veto_reason = _verify_verdict_consistency(
        verdict=verdict,
        rationale=verdict_parsed.get("rationale", ""),
        hypothesis=hypothesis,
        result_summary=result_summary,
    )
    if veto_reason:
        verdict = veto_verdict
        existing_rationale = str(verdict_parsed.get("rationale") or "")
        if existing_rationale:
            verdict_parsed["rationale"] = existing_rationale + " | " + veto_reason
        else:
            verdict_parsed["rationale"] = veto_reason
        existing_notes = str(verdict_parsed.get("notes") or "")
        if existing_notes:
            verdict_parsed["notes"] = existing_notes + "; " + veto_reason
        else:
            verdict_parsed["notes"] = veto_reason

    # Step 2: finding_extractor — extract structured findings (only for confirmed)
    extracted_findings: list[dict[str, Any]] = []
    if verdict == "confirmed":
        finding_messages, finding_schema = build_finding_extractor_messages(
            hypothesis=hypothesis,
            result_rows=result_summary.get("sample_rows") or [],
            verdict=verdict,
            rationale=verdict_parsed.get("rationale", ""),
        )
        finding_parsed = request_llm_json(
            messages=finding_messages,
            model=model,
            base_url=base_url,
            json_schema=finding_schema,
            status_callback=status_callback,
            audit_callback=(lambda msgs, out, parsed, _p="check-finding-extract": audit_callback(_p, msgs, out, parsed)) if audit_callback else None,
        )
        extracted_findings = finding_parsed.get("findings") or []

    # Step 3: memory_updater — propose durable memory writes
    memory_messages, memory_schema = build_memory_updater_messages(
        hypothesis=hypothesis,
        verdict=verdict,
        rationale=verdict_parsed.get("rationale", ""),
        result_summary=result_summary,
        time_range=time_range or {},
    )
    memory_parsed = request_llm_json(
        messages=memory_messages,
        model=model,
        base_url=base_url,
        json_schema=memory_schema,
        status_callback=status_callback,
        audit_callback=(lambda msgs, out, parsed, _p="check-memory-update": audit_callback(_p, msgs, out, parsed)) if audit_callback else None,
    )

    merged = {
        "query_id": verdict_parsed.get("query_id") or planned_query.query_id,
        "verdict": verdict,
        "rationale": verdict_parsed.get("rationale", ""),
        "finding_updates": [],
        "suspicious_evidence": [],
        "new_hypotheses": memory_parsed.get("new_hypotheses") or [],
        "memory_updates": memory_parsed.get("memory_updates") or {},
        "report_text": verdict_parsed.get("rationale", "") or "",
        "missing_checks": [],
        "notes": "",
        "extracted_findings": extracted_findings,
    }
    guarded = _guardrail_check_payload(merged, finding_candidates, result_summary, fallback_info=fallback_info)

    result = CheckResult(
        query_id=guarded.get("query_id") or planned_query.query_id,
        verdict=str(guarded.get("verdict") or "inconclusive"),
        finding_updates=guarded.get("finding_updates") or [],
        suspicious_evidence=guarded.get("suspicious_evidence") or [],
        new_hypotheses=_parse_new_hypotheses(guarded.get("new_hypotheses")),
        memory_updates=guarded.get("memory_updates") or {},
        report_text=str(guarded.get("report_text") or ""),
        new_leads=0,
        progress=False,
        raw_response=merged,
    )
    result.new_leads, result.progress = apply_check_result(
        case=case,
        db=db,
        session_id=session_id,
        planned_query=planned_query,
        hypothesis=hypothesis,
        result_summary=result_summary,
        check_result=result,
    )
    return result
