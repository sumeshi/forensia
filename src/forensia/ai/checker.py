from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import (
    build_check_messages,
    build_check_memory_updates_messages,
    build_check_suspicious_evidence_messages,
    build_check_verdict_messages,
    build_finding_extractor_messages,
    build_memory_updater_messages,
    build_verdict_review_messages,
    resolve_rule_context,
)
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import ENTITY_ROLES, ENTITY_TYPE_ALIASES, Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value

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

    return {
        "row_count": len(rows),
        "head_rows": head_rows,
        "tail_rows": tail_rows,
        "sample_rows": sample_rows,
        "distinct_counts": distinct_counts,
        "evidence_ids": evidence_ids[:sample_size],
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


def _filter_memory_updates(updates: Any, observed_evidence_ids: set[str]) -> dict[str, Any]:
    """Filter memory updates to only include valid entities and observed evidence.

    Durable memory keys (facts, timeline, resolved_gaps) require non-empty
    evidence_ids. Entity entries are validated against ENTITY_TYPE_ALIASES,
    ENTITY_ROLES, and placeholder-value exclusion rules.
    """
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
            filtered_items.append(payload)
        filtered[key] = filtered_items
    return filtered


def _guardrail_check_payload(
    parsed: dict[str, Any],
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
) -> dict[str, Any]:
    """Apply safety guardrails to the raw LLM check response.

    Forces inconclusive on zero-evidence confirmed/newlead. Filters finding_updates
    to allowed IDs and enforces verdict-constrained delta signs.
    """
    verdict = _normalize_verdict(parsed.get("verdict"))
    observed_evidence_ids = _collect_observed_evidence_ids(result_summary)
    zero_evidence = _has_zero_evidence(result_summary, observed_evidence_ids)
    if zero_evidence and verdict in {"confirmed", "newlead"}:
        verdict = "inconclusive"

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
        "memory_updates": _filter_memory_updates(parsed.get("memory_updates"), observed_evidence_ids),
        "report_text": parsed.get("report_text") or "",
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
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
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
            json.dumps(evidence, ensure_ascii=False),
            report_text,
            json.dumps(missing_checks, ensure_ascii=False),
            now,
        ),
    )
    return finding_id


def apply_check_result(
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
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

    if check_result.verdict == "newlead":
        finding_id = _insert_investigation_finding(
            case=case,
            db=db,
            session_id=session_id,
            iteration=iteration,
            planned_query=planned_query,
            hypothesis=hypothesis,
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
    iteration: int,
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
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    query_index: int = 1,
    max_queries: int = 5,
    fallback_info: dict[str, Any] | None = None,
    use_phased_check: bool = True,
) -> CheckResult:
    """Run the full LLM-based query result check: verdict + memory + suspicious evidence.

    Supports phased checking (separate LLM calls for verdict, memory, and suspicious
    evidence) when use_phased_check=True, or a single combined call otherwise.
    Applies guardrails via _guardrail_check_payload and persists results via
    apply_check_result.
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

    if use_phased_check:
        # Step 1: verdict_reviewer — classify result against hypothesis
        verdict_messages = build_verdict_review_messages(
            hypothesis=hypothesis,
            planned_query=planned_query,
            result_summary=result_summary,
            time_range={},
        )
        verdict_parsed = request_llm_json(
            messages=verdict_messages,
            model=model,
            base_url=base_url,
            status_callback=status_callback,
        )
        verdict = _normalize_verdict(verdict_parsed.get("verdict"))

        # Step 2: finding_extractor — extract structured findings (only for confirmed)
        extracted_findings: list[dict[str, Any]] = []
        if verdict == "confirmed":
            finding_messages = build_finding_extractor_messages(
                hypothesis=hypothesis,
                result_rows=result_summary.get("sample_rows") or [],
                verdict=verdict,
                rationale=verdict_parsed.get("rationale", ""),
            )
            finding_parsed = request_llm_json(
                messages=finding_messages,
                model=model,
                base_url=base_url,
                status_callback=status_callback,
            )
            extracted_findings = finding_parsed.get("findings") or []

        # Step 3: memory_updater — propose durable memory writes
        memory_messages = build_memory_updater_messages(
            hypothesis=hypothesis,
            verdict=verdict,
            rationale=verdict_parsed.get("rationale", ""),
        )
        memory_parsed = request_llm_json(
            messages=memory_messages,
            model=model,
            base_url=base_url,
            status_callback=status_callback,
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
        parsed = merged
    else:
        messages = build_check_messages(
            planned_query=planned_query,
            hypothesis=hypothesis,
            finding_candidates=finding_candidates,
            result_summary=result_summary,
            overview_md=overview_md,
            memory_context_md=memory_context_md,
            query_index=query_index,
            max_queries=max_queries,
            observed_evidence_ids=observed_evidence_ids,
            rule_context=rule_context,
            fallback_info=fallback_info,
        )
        parsed = request_llm_json(
            messages=messages,
            model=model,
            base_url=base_url,
            status_callback=status_callback,
            audit_callback=audit_callback,
        )

    guarded = _guardrail_check_payload(parsed, finding_candidates, result_summary)

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
        raw_response=parsed,
    )
    result.new_leads, result.progress = apply_check_result(
        case=case,
        db=db,
        session_id=session_id,
        iteration=iteration,
        planned_query=planned_query,
        hypothesis=hypothesis,
        result_summary=result_summary,
        check_result=result,
    )
    return result
