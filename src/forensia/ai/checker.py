from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import build_check_messages
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB

VALID_VERDICTS = {"confirmed", "refuted", "inconclusive", "newlead"}


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

    return {
        "row_count": len(rows),
        "sample_rows": rows[:sample_size],
        "evidence_ids": evidence_ids[:sample_size],
    }


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def _normalize_verdict(value: Any) -> str:
    verdict = str(value or "").strip().lower()
    return verdict if verdict in VALID_VERDICTS else "inconclusive"


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
    finding_id = f"hypothesis:{hypothesis.id}" if hypothesis else f"query:{planned_query.query_id}"
    missing_checks = raw_response.get("missing_checks") or []
    notes = str(raw_response.get("notes") or "")
    db.execute("DELETE FROM ai_reviews WHERE finding_id = ?", (finding_id,))
    db.execute(
        """
        INSERT INTO ai_reviews (
            review_id, finding_id, verdict, report_text, missing_checks,
            confidence_adjustment, notes, raw_response, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"review-{finding_id}",
            finding_id,
            verdict,
            report_text,
            json.dumps(missing_checks if isinstance(missing_checks, list) else [], ensure_ascii=False),
            0.0,
            notes,
            json.dumps(raw_response, ensure_ascii=False, default=str),
            datetime.now(UTC).replace(tzinfo=None),
        ),
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
    finding_id = f"{session_id}-{planned_query.query_id}-finding"
    language = str(get_llm_settings()["output_language"]).lower()
    prefix = "調査:" if language.startswith("ja") else "Investigation:"
    title = f"{prefix} {planned_query.purpose}"
    summary = report_text
    evidence = result_summary.get("sample_rows", [])
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
) -> CheckResult:
    overview_md = overview_md if overview_md is not None else memory.load_overview()
    memory_context_md = memory_context_md if memory_context_md is not None else memory.load_compact_context(
        ["facts.md", "timeline.md", "tasks.md"],
        max_bytes=max(1024, memory.max_bytes // 2),
    )
    messages = build_check_messages(
        planned_query=planned_query,
        hypothesis=hypothesis,
        finding_candidates=finding_candidates,
        result_summary=result_summary,
        overview_md=overview_md,
        memory_context_md=memory_context_md,
    )
    parsed = request_llm_json(
        messages=messages,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )

    result = CheckResult(
        query_id=parsed.get("query_id", planned_query.query_id),
        verdict=_normalize_verdict(parsed.get("verdict")),
        finding_updates=parsed.get("finding_updates") or [],
        suspicious_evidence=parsed.get("suspicious_evidence") or [],
        new_hypotheses=_parse_new_hypotheses(parsed.get("new_hypotheses")),
        memory_updates=parsed.get("memory_updates") or {},
        report_text=parsed.get("report_text") or "",
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
