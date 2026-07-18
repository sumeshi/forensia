"""Persistence of check results: reviews, assessments, findings."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from forensia.ai.checking.check_normalize import (
    CheckResult,
    _clamp_confidence,
    _collect_observed_evidence_ids,
)
from forensia.core.case import Case
from forensia.core.session import (
    Hypothesis,
    PlannedQuery,
)
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value

logger = logging.getLogger(__name__)


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
    finding_id = (
        f"hypothesis:{hypothesis.id}"
        if hypothesis
        else f"query:{planned_query.query_id}"
    )
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


def insert_investigation_finding(
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


def _apply_finding_updates(
    db: CaseDB,
    check_result: CheckResult,
    missing_checks: list,
    notes: str,
) -> bool:
    """Apply per-finding status/confidence updates. Returns True on a significant delta."""
    significant_delta = False
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
    return significant_delta


def _is_duplicate_extracted_finding(
    db: CaseDB, title: str, evidence_ids: list[str]
) -> bool:
    """Check whether an extracted finding duplicates an existing one by title + evidence-id set."""
    existing_by_content = db.execute(
        """
        SELECT finding_id, title, evidence FROM findings
        WHERE rule_id = 'hypothesis-extraction' AND title = ?
        """,
        (title,),
    ).fetchone()
    if not existing_by_content:
        return False
    try:
        existing_evidence_ids = set()
        existing_evidence = json.loads(existing_by_content[2] or "[]")
        for ev_row in existing_evidence if isinstance(existing_evidence, list) else []:
            if isinstance(ev_row, dict):
                eid = str(ev_row.get("evidence_id") or "").strip()
                if eid:
                    existing_evidence_ids.add(eid)
        if existing_evidence_ids and set(evidence_ids) == existing_evidence_ids:
            return True
    except Exception:
        logger.debug(
            "Failed to compare evidence ids for duplicate finding check", exc_info=True
        )
    return False


def _persist_extracted_findings(
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis,
    result_summary: dict[str, Any],
    check_result: CheckResult,
) -> None:
    """Persist finding_extractor output (T-04) for a confirmed verdict, skipping duplicates."""
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
        if _is_duplicate_extracted_finding(db, title, evidence_ids):
            continue
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


def _apply_newlead_finding(
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    result_summary: dict[str, Any],
    check_result: CheckResult,
    missing_checks: list,
    notes: str,
) -> None:
    """Insert an investigation finding and its AI review for a newlead verdict."""
    finding_id = insert_investigation_finding(
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
    significant_delta = _apply_finding_updates(db, check_result, missing_checks, notes)
    if check_result.verdict == "confirmed" and hypothesis:
        _persist_extracted_findings(
            db, session_id, planned_query, hypothesis, result_summary, check_result
        )
    if check_result.verdict == "newlead":
        _apply_newlead_finding(
            db,
            session_id,
            planned_query,
            result_summary,
            check_result,
            missing_checks,
            notes,
        )
        new_leads += 1

    progress = (
        new_leads > 0 or significant_delta or len(check_result.new_hypotheses) > 0
    )
    return new_leads, progress
