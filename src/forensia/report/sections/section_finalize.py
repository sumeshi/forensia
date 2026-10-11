"""Finalize a rendered section: quality gates, claim extraction, DB persistence, gap reporting."""

from __future__ import annotations

import re
from typing import Any

from forensia.core.textutil import normalize_localized_dates
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import find_missing_evidence_ids
from forensia.db.query import normalize_value
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.render.markdown import _render_json_table_blocks
from forensia.report.sections.quality_gates import (
    _quality_gate_section,
)
from forensia.report.sections.section_quality import (
    _duplicate_finding_titles,
    _section_confidence,
    _validate_body_evidence_ids,
    collect_gaps,
)
from forensia.report.sections.section_store import (
    _upsert_claims,
    _upsert_report_section,
)


def preprocess_section_body(
    body: str,
) -> str:
    body = re.sub(r"^\*\*Status:\*\*.*$", "", body, flags=re.MULTILINE).strip()
    body = normalize_localized_dates(body)
    return _render_json_table_blocks(body)


def _collect_initial_gaps(
    db: CaseDB,
    section_key: str,
    body: str,
    extra_gaps: list[str] | None = None,
) -> tuple[list[str], float]:
    candidate_gaps = collect_gaps({section_key: body})
    candidate_confidence = _section_confidence(body)
    for gap in extra_gaps or []:
        if gap not in candidate_gaps:
            candidate_gaps.append(gap)
    missing_evidence_ids = _validate_body_evidence_ids(db, body)
    if missing_evidence_ids:
        candidate_gaps.append(
            f"Referenced evidence_id values not found in database: {', '.join(missing_evidence_ids[:5])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    return candidate_gaps, candidate_confidence


def _read_persisted_section(db: CaseDB, section_key: str) -> dict[str, Any]:
    row = db.execute(
        "SELECT body, confidence, gaps FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    persisted_confidence = float(row[1] or 0.0)
    persisted_gaps = normalize_value(row[2]) or []
    if not isinstance(persisted_gaps, list):
        persisted_gaps = []
    return {
        "gaps": persisted_gaps,
        "confidence": persisted_confidence,
        "updated": False,
    }


def validate_section_evidence_ids(db: CaseDB, body: str) -> tuple[str, list[str]]:
    """Validate evidence IDs in body against DB. Return (cleaned_body, gaps).

    Detection delegates to the authoritative shared lookup; this owner only
    strips unresolvable references from the body.
    """
    ids_found = sorted(set(EVIDENCE_ID_PATTERN.findall(body)))
    if not ids_found:
        return body, []

    invalid = find_missing_evidence_ids(db, ids_found)
    if not invalid:
        return body, []

    cleaned = body
    for inv in invalid:
        cleaned = re.sub(rf"\b{re.escape(inv)}\b", "", cleaned)
    cleaned = re.sub(r"([（(])\s*(?:,\s*)+", r"\1", cleaned)
    cleaned = re.sub(r"(?:\s*,)+\s*([)）])", r"\1", cleaned)
    cleaned = re.sub(r"（\s*）|\(\s*\)", "", cleaned)
    cleaned = re.sub(r"  +", " ", cleaned)
    cleaned = re.sub(r",\s*,", ",", cleaned)
    cleaned = cleaned.strip().strip(",").strip()

    gaps = [f"cited evidence ids not found: {', '.join(invalid)}"]
    return cleaned, gaps


def assess_section_candidate(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]] | None = None,
    extra_gaps: list[str] | None = None,
) -> dict[str, Any]:
    """Run the persisted-section gates without changing the section or its links."""
    body = preprocess_section_body(body)
    if db is not None and body:
        body, id_gaps = validate_section_evidence_ids(db, body)
    else:
        id_gaps = []
    candidate_gaps, candidate_confidence = _collect_initial_gaps(
        db, section_key, body, extra_gaps
    )
    if id_gaps:
        candidate_gaps.extend(id_gaps)
        candidate_confidence = min(candidate_confidence, 0.5)
    candidate_gaps, candidate_confidence = _quality_gate_section(
        section_key,
        title,
        body,
        candidate_gaps,
        candidate_confidence,
        evidence_results,
        db=db,
    )
    duplicate_titles = _duplicate_finding_titles(db, body)
    if duplicate_titles:
        candidate_gaps.append(
            f"Finding titles are repeated too often in this section: {', '.join(duplicate_titles[:3])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    return {
        "body": body,
        "gaps": candidate_gaps,
        "confidence": candidate_confidence,
    }


def finalize_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
    extra_gaps: list[str] | None = None,
) -> dict[str, Any]:
    """UPSERT the section into DuckDB. Returns gap list and confidence."""
    assessed = assess_section_candidate(
        db, section_key, title, body, evidence_results, extra_gaps
    )
    body = assessed["body"]
    candidate_gaps = assessed["gaps"]
    candidate_confidence = assessed["confidence"]
    updated = _upsert_report_section(
        db=db,
        section_key=section_key,
        title=title,
        body=body,
        confidence=candidate_confidence,
        gaps=candidate_gaps,
        session_id=session_id,
    )
    if not updated:
        return _read_persisted_section(db, section_key)
    _upsert_claims(db, section_key)
    return {
        "gaps": candidate_gaps,
        "confidence": candidate_confidence,
        "updated": True,
    }
