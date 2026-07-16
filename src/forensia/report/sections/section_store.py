"""Persistence of report sections, claims, and section trace dumps."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.report.evidence_refs import (
    _extract_evidence_ids_from_value,
)
from forensia.report.sections.section_quality import GAP_PATTERN

_SCAFFOLD_PATTERNS = [
    re.compile(r"\*\*Status:\*\*.*"),
    re.compile(r"\*\*ID:\*\*.*"),
    re.compile(r"### Answer"),
    re.compile(r"### Missing Reason"),
    re.compile(r"### Queries Run"),
    re.compile(r"\*Block skipped:\*.*"),
    re.compile(r"\*Section block failed:\*.*"),
    re.compile(r"### Structured Data"),
    re.compile(r"^-?\s*(JSON|CSV):\s+.*", re.IGNORECASE),
    re.compile(r"^-\s*structured:.*", re.IGNORECASE),
    re.compile(r"^\|.*\|$"),
    re.compile(r"^\|[-:|\s]+\|$"),
]


def _extract_claim_texts(body: str) -> list[str]:
    """Extract distinct claim-paragraph texts from a section body, skipping headings and gap markers."""
    lines = body.splitlines()
    filtered_lines = []
    skip_metadata_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            skip_metadata_block = False
        if stripped in {"### Missing Reason", "### Queries Run", "### Structured Data"}:
            skip_metadata_block = True
        if stripped.startswith("### ") and stripped not in {
            "### Missing Reason",
            "### Queries Run",
            "### Structured Data",
        }:
            skip_metadata_block = False
        if (
            stripped
            and not skip_metadata_block
            and not any(p.match(stripped) for p in _SCAFFOLD_PATTERNS)
        ):
            filtered_lines.append(line)
        else:
            filtered_lines.append("")
    body = "\n".join(filtered_lines)
    claims: list[str] = []
    seen: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", body):
        text = paragraph.strip()
        if not text or text.startswith("#") or GAP_PATTERN.search(text):
            continue
        normalized = " ".join(
            line.strip("- ").strip() for line in text.splitlines() if line.strip()
        )
        key = _claim_text_key(normalized)
        if (
            normalized
            and normalized not in ("[]", "{}", "<!--", "-->")
            and key not in seen
        ):
            seen.add(key)
            claims.append(normalized)
    return claims


def _claim_text_key(text: str) -> str:
    return " ".join(text.lower().split())


def _collect_claim_provenance(
    evidence_results: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Aggregate all evidence, finding, and hypothesis IDs referenced across a list of evidence result dicts."""
    max_evidence_ids = 25
    max_other_ids = 25
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    for result in evidence_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        row_evidence_ids: list[str] = []
        for row in (
            (result.get("sample_rows") or [])
            + (result.get("head_rows") or [])
            + (result.get("tail_rows") or [])
        ):
            row_evidence_ids.extend(_extract_evidence_ids_from_value(row))
        for evidence_id in [*(result.get("evidence_ids") or []), *row_evidence_ids]:
            value = str(evidence_id)
            if (
                value
                and value not in seen_evidence_ids
                and len(evidence_ids) < max_evidence_ids
            ):
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        for finding_id in result.get("finding_ids") or []:
            value = str(finding_id)
            if (
                value
                and value not in seen_finding_ids
                and len(finding_ids) < max_other_ids
            ):
                seen_finding_ids.add(value)
                finding_ids.append(value)
        for hypothesis_id in result.get("hypothesis_ids") or []:
            value = str(hypothesis_id)
            if (
                value
                and value not in seen_hypothesis_ids
                and len(hypothesis_ids) < max_other_ids
            ):
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
    }


def _claim_support_status(
    db: CaseDB,
    evidence_ids: list[str],
    finding_ids: list[str],
    hypothesis_ids: list[str],
) -> str:
    """Determine whether a set of evidence/finding/hypothesis IDs are all present in their respective tables."""
    if not evidence_ids and not finding_ids and not hypothesis_ids:
        return "unsupported"
    if finding_ids:
        placeholders = ", ".join("?" for _ in finding_ids)
        found_finding_ids = {
            str(row[0])
            for row in db.execute(
                f"SELECT finding_id FROM findings WHERE finding_id IN ({placeholders})",
                tuple(finding_ids),
            ).fetchall()
        }
        if any(finding_id not in found_finding_ids for finding_id in finding_ids):
            return "orphaned_reference"
    if hypothesis_ids:
        placeholders = ", ".join("?" for _ in hypothesis_ids)
        hypothesis_rows = db.execute(
            f"SELECT hypothesis_id, sufficiency_status, human_review_required "
            f"FROM hypotheses WHERE hypothesis_id IN ({placeholders})",
            tuple(hypothesis_ids),
        ).fetchall()
        found_hypothesis_ids = {
            str(row[0])
            for row in hypothesis_rows
        }
        if any(
            hypothesis_id not in found_hypothesis_ids
            for hypothesis_id in hypothesis_ids
        ):
            return "orphaned_reference"
        sufficiency_states = {
            str(row[1] or "")
            for row in hypothesis_rows
        }
        if "unobservable" in sufficiency_states:
            return "unobservable"
        if any(bool(row[2]) for row in hypothesis_rows):
            return "needs_review"
        if sufficiency_states & {"insufficient", "needs_review"}:
            return "needs_review"
        if "partial" in sufficiency_states:
            return "partially_supported"
    if evidence_ids:
        placeholders = ", ".join("?" for _ in evidence_ids)
        found_evidence_ids = {
            str(row[0])
            for row in db.execute(
                f"""
                SELECT evidence_id FROM evtx_events WHERE evidence_id IN ({placeholders})
                UNION
                SELECT evidence_id FROM mft_entries WHERE evidence_id IN ({placeholders})
                UNION
                SELECT evidence_id FROM prefetch_executions WHERE evidence_id IN ({placeholders})
                UNION
                SELECT evidence_id FROM prefetch_timeline WHERE evidence_id IN ({placeholders})
                """,
                tuple(evidence_ids * 4),
            ).fetchall()
        }
        if any(evidence_id not in found_evidence_ids for evidence_id in evidence_ids):
            return "orphaned_reference"
    return "supported"


def _upsert_claims(
    db: CaseDB,
    section_key: str,
    body: str,
    evidence_results: list[dict[str, Any]],
) -> list[str]:
    """Extract claims from a section body, delete stale rows, and insert fresh claim records with provenance."""
    now = datetime.now(UTC).replace(tzinfo=None)
    claims = _extract_claim_texts(body)
    provenance = _collect_claim_provenance(evidence_results)
    support_status = _claim_support_status(
        db,
        provenance["evidence_ids"],
        provenance["finding_ids"],
        provenance["hypothesis_ids"],
    )
    db.execute("DELETE FROM claims WHERE section_key = ?", (section_key,))
    rows: list[tuple[Any, ...]] = []
    for index, claim_text in enumerate(claims, start=1):
        claim_id = hashlib.sha1(
            f"{section_key}-{index}-{claim_text}".encode()
        ).hexdigest()[:16]
        rows.append(
            (
                claim_id,
                section_key,
                claim_text,
                json.dumps(provenance["finding_ids"], ensure_ascii=False),
                json.dumps(provenance["hypothesis_ids"], ensure_ascii=False),
                json.dumps(provenance["evidence_ids"], ensure_ascii=False),
                support_status,
                now,
                now,
            )
        )
    db.insert_many(
        """
        INSERT INTO claims (
            claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
            support_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if not claims:
        return []
    text_groups = fetch_records(
        db,
        """
        SELECT claim_id, claim_text, section_key, finding_ids, hypothesis_ids, evidence_ids, support_status
        FROM claims
        WHERE claim_text IN (
            SELECT claim_text FROM claims GROUP BY claim_text HAVING COUNT(*) > 1
        )
        ORDER BY claim_text, section_key, claim_id
        """,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in text_groups:
        grouped.setdefault(
            _claim_text_key(str(row.get("claim_text") or "")), []
        ).append(row)
    for rows_for_text in grouped.values():
        provenance_keys = {
            json.dumps(
                {
                    "finding_ids": normalize_value(row.get("finding_ids")) or [],
                    "hypothesis_ids": normalize_value(row.get("hypothesis_ids")) or [],
                    "evidence_ids": normalize_value(row.get("evidence_ids")) or [],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            for row in rows_for_text
        }
        if len(provenance_keys) <= 1:
            continue
        for row in rows_for_text:
            db.execute(
                "UPDATE claims SET support_status = 'needs_review', updated_at = ? WHERE claim_id = ?",
                (now, str(row["claim_id"])),
            )
    statuses = fetch_records(
        db,
        "SELECT DISTINCT support_status FROM claims WHERE section_key = ?",
        (section_key,),
    )
    return [
        str(row.get("support_status") or "")
        for row in statuses
        if str(row.get("support_status") or "")
    ]


def _update_section_quality_only(
    db: CaseDB,
    section_key: str,
    confidence: float,
    gaps: list[str],
) -> None:
    """Update confidence and gaps for a section without overwriting body or status history."""
    row = db.execute(
        "SELECT status FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(row[0] or "draft") if row else "draft"
    if gaps or confidence < 0.9:
        next_status = (
            existing_status
            if existing_status in {"ai_exhausted", "human_reviewed"}
            else "draft"
        )
    else:
        next_status = existing_status
    db.execute(
        """
        UPDATE report_sections
        SET confidence = ?, gaps = ?, status = ?
        WHERE section_key = ?
        """,
        (confidence, json.dumps(gaps, ensure_ascii=False), next_status, section_key),
    )


def _upsert_report_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    confidence: float,
    gaps: list[str],
    session_id: str | None = None,
) -> bool:
    """Insert or update a report_sections row, skipping if the section is human_reviewed with existing content."""
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        "SELECT status, update_count, body FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(existing[0] or "draft") if existing else "draft"
    if existing_status == "human_reviewed" and str(existing[2] or "").strip():
        return False
    update_count = int(existing[1] or 0) + 1 if existing else 1
    if gaps or confidence < 0.9:
        next_status = "draft"
    elif existing_status == "human_reviewed":
        next_status = "human_reviewed"
    elif existing_status == "ai_exhausted":
        next_status = "ai_exhausted"
    else:
        next_status = "stable"
    db.execute(
        """
        INSERT INTO report_sections (
            section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at, stale
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (section_key) DO UPDATE SET
            title = excluded.title,
            body = excluded.body,
            confidence = excluded.confidence,
            status = excluded.status,
            update_count = excluded.update_count,
            gaps = excluded.gaps,
            last_filled_session = excluded.last_filled_session,
            last_filled_at = excluded.last_filled_at,
            stale = FALSE
        """,
        (
            section_key,
            title,
            body,
            confidence,
            next_status,
            update_count,
            json.dumps(gaps, ensure_ascii=False),
            session_id,
            now,
            False,
        ),
    )
    return True


def mark_report_sections_ai_exhausted(db: CaseDB) -> None:
    """Mark all report sections that have body content as ai_exhausted."""
    db.execute(
        """
        UPDATE report_sections
        SET status = 'ai_exhausted'
        WHERE COALESCE(body, '') != ''
        """
    )


def set_report_section_status(db: CaseDB, section_key: str, status: str) -> None:
    """Set a report section's status after validating it is a supported value."""
    if status not in {"draft", "stable", "ai_exhausted", "human_reviewed"}:
        raise ValueError(f"unsupported report section status: {status}")
    db.execute(
        """
        UPDATE report_sections
        SET status = ?
        WHERE section_key = ?
        """,
        (status, section_key),
    )


def fetch_report_sections(db: CaseDB) -> list[dict[str, Any]]:
    """Fetch all report section rows ordered by section_key."""
    return fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )


def load_report_sections_map(db: CaseDB) -> dict[str, str]:
    """Load report sections as a dict mapping section_key to body."""
    return {
        str(row.get("section_key")): str(row.get("body") or "")
        for row in fetch_report_sections(db)
    }


def _dump_section_trace_json(
    case: Case, section_key: str, evidence_results: list[dict[str, Any]]
) -> None:
    """Write non-row evidence results to reports/debug/<section_key>_trace.json."""
    trace_rows = [
        normalize_value(result)
        for result in evidence_results
        if str(result.get("kind") or "rows") != "rows"
    ]
    if not trace_rows:
        return
    debug_dir = case.reports_dir / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    out_path = debug_dir / f"{section_key}_trace.json"
    out_path.write_text(
        json.dumps(trace_rows, ensure_ascii=False, default=str, indent=2),
        encoding="utf-8",
    )


def _dump_section_questions_json(case: Case, db: CaseDB, section_key: str) -> None:
    """Write resolved QuestionSpec rows to reports/debug/<section_key>_questions.json."""
    rows = fetch_records(
        db,
        """
        SELECT question_id, section_key, block_heading, question_text, question_type,
               answer_spec, intent, confidence, matched_rule, required_evidence,
               status, created_at, updated_at
        FROM section_questions
        WHERE section_key = ?
        ORDER BY block_heading, question_id
        """,
        (section_key,),
    )
    if not rows:
        return
    debug_dir = case.reports_dir / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    out_path = debug_dir / f"{section_key}_questions.json"
    normalized = [normalize_value(row) for row in rows]
    out_path.write_text(
        json.dumps(normalized, ensure_ascii=False, default=str, indent=2),
        encoding="utf-8",
    )


def _dump_section_evidence_json(
    case: Case, section_key: str, rows: list[dict[str, Any]]
) -> None:
    """Write flat evidence rows to reports/evidence/<section_key>.json."""
    if not rows:
        return
    evidence_dir = case.reports_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / f"{section_key}.json"
    out_path.write_text(
        json.dumps(rows, ensure_ascii=False, default=str, indent=2), encoding="utf-8"
    )


dump_section_questions_json = _dump_section_questions_json
extract_claim_texts = _extract_claim_texts
