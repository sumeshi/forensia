"""Persistence of current report sections and evidence-backed hypothesis claims."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.evidence.links import load_evidence_links
from forensia.report.sections.report_input import active_report_section_keys


def _upsert_claims(db: CaseDB, section_key: str) -> None:
    """Project adjudicated hypotheses backed by current, section-linked evidence."""
    rows = fetch_records(
        db,
        """
        SELECT DISTINCT h.hypothesis_id, h.description, h.status
        FROM section_evidence se
        JOIN hypothesis_evidence he ON he.evidence_id = se.evidence_id
        JOIN hypotheses h ON h.hypothesis_id = he.hypothesis_id
        WHERE se.section_key = ? AND COALESCE(h.description, '') != ''
        ORDER BY h.hypothesis_id
        """,
        (section_key,),
    )
    section_evidence_ids = {
        str(row[0])
        for row in db.execute(
            "SELECT DISTINCT evidence_id FROM section_evidence "
            "WHERE section_key = ? AND evidence_id IS NOT NULL",
            [section_key],
        ).fetchall()
        if row[0]
    }
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        hypothesis_id = str(row.get("hypothesis_id") or "")
        status = str(row.get("status") or "")
        if not hypothesis_id or status not in {"confirmed", "refuted"}:
            continue
        expected_roles = (
            {"supporting", "corroborating"}
            if status == "confirmed"
            else {"contradictory"}
        )
        admitted = [
            link
            for link in load_evidence_links(db, hypothesis_id, current_only=True)
            if link.assessment_id
            and link.role in expected_roles
            and link.evidence_id in section_evidence_ids
        ]
        if not admitted:
            continue
        grouped[hypothesis_id] = {
            "description": str(row.get("description") or "").strip(),
            "status": status,
            "evidence_ids": {link.evidence_id for link in admitted},
            "finding_ids": {link.finding_id for link in admitted if link.finding_id},
        }

    db.execute("DELETE FROM claims WHERE section_key = ?", (section_key,))
    now = datetime.now(UTC).replace(tzinfo=None)
    inserts = []
    for hypothesis_id, item in sorted(grouped.items()):
        evidence_ids = sorted(item["evidence_ids"])
        if not evidence_ids:
            continue
        status = str(item["status"] or "unknown")
        claim_text = (
            f"{status.replace('_', ' ').title()} hypothesis: {item['description']}"
        )
        claim_id = hashlib.sha1(f"{section_key}\0{hypothesis_id}".encode()).hexdigest()[
            :16
        ]
        inserts.append(
            (
                claim_id,
                section_key,
                claim_text,
                json.dumps(sorted(item["finding_ids"]), ensure_ascii=False),
                json.dumps([hypothesis_id], ensure_ascii=False),
                json.dumps(evidence_ids, ensure_ascii=False),
                "supported",
                now,
                now,
            )
        )
    if inserts:
        db.insert_many(
            """
            INSERT INTO claims (
                claim_id, section_key, claim_text, finding_ids, hypothesis_ids,
                evidence_ids, support_status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            inserts,
        )


def _update_section_quality_only(
    db: CaseDB,
    section_key: str,
    confidence: float,
    gaps: list[str],
) -> None:
    row = db.execute(
        "SELECT status FROM report_sections WHERE section_key = ?", (section_key,)
    ).fetchone()
    existing_status = str(row[0] or "draft") if row else "draft"
    next_status = (
        (
            existing_status
            if existing_status in {"ai_exhausted", "human_reviewed"}
            else "draft"
        )
        if gaps or confidence < 0.9
        else existing_status
    )
    db.execute(
        "UPDATE report_sections SET confidence = ?, gaps = ?, status = ? WHERE section_key = ?",
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
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        "SELECT status, update_count, body FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(existing[0] or "draft") if existing else "draft"
    if existing_status == "human_reviewed" and str(existing[2] or "").strip():
        return False
    update_count = int(existing[1] or 0) + 1 if existing else 1
    next_status = "draft" if gaps or confidence < 0.9 else "ai_exhausted"
    db.execute(
        """
        INSERT INTO report_sections (
            section_key, title, body, confidence, status, update_count, gaps,
            last_filled_session, last_filled_at, stale
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
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
        ),
    )
    return True


def mark_report_sections_ai_exhausted(db: CaseDB) -> None:
    keys = active_report_section_keys(db)
    if keys is not None and not keys:
        return
    clause = (
        "AND section_key IN (" + ", ".join("?" for _ in keys) + ")"
        if keys is not None
        else ""
    )
    db.execute(
        f"""
        UPDATE report_sections
        SET status = 'ai_exhausted'
        WHERE COALESCE(body, '') != '' {clause}
        """,
        tuple(keys) if keys is not None else (),
    )


def fetch_report_sections(db: CaseDB) -> list[dict[str, Any]]:
    keys = active_report_section_keys(db)
    clause = (
        "WHERE section_key IN (" + ", ".join("?" for _ in keys) + ")"
        if keys is not None
        else ""
    )
    return fetch_records(
        db,
        f"""
        SELECT section_key, title, body, confidence, status, update_count, gaps,
               last_filled_session, last_filled_at, stale
        FROM report_sections {clause} ORDER BY section_key
        """,
        tuple(keys) if keys is not None else (),
    )


def load_report_sections_map(db: CaseDB) -> dict[str, str]:
    return {
        str(row.get("section_key")): str(row.get("body") or "")
        for row in fetch_report_sections(db)
    }
