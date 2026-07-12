"""Report-section DTO projection.

This lives in the reporting layer because building the section DTO includes
server-side Markdown/HTML rendering of section bodies. Keeping it here avoids an
upward dependency from the platform ``api`` layer into ``report``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from forensia.api.dto import ReportSectionDTO
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.report.render.evidence_map import build_evidence_map
from forensia.report.render.html import (
    _inject_evidence_interactivity,
    render_markdown_fragment,
)


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: normalize_value(value) for key, value in row.items()}


def list_report_sections_dto(db: CaseDB) -> list[ReportSectionDTO]:
    """Return all report sections with synthetic gap hypothesis IDs."""
    rows = fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )
    evidence_by_section: dict[str, list[str]] = {}
    for row in fetch_records(
        db,
        """
        SELECT section_key, evidence_id
        FROM section_evidence
        WHERE COALESCE(evidence_id, '') != ''
        ORDER BY section_key, created_at, evidence_id
        """,
    ):
        section_key = str(row.get("section_key") or "")
        evidence_id = str(row.get("evidence_id") or "").strip()
        if not section_key or not evidence_id:
            continue
        bucket = evidence_by_section.setdefault(section_key, [])
        if evidence_id not in bucket:
            bucket.append(evidence_id)
    items: list[ReportSectionDTO] = []
    for row in rows:
        normalized = _normalize_row(row)
        section_key = str(normalized.get("section_key") or "")
        evidence_ids = evidence_by_section.get(section_key, [])
        gaps = normalized.get("gaps") or []
        if not isinstance(gaps, list):
            gaps = []
        normalized["gaps"] = gaps
        normalized["status"] = str(normalized.get("status") or "draft")
        normalized["update_count"] = int(normalized.get("update_count") or 0)
        normalized["gap_hypothesis_ids"] = [
            f"gap-{hashlib.sha1(str(gap).encode('utf-8')).hexdigest()[:10]}"
            for gap in gaps
        ]
        normalized["gap_count"] = len(gaps)
        normalized["evidence_ids"] = evidence_ids
        normalized["evidence_count"] = len(evidence_ids)
        items.append(ReportSectionDTO.model_validate(normalized))

    # Populate body_html (server-rendered HTML from markdown body)
    non_empty_bodies = [item.body for item in items if item.body]
    if non_empty_bodies:
        all_bodies = "\n\n".join(non_empty_bodies)
        evidence_map = build_evidence_map(db, all_bodies)
        for item in items:
            if item.body:
                html = str(render_markdown_fragment(item.body))
                item.body_html = _inject_evidence_interactivity(html, evidence_map)

    return items
