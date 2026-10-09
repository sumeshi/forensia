"""Read-only status summaries for persisted report sections."""

from __future__ import annotations

import json
from typing import Any

from forensia.core.identifiers import gap_hypothesis_id
from forensia.db.database import CaseDB
from forensia.report.sections.section_store import fetch_report_sections


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float, returning a default on None/invalid input."""
    if value is None:
        return default
    try:
        return float(value)
    except TypeError, ValueError:
        return default


def build_report_status(
    db: CaseDB,
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Build a summary dict of report sections with gaps and focus markers."""
    sections = fetch_report_sections(db)
    items = []
    focus = set(focus_sections or [])
    for row in sections:
        gaps = row.get("gaps") or []
        if isinstance(gaps, str):
            try:
                gaps = json.loads(gaps)
            except json.JSONDecodeError:
                gaps = []
        valid_gaps = gaps if isinstance(gaps, list) else []
        items.append(
            {
                "section_key": row.get("section_key"),
                "title": row.get("title"),
                "confidence": _safe_float(row.get("confidence")),
                "status": str(row.get("status") or "draft"),
                "update_count": int(row.get("update_count") or 0),
                "gap_count": len(valid_gaps),
                "gaps": valid_gaps,
                "gap_hypothesis_ids": [
                    gap_hypothesis_id(str(gap)) for gap in valid_gaps
                ],
                "body": str(row.get("body") or ""),
                "is_writing": str(row.get("section_key") or "")
                == str(current_section or ""),
                "is_highlighted": str(row.get("section_key") or "") in focus,
            }
        )
    return {
        "current_section": current_section,
        "focus_sections": focus_sections or [],
        "items": items,
        "total_gaps": sum(item["gap_count"] for item in items),
        "total_body_chars": sum(len(item["body"]) for item in items),
    }


def overlay_report_status(
    base_status: dict[str, Any],
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Overlay current section and focus markers onto a base status dict."""
    focus = set(focus_sections or [])
    items = []
    for row in base_status.get("items", []):
        item = dict(row)
        item["is_writing"] = str(item.get("section_key") or "") == str(
            current_section or ""
        )
        item["is_highlighted"] = str(item.get("section_key") or "") in focus
        items.append(item)
    return {
        **base_status,
        "current_section": current_section,
        "focus_sections": list(focus_sections or []),
        "items": items,
    }
