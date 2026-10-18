"""Read-only status summaries for persisted report sections."""

from __future__ import annotations

import json
from typing import Any

from forensia.core.identifiers import gap_hypothesis_id
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import find_missing_evidence_ids
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.report_validation import has_failure_marker
from forensia.report.sections.report_input import active_report_section_keys
from forensia.report.sections.section_run_store import load_section_signature
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
    row_by_key = {str(row.get("section_key") or ""): row for row in sections}
    adopted_keys = active_report_section_keys(db)
    required_keys = (
        list(adopted_keys)
        if adopted_keys is not None
        else sorted(key for key in row_by_key if key)
    )
    linked_refs = db.execute(
        "SELECT section_key, evidence_id FROM section_evidence"
    ).fetchall()
    body_refs = {
        key: EVIDENCE_ID_PATTERN.findall(str(row.get("body") or ""))
        for key, row in row_by_key.items()
    }
    refs_by_section: dict[str, set[str]] = {}
    for key, evidence_id in linked_refs:
        if evidence_id:
            refs_by_section.setdefault(str(key), set()).add(str(evidence_id))
    for key, refs in body_refs.items():
        refs_by_section.setdefault(key, set()).update(refs)
    all_refs = sorted({ref for refs in refs_by_section.values() for ref in refs})
    invalid_refs = set(find_missing_evidence_ids(db, all_refs)) if all_refs else set()
    missing_sections: list[str] = []
    stale_sections: list[str] = []
    invalid_reference_sections: list[str] = []
    items = []
    focus = set(focus_sections or [])
    for section_key in required_keys:
        row = row_by_key.get(section_key, {})
        gaps = row.get("gaps") or []
        if isinstance(gaps, str):
            try:
                gaps = json.loads(gaps)
            except json.JSONDecodeError:
                gaps = []
        valid_gaps = gaps if isinstance(gaps, list) else []
        body = str(row.get("body") or "")
        stale = bool(row.get("stale", True))
        signature = load_section_signature(db, section_key)
        section_invalid_refs = sorted(
            refs_by_section.get(section_key, set()) & invalid_refs
        )
        current_output = (
            bool(body.strip())
            and not stale
            and bool(signature)
            and not has_failure_marker(body)
        )
        if not current_output:
            missing_sections.append(section_key)
        if stale:
            stale_sections.append(section_key)
        if section_invalid_refs:
            invalid_reference_sections.append(section_key)
        items.append(
            {
                "section_key": section_key,
                "title": row.get("title"),
                "confidence": _safe_float(row.get("confidence")),
                "status": str(row.get("status") or "draft"),
                "update_count": int(row.get("update_count") or 0),
                "gap_count": len(valid_gaps),
                "gaps": valid_gaps,
                "gap_hypothesis_ids": [
                    gap_hypothesis_id(str(gap)) for gap in valid_gaps
                ],
                "body": body,
                "stale": stale,
                "current_output": current_output,
                "current_signature": signature,
                "invalid_evidence_refs": section_invalid_refs,
                "is_writing": section_key == str(current_section or ""),
                "is_highlighted": section_key in focus,
            }
        )
    return {
        "current_section": current_section,
        "focus_sections": focus_sections or [],
        "items": items,
        "required_section_keys": required_keys,
        "missing_section_keys": sorted(set(missing_sections)),
        "stale_section_keys": sorted(set(stale_sections)),
        "invalid_reference_sections": sorted(set(invalid_reference_sections)),
        "complete": bool(required_keys)
        and not missing_sections
        and not stale_sections
        and not invalid_reference_sections,
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
