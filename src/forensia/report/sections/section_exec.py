"""Bounded deterministic recipes used to build current report projections."""

from __future__ import annotations

from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.answers.keypoint_catalog import _resolve_evidence_results
from forensia.report.render.formats import load_report_formats


def _execute_keypoint(
    case: Case, db: CaseDB, keypoint: str
) -> tuple[str, dict[str, Any]]:
    """Recompute one registered read-only recipe against the current CaseDB."""
    source_ref = str(keypoint or "").strip()
    if not source_ref:
        raise ValueError("report keypoint must not be empty")
    results = _resolve_evidence_results(db, keypoints=[source_ref])
    if not results:
        raise ValueError(f"report keypoint produced no result: {source_ref}")
    result = dict(results[0])
    result.setdefault("source_ref", source_ref)
    result.setdefault("source_kind", "keypoint")
    from forensia.config import get_llm_settings

    language = str(get_llm_settings().get("output_language", "ja")).casefold()
    captions = load_report_formats(getattr(case, "report_template_dir", None)).get(
        "keypoint_descriptions", {}
    )
    localized = captions.get(language, {}) if isinstance(captions, dict) else {}
    if isinstance(localized, dict) and source_ref in localized:
        result["description"] = str(localized[source_ref])
    return source_ref, result
