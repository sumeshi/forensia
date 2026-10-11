"""Bounded deterministic recipes used to build current report projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.answers.keypoint_catalog import _resolve_evidence_results


@dataclass(slots=True)
class SectionBlockResult:
    body: str
    evidence_results: list[dict[str, Any]]
    iterations: int
    status: str


def _execute_keypoint(
    case: Case, db: CaseDB, keypoint: str
) -> tuple[str, dict[str, Any]]:
    """Recompute one registered read-only recipe against the current CaseDB."""
    del case
    source_ref = str(keypoint or "").strip()
    if not source_ref:
        raise ValueError("report keypoint must not be empty")
    results = _resolve_evidence_results(db, keypoints=[source_ref])
    if not results:
        raise ValueError(f"report keypoint produced no result: {source_ref}")
    result = dict(results[0])
    result.setdefault("source_ref", source_ref)
    result.setdefault("source_kind", "keypoint")
    return source_ref, result
