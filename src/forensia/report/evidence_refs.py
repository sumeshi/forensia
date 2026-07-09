"""Evidence-id extraction and SQL LIKE helpers shared by keypoint queries."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value

# ── SQL helpers used by keypoint lambdas ──


def _sql_like_any(column: str, *patterns: str) -> str:
    lowered = f"LOWER(COALESCE({column}, ''))"
    return (
        "("
        + " OR ".join(f"{lowered} LIKE '{pattern.lower()}'" for pattern in patterns)
        + ")"
    )


def _path_like_any(column: str, *segments: str) -> str:
    patterns = []
    for segment in segments:
        normalized = str(segment or "").strip().strip("/\\").lower().replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        if not parts:
            continue
        slash_pattern = "%/" + "/".join(parts) + "/%"
        backslash_pattern = "%\\" + "\\".join(parts) + "\\%"
        patterns.extend((slash_pattern, backslash_pattern))
    return _sql_like_any(column, *patterns)


def _like_any_or_false(column: str, patterns: tuple[str, ...]) -> str:
    return _sql_like_any(column, *patterns) if patterns else "FALSE"


def _path_like_any_or_false(column: str, segments: tuple[str, ...]) -> str:
    return _path_like_any(column, *segments) if segments else "FALSE"


def _extension_in_sql(column: str, extensions: tuple[str, ...]) -> str:
    if not extensions:
        return "FALSE"
    values = ", ".join(f"'{extension}'" for extension in extensions)
    return f"LOWER(COALESCE({column}, '')) IN ({values})"


# ── Pattern ──

EVIDENCE_ID_PATTERN = re.compile(
    r"\b(?:evtx-[a-zA-Z][a-zA-Z0-9.-]*-\d{12}|mft-\d{12,15}-\d{2,4}|prefetch-[a-zA-Z][a-zA-Z0-9._-]+-[a-f0-9]{5,32})\b"
)

EvidenceResolver = Callable[[CaseDB], list[dict[str, Any]]]


# ── Evidence ID extraction helpers ──


def _extract_evidence_ids_from_value(value: Any) -> list[str]:
    """Extract evidence_id values from nested row/finding payloads."""
    ids: list[str] = []
    seen: set[str] = set()

    def add(raw: Any) -> None:
        text = str(raw or "").strip()
        if text and text not in seen:
            seen.add(text)
            ids.append(text)

    def walk(item: Any) -> None:
        if isinstance(item, str):
            stripped = item.strip()
            if not stripped:
                return
            if EVIDENCE_ID_PATTERN.fullmatch(stripped):
                add(stripped)
                return
            if stripped[:1] in {"[", "{"}:
                try:
                    walk(json.loads(stripped))
                except json.JSONDecodeError:
                    return
            return
        if isinstance(item, dict):
            add(item.get("evidence_id"))
            many = item.get("evidence_ids")
            if isinstance(many, list):
                for value in many:
                    add(value)
            for key in ("evidence", "rows", "answer"):
                if key in item:
                    walk(item.get(key))
            return
        if isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return ids


def _row_with_evidence_ids(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a row and expose nested finding evidence IDs for report prompts."""
    normalized = normalize_value(row)
    if not isinstance(normalized, dict):
        return {}
    evidence_ids = _extract_evidence_ids_from_value(normalized)
    if evidence_ids:
        normalized.setdefault("evidence_ids", evidence_ids)
        normalized.setdefault("evidence_id", evidence_ids[0])
    else:
        normalized["citable"] = False
    return normalized


# ── Summary builder ──


def _summarize_rows(
    *,
    source_type: str,
    source_id: str,
    description: str,
    rows: list[dict[str, Any]],
    max_rows: int = 20,
) -> dict[str, Any]:
    """Build a structured summary dict from a list of database rows, extracting evidence/finding/hypothesis IDs."""
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized_row = _row_with_evidence_ids(row)
        normalized_rows.append(normalized_row)
        for evidence_id in _extract_evidence_ids_from_value(normalized_row):
            value = str(evidence_id)
            if value not in seen_evidence_ids:
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        finding_id = row.get("finding_id")
        if finding_id:
            value = str(finding_id)
            if value not in seen_finding_ids:
                seen_finding_ids.add(value)
                finding_ids.append(value)
        hypothesis_id = row.get("hypothesis_id")
        if hypothesis_id:
            value = str(hypothesis_id)
            if value not in seen_hypothesis_ids:
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        source_type: source_id,
        "description": description,
        "kind": "rows" if source_type == "keypoint" else "trace",
        "source_kind": source_type,
        "source_ref": source_id,
        "row_count": len(rows),
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
        "sample_rows": normalized_rows[:max_rows],
    }


# ── Keypoint query helper ──


def _report_keypoint_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return fetch_records(db, query)


# ── Gap extraction helper ──


def _extract_needed_evidence(latest_reasoning: str | None) -> str:
    """Parse missing_questions from latest_reasoning JSON, return first 2 items joined."""
    if not latest_reasoning:
        return ""
    try:
        parsed = json.loads(latest_reasoning)
        missing = parsed.get("missing_questions", [])
        if isinstance(missing, list) and missing:
            items = [str(q).strip() for q in missing if q]
            return "; ".join(items[:2])
    except json.JSONDecodeError, TypeError:
        pass
    return ""

