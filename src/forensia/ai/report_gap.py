"""Report status and gap tracking: build per-section status, turn gaps into hypotheses."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from forensia.ai.hypotheses.hypothesis_manager import admit_new_hypothesis
from forensia.ai.hypotheses.hypothesis_model import (
    _extract_entities_from_text,
    _propose_confirm_when,
    gap_hypothesis_id,
)
from forensia.ai.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, SessionState
from forensia.core.textutil import normalize_text as _normalize_text
from forensia.db.database import CaseDB
from forensia.report.sections.section_store import fetch_report_sections


class GapHypothesisOutput(BaseModel):
    """Pydantic model for validating LLM output when generating gap hypotheses."""

    required_entities: list[str] = Field(min_length=0)
    confirm_when: dict[str, Any] | None = None
    description: str | None = None

    @field_validator("required_entities", mode="before")
    @classmethod
    def coerce_required_entities(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v] if v else []
        if not isinstance(v, list):
            return []
        return [str(e) for e in v if e]

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str | None) -> str | None:
        if v is None:
            return v
        lowered = v.lower()
        prohibited = {
            "unknown",
            "cannot confirm",
            "cannot verify",
            "insufficient evidence",
        }
        for phrase in prohibited:
            if phrase in lowered:
                raise ValueError(f"Description contains prohibited phrase: '{phrase}'")
        return v


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float, returning a default on None/invalid input."""
    if value is None:
        return default
    try:
        return float(value)
    except TypeError, ValueError:
        return default


def _build_report_status(
    db: CaseDB,
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Build a summary dict of all report sections with gaps, confidence, and focus markers."""
    sections = fetch_report_sections(db)
    items = []
    for row in sections:
        gaps = row.get("gaps") or []
        if isinstance(gaps, str):
            try:
                gaps = json.loads(gaps)
            except json.JSONDecodeError:
                gaps = []
        items.append(
            {
                "section_key": row.get("section_key"),
                "title": row.get("title"),
                "confidence": _safe_float(row.get("confidence")),
                "status": str(row.get("status") or "draft"),
                "update_count": int(row.get("update_count") or 0),
                "gap_count": len(gaps) if isinstance(gaps, list) else 0,
                "gaps": gaps if isinstance(gaps, list) else [],
                "gap_hypothesis_ids": [gap_hypothesis_id(str(gap)) for gap in gaps]
                if isinstance(gaps, list)
                else [],
                "body": str(row.get("body") or ""),
                "is_writing": str(row.get("section_key") or "")
                == str(current_section or ""),
                "is_highlighted": str(row.get("section_key") or "")
                in set(focus_sections or []),
            }
        )
    total_gaps = sum(int(item["gap_count"]) for item in items)
    total_body_chars = sum(len(str(item["body"])) for item in items)
    return {
        "current_section": current_section,
        "focus_sections": focus_sections or [],
        "items": items,
        "total_gaps": total_gaps,
        "total_body_chars": total_body_chars,
    }


def _overlay_report_status(
    base_status: dict[str, Any],
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Overlay current section and focus markers onto a base report status dict."""
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


def report_cycle_progress(previous: dict[str, int], current: dict[str, int]) -> bool:
    """Check whether the report made progress (fewer gaps or more content) since the last cycle."""
    return current.get("total_gaps", 0) < previous.get("total_gaps", 0) or current.get(
        "total_body_chars", 0
    ) > previous.get("total_body_chars", 0)


def _has_internal_db_signals(text: str) -> bool:
    """Check if text contains signals that it can be answered from the case database.

    Priority signals: event IDs (4xxx), DB table names, artifact keywords.
    """
    # Event ID pattern: 4xxx (4624, 4688, 4776, etc.)
    if re.search(r"\b4\d{3}\b", text):
        return True
    # DB table/keyword signals - match evidence table names and artifact patterns.
    # Do not add bare English function words ("from", "where") here — they appear
    # in ordinary prose and would route every gap to the DB.
    db_keywords = [
        "prefetch",
        "mft_",
        " evtx",
        "evtx_",
        "logon event",
        "logoff event",
        "event id ",
        "select ",
        ".evtx",
        ".pf",
        "table_name",
        "artifact",
    ]
    lowered = text.lower()
    for kw in db_keywords:
        if kw in lowered:
            return True
    return False


def classify_gap_kind(description: str) -> str:
    """Determine whether a gap requires external lookup, human decision, or internal DB check.

    Routing priority:
    1. Internal-DB signals (event IDs, table names) → internal_db_check (overrides other keywords)
    2. External lookup keywords → external_lookup
    3. Narrow human/business decision keywords → human_decision
    4. Default → internal_db_check
    """
    lowered = description.lower()

    # Priority 1: Internal-DB signals take precedence
    if _has_internal_db_signals(lowered):
        return "internal_db_check"

    # Priority 2: External lookup keywords
    if any(
        token in lowered
        for token in (
            "whois",
            "osint",
            "external",
            "ownership",
            "threat intel",
            "reputation",
            "ip reputation",
            "geo lookup",
            "dns lookup",
            "certificate",
            "public record",
            "internet",
        )
    ):
        return "external_lookup"

    # Priority 3: Narrow human/business decision keywords only
    if any(
        token in lowered
        for token in (
            "hearing",
            "stakeholder",
            "approval",
            "confirm with",
            "manager",
            "business owner",
            "interview",
        )
    ):
        return "human_decision"

    # Default: internal DB check
    return "internal_db_check"


def _parse_gap_hypothesis_output(
    output: dict[str, Any], gap_text: str
) -> tuple[list[str], dict[str, Any] | None]:
    """Parse LLM output for a gap hypothesis, falling back to heuristics when needed.

    Returns (required_entities, confirm_when) tuple.
    Uses GapHypothesisOutput Pydantic model for validation.
    """
    try:
        validated = GapHypothesisOutput(**output)
        return validated.required_entities, validated.confirm_when
    except Exception:
        pass  # Fall through to safety-net heuristics

    required_entities = output.get("required_entities")
    confirm_when = output.get("confirm_when")

    # Apply safety-net heuristics only when LLM output is missing these fields
    if not required_entities or not isinstance(required_entities, list):
        required_entities = _extract_entities_from_text(gap_text)
    else:
        required_entities = [str(e) for e in required_entities if e]

    if not confirm_when or not isinstance(confirm_when, dict):
        confirm_when = _propose_confirm_when(required_entities)

    return required_entities, confirm_when


# _extract_refuted_tokens and _gap_references_refuted moved to
# hypothesis_manager.py (shared with the unified admission gate).
# Imported above.


def inject_gap_hypotheses(
    db: CaseDB,
    state: SessionState,
    gaps: list[str],
    session_id: str,
    memory: MemoryManager | None = None,
    llm_output: dict[str, Any] | None = None,
) -> int:
    """Convert unresolved report gaps into active hypotheses, skipping duplicates and non-DB gaps.

    Uses the unified admission gate (admit_new_hypothesis) to check against
    active, resolved, and refuted hypotheses — preventing refuted claims like
    poqexec.exe from being re-admitted through the gap injection path.
    """
    import hashlib

    added = 0
    current_gap_ids = {
        "GAP-" + hashlib.sha256(str(gap).encode()).hexdigest()[:16]
        for gap in gaps
        if _normalize_text(str(gap))
    }
    gap_sections: dict[str, str] = {}
    for section_key, raw_gaps in db.execute(
        "SELECT section_key, gaps FROM report_sections WHERE gaps IS NOT NULL"
    ).fetchall():
        section_gaps = raw_gaps
        if isinstance(section_gaps, str):
            try:
                section_gaps = json.loads(section_gaps)
            except TypeError, ValueError:
                section_gaps = []
        for section_gap in section_gaps if isinstance(section_gaps, list) else []:
            gap_sections[_normalize_text(str(section_gap))] = str(section_key or "")
    if current_gap_ids:
        placeholders = ", ".join("?" for _ in current_gap_ids)
        db.execute(
            f"UPDATE report_gaps SET status = 'resolved', updated_at = now() "
            f"WHERE status = 'open' AND gap_id NOT IN ({placeholders})",
            sorted(current_gap_ids),
        )
    else:
        db.execute(
            "UPDATE report_gaps SET status = 'resolved', updated_at = now() "
            "WHERE status = 'open'"
        )
    db.execute(
        "UPDATE investigation_tasks SET status = 'resolved', updated_at = now() "
        "WHERE status = 'open' AND gap_id IN "
        "(SELECT gap_id FROM report_gaps WHERE status = 'resolved')"
    )
    for gap in gaps:
        normalized_gap = _normalize_text(gap)
        if not normalized_gap:
            continue

        # Try to get required_entities/confirm_when from LLM output first
        required_entities, confirm_when = _parse_gap_hypothesis_output(
            llm_output or {}, gap
        )
        gap_hash = hashlib.sha256(gap.encode()).hexdigest()[:16]
        gap_id = f"GAP-{gap_hash}"

        # Build a candidate hypothesis for the unified admission gate
        candidate = Hypothesis(
            id=gap_hypothesis_id(gap),
            description=gap,
            status="active",
            verdict=None,
            summary="",
            required_entities=required_entities,
            confirm_when=confirm_when,
            source_gap_id=gap_id,
        )

        gap_kind = classify_gap_kind(gap)
        # Normalize gap to report_gaps table
        section_key = gap_sections.get(normalized_gap, "")
        db.execute(
            """INSERT INTO report_gaps (gap_id, section_key, description, kind, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'open', now(), now())
               ON CONFLICT (gap_id) DO UPDATE SET
                   description = EXCLUDED.description,
                   kind = EXCLUDED.kind,
                   section_key = CASE WHEN EXCLUDED.section_key = '' THEN report_gaps.section_key ELSE EXCLUDED.section_key END,
                   status = 'open',
                   updated_at = now()""",
            [gap_id, section_key, gap, gap_kind],
        )

        if gap_kind != "internal_db_check":
            # Create investigation_task for external/human tasks
            task_id = f"TASK-{gap_hash}"
            db.execute(
                """INSERT INTO investigation_tasks (task_id, kind, description, status, gap_id, created_at, updated_at)
                   VALUES (?, ?, ?, 'open', ?, now(), now())
                   ON CONFLICT (task_id) DO UPDATE SET status = 'open', updated_at = now()""",
                [task_id, gap_kind, gap, gap_id],
            )
            db.execute(
                "UPDATE report_gaps SET task_id = ? WHERE gap_id = ?",
                [task_id, gap_id],
            )
            continue

        # --- Unified admission gate (G-5) ---
        ok, reason = admit_new_hypothesis(candidate, state)
        if not ok:
            continue

        state.active_hypotheses.append(candidate)
        _upsert_hypothesis(db, candidate, origin="report_gap", session_id=session_id)
        # Link gap to hypothesis
        db.execute(
            "UPDATE report_gaps SET hypothesis_id = ?, updated_at = now() WHERE gap_id = ?",
            [candidate.id, gap_id],
        )
        added += 1
    if memory is not None:
        project_investigation_tasks(db, memory)
    return added


def project_investigation_tasks(db: CaseDB, memory: MemoryManager) -> None:
    """Project authoritative open tasks into a replaceable Markdown section."""
    rows = db.execute(
        "SELECT task_id, kind, description, reason FROM investigation_tasks "
        "WHERE status = 'open' ORDER BY created_at, task_id"
    ).fetchall()
    begin = "<!-- forensia:investigation-tasks:start -->"
    end = "<!-- forensia:investigation-tasks:end -->"
    lines = [begin, "## Investigation Tasks"]
    if rows:
        for task_id, kind, description, reason in rows:
            suffix = f" — {reason}" if reason else ""
            lines.append(f"- [{kind}] {description}{suffix} ({task_id})")
    else:
        lines.append("- none")
    lines.append(end)
    managed = "\n".join(lines)
    path = memory.tasks_memory_path
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Tasks\n"
    if begin in existing and end in existing:
        prefix, remainder = existing.split(begin, 1)
        _, suffix = remainder.split(end, 1)
        content = prefix.rstrip() + "\n\n" + managed + suffix
    else:
        content = existing.rstrip() + "\n\n" + managed + "\n"
    path.write_text(content, encoding="utf-8")
