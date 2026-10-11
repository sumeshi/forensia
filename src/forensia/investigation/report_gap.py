"""Report status and gap tracking: build per-section status, turn gaps into hypotheses."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from forensia.core.identifiers import gap_hypothesis_id, report_gap_id
from forensia.core.progress_event import progress_event
from forensia.core.session import Hypothesis, SessionState
from forensia.core.textutil import normalize_text as _normalize_text
from forensia.db.database import CaseDB
from forensia.investigation.hypotheses.hypothesis_manager import admit_new_hypothesis
from forensia.investigation.hypotheses.hypothesis_model import (
    _extract_entities_from_text,
    _propose_confirm_when,
    hypothesis_similarity,
)
from forensia.investigation.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.investigation.verification.sufficiency import (
    EvidenceLink,
    derivation_root_key,
)
from forensia.investigation.work_judgment import open_work_refs
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
        # Fail-closed vocabulary: a report-requirement hypothesis must describe a
        # concrete, investigable claim.  Material unknowns, placeholders, and
        # self-defeating hedges are rejected so they become bounded gaps rather
        # than durable hypotheses.
        prohibited = {
            "unknown",
            "cannot confirm",
            "cannot verify",
            "insufficient evidence",
            "n/a",
            "tbd",
            "none",
            "null",
            "placeholder",
            "unresolved",
        }
        for phrase in prohibited:
            if phrase in lowered:
                raise ValueError(f"Description contains prohibited phrase: '{phrase}'")
        # Unresolved template/angle-bracket placeholders are never admissible.
        if re.search(r"\{[A-Za-z_][A-Za-z0-9_]*\}|<[^>]+>", v):
            raise ValueError("Description contains unresolved placeholder token")
        # Entity-scoped unknowns (e.g. "unknown src_ip", "target_user is null").
        if re.search(
            r"\b(?:unknown|null|none)\b\s+(?:src_ip|target_user|subject_user|"
            r"computer|host|account|user|process|file|ip)\b",
            lowered,
        ):
            raise ValueError("Description names an unknown entity")
        if re.search(
            r"\b(?:src_ip|target_user|subject_user|computer|host|account|"
            r"user|process|file|ip)\b\s+(?:is\s+)?(?:unknown|null|none)\b",
            lowered,
        ):
            raise ValueError("Description names an unknown entity")
        return v


def evaluation_snapshot(db: CaseDB) -> dict[str, Any]:
    """Capture durable semantic state at the loop's state-commit point."""
    sources = db.execute(
        "SELECT source_id, artifact_family, ingest_status, row_count, error_code "
        "FROM evidence_sources ORDER BY source_id"
    ).fetchall()
    coverage = db.execute(
        "SELECT capability, host, channel, source_family, state "
        "FROM evidence_coverage ORDER BY capability, host, channel, source_family"
    ).fetchall()
    links = [
        {
            "root": derivation_root_key(
                EvidenceLink(
                    link_id=str(row[0]),
                    hypothesis_id=str(row[1] or ""),
                    evidence_id=str(row[2] or ""),
                    finding_id="",
                    query_id="",
                    assessment_id=str(row[3] or ""),
                    role=str(row[4] or ""),
                    source_family="",
                    source_file=str(row[5] or ""),
                    derivation_group=str(row[6] or ""),
                    strength="moderate",
                )
            ),
            "assessed": bool(str(row[3] or "")),
            "contradictory": str(row[4] or "") == "contradictory",
        }
        for row in db.execute(
            "SELECT link_id, hypothesis_id, evidence_id, assessment_id, role, "
            "source_file, derivation_group FROM hypothesis_evidence"
        ).fetchall()
    ]
    observations = sorted({link["root"] for link in links if link["assessed"]})
    contradictions = sorted(
        {link["root"] for link in links if link["assessed"] and link["contradictory"]}
    )
    identity_payload = json.dumps(
        {"sources": sources, "coverage": coverage},
        default=str,
        sort_keys=True,
    )
    return {
        "identity": hashlib.sha256(identity_payload.encode()).hexdigest()[:16],
        "open_work": tuple(
            (ref.hypothesis_ids, ref.gap_ids, ref.task_ids)
            for ref in open_work_refs(db)
        ),
        "observations": tuple(observations),
        "contradictions": tuple(contradictions),
    }


def report_cycle_progress(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    """Whether durable semantic state changed in a way that requires work.

    Compares two ``evaluation_snapshot`` dicts.  Two categories count:
    genuinely new information (an unresolved work ref appeared or was
    resolved, a new observation root, a new unhandled contradiction root) and
    a change that triggers re-evaluation (source / Coverage identity changed —
    same-count source replacements and Coverage downgrades included).  Prose
    growth, same-root refetches, and status round-trips that leave the same
    refs never count, so the no-progress budget is not refreshed by
    uninformative activity.
    """
    previous_open = previous.get("open_work")
    current_open = current.get("open_work")
    if previous_open is None and current_open is None:
        return False
    if set(previous_open or ()) != set(current_open or ()):
        return True
    for name in ("observations", "contradictions"):
        added = set(current.get(name) or ()) - set(previous.get(name) or ())
        if added:
            return True
    return previous.get("identity") != current.get("identity")


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


def _retry_condition_for_gap_kind(kind: str) -> str:
    if kind in {"external_lookup", "human_decision"}:
        return "human_or_external_result"
    return "new_evidence_or_coverage"


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


def _existing_hypothesis(state: SessionState, description: str) -> Hypothesis | None:
    """Return equivalent active/resolved work before admitting a candidate."""
    matches = [
        (hypothesis_similarity(description, item.description), item)
        for item in [*state.active_hypotheses, *state.resolved_hypotheses]
    ]
    if not matches:
        return None
    score, item = max(matches, key=lambda pair: pair[0])
    return item if score >= 0.85 else None


def _persist_admission_outcome(
    db: CaseDB, gap_id: str, outcome: str, reason: str
) -> None:
    """Persist a rejected or review outcome without a Hypothesis."""
    # Keep a rejected report request visible as an open Gap for existing API
    # consumers; the durable outcome is carried by coverage_reason.
    status = "open" if outcome == "rejected" else outcome
    db.execute(
        "UPDATE report_gaps SET status = ?, coverage_reason = ?, updated_at = now() "
        "WHERE gap_id = ?",
        [status, reason, gap_id],
    )


# _extract_refuted_tokens and _gap_references_refuted moved to
# hypothesis_manager.py (shared with the unified admission gate).
# Imported above.


def _handle_orphaned_section_gaps(db: CaseDB, keep_open_ids: set[str]) -> None:
    """Note absent report requests without resolving or withdrawing their work.

    Text similarity and a shared section do not establish requirement identity.
    The existing conclusion/review owner must close admitted Gap/Task state.
    """
    params = sorted(keep_open_ids)
    excluded = ""
    if params:
        placeholders = ", ".join("?" for _ in params)
        excluded = f" AND gap_id NOT IN ({placeholders})"
    orphans = db.execute(
        "SELECT gap_id, coverage_reason FROM report_gaps "
        "WHERE status = 'open' AND origin = 'section'" + excluded,
        params,
    ).fetchall()
    for gap_id, existing_reason in orphans:
        if not str(existing_reason or "").strip():
            db.execute(
                "UPDATE report_gaps SET coverage_reason = 'report_request_absent', "
                "updated_at = now() WHERE gap_id = ?",
                [gap_id],
            )
        db.execute(
            "UPDATE investigation_tasks SET reason = 'report_request_absent', "
            "updated_at = now() WHERE status IN ('open', 'in_progress') "
            "AND gap_id = ? AND (reason IS NULL OR reason = '')",
            [gap_id],
        )


def inject_gap_hypotheses(
    db: CaseDB,
    state: SessionState,
    gaps: list[str],
    session_id: str,
    llm_output: dict[str, Any] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    *,
    origin: Literal["section", "human"] = "section",
) -> int:
    """Convert unresolved report gaps into active hypotheses, skipping duplicates and non-DB gaps.

    Uses the unified admission gate (admit_new_hypothesis) to check against
    active, resolved, and refuted hypotheses — preventing refuted claims like
    poqexec.exe from being re-admitted through the gap injection path.

    Prose absence is not resolution (GOAL 9.4): an open section-origin Gap
    whose request string left the report prose keeps its open state. Similarity
    and section membership never resolve work; conclusive linked work is
    closed by its own owner (resolve_linked_work).
    """
    added = 0
    current_gap_ids = {
        report_gap_id(str(gap)) for gap in gaps if _normalize_text(str(gap))
    }
    gap_sections: dict[str, str] = {}
    prose_gap_ids: set[str] = set()
    for row in fetch_report_sections(db):
        section_key, raw_gaps = row["section_key"], row["gaps"]
        if raw_gaps is None:
            continue
        section_gaps = raw_gaps
        if isinstance(section_gaps, str):
            try:
                section_gaps = json.loads(section_gaps)
            except TypeError, ValueError:
                section_gaps = []
        for section_gap in section_gaps if isinstance(section_gaps, list) else []:
            normalized = _normalize_text(str(section_gap))
            gap_sections[normalized] = str(section_key or "")
            if normalized:
                prose_gap_ids.add(report_gap_id(str(section_gap)))
    # A Gap stays requested while its string is in the stored section prose
    # (including sections not refreshed in this cycle) or in this run's list.
    keep_open_ids = prose_gap_ids | current_gap_ids
    if origin == "section":
        _handle_orphaned_section_gaps(db, keep_open_ids)
    for gap in gaps:
        normalized_gap = _normalize_text(gap)
        if not normalized_gap:
            continue

        gap_id = report_gap_id(gap)
        gap_hash = gap_id.removeprefix("GAP-")
        gap_kind = classify_gap_kind(gap)
        # Normalize gap to report_gaps table
        section_key = gap_sections.get(normalized_gap, "")
        prior_gap = db.execute(
            "SELECT status FROM report_gaps WHERE gap_id = ?", [gap_id]
        ).fetchone()
        db.execute(
            """INSERT INTO report_gaps (gap_id, section_key, description, kind, status, origin, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'open', ?, now(), now())
               ON CONFLICT (gap_id) DO UPDATE SET
                   description = EXCLUDED.description,
                   kind = EXCLUDED.kind,
                   section_key = CASE WHEN EXCLUDED.section_key = '' THEN report_gaps.section_key ELSE EXCLUDED.section_key END,
                   status = 'open',
                   origin = CASE
                       WHEN report_gaps.origin = 'human' OR EXCLUDED.origin = 'human'
                       THEN 'human' ELSE 'section' END,
                   coverage_reason = NULL,
                   updated_at = now()""",
            [gap_id, section_key, gap, gap_kind, origin],
        )
        if progress_callback and (prior_gap is None or prior_gap[0] != "open"):
            progress_callback(
                progress_event(
                    "report_gap.admitted",
                    "completed",
                    severity="info",
                    reason="section_gap_opened",
                    refs={"gap_id": gap_id},
                    stage="report_admission",
                    session_id=session_id,
                    summary="report gap admitted for investigation",
                    gap_kind=gap_kind,
                    section_key=section_key or None,
                )
            )

        existing = _existing_hypothesis(state, gap)
        if existing is not None:
            if existing.status in {"confirmed", "refuted"}:
                db.execute(
                    "UPDATE report_gaps SET hypothesis_id = ?, status = 'resolved', "
                    "updated_at = now() WHERE gap_id = ?",
                    [existing.id, gap_id],
                )
            else:
                # untestable means the scope could not answer the request yet
                # (GOAL 9.4): it is not evidence-acquisition completion, so the
                # Gap stays open with the blocking outcome recorded.
                db.execute(
                    "UPDATE report_gaps SET hypothesis_id = ?, status = 'open', "
                    "coverage_reason = 'linked_hypothesis_untestable', updated_at = now() "
                    "WHERE gap_id = ?",
                    [existing.id, gap_id],
                )
            if progress_callback:
                progress_callback(
                    progress_event(
                        "report_gap.linked",
                        "completed",
                        reason="existing_hypothesis",
                        refs={"gap_id": gap_id, "hypothesis_id": existing.id},
                        stage="report_admission",
                        session_id=session_id,
                        summary="report gap linked to existing hypothesis",
                    )
                )
            continue

        existing_task = db.execute(
            "SELECT task_id FROM investigation_tasks WHERE lower(trim(description)) = "
            "lower(trim(?)) AND status IN ('open', 'in_progress') LIMIT 1",
            [gap],
        ).fetchone()
        if existing_task:
            db.execute(
                "UPDATE report_gaps SET task_id = ?, updated_at = now() WHERE gap_id = ?",
                [str(existing_task[0]), gap_id],
            )
            if progress_callback:
                progress_callback(
                    progress_event(
                        "report_gap.linked",
                        "completed",
                        reason="existing_task",
                        refs={"gap_id": gap_id, "task_id": str(existing_task[0])},
                        stage="report_admission",
                        session_id=session_id,
                        summary="report gap linked to existing task",
                    )
                )
            continue

        if gap_kind != "internal_db_check":
            # Create investigation_task for external/human tasks
            task_id = f"TASK-{gap_hash}"
            db.execute(
                """INSERT INTO investigation_tasks (
                       task_id, kind, description, status, gap_id, owner_phase,
                       retry_condition, created_at, updated_at
                   ) VALUES (?, ?, ?, 'open', ?, 'report_admission', ?, now(), now())
                   ON CONFLICT (task_id) DO UPDATE SET status = 'open',
                       owner_phase = 'report_admission', retry_condition = EXCLUDED.retry_condition,
                       updated_at = now()""",
                [
                    task_id,
                    gap_kind,
                    gap,
                    gap_id,
                    _retry_condition_for_gap_kind(gap_kind),
                ],
            )
            db.execute(
                "UPDATE report_gaps SET task_id = ? WHERE gap_id = ?",
                [task_id, gap_id],
            )
            if progress_callback:
                progress_callback(
                    progress_event(
                        "investigation.task_admitted",
                        "completed",
                        severity="success",
                        reason="report_gap_requires_external_action",
                        refs={"gap_id": gap_id, "task_id": task_id},
                        stage="report_admission",
                        session_id=session_id,
                        summary="report gap admitted as an investigation task",
                        task_kind=gap_kind,
                    )
                )
            continue

        required_entities, confirm_when = _parse_gap_hypothesis_output(
            llm_output or {}, gap
        )
        try:
            candidate = Hypothesis(
                id=gap_hypothesis_id(gap),
                description=gap,
                status="active",
                required_entities=required_entities,
                confirm_when=confirm_when,
                source_gap_id=gap_id,
            )
        except Exception as exc:
            _persist_admission_outcome(
                db,
                gap_id,
                "needs_review",
                f"verification_spec_invalid:{type(exc).__name__}",
            )
            if progress_callback:
                progress_callback(
                    progress_event(
                        "hypothesis.admission_skipped",
                        "skipped",
                        severity="warning",
                        reason=f"verification_spec_invalid:{type(exc).__name__}",
                        refs={"gap_id": gap_id},
                        stage="report_admission",
                        session_id=session_id,
                        summary="report gap hypothesis requires review",
                    )
                )
            continue

        # --- Unified admission gate (G-5) ---
        ok, reason = admit_new_hypothesis(candidate, state)
        if not ok:
            outcome = (
                "rejected"
                if reason.startswith(("duplicate", "refuted", "invalid"))
                else "needs_review"
            )
            _persist_admission_outcome(db, gap_id, outcome, f"admission_{reason}")
            if progress_callback:
                progress_callback(
                    progress_event(
                        "hypothesis.admission_skipped",
                        "skipped",
                        severity="warning",
                        reason=f"admission_{reason}",
                        refs={"gap_id": gap_id},
                        stage="report_admission",
                        session_id=session_id,
                        summary="report gap hypothesis was not admitted",
                    )
                )
            continue

        state.active_hypotheses.append(candidate)
        _upsert_hypothesis(db, candidate, origin="report_gap", session_id=session_id)
        # Link gap to hypothesis
        db.execute(
            "UPDATE report_gaps SET hypothesis_id = ?, updated_at = now() WHERE gap_id = ?",
            [candidate.id, gap_id],
        )
        if progress_callback:
            progress_callback(
                progress_event(
                    "hypothesis.admitted",
                    "completed",
                    severity="success",
                    reason="report_gap_internal_check",
                    refs={"gap_id": gap_id, "hypothesis_id": candidate.id},
                    stage="report_admission",
                    session_id=session_id,
                    summary="report gap admitted as an internal investigation hypothesis",
                )
            )
        added += 1
    return added
