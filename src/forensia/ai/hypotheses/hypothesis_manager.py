"""Hypothesis lifecycle; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.hypotheses.hypothesis_manager.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from forensia.ai.hypotheses.hypothesis_model import (
    _best_hypothesis_match,
    _clean_confirm_when,
    _extract_entities_from_text,
    _extract_refuted_tokens,
    _filter_valid_entities,
    _gap_references_refuted,
    _merge_hypothesis_fields,
    _merge_string_lists,
    _normalize_hypothesis_description,
    _propose_confirm_when,
    gap_hypothesis_id,
    hypothesis_evidence_strength,
)
from forensia.ai.hypotheses.hypothesis_store import (
    _all_hypotheses,
    _next_hypothesis_id,
    _upsert_hypothesis,
)
from forensia.ai.hypotheses.relations import propagate_verdict
from forensia.ai.investigation.work_state import resolve_linked_work
from forensia.core.log import log as _log
from forensia.core.session import Hypothesis, SessionState
from forensia.core.textutil import normalize_text as _normalize_text
from forensia.db.database import CaseDB
from forensia.knowledge.rules.loader import load_rule_by_id
from forensia.report.sections.section_taxonomy import (
    guess_related_sections as _guess_related_sections,
)
from forensia.report.sections.section_taxonomy import (
    sections_for_keypoint as _sections_for_keypoint,
)

logger = logging.getLogger(__name__)

MAX_ACTIVE_HYPOTHESES = 8


def merge_active_hypotheses(
    db: CaseDB,
    current: list[Hypothesis],
    updates: list[Hypothesis],
    resolved: list[Hypothesis],
    session_id: str,
    origin: str,
) -> list[Hypothesis]:
    """Merge incoming hypotheses into the active set with dedup, aliasing, and an active cap."""
    resolved_ids = {item.id for item in resolved}
    by_id = {item.id: item for item in current if item.id not in resolved_ids}
    skipped_for_cap: list[str] = []
    alias_map: dict[str, str] = {}
    active_by_description = {
        _normalize_hypothesis_description(item.description): item
        for item in current
        if item.id not in resolved_ids
    }
    resolved_by_description = {
        _normalize_hypothesis_description(item.description): item for item in resolved
    }
    for item in updates:
        if item.id in resolved_ids or item.status in {"confirmed", "refuted"}:
            continue
        incoming_id = alias_map.get(item.id, item.id)
        # FIRST: Check against resolved hypotheses — prevents the same claim
        # from existing as both confirmed AND refuted.
        resolved_existing = resolved_by_description.get(
            _normalize_hypothesis_description(item.description)
        )
        resolved_score: float | None = None
        if resolved_existing is None:
            best_resolved, best_resolved_score = _best_hypothesis_match(
                resolved, item.description
            )
            if best_resolved is not None and best_resolved_score > 0.85:
                resolved_existing = best_resolved
                resolved_score = best_resolved_score
        if resolved_existing is not None:
            resolved_strength = hypothesis_evidence_strength(resolved_existing)

            # Default: bind to resolved. The resolved hypothesis's verdict
            # stands — do NOT create a duplicate active hypothesis.
            merged = _merge_hypothesis_fields(resolved_existing, item)
            alias_map[item.id] = merged.id
            resolved_by_description[
                _normalize_hypothesis_description(merged.description)
            ] = merged
            _upsert_hypothesis(
                db,
                merged,
                origin="resolved",
                session_id=session_id,
                resolved_session=session_id,
            )
            score_str = (
                f"score={resolved_score:.2f}"
                if resolved_score is not None
                else "exact match"
            )
            _log(
                "HYPOTHESIS",
                f"bound to resolved {resolved_existing.id} "
                f"(verdict={resolved_existing.verdict}, "
                f"strength={resolved_strength}): "
                f"incoming similar ({score_str}); "
                f"not creating duplicate",
            )
            continue
        # SECOND: Check against active hypotheses for dedup/merge within the
        # active set. This runs AFTER the resolved check so that a near-duplicate
        # of a resolved hypothesis is always caught regardless of coincidental
        # similarity with an existing active hypothesis.
        existing = by_id.get(incoming_id)
        if existing is None:
            existing = active_by_description.get(
                _normalize_hypothesis_description(item.description)
            )
        if existing is None:
            best_active, best_active_score = _best_hypothesis_match(
                list(by_id.values()), item.description
            )
            if best_active is not None and best_active_score > 0.85:
                existing = best_active
        if existing is not None:
            merged = _merge_hypothesis_fields(existing, item)
            alias_map[item.id] = merged.id
            by_id[merged.id] = merged
            if existing.id != merged.id:
                by_id.pop(existing.id, None)
            active_by_description[
                _normalize_hypothesis_description(merged.description)
            ] = merged
            _upsert_hypothesis(db, merged, origin=origin, session_id=session_id)
            continue
        # Cap the active set. Updates to existing hypotheses already happened
        # above (in the merge branches); only NEW additions are subject to the
        # cap. Excess hypotheses are dropped (not persisted) so the planner
        # prompt stays bounded across cycles.
        if len(by_id) >= MAX_ACTIVE_HYPOTHESES:
            skipped_for_cap.append(item.description or item.id)
            continue
        assigned_id = incoming_id
        if not re.fullmatch(r"H-\d{3}", assigned_id):
            assigned_id = _next_hypothesis_id(db)
        while assigned_id in by_id or assigned_id in resolved_ids:
            assigned_id = f"H-{int(assigned_id.split('-', 1)[1]) + 1:03d}"
        alias_map[item.id] = assigned_id
        hypothesis = Hypothesis(
            id=assigned_id,
            description=item.description,
            status="active",
            verdict=None,
            summary=item.summary,
            source_rule_ids=_merge_string_lists(item.source_rule_ids),
            source_decl_id=item.source_decl_id,
            source_gap_id=item.source_gap_id,
            required_entities=_merge_string_lists(item.required_entities),
            confirm_when=_clean_confirm_when(item.confirm_when),
            refute_when=item.refute_when,
            evidence_requirements=item.evidence_requirements,
            target_keypoint_id=item.target_keypoint_id,
        )
        by_id[assigned_id] = hypothesis
        active_by_description[
            _normalize_hypothesis_description(hypothesis.description)
        ] = hypothesis
        _upsert_hypothesis(db, hypothesis, origin=origin, session_id=session_id)
    if skipped_for_cap:
        _log(
            "CAP",
            f"active hypothesis cap reached ({MAX_ACTIVE_HYPOTHESES}); skipped {len(skipped_for_cap)} new: {skipped_for_cap[:3]}…",
        )
    return list(by_id.values())


def _interpolate_follow_up(
    follow_up: str,
    sample_rows: list[dict[str, Any]] | None,
) -> str | None:
    """Render {placeholder} keys in a follow-up question from query sample rows.

    Returns the interpolated text, or None when any placeholder cannot be
    resolved (such follow-ups must be skipped, never stored verbatim).
    """
    keys = re.findall(r"\{(\w+)\}", follow_up)
    if not keys:
        return follow_up
    rendered = follow_up
    for key in keys:
        value = None
        for row in sample_rows or []:
            if not isinstance(row, dict):
                continue
            candidate = row.get(key)
            if candidate is not None and str(candidate).strip():
                value = str(candidate).strip()
                break
        if value is None:
            return None
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


def _feed_verdict_to_timeline(
    db: CaseDB,
    hypothesis_id: str,
    verdict: str,
    description: str,
    sample_rows: list[dict[str, Any]] | None,
) -> None:
    """Feeder (b): insert the decisive query row timestamp into case_timeline."""
    if verdict not in {"confirmed", "refuted"}:
        return
    timestamp = None
    host = ""
    evidence_id = ""
    for row in sample_rows or []:
        if not isinstance(row, dict):
            continue
        for ts_key in (
            "timestamp",
            "logon_time",
            "exec_time",
            "last_exec_time",
            "si_modified",
        ):
            candidate = row.get(ts_key)
            if candidate is not None and str(candidate).strip():
                timestamp = candidate
                host = str(row.get("computer") or row.get("host") or "")
                evidence_id = str(row.get("evidence_id") or "")
                break
        if timestamp is not None:
            break
    if timestamp is None:
        return
    try:
        db.execute(
            """
            INSERT INTO case_timeline (entry_id, timestamp, source, ref_id, host, summary, evidence_id)
            VALUES (?, ?, 'verdict', ?, ?, ?, ?)
            ON CONFLICT (entry_id) DO NOTHING
            """,
            (
                f"tl-verdict-{hypothesis_id}",
                timestamp,
                hypothesis_id,
                host,
                f"{verdict}: {description}"[:200],
                evidence_id,
            ),
        )
    except Exception:
        logger.debug("Failed to insert verdict entry into case_timeline", exc_info=True)


# _guess_related_sections: canonical implementation moved to report/section_taxonomy.py
# Re-exported via the import at the top of this file.


MAX_SECTION_UPDATES = 5


# _sections_for_keypoint: canonical implementation moved to report/section_taxonomy.py
# Re-exported via the import at the top of this file.


def mark_section_stale(db: CaseDB, section_key: str) -> None:
    """Mark a report section as stale, respecting the update_count cap."""
    db.execute(
        "UPDATE report_sections SET stale = TRUE WHERE section_key = ? AND update_count < ?",
        (section_key, MAX_SECTION_UPDATES),
    )


def resolve_hypothesis(
    db: CaseDB,
    state: SessionState,
    hypothesis_id: str,
    verdict: str,
    summary: str,
    session_id: str,
    sample_rows: list[dict[str, Any]] | None = None,
) -> None:
    """Mark a hypothesis as confirmed or refuted, generate follow-ups, and mark stale sections.

    R8-01: Enforces DB invariants:
    - confirmed requires sufficiency_status == 'sufficient'
    - confirmed requires at least 1 supporting EvidenceLink
    If invariants are violated, the hypothesis is set to needs_review instead.
    """

    # R8-01: DB invariant enforcement for confirmed verdicts
    needs_review_blocked = False
    if verdict == "confirmed":
        from forensia.ai.checking.sufficiency import load_evidence_links

        # Check sufficiency invariant
        suff_row = db.execute(
            "SELECT sufficiency_status FROM hypotheses WHERE hypothesis_id = ?",
            (hypothesis_id,),
        ).fetchone()
        suff_status = str(suff_row[0]) if suff_row else "unknown"
        if suff_status != "sufficient":
            _log(
                "INVARIANT",
                f"{hypothesis_id} confirmed blocked: sufficiency_status={suff_status}",
            )
            needs_review_blocked = True
            summary = (
                f"[invariant] Confirmed blocked: sufficiency_status={suff_status}. "
                f"Original: {summary}"
            )

        # Check EvidenceLink invariant
        links = load_evidence_links(db, hypothesis_id)
        supporting = [l for l in links if l.role == "supporting"]
        if not supporting:
            _log(
                "INVARIANT",
                f"{hypothesis_id} confirmed blocked: no supporting evidence links",
            )
            needs_review_blocked = True
            summary = (
                f"[invariant] Confirmed blocked: no supporting EvidenceLink. "
                f"Original: {summary}"
            )

    # If invariant blocked, set to needs_review and keep in active set
    if needs_review_blocked:
        for item in state.active_hypotheses:
            if item.id == hypothesis_id:
                item.status = "needs_review"
                item.verdict = None
                item.summary = summary
                _upsert_hypothesis(
                    db=db,
                    hypothesis=item,
                    origin="invariant_blocked",
                    session_id=session_id,
                )
                _log(
                    "RESOLVE",
                    f"{hypothesis_id} — needs_review (invariant blocked confirmed)",
                )
                break
        return

    remaining: list[Hypothesis] = []
    stale_sections: list[str] = []
    follow_up_hypotheses: list[Hypothesis] = []
    known_by_description: set[str] = {
        _normalize_text(item.description) for item in _all_hypotheses(state)
    }
    resolved_by_description: set[str] = {
        _normalize_text(item.description) for item in state.resolved_hypotheses
    }
    for item in state.active_hypotheses:
        if item.id == hypothesis_id:
            resolved = Hypothesis(
                id=item.id,
                description=item.description,
                status=verdict
                if verdict in {"untestable"}
                else ("confirmed" if verdict == "confirmed" else "refuted"),
                verdict=verdict,
                summary=summary,
                source_rule_ids=item.source_rule_ids,
                source_decl_id=item.source_decl_id,
                source_gap_id=item.source_gap_id,
                required_entities=item.required_entities,
                confirm_when=item.confirm_when,
                refute_when=item.refute_when,
                evidence_requirements=item.evidence_requirements,
                target_keypoint_id=item.target_keypoint_id,
            )
            state.resolved_hypotheses.append(resolved)
            _upsert_hypothesis(
                db=db,
                hypothesis=resolved,
                origin="check_new",
                session_id=session_id,
                resolved_session=session_id,
            )
            if verdict in {"confirmed", "refuted"}:
                resolve_linked_work(db, hypothesis_id)
            # Sufficiency is independently assessed and persisted before
            # settlement.  Never rewrite it merely to agree with a verdict.
            # Propagate verdict through relations
            propagate_verdict(db, hypothesis_id=hypothesis_id, verdict=verdict)
            _feed_verdict_to_timeline(
                db, item.id, verdict, item.description, sample_rows
            )
            # R5-03: Mark stale based on target_keypoint_id (runs regardless of source_rule_ids)
            if item.target_keypoint_id:
                stale_sections.extend(_sections_for_keypoint(item.target_keypoint_id))
            # R5-03: Mark stale based on description keyword matching
            stale_sections.extend(_guess_related_sections(item.description))
            # DESIGN-2: Mark related sections as stale based on report_sections declaration
            # DESIGN-4: Generate follow-up gaps from confirmed hypothesis
            for source_rule_id in item.source_rule_ids:
                rule = load_rule_by_id(source_rule_id)
                if rule:
                    # T-07: Use source_decl_id to find the exact declaration (fall back to id match)
                    decl_id_lookup = (
                        item.source_decl_id if item.source_decl_id else item.id
                    )
                    decl = next(
                        (h for h in rule.hypotheses if h.id == decl_id_lookup), None
                    )
                    # BUG-3 fallback: try matching by declaration id == item.id when source_decl_id match fails
                    if decl is None and item.source_decl_id is not None:
                        decl = next(
                            (h for h in rule.hypotheses if h.id == item.id), None
                        )
                    if decl and decl.report_sections:
                        stale_sections.extend(decl.report_sections)
                    if verdict == "confirmed" and decl and decl.follow_up_questions:
                        for follow_up in decl.follow_up_questions:
                            # R2-03: interpolate {placeholders} from the confirming
                            # query's sample rows; skip unresolvable follow-ups.
                            rendered = _interpolate_follow_up(follow_up, sample_rows)
                            if rendered is None:
                                _log(
                                    "RESOLVE",
                                    f"[follow-up] skipped (unresolved placeholders): {follow_up[:80]}",
                                )
                                continue
                            normalized = _normalize_text(rendered)
                            if (
                                normalized not in known_by_description
                                and normalized not in resolved_by_description
                            ):
                                follow_up_hypotheses.append(
                                    Hypothesis(
                                        id=gap_hypothesis_id(rendered),
                                        description=rendered,
                                        status="active",
                                        verdict=None,
                                        summary="",
                                        source_rule_ids=[source_rule_id],
                                        required_entities=_extract_entities_from_text(
                                            rendered
                                        ),
                                        confirm_when=_propose_confirm_when(
                                            _extract_entities_from_text(rendered)
                                        ),
                                    )
                                )
        else:
            remaining.append(item)
    state.active_hypotheses = remaining

    # Mark stale sections in report_sections table
    seen_sections: set[str] = set()
    for section_key in stale_sections:
        if section_key in seen_sections:
            continue
        seen_sections.add(section_key)
        mark_section_stale(db, section_key)

    # DESIGN-4: Add follow-up hypotheses to active list
    for follow_up in follow_up_hypotheses:
        state.active_hypotheses.append(follow_up)
        _upsert_hypothesis(db, follow_up, origin="follow_up", session_id=session_id)


ADMISSION_THRESHOLD = 0.85


def admit_new_hypothesis(
    candidate: Hypothesis,
    state: SessionState,
    *,
    threshold: float = ADMISSION_THRESHOLD,
) -> tuple[bool, str]:
    """Unified admission gate for new hypotheses.

    Checks the candidate against **active** AND **resolved** hypotheses for
    similarity, against **refuted** hypothesis tokens, and validates entity
    names.  Returns ``(accepted, reason)`` where *reason* is a short label
    explaining the decision (logged via ``_log('HYPOTHESIS', …)``).

    Replaces the fragmented checks that previously lived in:
    - ``_dedup_new_hypotheses``  (active-only similarity)
    - ``_inject_gap_hypotheses``  (inline refuted-token + description checks)
    - ``check_new`` path          (no gate at all)
    """
    description = candidate.description or ""
    if not description.strip():
        return False, "empty-description"

    # --- 1. Check against RESOLVED hypotheses ----------------------------
    resolved_match, resolved_score = _best_hypothesis_match(
        state.resolved_hypotheses, description
    )
    if resolved_match is not None and resolved_score >= threshold:
        _log(
            "HYPOTHESIS",
            f"admission REJECTED (duplicate-of-resolved): "
            f"'{description[:80]}' ~ {resolved_match.id} "
            f"(score={resolved_score:.2f})",
        )
        return False, "duplicate-of-resolved"

    # --- 2. Check against ACTIVE hypotheses ------------------------------
    active_match, active_score = _best_hypothesis_match(
        state.active_hypotheses, description
    )
    if active_match is not None and active_score >= threshold:
        _log(
            "HYPOTHESIS",
            f"admission REJECTED (duplicate-of-active): "
            f"'{description[:80]}' ~ {active_match.id} "
            f"(score={active_score:.2f})",
        )
        return False, "duplicate-of-active"

    # --- 3. Check against REFUTED hypothesis tokens ----------------------
    refuted_descriptions = [
        h.description for h in state.resolved_hypotheses if h.status == "refuted"
    ]
    refuted_tokens = _extract_refuted_tokens(refuted_descriptions)
    if _gap_references_refuted(description, refuted_tokens):
        _log(
            "HYPOTHESIS",
            f"admission REJECTED (refuted-claim): "
            f"'{description[:80]}' contains refuted tokens "
            f"{sorted(refuted_tokens)[:5]}",
        )
        return False, "refuted-claim"

    # --- 4. Entity validity check ----------------------------------------
    if candidate.required_entities:
        valid_entities = _filter_valid_entities(candidate.required_entities)
        if not valid_entities:
            _log(
                "HYPOTHESIS",
                f"admission REJECTED (invalid-entities): "
                f"'{description[:80]}' — entities={candidate.required_entities}",
            )
            return False, "invalid-entities"

    return True, "accepted"
