from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import json

from forensia.ai.prompts import resolve_rule_context

from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.rules.loader import load_rule_by_id


def _clean_confirm_when(confirm_when: dict[str, Any] | None, db: CaseDB | None = None) -> dict[str, Any] | None:
    """Remove non-finding_id entries from confirm_when.co_observed_event_ids.
    
    Validates that each entry is either a valid finding_id (matching DB pattern)
    or a valid event_id (integer). Drops keypoint names, free text, etc.
    """
    if not confirm_when or not isinstance(confirm_when, dict):
        return confirm_when
    
    co_observed = confirm_when.get("co_observed_event_ids")
    if not co_observed or not isinstance(co_observed, list):
        return confirm_when
    
    cleaned: list[str] = []
    for entry in co_observed:
        entry_str = str(entry).strip()
        if not entry_str:
            continue
        # Keep valid finding_ids (pattern: windows-xxx-yyyy-xxxx-xxxx)
        if re.match(r'^[a-z]+-[a-z0-9]+-[0-9]+-[a-z0-9-]+$', entry_str):
            cleaned.append(entry_str)
            continue
        # Keep valid event_ids (pure integers)
        try:
            int(entry_str)
            cleaned.append(entry_str)
            continue
        except ValueError:
            pass
        # Skip everything else (keypoint names, free text, etc.)
        continue
    
    if not cleaned:
        confirm_when.pop("co_observed_event_ids", None)
    else:
        confirm_when["co_observed_event_ids"] = cleaned
    
    return confirm_when if any(confirm_when.values()) else None


def _recent_reasoning_rows(db: CaseDB, hypothesis_id: str, limit: int = 10) -> list[dict[str, Any]]:
    """Fetch the most recent reasoning entries for a given hypothesis."""
    return fetch_records(
        db,
        """
        SELECT phase, verdict, query_id, body, created_at
        FROM hypothesis_reasoning
        WHERE hypothesis_id = ?
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (hypothesis_id, limit),
    )


def _render_hypothesis_memory(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Render a hypothesis as a Markdown memory block with status, verdict, and recent reasoning."""
    lines = [
        f"# Hypothesis {hypothesis.id}",
        "",
        "## Status",
        f"- {hypothesis.status}",
        "",
        "## Verdict",
        f"- {hypothesis.verdict or 'pending'}",
        "",
        "## Description",
        hypothesis.description,
        "",
        "## Summary",
        hypothesis.summary or "-",
    ]
    if db is not None:
        reasoning_rows = _recent_reasoning_rows(db, hypothesis.id)
        if reasoning_rows:
            lines.extend(["", "## Reasoning"])
            for row in reasoning_rows:
                phase = str(row.get("phase") or "")
                verdict = str(row.get("verdict") or "-")
                query_id = str(row.get("query_id") or "-")
                body = " ".join(str(row.get("body") or "").split())[:240]
                lines.append(f"- [{phase}] verdict={verdict} query={query_id} :: {body}")
    return "\n".join(lines) + "\n"


def _normalize_hypothesis_description(description: str) -> str:
    return " ".join(str(description or "").lower().split())


def _merge_string_lists(*values: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value_list in values:
        for value in value_list:
            item = str(value or "").strip()
            if not item or item in seen:
                continue
            seen.add(item)
            merged.append(item)
    return merged


def _next_hypothesis_id(db: CaseDB) -> str:
    """Generate the next sequential hypothesis ID in H-NNN format."""
    row = db.execute(
        """
        SELECT COALESCE(MAX(CAST(regexp_extract(hypothesis_id, '^H-(\\d+)$', 1) AS INTEGER)), 0)
        FROM hypotheses
        WHERE regexp_matches(hypothesis_id, '^H-(\\d+)$')
        """,
    ).fetchone()
    next_num = int(row[0] or 0) + 1 if row else 1
    return f"H-{next_num:03d}"


def _merge_hypothesis_fields(existing: Hypothesis, incoming: Hypothesis) -> Hypothesis:
    """Merge fields from an incoming hypothesis into an existing one, preserving existing status and verdict."""
    source_rule_ids = _merge_string_lists(existing.source_rule_ids, incoming.source_rule_ids)
    required_entities = _merge_string_lists(existing.required_entities, incoming.required_entities)
    confirm_when = existing.confirm_when or incoming.confirm_when
    if confirm_when:
        confirm_when = _clean_confirm_when(dict(confirm_when) if isinstance(confirm_when, dict) else confirm_when)
    return Hypothesis(
        id=existing.id,
        description=existing.description or incoming.description,
        status=existing.status,
        verdict=existing.verdict,
        summary=existing.summary or incoming.summary,
        source_rule_ids=source_rule_ids,
        required_entities=required_entities,
        confirm_when=confirm_when if isinstance(confirm_when, dict) else None,
        refute_when=existing.refute_when or incoming.refute_when,
        fallback_phase=existing.fallback_phase or incoming.fallback_phase,
        fallback_source_rule_id=existing.fallback_source_rule_id or incoming.fallback_source_rule_id,
        target_keypoint_id=existing.target_keypoint_id or incoming.target_keypoint_id,
    )


def _hypothesis_tokens(description: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", _normalize_hypothesis_description(description)) if token}


def _extract_semantic_triple(description: str) -> dict[str, str]:
    """Extract (actor, action, target) triple from a hypothesis description."""
    text = str(description or "").strip().casefold()
    actor = ""
    action = ""
    target = ""
    for pattern, group in [(r"(?:by|from|via)\s+(an?\s+)?([a-z0-9_-]+)", 2), (r"(external ip|attacker|user|admin|malicious|suspicious)", 1)]:
        m = re.search(pattern, text)
        if m:
            actor = m.group(group)
            break
    for pattern in [r"(lateral movement|rdp|remote desktop|persistence|privilege escalation|defense evasion|credential access|discovery|exfiltration)", r"(create|install|deploy|modify|delete|clear|disable|bypass|elevat|escalat)", r"(execut|run|launch|invoke|schedule)"]:
        m = re.search(pattern, text)
        if m:
            action = m.group(1)
            break
    for pattern, group in [(r"(?:to|on|into|onto)\s+(an?\s+)?([a-z0-9_-]+)", 2), (r"(?:account|service|task|process|host|server|user|group|log|event|file|folder|key)", 1)]:
        m = re.search(pattern, text)
        if m:
            target = m.group(group if group else 1)
            break
    return {"actor": actor or "unknown", "action": action or "unknown", "target": target or "unknown"}


def _semantic_hypothesis_similarity(left: str, right: str) -> float:
    """Compute similarity using (actor, action, target) triples."""
    left_triple = _extract_semantic_triple(left)
    right_triple = _extract_semantic_triple(right)
    matches = 0
    for key in ("actor", "action", "target"):
        lv = left_triple.get(key, "").strip().lower()
        rv = right_triple.get(key, "").strip().lower()
        if lv and rv:
            if lv == rv or lv in rv or rv in lv:
                matches += 1
        elif not lv and not rv:
            matches += 1
    return matches / 3


def _hypothesis_similarity(left: str, right: str) -> float:
    """Compute similarity between two hypothesis descriptions using token overlap and semantic triples."""
    left_tokens = _hypothesis_tokens(left)
    right_tokens = _hypothesis_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    surface_score = len(left_tokens & right_tokens) / len(union)
    semantic_score = _semantic_hypothesis_similarity(left, right)
    left_triple = _extract_semantic_triple(left)
    right_triple = _extract_semantic_triple(right)
    all_unknown = all(v == "unknown" for v in left_triple.values()) or all(v == "unknown" for v in right_triple.values())
    if all_unknown:
        return surface_score
    return max(surface_score, semantic_score)


def _find_hypothesis_by_description(
    hypotheses: list[Hypothesis],
    description: str,
) -> Hypothesis | None:
    """Find a hypothesis in the list by exact normalized description match."""
    target = _normalize_hypothesis_description(description)
    if not target:
        return None
    for hypothesis in hypotheses:
        if _normalize_hypothesis_description(hypothesis.description) == target:
            return hypothesis
    return None


def _best_hypothesis_match(
    hypotheses: list[Hypothesis],
    description: str,
) -> tuple[Hypothesis | None, float]:
    """Find the best fuzzy match for a description among the given hypotheses."""
    best_hypothesis: Hypothesis | None = None
    best_score = 0.0
    for hypothesis in hypotheses:
        score = _hypothesis_similarity(hypothesis.description, description)
        if score > best_score:
            best_score = score
            best_hypothesis = hypothesis
    return best_hypothesis, best_score



def _row_to_hypothesis(row: dict[str, Any]) -> Hypothesis:
    """Convert a database result row into a Hypothesis object, parsing JSON fields."""
    verdict = row.get("verdict")
    source_rule_ids = row.get("source_rule_ids")
    required_entities = row.get("required_entities")
    confirm_when = row.get("confirm_when")
    if isinstance(source_rule_ids, str):
        try:
            import json
            source_rule_ids = json.loads(source_rule_ids)
        except Exception:
            source_rule_ids = []
    if not isinstance(source_rule_ids, list):
        source_rule_ids = []
    if isinstance(required_entities, str):
        try:
            import json
            required_entities = json.loads(required_entities)
        except Exception:
            required_entities = []
    if not isinstance(required_entities, list):
        required_entities = []
    if isinstance(confirm_when, str):
        try:
            import json
            confirm_when = json.loads(confirm_when)
        except Exception:
            confirm_when = None
    return Hypothesis(
        id=str(row.get("hypothesis_id") or ""),
        description=str(row.get("description") or ""),
        status=str(row.get("status") or "active"),
        verdict=str(verdict) if verdict else None,
        summary=str(row.get("summary") or ""),
        source_rule_ids=[str(item) for item in source_rule_ids if item],
        required_entities=[str(item) for item in required_entities if item],
        confirm_when=confirm_when if isinstance(confirm_when, dict) else None,
        target_keypoint_id=row.get("target_keypoint_id"),
    )


def _load_persisted_hypotheses(db: CaseDB) -> tuple[list[Hypothesis], list[Hypothesis]]:
    """Load all hypotheses from the database, partitioned into active and resolved."""
    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids, required_entities, confirm_when, target_keypoint_id
        FROM hypotheses
        ORDER BY created_at, hypothesis_id
        """,
    )
    active: list[Hypothesis] = []
    resolved: list[Hypothesis] = []
    for row in rows:
        hypothesis = _row_to_hypothesis(row)
        if hypothesis.status == "active":
            active.append(hypothesis)
        else:
            resolved.append(hypothesis)
    return active, resolved


def _upsert_hypothesis(
    db: CaseDB,
    hypothesis: Hypothesis,
    origin: str,
    session_id: str,
    resolved_session: str | None = None,
) -> None:
    """Insert or update a hypothesis row, preserving original creation metadata on conflict."""
    from forensia.core.verdicts import assert_valid_verdict
    if hypothesis.verdict is not None:
        assert_valid_verdict(hypothesis.verdict, "hypothesis_verdict")
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        """
        SELECT origin, created_session, created_at, resolved_session
        FROM hypotheses
        WHERE hypothesis_id = ?
        """,
        (hypothesis.id,),
    ).fetchone()
    created_origin = origin
    created_session = session_id
    created_at = now
    prior_resolved_session = resolved_session
    if existing is not None:
        created_origin = str(existing[0] or origin)
        created_session = str(existing[1] or session_id)
        created_at = existing[2] or now
        if prior_resolved_session is None:
            prior_resolved_session = existing[3]

    # QA3-8: Clean confirm_when before persisting
    clean_confirm_when = _clean_confirm_when(hypothesis.confirm_when, db)

    db.execute(
        """
        INSERT INTO hypotheses (
            hypothesis_id, description, status, verdict, summary, origin,
            created_session, resolved_session, created_at, updated_at, source_rule_ids,
            required_entities, confirm_when, target_keypoint_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (hypothesis_id) DO UPDATE SET
            description = excluded.description,
            status = excluded.status,
            verdict = excluded.verdict,
            summary = excluded.summary,
            origin = excluded.origin,
            created_session = excluded.created_session,
            resolved_session = excluded.resolved_session,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            source_rule_ids = excluded.source_rule_ids,
            required_entities = excluded.required_entities,
            confirm_when = excluded.confirm_when,
            target_keypoint_id = COALESCE(excluded.target_keypoint_id, hypotheses.target_keypoint_id)
        """,
        (
            hypothesis.id,
            hypothesis.description,
            hypothesis.status,
            hypothesis.verdict,
            hypothesis.summary,
            created_origin,
            created_session,
            prior_resolved_session,
            created_at,
            now,
            json.dumps(hypothesis.source_rule_ids, ensure_ascii=False),
            json.dumps(hypothesis.required_entities, ensure_ascii=False),
            json.dumps(clean_confirm_when, ensure_ascii=False) if clean_confirm_when else None,
            hypothesis.target_keypoint_id,
        ),
    )


MAX_ACTIVE_HYPOTHESES = 8


def _merge_active_hypotheses(
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
    active_by_description = {_normalize_hypothesis_description(item.description): item for item in current if item.id not in resolved_ids}
    resolved_by_description = {_normalize_hypothesis_description(item.description): item for item in resolved}
    for item in updates:
        if item.id in resolved_ids or item.status in {"confirmed", "refuted"}:
            continue
        incoming_id = alias_map.get(item.id, item.id)
        existing = by_id.get(incoming_id)
        if existing is None:
            existing = active_by_description.get(_normalize_hypothesis_description(item.description))
        if existing is None:
            best_active, best_active_score = _best_hypothesis_match(list(by_id.values()), item.description)
            if best_active is not None and best_active_score > 0.85:
                existing = best_active
        if existing is not None:
            merged = _merge_hypothesis_fields(existing, item)
            alias_map[item.id] = merged.id
            by_id[merged.id] = merged
            if existing.id != merged.id:
                by_id.pop(existing.id, None)
            active_by_description[_normalize_hypothesis_description(merged.description)] = merged
            _upsert_hypothesis(db, merged, origin=origin, session_id=session_id)
            continue
        resolved_existing = resolved_by_description.get(_normalize_hypothesis_description(item.description))
        if resolved_existing is None:
            best_resolved, best_resolved_score = _best_hypothesis_match(resolved, item.description)
            if best_resolved is not None and best_resolved_score > 0.85:
                resolved_existing = best_resolved
        if resolved_existing is not None:
            merged = _merge_hypothesis_fields(resolved_existing, item)
            alias_map[item.id] = merged.id
            resolved_by_description[_normalize_hypothesis_description(merged.description)] = merged
            _upsert_hypothesis(db, merged, origin="resolved", session_id=session_id, resolved_session=session_id)
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
            required_entities=_merge_string_lists(item.required_entities),
            confirm_when=_clean_confirm_when(item.confirm_when),
            target_keypoint_id=item.target_keypoint_id,
        )
        by_id[assigned_id] = hypothesis
        active_by_description[_normalize_hypothesis_description(hypothesis.description)] = hypothesis
        _upsert_hypothesis(db, hypothesis, origin=origin, session_id=session_id)
    if skipped_for_cap:
        try:
            from forensia.ai.investigator import _log
            _log("CAP", f"active hypothesis cap reached ({MAX_ACTIVE_HYPOTHESES}); skipped {len(skipped_for_cap)} new: {skipped_for_cap[:3]}…")
        except Exception:
            pass
    return list(by_id.values())


def _resolve_hypothesis(
    db: CaseDB,
    state: SessionState,
    hypothesis_id: str,
    verdict: str,
    summary: str,
    session_id: str,
) -> None:
    """Mark a hypothesis as confirmed or refuted, generate follow-ups, and mark stale sections."""
    from forensia.ai.report_gap import _extract_entities_from_text, _gap_hypothesis_id, _normalize_text, _propose_confirm_when
    
    remaining: list[Hypothesis] = []
    stale_sections: list[str] = []
    follow_up_hypotheses: list[Hypothesis] = []
    known_by_description: set[str] = {_normalize_text(item.description) for item in _all_hypotheses(state)}
    resolved_by_description: set[str] = {_normalize_text(item.description) for item in state.resolved_hypotheses}
    for item in state.active_hypotheses:
        if item.id == hypothesis_id:
            resolved = Hypothesis(
                id=item.id,
                description=item.description,
                status="confirmed" if verdict == "confirmed" else "refuted",
                verdict=verdict,
                summary=summary,
                source_rule_ids=item.source_rule_ids,
                required_entities=item.required_entities,
                confirm_when=item.confirm_when,
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
            # DESIGN-2: Mark related sections as stale based on report_sections declaration
            # DESIGN-4: Generate follow-up gaps from confirmed hypothesis
            for source_rule_id in item.source_rule_ids:
                rule = load_rule_by_id(source_rule_id)
                if rule:
                    # BUG-3 fix: Use hypothesis-level report_sections
                    # Match hypothesis by finding the declaration that corresponds to this hypothesis id
                    decl = next(
                        (h for h in rule.hypotheses if h.id == item.id),
                        None
                    )
                    if decl and decl.report_sections:
                        stale_sections.extend(decl.report_sections)
                    if verdict == "confirmed" and decl and decl.follow_up_questions:
                        for follow_up in decl.follow_up_questions:
                            normalized = _normalize_text(follow_up)
                            if normalized not in known_by_description and normalized not in resolved_by_description:
                                follow_up_hypotheses.append(
                                    Hypothesis(
                                        id=_gap_hypothesis_id(follow_up),
                                        description=follow_up,
                                        status="active",
                                        verdict=None,
                                        summary="",
                                        source_rule_ids=[source_rule_id],
                                        required_entities=_extract_entities_from_text(follow_up),
                                        confirm_when=_propose_confirm_when(_extract_entities_from_text(follow_up)),
                                    )
                                )
        else:
            remaining.append(item)
    state.active_hypotheses = remaining
    
    # Mark stale sections in report_sections table
    for section_key in stale_sections:
        db.execute(
            "UPDATE report_sections SET stale = TRUE WHERE section_key = ?",
            (section_key,),
        )
    
    # DESIGN-4: Add follow-up hypotheses to active list
    for follow_up in follow_up_hypotheses:
        state.active_hypotheses.append(follow_up)
        _upsert_hypothesis(db, follow_up, origin="follow_up", session_id=session_id)


def _all_hypotheses(state: SessionState) -> list[Hypothesis]:
    return [*state.active_hypotheses, *state.resolved_hypotheses]
