from __future__ import annotations

from datetime import UTC, datetime
import re
from typing import Any

import json

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import resolve_rule_context
from forensia.config import resolve_llm_config
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.rules.loader import load_rule_by_id


def _recent_reasoning_rows(db: CaseDB, hypothesis_id: str, limit: int = 10) -> list[dict[str, Any]]:
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
    source_rule_ids = _merge_string_lists(existing.source_rule_ids, incoming.source_rule_ids)
    required_entities = _merge_string_lists(existing.required_entities, incoming.required_entities)
    confirm_when = existing.confirm_when or incoming.confirm_when
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
    )


def _hypothesis_tokens(description: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]+", _normalize_hypothesis_description(description)) if token}


def _hypothesis_similarity(left: str, right: str) -> float:
    left_tokens = _hypothesis_tokens(left)
    right_tokens = _hypothesis_tokens(right)
    if not left_tokens or not right_tokens:
        return 0.0
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    return len(left_tokens & right_tokens) / len(union)


def _find_hypothesis_by_description(
    hypotheses: list[Hypothesis],
    description: str,
) -> Hypothesis | None:
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
    best_hypothesis: Hypothesis | None = None
    best_score = 0.0
    for hypothesis in hypotheses:
        score = _hypothesis_similarity(hypothesis.description, description)
        if score > best_score:
            best_score = score
            best_hypothesis = hypothesis
    return best_hypothesis, best_score


def _ask_same_hypothesis(
    *,
    existing: Hypothesis,
    incoming: Hypothesis,
    base_url: str,
    model: str,
) -> bool:
    system = (
        "<TASK>You judge whether two hypothesis descriptions refer to the same underlying hypothesis.</TASK>\n"
        "<OUTPUT_SCHEMA>{\"same_hypothesis\": true|false, \"reason\": \"short explanation\"}</OUTPUT_SCHEMA>\n"
        "<RULES>\n"
        "Return JSON only.\n"
        "Answer true only when the descriptions are substantively the same investigative claim.\n"
        "Answer false when the new wording introduces a materially different actor, action, target, or condition.\n"
        "</RULES>\n"
    )
    user = (
        f"existing_hypothesis: {existing.model_dump()}\n"
        f"incoming_hypothesis: {incoming.model_dump()}\n"
    )
    try:
        response = request_llm_json(
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            base_url=base_url,
            model=model,
        )
    except Exception:
        return True
    return bool(response.get("same_hypothesis"))


def _row_to_hypothesis(row: dict[str, Any]) -> Hypothesis:
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
    )


def _load_persisted_hypotheses(db: CaseDB) -> tuple[list[Hypothesis], list[Hypothesis]]:
    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids, required_entities, confirm_when
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

    db.execute(
        """
        INSERT INTO hypotheses (
            hypothesis_id, description, status, verdict, summary, origin,
            created_session, resolved_session, created_at, updated_at, source_rule_ids,
            required_entities, confirm_when
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            confirm_when = excluded.confirm_when
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
            json.dumps(hypothesis.confirm_when, ensure_ascii=False) if hypothesis.confirm_when else None,
        ),
    )


def _merge_active_hypotheses(
    db: CaseDB,
    current: list[Hypothesis],
    updates: list[Hypothesis],
    resolved: list[Hypothesis],
    session_id: str,
    origin: str,
    base_url: str | None = None,
    model: str | None = None,
) -> list[Hypothesis]:
    resolved_base_url, resolved_model = resolve_llm_config(base_url, model)
    llm_enabled = bool(resolved_base_url and resolved_model)
    resolved_ids = {item.id for item in resolved}
    by_id = {item.id: item for item in current if item.id not in resolved_ids}
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
            if best_active is not None and best_active_score > 0.8:
                if llm_enabled and not _ask_same_hypothesis(
                    existing=best_active,
                    incoming=item,
                    base_url=str(resolved_base_url),
                    model=str(resolved_model),
                ):
                    best_active = None
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
            if best_resolved is not None and best_resolved_score > 0.8:
                if llm_enabled and not _ask_same_hypothesis(
                    existing=best_resolved,
                    incoming=item,
                    base_url=str(resolved_base_url),
                    model=str(resolved_model),
                ):
                    best_resolved = None
                resolved_existing = best_resolved
        if resolved_existing is not None:
            merged = _merge_hypothesis_fields(resolved_existing, item)
            alias_map[item.id] = merged.id
            resolved_by_description[_normalize_hypothesis_description(merged.description)] = merged
            _upsert_hypothesis(db, merged, origin="resolved", session_id=session_id, resolved_session=session_id)
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
            confirm_when=item.confirm_when,
        )
        by_id[assigned_id] = hypothesis
        active_by_description[_normalize_hypothesis_description(hypothesis.description)] = hypothesis
        _upsert_hypothesis(db, hypothesis, origin=origin, session_id=session_id)
    return list(by_id.values())


def _resolve_hypothesis(
    db: CaseDB,
    state: SessionState,
    hypothesis_id: str,
    verdict: str,
    summary: str,
    session_id: str,
) -> None:
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
