from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import json

from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


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
) -> list[Hypothesis]:
    resolved_ids = {item.id for item in resolved}
    by_id = {item.id: item for item in current if item.id not in resolved_ids}
    for item in updates:
        if item.id in resolved_ids or item.status in {"confirmed", "refuted"}:
            continue
        hypothesis = Hypothesis(
            id=item.id,
            description=item.description,
            status="active",
            verdict=None,
            summary=item.summary,
            source_rule_ids=item.source_rule_ids,
            required_entities=item.required_entities,
            confirm_when=item.confirm_when,
        )
        by_id[item.id] = hypothesis
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
    remaining: list[Hypothesis] = []
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
        else:
            remaining.append(item)
    state.active_hypotheses = remaining


def _all_hypotheses(state: SessionState) -> list[Hypothesis]:
    return [*state.active_hypotheses, *state.resolved_hypotheses]
