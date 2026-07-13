"""Observational retrieval telemetry stored outside the evidence SSoT."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from forensia.db.database import CaseDB


def record_retrieval_event(
    db: CaseDB,
    *,
    session_id: str | None,
    scope_kind: str,
    scope_id: str | None,
    phase: str,
    source_kind: str,
    query_terms: list[str],
    candidate_count: int,
    selected_refs: list[str],
    selected_chars: int,
    budget: int,
    rejected_refs: list[str] | None = None,
) -> None:
    """Record what retrieval exposed; never feed observations into ranking."""
    db.execute(
        """
        INSERT INTO retrieval_events (
            event_id, session_id, scope_kind, scope_id, phase, source_kind,
            query_terms, candidate_count, selected_refs, rejected_refs,
            selected_chars, budget, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            session_id,
            scope_kind,
            scope_id,
            phase,
            source_kind,
            json.dumps(query_terms, ensure_ascii=False),
            candidate_count,
            json.dumps(selected_refs, ensure_ascii=False),
            json.dumps(rejected_refs or [], ensure_ascii=False),
            selected_chars,
            budget,
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
