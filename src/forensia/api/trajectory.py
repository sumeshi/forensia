"""Bounded API projections for the durable investigation trajectory.

This module owns the read-side projection for logical calls, provider attempts,
deterministic operations, and retrieval decisions. It deliberately queries the
trace tables directly and does not import the workflow/AI layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from forensia.api.cache import snapshot_metadata
from forensia.api.dto import (
    AttemptPageDTO,
    DeterministicOpDTO,
    LogicalCallDTO,
    LogicalCallPageDTO,
    ProviderAttemptDTO,
    SessionTrajectoryDTO,
)
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value


def _row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: normalize_value(value) for key, value in row.items()}


def _attempt_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = _row(row)
    # Raw provider output must remain byte-for-byte readable text. Generic DB
    # normalization would parse JSON-looking responses into objects.
    normalized["response_body"] = row.get("response_body")
    return normalized


def list_logical_calls_page_dto(
    db: CaseDB,
    session_id: str,
    *,
    phase: str | None = None,
    hypothesis_id: str | None = None,
    section_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> LogicalCallPageDTO:
    clauses = ["lc.session_id = ?"]
    params: list[Any] = [session_id]
    if phase:
        clauses.append("lc.phase = ?")
        params.append(phase)
    if hypothesis_id:
        clauses.append("lc.hypothesis_id = ?")
        params.append(hypothesis_id)
    if section_id:
        clauses.append("lc.section_id = ?")
        params.append(section_id)
    if status:
        clauses.append("lc.status = ?")
        params.append(status)
    where = " AND ".join(clauses)
    count_where = where.replace("lc.", "")
    total_row = db.execute(
        f"SELECT COUNT(*) FROM llm_logical_calls WHERE {count_where}", params
    ).fetchone()
    total = int(total_row[0] or 0) if total_row else 0
    rows = fetch_records(
        db,
        f"""
        SELECT lc.logical_call_id, lc.session_id, lc.parent_logical_call_id,
               lc.phase, lc.iteration, lc.hypothesis_id, lc.section_id,
               lc.action_id, lc.request_fingerprint, lc.status, lc.created_at,
               COUNT(a.attempt_id) AS attempt_count,
               SUM(CASE WHEN a.error_type IS NOT NULL OR a.http_status >= 400 THEN 1 ELSE 0 END) AS failures,
               SUM(CASE WHEN a.retry_ordinal > 0 THEN 1 ELSE 0 END) AS retries,
               SUM(CASE WHEN a.duplicate_of IS NOT NULL THEN 1 ELSE 0 END) AS duplicates
        FROM llm_logical_calls lc
        LEFT JOIN llm_provider_attempts a ON a.logical_call_id = lc.logical_call_id
        WHERE {where}
        GROUP BY lc.logical_call_id, lc.session_id, lc.parent_logical_call_id,
                 lc.phase, lc.iteration, lc.hypothesis_id, lc.section_id,
                 lc.action_id, lc.request_fingerprint, lc.status, lc.created_at
        ORDER BY lc.created_at, lc.logical_call_id
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    )
    items = [LogicalCallDTO.model_validate(_row(row)) for row in rows]
    return LogicalCallPageDTO(
        session_id=session_id,
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        is_sample=total > offset + len(items),
        filters={
            "phase": phase,
            "hypothesis_id": hypothesis_id,
            "section_id": section_id,
            "status": status,
        },
    )


def get_logical_call_attempts_page_dto(
    db: CaseDB,
    logical_call_id: str,
    *,
    status: str | None = None,
    retry_class: str | None = None,
    duplicate_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> AttemptPageDTO:
    clauses = ["logical_call_id = ?"]
    params: list[Any] = [logical_call_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if retry_class:
        clauses.append("retry_class = ?")
        params.append(retry_class)
    if duplicate_only:
        clauses.append("duplicate_of IS NOT NULL")
    where = " AND ".join(clauses)
    total_row = db.execute(
        f"SELECT COUNT(*) FROM llm_provider_attempts WHERE {where}", params
    ).fetchone()
    total = int(total_row[0] or 0) if total_row else 0
    rows = fetch_records(
        db,
        f"""
        SELECT attempt_id, logical_call_id, parent_attempt_id, session_id, phase,
               retry_ordinal, endpoint, provider, model, schema_mode,
               request_fingerprint, configured_output_limit,
               reasoning_reserve_tokens, known_context_limit,
               requested_output_limit, effective_output_limit, input_chars,
               output_chars, connect_timeout_ms, read_timeout_ms,
               logical_deadline_ms, retry_class, retry_reason, policy_decision,
               request_changed_fields, prompt_metadata, request_body, response_body,
               start_time, end_time,
               duration_ms, http_status, error_type, error_code,
               error_body_summary, exception_class, finish_reason, parse_status,
               truncated, accepted, discarded_reason, response_fingerprint,
               action_fingerprint, duplicate_of, input_tokens, output_tokens,
               input_tokens_source, output_tokens_source, status
        FROM llm_provider_attempts
        WHERE {where}
        ORDER BY retry_ordinal, start_time, attempt_id
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    )
    items = [ProviderAttemptDTO.model_validate(_attempt_row(row)) for row in rows]
    session_row = db.execute(
        "SELECT session_id FROM llm_provider_attempts WHERE logical_call_id = ? LIMIT 1",
        (logical_call_id,),
    ).fetchone()
    return AttemptPageDTO(
        logical_call_id=logical_call_id,
        session_id=str(session_row[0]) if session_row else None,
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        is_sample=total > offset + len(items),
        filters={"status": status, "retry_class": retry_class, "duplicate_only": duplicate_only},
    )


def get_session_trajectory_dto(db: CaseDB, session_id: str) -> SessionTrajectoryDTO:
    session_row = db.execute(
        "SELECT started_at, finished_at, status, terminal_reason "
        "FROM investigation_sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if session_row is None:
        return SessionTrajectoryDTO(session_id=session_id, state="not_found")
    started_at, finished_at = session_row[0], session_row[1]
    wall_time_ms = None
    if started_at is not None and finished_at is not None:
        try:
            wall_time_ms = int((finished_at - started_at).total_seconds() * 1000)
        except Exception:
            pass
    aggregate_row = db.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM llm_logical_calls WHERE session_id = ?),
          (SELECT COUNT(*) FROM llm_provider_attempts WHERE session_id = ?),
          (SELECT COUNT(*) FROM llm_provider_attempts WHERE session_id = ? AND (error_type IS NOT NULL OR http_status >= 400)),
          (SELECT COUNT(*) FROM llm_provider_attempts WHERE session_id = ? AND retry_ordinal > 0),
          (SELECT COUNT(*) FROM llm_provider_attempts WHERE session_id = ? AND duplicate_of IS NOT NULL),
          (SELECT COALESCE(SUM(input_tokens), 0) FROM llm_provider_attempts WHERE session_id = ? AND input_tokens_source = 'provider_actual'),
          (SELECT COALESCE(SUM(output_tokens), 0) FROM llm_provider_attempts WHERE session_id = ? AND output_tokens_source = 'provider_actual'),
          (SELECT COUNT(*) FROM llm_deterministic_ops WHERE session_id = ?)
        """,
        (session_id,) * 8,
    ).fetchone()
    aggregate = {
        "session_id": session_id,
        "logical_call_count": int(aggregate_row[0] or 0),
        "provider_attempt_count": int(aggregate_row[1] or 0),
        "provider_attempt_failures": int(aggregate_row[2] or 0),
        "provider_attempt_retries": int(aggregate_row[3] or 0),
        "duplicate_attempts": int(aggregate_row[4] or 0),
        "actual_input_tokens": int(aggregate_row[5] or 0),
        "actual_output_tokens": int(aggregate_row[6] or 0),
        "deterministic_op_count": int(aggregate_row[7] or 0),
    }
    phase_rows = db.execute(
        "SELECT COALESCE(phase, 'unknown'), SUM(COALESCE(duration_ms, 0)) "
        "FROM llm_provider_attempts WHERE session_id = ? GROUP BY phase",
        (session_id,),
    ).fetchall()
    latency_by_phase = {str(row[0]): int(row[1] or 0) for row in phase_rows}
    det_row = db.execute(
        "SELECT COALESCE(SUM(duration_ms), 0) FROM llm_deterministic_ops WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    explained = int(det_row[0] or 0) + sum(latency_by_phase.values())
    metadata = snapshot_metadata(db)
    det_rows = fetch_records(
        db,
        "SELECT op_id, session_id, phase, hypothesis_id, section_id, op_type, target, duration_ms, note, created_at "
        "FROM llm_deterministic_ops WHERE session_id = ? ORDER BY created_at, op_id LIMIT 500",
        (session_id,),
    )
    retrieval_rows = fetch_records(
        db,
        "SELECT event_id, session_id, scope_kind, scope_id, phase, source_kind, query_terms, candidate_count, selected_refs, rejected_refs, selected_chars, budget, created_at "
        "FROM retrieval_events WHERE session_id = ? ORDER BY created_at, event_id LIMIT 500",
        (session_id,),
    )
    return SessionTrajectoryDTO(
        session_id=session_id,
        started_at=str(started_at) if started_at is not None else None,
        finished_at=str(finished_at) if finished_at is not None else None,
        status=str(session_row[2] or "unknown"),
        terminal_reason=str(session_row[3]) if session_row[3] else None,
        timezone="UTC",
        wall_time_ms=wall_time_ms,
        explained_time_ms=explained,
        unexplained_wall_time_ms=(max(0, wall_time_ms - explained) if wall_time_ms is not None else None),
        latency_by_phase=latency_by_phase,
        aggregates=aggregate,
        deterministic_operations=[DeterministicOpDTO.model_validate(_row(row)) for row in det_rows],
        retrieval_events=[_row(row) for row in retrieval_rows],
        snapshot_revision=metadata.get("generation_revision"),
        generated_at=datetime.now(UTC).isoformat(),
        authoritative_updated_at=metadata.get("authoritative_updated_at"),
        state=metadata.get("state"),
    )
