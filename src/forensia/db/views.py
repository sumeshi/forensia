"""Bounded read projections shared by live and stopped case viewers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal, get_args

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record
from forensia.db.progress import list_progress_events

DetailKind = Literal[
    "hypothesis",
    "task",
    "gap",
    "finding",
    "evidence",
    "step",
    "query_receipt",
    "command_receipt",
    "assessment",
    "reasoning",
    "section",
    "retrieval",
    "llm_call",
    "llm_attempt",
    "event",
]
DETAIL_KINDS = frozenset(get_args(DetailKind))
_DETAIL_LIMIT = 100
_VALUE_LIMIT = 16_384

# Select explicit parent pipeline lifecycle transitions, not child progress.
_PIPELINE_STAGE_EVENT_SQL = """
    SELECT event_index, kind, stage, status, summary, reason, refs, created_at,
           json_extract_string(payload, '$.run_id') AS run_id
    FROM trace.progress_events
    WHERE json_extract_string(payload, '$.scope') = 'pipeline_stage'
      AND kind IN ('pipeline.ingest', 'pipeline.normalize', 'pipeline.analyze')
    ORDER BY event_index DESC
    LIMIT 1
"""


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _bounded(
    value: Any, limit: int = _VALUE_LIMIT, max_items: int = _DETAIL_LIMIT
) -> Any:
    """Keep detail projections finite even when a stored LLM/query result is large."""
    if isinstance(value, dict):
        items = list(value.items())[:max_items]
        result = {str(k): _bounded(v, limit, max_items) for k, v in items}
        if len(items) < len(value):
            result["_truncated"] = True
        return result
    if isinstance(value, list):
        result = [_bounded(v, limit, max_items) for v in value[:max_items]]
        if len(value) > max_items:
            result.append({"_truncated": True})
        return result
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and len(value) > limit:
        return {"truncated": True, "preview": value[:limit]}
    return value


def _row(
    db: CaseDB, sql: str, params: tuple[Any, ...], *, bounded: bool = True
) -> dict[str, Any] | None:
    result = db.execute(sql, params)
    columns = [item[0] for item in result.description]
    row = result.fetchone()
    if row is None:
        return None
    return {
        key: _bounded(_json_value(value)) if bounded else _json_value(value)
        for key, value in zip(columns, row, strict=True)
    }


def _elapsed_seconds(started_at: Any, ended_at: Any = None) -> int | None:
    """Return elapsed whole seconds between bounded timestamps."""
    try:
        started = (
            datetime.fromisoformat(started_at)
            if isinstance(started_at, str)
            else started_at
        )
        ended = (
            datetime.fromisoformat(ended_at) if isinstance(ended_at, str) else ended_at
        )
        if not isinstance(started, datetime):
            return None
        ended = ended if isinstance(ended, datetime) else datetime.now(UTC)
        started = started.replace(tzinfo=started.tzinfo or UTC).astimezone(UTC)
        ended = ended.replace(tzinfo=ended.tzinfo or UTC).astimezone(UTC)
        return max(0, int((ended - started).total_seconds()))
    except ValueError:
        return None


def case_snapshot(case: Case, db: CaseDB) -> dict[str, Any]:
    """Read one consistent, non-authoritative view of case progress."""
    with db.read_snapshot():
        finding_count = int(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
        hypothesis_count = int(
            db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]
        )
        hypothesis_statuses = {
            str(status): int(count)
            for status, count in db.execute(
                "SELECT COALESCE(status, 'unknown'), COUNT(*) FROM hypotheses GROUP BY 1 ORDER BY 1"
            ).fetchall()
        }
        open_tasks = int(
            db.execute(
                "SELECT COUNT(*) FROM investigation_tasks WHERE status IN ('open', 'in_progress')"
            ).fetchone()[0]
        )
        state_row = db.execute(
            "SELECT status, stop_reason_code, stop_reason, updated_at FROM investigation_state WHERE state_id = 'case'"
        ).fetchone()
        session_result = db.execute(
            "SELECT session_id, started_at, finished_at, iterations, status, terminal_reason, phase, status_reason "
            "FROM trace.investigation_sessions WHERE COALESCE(phase, '') != 'human_intervention' "
            "ORDER BY started_at DESC NULLS LAST LIMIT 1"
        )
        session_columns = [item[0] for item in session_result.description]
        session_row = session_result.fetchone()
        session = (
            {
                key: _bounded(value)
                for key, value in zip(session_columns, session_row, strict=True)
            }
            if session_row
            else None
        )
        usage = None
        if session:
            aggregate = llm_session_aggregates(db, session["session_id"])
            if aggregate["provider_attempt_count"]:
                usage = aggregate
        report = db.execute(
            "SELECT status, stale, COUNT(*) FROM report_sections GROUP BY status, stale ORDER BY status, stale"
        ).fetchall()
        latest_step = None
        pipeline_event = _row(
            db,
            _PIPELINE_STAGE_EVENT_SQL,
            (),
        )
        if session:
            settings = _row(
                db,
                "SELECT output_json FROM trace.investigation_steps WHERE session_id = ? AND phase = 'session-settings' ORDER BY created_at DESC LIMIT 1",
                (session["session_id"],),
            )
            latest_step = _row(
                db,
                "SELECT phase, hypothesis_id, iteration FROM trace.investigation_steps WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
                (session["session_id"],),
            )
            if session.get("status") != "running":
                latest_step = None
            budget_remaining = None
            budget_limit = None
            if settings and isinstance(settings.get("output_json"), dict):
                max_calls = settings["output_json"].get("max_llm_calls")
                if isinstance(max_calls, int):
                    budget_limit = max_calls
                if isinstance(max_calls, int) and max_calls > 0:
                    used = int(
                        db.execute(
                            "SELECT COUNT(*) FROM trace.llm_logical_calls WHERE session_id = ?",
                            [session["session_id"]],
                        ).fetchone()[0]
                    )
                    budget_remaining = max(0, max_calls - used)
            elapsed_seconds = _elapsed_seconds(
                session.get("started_at"), session.get("finished_at")
            )
        else:
            budget_remaining = budget_limit = elapsed_seconds = None
        session_anchor = None
        if session:
            session_anchor = session.get("started_at")
            if session.get("status") != "running":
                session_anchor = session.get("finished_at") or session_anchor
        pipeline_projection = (
            pipeline_event
            if pipeline_event
            and (
                not session
                or session_anchor is None
                or pipeline_event.get("created_at") >= session_anchor
            )
            else None
        )
        if pipeline_projection:
            pipeline_started_at = pipeline_projection.get("created_at")
            run_id = pipeline_projection.get("run_id")
            if run_id:
                run_start = _row(
                    db,
                    "SELECT MIN(created_at) AS created_at "
                    "FROM trace.progress_events "
                    "WHERE json_extract_string(payload, '$.scope') = 'pipeline_stage' "
                    "AND json_extract_string(payload, '$.run_id') = ?",
                    (run_id,),
                )
                if run_start and run_start.get("created_at") is not None:
                    pipeline_started_at = run_start["created_at"]
            pipeline_projection["elapsed_seconds"] = _elapsed_seconds(
                pipeline_started_at,
                None
                if pipeline_projection.get("status") == "running"
                else pipeline_projection.get("created_at"),
            )
            elapsed_seconds = pipeline_projection["elapsed_seconds"]
        if pipeline_projection:
            latest_step = (
                pipeline_projection
                if pipeline_projection.get("status") == "running"
                else None
            )
        highwater = int(
            db.execute(
                "SELECT COALESCE(MAX(event_index), 0) FROM trace.progress_events"
            ).fetchone()[0]
        )
        state = None
        if state_row:
            state = {
                "status": state_row[0],
                "stop_reason_code": state_row[1],
                "stop_reason": state_row[2],
                "updated_at": state_row[3].isoformat() if state_row[3] else None,
            }
        return {
            "case_name": case.path.name,
            "state": state,
            "session": session,
            "pipeline": pipeline_projection,
            "current_work": latest_step,
            "counts": {
                "findings": finding_count,
                "hypotheses": hypothesis_count,
                "hypothesis_statuses": hypothesis_statuses,
                "open_tasks": open_tasks,
            },
            "elapsed_seconds": elapsed_seconds,
            "budget_usage": usage,
            "budget_remaining_llm_calls": budget_remaining,
            "budget_limit_llm_calls": budget_limit,
            "report_status": [
                {"status": row[0], "stale": row[1], "count": row[2]} for row in report
            ],
            "event_highwater": highwater,
            "generated_at": datetime.now(UTC).isoformat(),
            "authoritative": False,
        }


def case_events(
    db: CaseDB, after_index: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    """Return a bounded page from the durable event stream."""
    if limit > _DETAIL_LIMIT:
        raise ValueError(f"limit must not exceed {_DETAIL_LIMIT}")
    return [_bounded(event) for event in list_progress_events(db, after_index, limit)]


def case_detail(
    db: CaseDB, kind: DetailKind, id: str, limit: int = 100, *, offset: int = 0
) -> dict[str, Any] | None:
    """Resolve a stable typed ID through fixed read queries only."""
    if limit < 1 or limit > _DETAIL_LIMIT:
        raise ValueError(f"limit must be between 1 and {_DETAIL_LIMIT}")
    if type(offset) is not int or offset < 0:
        raise ValueError("detail offset must be a nonnegative integer")
    queries: dict[str, tuple[str, str]] = {
        "hypothesis": (
            "SELECT * FROM hypotheses WHERE hypothesis_id = ?",
            "hypothesis_id",
        ),
        "task": ("SELECT * FROM investigation_tasks WHERE task_id = ?", "task_id"),
        "gap": ("SELECT * FROM report_gaps WHERE gap_id = ?", "gap_id"),
        "finding": (
            "SELECT * FROM findings WHERE finding_id = ? LIMIT 1",
            "finding_id",
        ),
        "step": (
            "SELECT * FROM trace.investigation_steps WHERE step_id = ?",
            "step_id",
        ),
        "query_receipt": (
            "SELECT step_id, session_id, hypothesis_id, iteration, input_json, output_json, created_at "
            "FROM trace.investigation_steps WHERE phase = 'do' AND "
            "json_extract_string(output_json, '$.tool_receipt.receipt_id') = ? "
            "ORDER BY created_at DESC LIMIT 1",
            "receipt_id",
        ),
        "command_receipt": (
            "SELECT command_id, operation, status, reason, result, created_at, updated_at FROM trace.runtime_commands WHERE command_id = ?",
            "command_id",
        ),
        "assessment": (
            "SELECT assessment_id, hypothesis_id, role, assessment_reason, "
            "matched_conditions, verification_spec_fingerprint, "
            "list(evidence_id ORDER BY evidence_id) AS evidence_ids, "
            "list(DISTINCT derivation_group ORDER BY derivation_group) AS derivation_groups "
            "FROM hypothesis_evidence WHERE assessment_id = ? "
            "GROUP BY ALL",
            "assessment_id",
        ),
        "reasoning": (
            "SELECT * FROM trace.hypothesis_reasoning WHERE entry_id = ?",
            "entry_id",
        ),
        "section": (
            "SELECT * FROM report_sections WHERE section_key = ?",
            "section_key",
        ),
        "retrieval": (
            "SELECT * FROM trace.retrieval_events WHERE event_id = ?",
            "event_id",
        ),
        "llm_call": (
            "SELECT c.*, (SELECT list(attempt_id ORDER BY start_time, attempt_id) "
            "FROM trace.llm_provider_attempts a WHERE a.logical_call_id = c.logical_call_id) "
            "AS attempt_ids FROM trace.llm_logical_calls c WHERE logical_call_id = ?",
            "logical_call_id",
        ),
        "llm_attempt": (
            "SELECT * FROM trace.llm_provider_attempts WHERE attempt_id = ?",
            "attempt_id",
        ),
        "event": (
            "SELECT * FROM trace.progress_events WHERE event_index = TRY_CAST(? AS BIGINT)",
            "event_index",
        ),
    }
    if kind == "evidence":
        row = lookup_evidence_record(db, id)
        return _detail_page(row, kind, id, offset) if row else None
    try:
        sql, _id_field = queries[kind]
    except KeyError as exc:
        raise ValueError(f"unsupported detail kind: {kind}") from exc
    row = _row(db, sql, (id,), bounded=False)
    if kind == "assessment":
        recorded = _row(
            db,
            "SELECT step_id, session_id, hypothesis_id, created_at, "
            "json_extract(output_json, '$.assessment') AS assessment "
            "FROM trace.investigation_steps "
            "WHERE json_extract_string(output_json, '$.assessment.assessment_id') = ? "
            "ORDER BY created_at DESC, step_id DESC LIMIT 1",
            (id,),
            bounded=False,
        )
        if recorded:
            recorded["current_links"] = row
            row = recorded
    if kind == "query_receipt" and row:
        output = row.get("output_json") or {}
        receipt = output.get("tool_receipt", {}) if isinstance(output, dict) else {}
        result_refs = (
            receipt.get("result_refs", {}) if isinstance(receipt, dict) else {}
        )
        evidence_ids = (
            result_refs.get("evidence_ids", []) if isinstance(result_refs, dict) else []
        )
        row["evidence"] = [
            evidence
            for evidence_id in evidence_ids[:limit]
            if (evidence := lookup_evidence_record(db, str(evidence_id))) is not None
        ]
    return _detail_page(row, kind, id, offset) if row else None


def _detail_page(
    row: dict[str, Any], kind: DetailKind, item_id: str, offset: int
) -> dict[str, Any]:
    """Page the original detail; previews must not permanently hide its tail."""
    serialized = json.dumps(
        row,
        ensure_ascii=False,
        indent=2,
        default=lambda value: (
            value.isoformat() if isinstance(value, datetime) else str(value)
        ),
    )
    if offset == 0 and len(serialized) <= _VALUE_LIMIT:
        return json.loads(serialized)
    end = min(offset + _VALUE_LIMIT, len(serialized))
    return {
        "kind": kind,
        "id": item_id,
        "text": serialized[offset:end],
        "offset": offset,
        "next_offset": end if end < len(serialized) else None,
        "total_chars": len(serialized),
    }


def llm_session_aggregates(db: CaseDB, session_id: str) -> dict[str, Any]:
    sid = session_id
    logical = db.execute(
        "SELECT COUNT(*) FROM trace.llm_logical_calls WHERE session_id = ?", (sid,)
    ).fetchone()[0]
    row = db.execute(
        """
        SELECT
            COUNT(*),
            SUM(CASE WHEN error_type IS NOT NULL OR http_status >= 400 THEN 1 ELSE 0 END),
            SUM(CASE WHEN retry_ordinal > 0 THEN 1 ELSE 0 END),
            SUM(CASE WHEN duplicate_of IS NOT NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN input_tokens_source = 'provider_actual' THEN input_tokens ELSE 0 END),
            SUM(CASE WHEN output_tokens_source = 'provider_actual' THEN output_tokens ELSE 0 END),
            SUM(CASE WHEN input_tokens_source = 'local_estimate' THEN input_tokens ELSE 0 END),
            SUM(CASE WHEN output_tokens_source = 'local_estimate' THEN output_tokens ELSE 0 END),
            SUM(CASE WHEN input_tokens_source = 'unknown' OR input_tokens IS NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN output_tokens_source = 'unknown' OR output_tokens IS NULL THEN 1 ELSE 0 END),
            SUM(CASE WHEN input_tokens_source = 'provider_actual' THEN 1 ELSE 0 END),
            SUM(CASE WHEN output_tokens_source = 'provider_actual' THEN 1 ELSE 0 END),
            SUM(CASE WHEN input_tokens_source = 'local_estimate' THEN 1 ELSE 0 END),
            SUM(CASE WHEN output_tokens_source = 'local_estimate' THEN 1 ELSE 0 END)
        FROM trace.llm_provider_attempts WHERE session_id = ?
        """,
        (sid,),
    ).fetchone()
    det = db.execute(
        "SELECT COUNT(*) FROM trace.llm_deterministic_ops WHERE session_id = ?",
        (sid,),
    ).fetchone()[0]
    return {
        "session_id": sid,
        "logical_call_count": logical,
        "provider_attempt_count": row[0] or 0,
        "provider_attempt_failures": row[1] or 0,
        "provider_attempt_retries": row[2] or 0,
        "duplicate_attempts": row[3] or 0,
        "actual_input_tokens": row[4] if row[10] else None,
        "actual_output_tokens": row[5] if row[11] else None,
        "estimated_input_tokens": row[6] if row[12] else None,
        "estimated_output_tokens": row[7] if row[13] else None,
        "unknown_input_usage_attempts": row[8] or 0,
        "unknown_output_usage_attempts": row[9] or 0,
        "actual_input_usage_attempts": row[10] or 0,
        "actual_output_usage_attempts": row[11] or 0,
        "estimated_input_usage_attempts": row[12] or 0,
        "estimated_output_usage_attempts": row[13] or 0,
        "deterministic_op_count": det,
    }
