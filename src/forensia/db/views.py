"""Bounded read projections shared by live and stopped case viewers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

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
]
_DETAIL_LIMIT = 100
_VALUE_LIMIT = 16_384


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


def _row(db: CaseDB, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    result = db.execute(sql, params)
    columns = [item[0] for item in result.description]
    row = result.fetchone()
    if row is None:
        return None
    return {
        key: _bounded(_json_value(value))
        for key, value in zip(columns, row, strict=True)
    }


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
            usage_row = db.execute(
                "SELECT SUM(input_tokens), SUM(output_tokens) FROM trace.llm_provider_attempts WHERE session_id = ?",
                [session["session_id"]],
            ).fetchone()
            if usage_row and (usage_row[0] is not None or usage_row[1] is not None):
                usage = {"input_tokens": usage_row[0], "output_tokens": usage_row[1]}
        report = db.execute(
            "SELECT status, stale, COUNT(*) FROM report_sections GROUP BY status, stale ORDER BY status, stale"
        ).fetchall()
        latest_step = None
        latest_event = _row(
            db,
            "SELECT event_index, kind, stage, status, summary, reason, refs, created_at "
            "FROM trace.progress_events ORDER BY event_index DESC LIMIT 1",
            (),
        )
        ingest_work = (
            latest_event
            if latest_event
            and latest_event.get("kind")
            in {"pipeline.ingest", "pipeline.normalize", "pipeline.analyze"}
            and latest_event.get("status") == "running"
            else None
        )
        if session:
            settings = _row(
                db,
                "SELECT output_json FROM trace.investigation_steps WHERE session_id = ? AND phase = 'session-settings' ORDER BY created_at DESC LIMIT 1",
                (session["session_id"],),
            )
            latest_event = _row(
                db,
                "SELECT event_index, kind, stage, status, summary, reason, refs, created_at FROM trace.progress_events WHERE session_id = ? ORDER BY event_index DESC LIMIT 1",
                (session["session_id"],),
            )
            latest_step = _row(
                db,
                "SELECT phase, hypothesis_id, iteration FROM trace.investigation_steps WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
                (session["session_id"],),
            )
            if session.get("status") != "running":
                latest_step = None
            if not ingest_work and (
                session.get("status") == "running"
                and latest_event
                and latest_event.get("status") == "running"
                and latest_event.get("stage") in {"ingest", "normalize", "analyze"}
            ):
                latest_step = {
                    key: latest_event[key]
                    for key in (
                        "event_index",
                        "kind",
                        "stage",
                        "status",
                        "summary",
                        "reason",
                        "refs",
                        "created_at",
                    )
                }
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
            started_at = session.get("started_at")
            finished_at = session.get("finished_at")
            elapsed_seconds = None
            try:
                started = (
                    datetime.fromisoformat(started_at)
                    if isinstance(started_at, str)
                    else started_at
                )
                end = (
                    datetime.fromisoformat(finished_at)
                    if isinstance(finished_at, str)
                    else finished_at
                )
                if isinstance(started, datetime):
                    if started.tzinfo is not None:
                        started = started.astimezone(UTC).replace(tzinfo=None)
                    if not isinstance(end, datetime):
                        end = datetime.now(UTC).replace(tzinfo=None)
                    elif end.tzinfo is not None:
                        end = end.astimezone(UTC).replace(tzinfo=None)
                    elapsed_seconds = max(0, int((end - started).total_seconds()))
            except ValueError:
                pass
        else:
            budget_remaining = budget_limit = elapsed_seconds = None
        if ingest_work:
            latest_step = ingest_work
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
    db: CaseDB, kind: DetailKind, id: str, limit: int = 100
) -> dict[str, Any] | None:
    """Resolve a stable typed ID through fixed read queries only."""
    if limit < 1 or limit > _DETAIL_LIMIT:
        raise ValueError(f"limit must be between 1 and {_DETAIL_LIMIT}")
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
            "FROM trace.investigation_steps WHERE phase = 'do' AND ("
            "json_extract_string(output_json, '$.tool_receipt.receipt_id') = ? OR "
            "json_extract_string(input_json, '$.planned_query.query_id') = ?) "
            "ORDER BY CASE WHEN json_extract_string(output_json, '$.tool_receipt.receipt_id') = ? THEN 0 ELSE 1 END, created_at DESC LIMIT 1",
            "receipt_id",
        ),
        "command_receipt": (
            "SELECT command_id, operation, status, reason, result, created_at, updated_at FROM trace.runtime_commands WHERE command_id = ?",
            "command_id",
        ),
    }
    if kind == "evidence":
        row = lookup_evidence_record(db, id)
        return _bounded(row, _VALUE_LIMIT, limit) if row else None
    try:
        sql, _id_field = queries[kind]
    except KeyError as exc:
        raise ValueError(f"unsupported detail kind: {kind}") from exc
    params = (id, id, id) if kind == "query_receipt" else (id,)
    row = _row(db, sql, params)
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
    return _bounded(row, _VALUE_LIMIT, limit) if row else None
