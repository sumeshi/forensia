"""Hypothesis persistence: load, upsert, and reasoning rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from forensia.core.session import Hypothesis, SessionState
from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


def _recent_reasoning_rows(
    db: CaseDB, hypothesis_id: str, limit: int = 10
) -> list[dict[str, Any]]:
    """Fetch the most recent reasoning entries for a given hypothesis."""
    return fetch_records(
        db,
        """
        SELECT phase, verdict, query_id, body, created_at
        FROM trace.hypothesis_reasoning
        WHERE hypothesis_id = ?
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (hypothesis_id, limit),
    )


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except TypeError, ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def load_hypothesis_attempts(db: CaseDB, hypothesis_id: str) -> list[dict[str, Any]]:
    """Project durable query receipts and their checks in chronological order.

    Receipt IDs are the attempt identity. Short planner query IDs are labels
    and may repeat after a resumed investigation.
    """
    rows = fetch_records(
        db,
        """
        SELECT step_id, iteration, phase, input_json, output_json, created_at
        FROM trace.investigation_steps
        WHERE hypothesis_id = ? AND phase IN ('do', 'check')
        ORDER BY created_at, step_id
        """,
        (hypothesis_id,),
    )
    attempts_by_ref: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        output = _json_object(row.get("output_json"))
        step_input = _json_object(row.get("input_json"))
        if row.get("phase") == "do":
            repeat_gate = output.get("repeat_gate")
            receipt = _json_object(output.get("tool_receipt"))
            attempt = _json_object(output.get("attempt"))
            query = _json_object(step_input.get("planned_query"))
            attempt_ref = str(
                attempt.get("attempt_ref")
                or receipt.get("receipt_id")
                or (row.get("step_id") if repeat_gate else "")
            ).strip()
            if not attempt_ref:
                continue
            projected = {
                "attempt_ref": attempt_ref,
                "iteration": row.get("iteration"),
                "query_id": str(receipt.get("call_id") or query.get("query_id") or ""),
                "query_fingerprint": str(
                    attempt.get("query_fingerprint") or receipt.get("query_hash") or ""
                ),
                "verification_spec_fingerprint": str(
                    attempt.get("verification_spec_fingerprint") or ""
                ),
                "evidence_scope_fingerprint": str(
                    attempt.get("evidence_scope_fingerprint") or ""
                ),
                "status": str(
                    attempt.get("status") or receipt.get("status") or "skipped"
                ),
                "retrieval_outcome": str(
                    attempt.get("retrieval_outcome")
                    or _json_object(output.get("retrieval_evaluation")).get("outcome")
                    or ""
                ),
                "returned_count": attempt.get(
                    "returned_count", receipt.get("returned_count")
                ),
                "evidence_ids": attempt.get("evidence_ids")
                or _json_object(receipt.get("result_refs")).get("evidence_ids")
                or output.get("evidence_ids")
                or [],
                "purpose": str(query.get("purpose") or ""),
                "normalized_sql": str(
                    query.get("sql")
                    or _json_object(receipt.get("arguments")).get("normalized_sql")
                    or ""
                ),
                "template_id": query.get("template_id"),
                "params": query.get("params") or {},
                "reason": str(
                    attempt.get("reason")
                    or receipt.get("reason")
                    or (repeat_gate or {}).get("reason_code")
                    or ""
                ),
                "error": str(attempt.get("error") or receipt.get("reason") or ""),
                "retryable": bool(attempt.get("retryable")),
                "repeat_gate": repeat_gate or attempt.get("repeat_gate") or {},
                "check_verdict": "",
                "check_summary": "",
                "assessment": {},
                "created_at": row.get("created_at"),
            }
            attempts_by_ref[attempt_ref] = projected
            order.append(attempt_ref)
            continue

        attempt_ref = str(output.get("attempt_ref") or "").strip()
        if not attempt_ref or attempt_ref not in attempts_by_ref:
            continue
        attempt = attempts_by_ref[attempt_ref]
        attempt["check_verdict"] = str(
            output.get("check_verdict") or output.get("verdict") or ""
        )
        attempt["check_summary"] = str(
            output.get("check_summary")
            or output.get("report_text")
            or output.get("rationale")
            or ""
        )[:500]
        attempt["assessment"] = _json_object(output.get("assessment"))
        attempt["missing_questions"] = output.get("missing_questions") or []

    return [attempts_by_ref[attempt_ref] for attempt_ref in order]


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


def _row_to_hypothesis(row: dict[str, Any]) -> Hypothesis:
    """Convert a database result row into a Hypothesis object.

    The canonical ``verification_spec`` column is the only stored condition
    representation.  A missing or unparsable spec is an explicit failure: the
    row is never reinterpreted from other stored data.
    """
    verdict = row.get("verdict")

    def string_list(column: str) -> list[str]:
        value = row.get(column)
        # These columns are nullable: SQL NULL denotes no declared entries.
        if value is None:
            return []
        try:
            if isinstance(value, str):
                value = json.loads(value)
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ValueError("expected a list of nonempty strings")
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"hypothesis {row.get('hypothesis_id')} has invalid {column}: {exc}"
            ) from exc
        return value

    source_rule_ids = string_list("source_rule_ids")
    required_entities = string_list("required_entities")
    raw_spec = row.get("verification_spec")
    if isinstance(raw_spec, str):
        try:
            raw_spec = json.loads(raw_spec)
        except Exception as exc:
            raise ValueError(
                f"hypothesis {row.get('hypothesis_id')} has an unparsable "
                f"verification_spec: {exc}"
            ) from exc
    if not isinstance(raw_spec, dict):
        raise ValueError(
            f"hypothesis {row.get('hypothesis_id')} has no canonical "
            "verification_spec; the case database does not match the current "
            "format (preserve the case and ingest into a new case directory)"
        )
    try:
        spec = VerificationSpec.model_validate(raw_spec)
    except Exception as exc:
        raise ValueError(
            f"hypothesis {row.get('hypothesis_id')} has an unsupported "
            f"verification_spec: {exc}"
        ) from exc
    return Hypothesis(
        id=str(row.get("hypothesis_id") or ""),
        description=str(row.get("description") or ""),
        status=str(row.get("status") or "active"),
        verdict=str(verdict) if verdict else None,
        summary=str(row.get("summary") or ""),
        source_rule_ids=[str(item) for item in source_rule_ids if item],
        source_decl_id=row.get("source_decl_id"),
        source_gap_id=row.get("source_gap_id"),
        required_entities=[str(item) for item in required_entities if item],
        verification_spec=spec,
        target_keypoint_id=row.get("target_keypoint_id"),
    )


def load_persisted_hypotheses(db: CaseDB) -> tuple[list[Hypothesis], list[Hypothesis]]:
    """Load all hypotheses from the database, partitioned into active and resolved."""
    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids,
               source_decl_id, required_entities, verification_spec, source_gap_id,
               target_keypoint_id
        FROM hypotheses
        ORDER BY created_at, hypothesis_id
        """,
    )
    active: list[Hypothesis] = []
    resolved: list[Hypothesis] = []
    terminal_work_ids = {
        str(row[0])
        for row in db.execute(
            "SELECT hypothesis_id FROM investigation_tasks "
            "WHERE owner_phase = 'termination' AND status = 'open' "
            "AND hypothesis_id IS NOT NULL"
        ).fetchall()
    }
    for row in rows:
        hypothesis = _row_to_hypothesis(row)
        if hypothesis.status == "active" or (
            hypothesis.status == "needs_review"
            and hypothesis.id not in terminal_work_ids
        ):
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
    """Insert or update a hypothesis row, preserving original creation metadata on conflict.

    The canonical ``verification_spec`` is written as-is; there is no
    declaration-shaped column to overwrite it from.
    """
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
        if hypothesis.status == "active":
            # Reopened hypotheses must not retain the terminal receipt that
            # previously put them in the resolved projection.
            prior_resolved_session = None
        elif prior_resolved_session is None:
            prior_resolved_session = existing[3]

    db.execute(
        """
        INSERT INTO hypotheses (
            hypothesis_id, description, status, verdict, summary, origin,
            created_session, resolved_session, created_at, updated_at, source_rule_ids,
            source_decl_id, required_entities, verification_spec, source_gap_id,
            target_keypoint_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            source_decl_id = excluded.source_decl_id,
            required_entities = excluded.required_entities,
            verification_spec = excluded.verification_spec,
            source_gap_id = COALESCE(excluded.source_gap_id, hypotheses.source_gap_id),
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
            hypothesis.source_decl_id,
            json.dumps(hypothesis.required_entities, ensure_ascii=False),
            json.dumps(
                hypothesis.verification_spec.model_dump(mode="json"),
                ensure_ascii=False,
            ),
            hypothesis.source_gap_id,
            hypothesis.target_keypoint_id,
        ),
    )


def _all_hypotheses(state: SessionState) -> list[Hypothesis]:
    return [*state.active_hypotheses, *state.resolved_hypotheses]
