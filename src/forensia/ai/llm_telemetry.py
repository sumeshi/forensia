"""Durable LLM telemetry: logical calls, provider attempts, deterministic ops.

This is the trace-DB extension of the audit owner (``ai/audit.py`` writes
per-call disk transcripts; this module writes the structured, queryable
trajectory). It deliberately does NOT create a separate telemetry database:
all rows live in the existing attached ``trace`` database.

Three record kinds are kept distinct (GOAL.md §5.1):

* ``logical call`` — one application-level decision unit (e.g. "plan the
  SQL query for hypothesis H"). It may contain zero, one, or many provider
  attempts (retries/timeouts) without double counting.
* ``provider attempt`` — one actual HTTP request, success or failure, with
  durable receipt fields so failed attempts are never lost.
* ``deterministic op`` — render/parse/validate/query work that consumes no
  LLM tokens and must not be counted as LLM work.

Only the host may finalize attempts; callers must always pair
``begin_attempt``/``finalize_attempt`` (use the ``attempt_span`` context
manager to guarantee finalization on every exit path).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any, Literal

from forensia.config import get_llm_settings
from forensia.db.database import CaseDB

# Active telemetry for the current run. The investigation session installs an
# LLMTelemetry instance here so that every LLM call site (including direct
# chat_completion calls from memory/compaction) is instrumented without
# threading the object through every signature.
_ACTIVE_TELEMETRY: ContextVar[LLMTelemetry | None] = ContextVar(
    "active_llm_telemetry", default=None
)
_ACTIVE_SCOPE: ContextVar[dict[str, Any]] = ContextVar(
    "active_llm_scope", default={}
)


def set_active_telemetry(
    telemetry: LLMTelemetry | None,
) -> Token[LLMTelemetry | None]:
    """Install telemetry for the current task and return a reset token."""
    return _ACTIVE_TELEMETRY.set(telemetry)


def reset_active_telemetry(token: Token[LLMTelemetry | None]) -> None:
    """Restore the caller's telemetry context after a session ends."""
    _ACTIVE_TELEMETRY.reset(token)


def get_active_telemetry() -> LLMTelemetry | None:
    return _ACTIVE_TELEMETRY.get()


@contextmanager
def telemetry_scope(**scope: Any) -> Iterator[None]:
    """Attach durable domain ownership to logical calls in this execution scope."""
    token = _ACTIVE_SCOPE.set({**_ACTIVE_SCOPE.get(), **scope})
    try:
        yield
    finally:
        _ACTIVE_SCOPE.reset(token)

RecordStatus = Literal["open", "success", "failed", "discarded"]
AttemptStatus = Literal[
    "success",
    "timeout",
    "transport_error",
    "provider_error",
    "parse_error",
    "application_discard",
]
TokenSource = Literal["provider_actual", "local_estimate", "unknown"]
DeadlineKind = Literal["connect", "read", "logical_call"]


def now_utc() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def compute_effective_output_limit(
    *,
    configured_max_tokens: int | None = None,
    reasoning_reserve_tokens: int | None = None,
    requested_override: int | None = None,
    known_context_limit: int | None = None,
    estimated_input_tokens: int | None = None,
) -> tuple[int, int, int, int]:
    """Return (configured, reserve, requested, effective) output token budget.

    ``configured`` is the user setting (``LLM_MAX_TOKENS``). ``reserve`` is the
    reasoning reserve. ``requested`` is what the caller asked for (defaults to
    configured when omitted). ``effective`` is what is actually sent on the wire:
    ``requested + reserve``. The reserve is added exactly once per request; it
    must never be re-added during a truncation retry (T-11.4). When a provider
    context limit is known, the effective budget is capped to stay within it.
    """

    settings = get_llm_settings()
    configured = int(
        configured_max_tokens if configured_max_tokens is not None else settings["max_tokens"]
    )
    reserve = int(
        reasoning_reserve_tokens
        if reasoning_reserve_tokens is not None
        else settings.get("reasoning_reserve_tokens", 0)
    )
    requested = int(requested_override if requested_override is not None else configured)
    effective = requested + reserve
    if known_context_limit and effective > known_context_limit:
        available = known_context_limit - max(0, estimated_input_tokens or 0)
        effective = max(1, min(effective, available))
    return configured, reserve, requested, effective


class LLMTelemetry:
    """Canonical sink for the three LLM telemetry record kinds."""

    def __init__(self, db: CaseDB, session_id: str | None = None) -> None:
        self.db = db
        self.session_id = session_id
        self._last_attempt_by_call: dict[str, str] = {}

    # --- logical call -----------------------------------------------------
    def begin_logical_call(
        self,
        *,
        phase: str,
        iteration: int | None = None,
        hypothesis_id: str | None = None,
        section_id: str | None = None,
        action_id: str | None = None,
        parent_logical_call_id: str | None = None,
        request_fingerprint: str | None = None,
        session_id: str | None = None,
    ) -> str:
        scope = _ACTIVE_SCOPE.get()
        iteration = iteration if iteration is not None else scope.get("iteration")
        hypothesis_id = hypothesis_id or scope.get("hypothesis_id")
        section_id = section_id or scope.get("section_id")
        action_id = action_id or scope.get("action_id")
        logical_call_id = f"lc-{uuid.uuid4().hex[:20]}"
        self.db.execute(
            """
            INSERT INTO llm_logical_calls (
                logical_call_id, session_id, parent_logical_call_id, phase,
                iteration, hypothesis_id, section_id, action_id,
                request_fingerprint, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                logical_call_id,
                session_id or self.session_id,
                parent_logical_call_id,
                phase,
                iteration,
                hypothesis_id,
                section_id,
                action_id,
                request_fingerprint,
                now_utc(),
            ),
        )
        return logical_call_id

    def close_logical_call(self, *, logical_call_id: str, status: RecordStatus) -> None:
        self.db.execute(
            "UPDATE llm_logical_calls SET status = ? WHERE logical_call_id = ?",
            (status, logical_call_id),
        )

    # --- provider attempt -------------------------------------------------
    def begin_attempt(
        self,
        *,
        logical_call_id: str,
        endpoint: str,
        provider: str,
        model: str,
        schema_mode: str,
        request_fingerprint: str | None,
        configured_output_limit: int,
        reasoning_reserve_tokens: int,
        known_context_limit: int | None,
        effective_output_limit: int,
        requested_output_limit: int,
        input_chars: int,
        connect_timeout_ms: int | None = None,
        read_timeout_ms: int | None = None,
        logical_deadline_ms: int | None = None,
        retry_ordinal: int = 0,
        parent_attempt_id: str | None = None,
        session_id: str | None = None,
        phase: str | None = None,
        retry_class: str | None = None,
        retry_reason: str | None = None,
        policy_decision: str | None = None,
        request_changed_fields: dict[str, Any] | None = None,
        prompt_metadata: dict[str, Any] | None = None,
        request_body: dict[str, Any] | None = None,
    ) -> str:
        attempt_id = f"pa-{uuid.uuid4().hex[:20]}"
        if parent_attempt_id is None:
            parent_attempt_id = self._last_attempt_by_call.get(logical_call_id)
        self._last_attempt_by_call[logical_call_id] = attempt_id
        self.db.execute(
            """
            INSERT INTO llm_provider_attempts (
                attempt_id, logical_call_id, parent_attempt_id, session_id, phase,
                retry_ordinal, endpoint, provider, model, schema_mode,
                request_fingerprint, configured_output_limit,
                reasoning_reserve_tokens, known_context_limit,
                requested_output_limit, effective_output_limit, input_chars,
                connect_timeout_ms, read_timeout_ms, logical_deadline_ms,
                retry_class, retry_reason, policy_decision, request_changed_fields,
                prompt_metadata, request_body,
                start_time, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                attempt_id,
                logical_call_id,
                parent_attempt_id,
                session_id or self.session_id,
                phase,
                retry_ordinal,
                endpoint,
                provider,
                model,
                schema_mode,
                request_fingerprint,
                configured_output_limit,
                reasoning_reserve_tokens,
                known_context_limit,
                requested_output_limit,
                effective_output_limit,
                input_chars,
                connect_timeout_ms,
                read_timeout_ms,
                logical_deadline_ms,
                retry_class,
                retry_reason,
                policy_decision,
                _json_or_none(request_changed_fields),
                _json_or_none(prompt_metadata),
                _json_or_none(request_body),
                now_utc(),
                now_utc(),
            ),
        )
        return attempt_id

    def record_attempt_response(
        self, *, attempt_id: str | None, response_body: str
    ) -> None:
        """Store the raw provider body as soon as an HTTP response is received."""
        if attempt_id is None:
            return
        self.db.execute(
            "UPDATE llm_provider_attempts SET response_body = ? WHERE attempt_id = ?",
            (response_body, attempt_id),
        )

    def finalize_attempt(
        self,
        *,
        attempt_id: str,
        status: AttemptStatus,
        end_time: datetime | None = None,
        duration_ms: int | None = None,
        http_status: int | None = None,
        error_type: str | None = None,
        error_code: str | None = None,
        error_body_summary: str | None = None,
        exception_class: str | None = None,
        finish_reason: str | None = None,
        parse_status: str | None = None,
        truncated: bool | None = None,
        accepted: bool | None = None,
        discarded_reason: str | None = None,
        response_fingerprint: str | None = None,
        action_fingerprint: str | None = None,
        duplicate_of: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        input_tokens_source: TokenSource = "unknown",
        output_tokens_source: TokenSource = "unknown",
        output_chars: int | None = None,
        deadline_fired: DeadlineKind | None = None,
        retry_class: str | None = None,
        retry_reason: str | None = None,
        policy_decision: str | None = None,
        request_changed_fields: dict[str, Any] | None = None,
        prompt_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Finalize a provider attempt. Always call (success, timeout, error, discard)."""

        self.db.execute(
            """
            UPDATE llm_provider_attempts SET
                end_time = ?,
                duration_ms = ?,
                http_status = ?,
                error_type = ?,
                error_code = ?,
                error_body_summary = ?,
                exception_class = ?,
                finish_reason = ?,
                parse_status = ?,
                truncated = ?,
                accepted = ?,
                discarded_reason = ?,
                response_fingerprint = ?,
                action_fingerprint = ?,
                duplicate_of = ?,
                input_tokens = ?,
                output_tokens = ?,
                input_tokens_source = ?,
                output_tokens_source = ?,
                output_chars = ?,
                deadline_fired = ?,
                retry_class = ?,
                retry_reason = ?,
                policy_decision = ?,
                request_changed_fields = ?,
                prompt_metadata = ?,
                status = ?
            WHERE attempt_id = ?
            """,
            (
                end_time or now_utc(),
                duration_ms,
                http_status,
                error_type,
                error_code,
                (error_body_summary or "")[:500] or None,
                exception_class,
                finish_reason,
                parse_status,
                truncated,
                accepted,
                discarded_reason,
                response_fingerprint,
                action_fingerprint,
                duplicate_of,
                input_tokens,
                output_tokens,
                input_tokens_source,
                output_tokens_source,
                output_chars,
                deadline_fired,
                retry_class,
                retry_reason,
                policy_decision,
                _json_or_none(request_changed_fields),
                _json_or_none(prompt_metadata),
                status,
                attempt_id,
            ),
        )

    def mark_duplicate(self, *, attempt_id: str, duplicate_of: str) -> None:
        self.db.execute(
            "UPDATE llm_provider_attempts SET duplicate_of = ? WHERE attempt_id = ?",
            (duplicate_of, attempt_id),
        )

    def get_attempt(self, attempt_id: str) -> dict[str, Any] | None:
        cur = self.db.execute(
            "SELECT * FROM llm_provider_attempts WHERE attempt_id = ?", (attempt_id,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        cols = [col[0] for col in cur.description]
        return dict(zip(cols, row))

    # --- deterministic op -------------------------------------------------
    def record_deterministic_op(
        self,
        *,
        phase: str,
        op_type: Literal["render", "validate", "parse", "query", "transform", "wait"],
        target: str,
        session_id: str | None = None,
        hypothesis_id: str | None = None,
        section_id: str | None = None,
        duration_ms: int | None = None,
        note: str | None = None,
    ) -> str:
        op_id = f"do-{uuid.uuid4().hex[:20]}"
        self.db.execute(
            """
            INSERT INTO llm_deterministic_ops (
                op_id, session_id, phase, hypothesis_id, section_id,
                op_type, target, duration_ms, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                op_id,
                session_id or self.session_id,
                phase,
                hypothesis_id,
                section_id,
                op_type,
                target,
                duration_ms,
                note,
                now_utc(),
            ),
        )
        return op_id

    # --- aggregate queries (T-12.5) --------------------------------------
    def session_aggregates(self, session_id: str | None = None) -> dict[str, Any]:
        sid = session_id or self.session_id
        logical = self.db.execute(
            "SELECT COUNT(*) FROM llm_logical_calls WHERE session_id = ?", (sid,)
        ).fetchone()[0]
        row = self.db.execute(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN error_type IS NOT NULL OR http_status >= 400 THEN 1 ELSE 0 END),
                SUM(CASE WHEN retry_ordinal > 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN duplicate_of IS NOT NULL THEN 1 ELSE 0 END),
                SUM(CASE WHEN input_tokens_source = 'provider_actual' THEN input_tokens ELSE 0 END),
                SUM(CASE WHEN output_tokens_source = 'provider_actual' THEN output_tokens ELSE 0 END)
            FROM llm_provider_attempts WHERE session_id = ?
            """,
            (sid,),
        ).fetchone()
        det = self.db.execute(
            "SELECT COUNT(*) FROM llm_deterministic_ops WHERE session_id = ?", (sid,)
        ).fetchone()[0]
        return {
            "session_id": sid,
            "logical_call_count": logical,
            "provider_attempt_count": row[0] or 0,
            "provider_attempt_failures": row[1] or 0,
            "provider_attempt_retries": row[2] or 0,
            "duplicate_attempts": row[3] or 0,
            "actual_input_tokens": row[4] or 0,
            "actual_output_tokens": row[5] or 0,
            "deterministic_op_count": det,
        }


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


@contextmanager
def attempt_span(
    telemetry: LLMTelemetry,
    *,
    logical_call_id: str,
    endpoint: str,
    provider: str,
    model: str,
    schema_mode: str,
    request_fingerprint: str | None,
    configured_output_limit: int,
    reasoning_reserve_tokens: int,
    known_context_limit: int | None,
    effective_output_limit: int,
    requested_output_limit: int,
    input_chars: int,
    phase: str | None = None,
    retry_ordinal: int = 0,
    parent_attempt_id: str | None = None,
    connect_timeout_ms: int | None = None,
    read_timeout_ms: int | None = None,
    logical_deadline_ms: int | None = None,
) -> Iterator[str]:
    """Create a provider-attempt receipt and guarantee finalization.

    The yielded value is the ``attempt_id``. Callers update the attempt inside
    the block via ``telemetry.finalize_attempt(attempt_id=..., ...)``; if they do
    not, the context manager finalizes it as an ``application_discard`` so no
    attempt is ever silently lost (T-11.1).
    """

    attempt_id = telemetry.begin_attempt(
        logical_call_id=logical_call_id,
        endpoint=endpoint,
        provider=provider,
        model=model,
        schema_mode=schema_mode,
        request_fingerprint=request_fingerprint,
        configured_output_limit=configured_output_limit,
        reasoning_reserve_tokens=reasoning_reserve_tokens,
        known_context_limit=known_context_limit,
        effective_output_limit=effective_output_limit,
        requested_output_limit=requested_output_limit,
        input_chars=input_chars,
        phase=phase,
        retry_ordinal=retry_ordinal,
        parent_attempt_id=parent_attempt_id,
        connect_timeout_ms=connect_timeout_ms,
        read_timeout_ms=read_timeout_ms,
        logical_deadline_ms=logical_deadline_ms,
    )
    finalized = False
    try:
        yield attempt_id
    except Exception:
        if not finalized:
            telemetry.finalize_attempt(
                attempt_id=attempt_id,
                status="application_discard",
                discarded_reason="uncaught_exception_in_call_site",
            )
        finalized = True
        raise
    finally:
        if not finalized:
            telemetry.finalize_attempt(
                attempt_id=attempt_id,
                status="application_discard",
                discarded_reason="attempt_left_unfinalized",
            )
