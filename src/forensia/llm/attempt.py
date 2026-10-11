"""One HTTP attempt of the LLM transport, durable as a provider-attempt receipt.

The HTTP transport import stays lazy at the call site: kernel
imports must not load httpx (its import chain pulls click/rich machinery).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from forensia.llm.telemetry import LLMTelemetry

if TYPE_CHECKING:
    import httpx


def _begin_attempt(
    telemetry: LLMTelemetry | None,
    logical_call_id: str | None,
    *,
    url: str,
    body: dict[str, Any],
    ordinal: int,
    model: str,
    schema_mode: str,
    request_fingerprint: str | None,
    configured: int,
    reserve: int,
    known_limit: int | None,
    effective: int,
    requested: int,
    input_chars: int,
    phase: str | None,
    retry_class: str | None,
    retry_reason: str | None,
    policy_decision: str | None,
    request_changed_fields: dict[str, Any] | None,
    prompt_metadata: dict[str, Any] | None,
) -> str | None:
    """Start the provider-attempt receipt; None when telemetry is inactive."""
    if telemetry is None or logical_call_id is None:
        return None
    return telemetry.begin_attempt(
        logical_call_id=logical_call_id,
        endpoint=url,
        provider="openai-compatible",
        model=model,
        schema_mode=schema_mode,
        request_fingerprint=request_fingerprint,
        configured_output_limit=configured,
        reasoning_reserve_tokens=reserve,
        known_context_limit=known_limit,
        effective_output_limit=effective,
        requested_output_limit=requested,
        input_chars=input_chars,
        connect_timeout_ms=5000,
        read_timeout_ms=300000,
        phase=phase,
        retry_ordinal=ordinal,
        retry_class=retry_class,
        retry_reason=retry_reason,
        policy_decision=policy_decision,
        request_changed_fields=request_changed_fields,
        prompt_metadata=prompt_metadata,
        request_body=body,
    )


def _record_attempt_failure(
    telemetry: LLMTelemetry | None,
    att_id: str | None,
    started: float,
    exc: Exception,
    *,
    timed_out: bool,
) -> None:
    """Durable timeout/transport receipt when the POST itself raises."""
    import httpx

    if not att_id or telemetry is None:
        return
    duration_ms = int((time.monotonic() - started) * 1000)
    if timed_out:
        telemetry.finalize_attempt(
            attempt_id=att_id,
            status="timeout",
            exception_class="httpx.TimeoutException",
            error_type="timeout",
            deadline_fired="read",
            duration_ms=duration_ms,
        )
    else:
        is_connect = isinstance(exc, httpx.ConnectError)
        telemetry.finalize_attempt(
            attempt_id=att_id,
            status="transport_error",
            exception_class=type(exc).__name__,
            error_type="connect" if is_connect else "transport",
            deadline_fired="connect" if is_connect else None,
            duration_ms=duration_ms,
        )


def _post_attempt(
    client: httpx.Client,
    *,
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    telemetry: LLMTelemetry | None,
    logical_call_id: str | None,
    ordinal: int,
    model: str,
    schema_mode: str,
    request_fingerprint: str | None,
    configured: int,
    reserve: int,
    known_limit: int | None,
    effective: int,
    requested: int,
    input_chars: int,
    phase: str | None,
    retry_class: str | None = None,
    retry_reason: str | None = None,
    policy_decision: str | None = None,
    request_changed_fields: dict[str, Any] | None = None,
    prompt_metadata: dict[str, Any] | None = None,
) -> tuple[Any, str | None, int, float]:
    """One HTTP attempt, durable as a provider-attempt receipt."""
    import httpx

    started = time.monotonic()
    att_id = _begin_attempt(
        telemetry,
        logical_call_id,
        url=url,
        body=body,
        ordinal=ordinal,
        model=model,
        schema_mode=schema_mode,
        request_fingerprint=request_fingerprint,
        configured=configured,
        reserve=reserve,
        known_limit=known_limit,
        effective=effective,
        requested=requested,
        input_chars=input_chars,
        phase=phase,
        retry_class=retry_class,
        retry_reason=retry_reason,
        policy_decision=policy_decision,
        request_changed_fields=request_changed_fields,
        prompt_metadata=prompt_metadata,
    )
    try:
        response = client.post(url, json=body, headers=headers)
    except httpx.TimeoutException as exc:
        _record_attempt_failure(telemetry, att_id, started, exc, timed_out=True)
        raise
    except httpx.RequestError as exc:
        _record_attempt_failure(telemetry, att_id, started, exc, timed_out=False)
        raise
    except Exception as exc:
        _record_attempt_failure(telemetry, att_id, started, exc, timed_out=False)
        raise
    if telemetry:
        response_body = response.text
        api_key = headers.get("Authorization", "").removeprefix("Bearer ")
        if api_key:
            response_body = response_body.replace(api_key, "[redacted]")
        telemetry.record_attempt_response(
            attempt_id=att_id, response_body=response_body
        )
    return response, att_id, int((time.monotonic() - started) * 1000), started
