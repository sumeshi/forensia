"""HTTP chat-completion client with server-outage detection and wait-for-recovery."""

from __future__ import annotations

import asyncio
import atexit
import json
import logging
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

import httpx

from forensia.ai.llm.request_metadata import (
    is_context_window_error as _is_context_window_error,
)
from forensia.ai.llm.request_metadata import prompt_metadata as _prompt_metadata
from forensia.ai.llm.request_metadata import request_fingerprint as _request_fingerprint
from forensia.ai.llm_telemetry import (
    LLMTelemetry,
    compute_effective_output_limit,
    get_active_telemetry,
    set_active_telemetry,
)
from forensia.config import get_llm_settings, settings
from forensia.core.progress_event import progress_event

logger = logging.getLogger(__name__)

__all__ = [
    "LLMServerUnavailableError",
    "LLMOutputTruncatedError",
    "LLMContextWindowError",
    "chat_completion",
    "async_chat_completion",
    "set_active_telemetry",
    "get_active_telemetry",
]


class LLMServerUnavailableError(RuntimeError):
    """Raised when LLM server is unresponsive after call-level retries. Caller should enter outage_wait."""


class LLMOutputTruncatedError(RuntimeError):
    """Raised when LLM response is truncated (finish_reason=length or empty content with non-empty reasoning)."""

    def __init__(self, message: str, *, content: str = "") -> None:
        super().__init__(message)
        self.content = content


class LLMContextWindowError(RuntimeError):
    """The provider rejected the request because its context window was exceeded."""

    def __init__(self, message: str, *, status_code: int, body: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body[:500]


@dataclass(frozen=True, slots=True)
class CompletionMetadata:
    input_tokens: int
    output_tokens: int
    usage_source: str
    finish_reason: str
    latency_ms: int


_LAST_COMPLETION_METADATA: ContextVar[CompletionMetadata | None] = ContextVar(
    "last_llm_completion_metadata", default=None
)


def get_last_completion_metadata() -> CompletionMetadata | None:
    """Return task-local metadata for the most recent completion."""

    return _LAST_COMPLETION_METADATA.get()


def _record_completion_metadata(
    *,
    data: dict[str, Any],
    messages: list[dict[str, str]],
    content: str,
    finish_reason: Any,
    started_at: float,
) -> None:
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    raw_input = usage.get("prompt_tokens", usage.get("input_tokens"))
    raw_output = usage.get("completion_tokens", usage.get("output_tokens"))
    measured = isinstance(raw_input, int) and isinstance(raw_output, int)
    input_tokens = (
        int(raw_input)
        if isinstance(raw_input, int)
        else max(1, sum(len(item.get("content", "")) for item in messages) // 4)
    )
    output_tokens = (
        int(raw_output)
        if isinstance(raw_output, int)
        else max(1, len(content) // 4)
    )
    _LAST_COMPLETION_METADATA.set(
        CompletionMetadata(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            usage_source="provider_actual" if measured else "local_estimate",
            finish_reason=str(finish_reason or "unknown"),
            latency_ms=max(0, int((time.monotonic() - started_at) * 1000)),
        )
    )


def _is_complete_json_object(content: str) -> bool:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    first = text.find("{")
    last = text.rfind("}")
    if first < 0 or last <= first:
        return False
    try:
        return isinstance(json.loads(text[first : last + 1]), dict)
    except (json.JSONDecodeError, TypeError):
        return False


_LLM_HTTP_RETRY_MAX = 3
_LLM_HTTP_RETRY_BACKOFF = [2.0, 4.0, 8.0]

_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=30.0)
_ASYNC_CLIENTS: dict[int, httpx.AsyncClient] = {}
_SYNC_CLIENTS: dict[int, httpx.Client] = {}
_HTTP_CLIENTS_LOCK = threading.Lock()

_SCHEMA_MODE_CACHE: dict[str, str] = {}
_SCHEMA_MODE_RANK = {"strict": 2, "compatible": 1, "none": 0}


def _initial_schema_mode(base_url: str) -> str:
    return _SCHEMA_MODE_CACHE.get(base_url, "strict")


def _remember_schema_mode(base_url: str, mode: str) -> None:
    current = _SCHEMA_MODE_CACHE.get(base_url, "strict")
    if _SCHEMA_MODE_RANK[mode] < _SCHEMA_MODE_RANK[current]:
        _SCHEMA_MODE_CACHE[base_url] = mode


def _schema_response_format(json_schema: dict, *, strict: bool) -> dict[str, Any]:
    """Build llama-server/OpenAI-compatible JSON schema response_format."""
    schema_payload: dict[str, Any] = {
        "name": json_schema.get("title", "Output"),
        "schema": json_schema,
    }
    if strict:
        schema_payload["strict"] = True
    return {
        "type": "json_schema",
        "json_schema": schema_payload,
    }


def _downgrade_schema_mode(
    body: dict[str, Any],
    json_schema: dict | None,
    schema_mode: str,
    status_callback: Callable[[str], None] | None,
    *,
    status_code: int,
    base_url: str,
) -> str | None:
    """Downgrade response_format only as far as required for server compatibility."""
    if not json_schema or schema_mode == "none":
        return None
    if schema_mode == "strict":
        body["response_format"] = _schema_response_format(json_schema, strict=False)
        _remember_schema_mode(base_url, "compatible")
        if status_callback:
            status_callback(
                f"LLM server rejected strict json_schema ({status_code}); "
                "retrying with compatible json_schema"
            )
        return "compatible"
    body.pop("response_format", None)
    _remember_schema_mode(base_url, "none")
    if status_callback:
        status_callback(
            f"LLM server rejected json_schema ({status_code}); "
            "retrying without response_format constraint"
        )
    return "none"


def _close_http_clients() -> None:
    """Close all cached HTTP clients (sync and async) at interpreter exit."""
    with _HTTP_CLIENTS_LOCK:
        sync_clients = list(_SYNC_CLIENTS.values())
        async_clients = list(_ASYNC_CLIENTS.values())
        _SYNC_CLIENTS.clear()
        _ASYNC_CLIENTS.clear()
    for client in sync_clients:
        client.close()
    for client in async_clients:
        try:
            asyncio.run(client.aclose())
        except Exception:
            logger.debug(
                "Failed to close async HTTP client at interpreter exit", exc_info=True
            )


atexit.register(_close_http_clients)


def _get_http_client() -> httpx.Client:
    """Get or create a per-thread synchronous HTTP client."""
    thread_id = threading.get_ident()
    with _HTTP_CLIENTS_LOCK:
        client = _SYNC_CLIENTS.get(thread_id)
        if client is None:
            client = httpx.Client(timeout=_HTTP_TIMEOUT)
            _SYNC_CLIENTS[thread_id] = client
        return client


def _auth_headers() -> dict[str, str]:
    if settings.llm_api_key:
        return {"Authorization": f"Bearer {settings.llm_api_key}"}
    return {}


def _redacted_error_body(response: httpx.Response) -> str:
    """Return a bounded provider error summary without credentials."""
    return response.text.replace("Authorization", "[redacted]")[:500]


def _close_logical_call_if_owned(
    telemetry: LLMTelemetry | None,
    logical_call_id: str | None,
    *,
    owned: bool,
    status: str,
) -> None:
    if telemetry is not None and owned and logical_call_id is not None:
        telemetry.close_logical_call(logical_call_id=logical_call_id, status=status)  # type: ignore[arg-type]


def _record_wait(telemetry: LLMTelemetry | None, duration_s: float, target: str) -> None:
    if telemetry is None or duration_s <= 0:
        return
    try:
        telemetry.record_deterministic_op(
            phase="llm_wait",
            op_type="wait",
            target=target,
            duration_ms=int(duration_s * 1000),
        )
    except Exception:
        logger.debug("unable to record LLM wait interval", exc_info=True)


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

    att_id: str | None = None
    if telemetry is not None and logical_call_id is not None:
        att_id = telemetry.begin_attempt(
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
        )
    started = time.monotonic()
    try:
        response = client.post(url, json=body, headers=headers)
    except httpx.TimeoutException:
        if att_id:
            telemetry.finalize_attempt(  # type: ignore[union-attr]
                attempt_id=att_id,
                status="timeout",
                exception_class="httpx.TimeoutException",
                error_type="timeout",
                deadline_fired="read",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        raise
    except httpx.RequestError as exc:
        if att_id:
            telemetry.finalize_attempt(  # type: ignore[union-attr]
                attempt_id=att_id,
                status="transport_error",
                exception_class=type(exc).__name__,
                error_type="connect" if isinstance(exc, httpx.ConnectError) else "transport",
                deadline_fired="connect" if isinstance(exc, httpx.ConnectError) else None,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        raise
    return response, att_id, int((time.monotonic() - started) * 1000), started


async def _a_post_attempt(
    client: httpx.AsyncClient,
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
    att_id: str | None = None
    if telemetry is not None and logical_call_id is not None:
        att_id = telemetry.begin_attempt(
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
        )
    started = time.monotonic()
    try:
        response = await client.post(url, json=body, headers=headers)
    except httpx.TimeoutException:
        if att_id:
            telemetry.finalize_attempt(  # type: ignore[union-attr]
                attempt_id=att_id,
                status="timeout",
                exception_class="httpx.TimeoutException",
                error_type="timeout",
                deadline_fired="read",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        raise
    except httpx.RequestError as exc:
        if att_id:
            telemetry.finalize_attempt(  # type: ignore[union-attr]
                attempt_id=att_id,
                status="transport_error",
                exception_class=type(exc).__name__,
                error_type="connect" if isinstance(exc, httpx.ConnectError) else "transport",
                deadline_fired="connect" if isinstance(exc, httpx.ConnectError) else None,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        raise
    return response, att_id, int((time.monotonic() - started) * 1000), started


async def _get_async_client() -> httpx.AsyncClient:
    """Get or create a per-event-loop async HTTP client."""
    loop_id = id(asyncio.get_running_loop())
    with _HTTP_CLIENTS_LOCK:
        client = _ASYNC_CLIENTS.get(loop_id)
        if client is None:
            client = httpx.AsyncClient(timeout=_HTTP_TIMEOUT)
            _ASYNC_CLIENTS[loop_id] = client
        return client


async def async_chat_completion(
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    max_tokens: int | None = None,
    status_callback: Callable[[str], None] | None = None,
    json_schema: dict | None = None,
    *,
    logical_call_id: str | None = None,
    attempt_ordinal: int = 0,
    phase: str | None = None,
    retry_class: str | None = None,
    retry_reason: str | None = None,
    policy_decision: str | None = None,
    request_changed_fields: dict[str, Any] | None = None,
) -> str:
    """Send a chat completion request to the LLM server (async). Returns the response text."""
    llm_settings = get_llm_settings()
    configured, reserve, requested, effective = compute_effective_output_limit(
        requested_override=max_tokens,
        known_context_limit=llm_settings.get("llm_context_window_tokens"),
        estimated_input_tokens=sum(len(item.get("content", "")) for item in messages) // 4,
    )
    known_limit = llm_settings.get("llm_context_window_tokens")

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": effective,
    }
    schema_mode = "none"
    if json_schema:
        schema_mode = _initial_schema_mode(base_url)
        if schema_mode == "strict":
            body["response_format"] = _schema_response_format(json_schema, strict=True)
        elif schema_mode == "compatible":
            body["response_format"] = _schema_response_format(json_schema, strict=False)

    telemetry = get_active_telemetry()
    owned = False
    if telemetry is not None and logical_call_id is None:
        logical_call_id = telemetry.begin_logical_call(phase=phase or "chat_completion")
        owned = True
    request_fingerprint = _request_fingerprint(messages) if telemetry else None
    input_chars = sum(len(item.get("content", "")) for item in messages)
    prompt_metadata = _prompt_metadata(messages)

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        downgrade_tries = 0
        response = None
        while downgrade_tries <= 2:
            try:
                response, att_id, duration, started = await _a_post_attempt(
                    await _get_async_client(),
                    url=url,
                    body=body,
                    headers=_auth_headers(),
                    telemetry=telemetry,
                    logical_call_id=logical_call_id,
                    ordinal=attempt_ordinal,
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
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt == _LLM_HTTP_RETRY_MAX:
                    _close_logical_call_if_owned(
                        telemetry, logical_call_id, owned=owned, status="failed"
                    )
                    raise LLMServerUnavailableError(
                        f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries"
                    )
                if status_callback:
                    status_callback(
                        f"LLM server error — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                    )
                wait_s = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                _record_wait(telemetry, wait_s, "http_retry_backoff")
                await asyncio.sleep(wait_s)
                break
            if response.status_code == 400 and json_schema:
                next_mode = _downgrade_schema_mode(
                    body, json_schema, schema_mode, status_callback,
                    status_code=400, base_url=base_url,
                )
                if next_mode is not None:
                    if att_id:
                        telemetry.finalize_attempt(  # type: ignore[union-attr]
                            attempt_id=att_id, status="provider_error",
                            http_status=400, error_type="http", error_code="400",
                            duration_ms=duration, retry_class="schema_downgrade",
                            retry_reason="server_rejected_response_format",
                        )
                    schema_mode = next_mode
                    downgrade_tries += 1
                    continue
            break
        if response is None:
            continue

        status = response.status_code
        error_body = _redacted_error_body(response)
        if _is_context_window_error(status, error_body):
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id,
                    status="provider_error",
                    http_status=status,
                    error_type="context_window",
                    error_code="context_window_exceeded",
                    error_body_summary=error_body,
                    duration_ms=duration,
                    retry_class="context_window",
                    retry_reason="provider rejected request context",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMContextWindowError(
                "LLM provider rejected the request context window",
                status_code=status,
                body=error_body,
            )
        if status >= 500:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id, status="provider_error", http_status=status,
                    error_type="http", error_code=str(status),
                    error_body_summary=error_body, duration_ms=duration,
                )
            if json_schema and "Failed to parse input" in response.text:
                next_mode = _downgrade_schema_mode(
                    body, json_schema, schema_mode, status_callback,
                    status_code=status, base_url=base_url,
                )
                if next_mode is not None:
                    schema_mode = next_mode
            if attempt == _LLM_HTTP_RETRY_MAX:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                raise LLMServerUnavailableError(
                    f"LLM server returned {status} after {_LLM_HTTP_RETRY_MAX} retries"
                )
            if status_callback:
                status_callback(
                    f"LLM server {status} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                )
            wait_s = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            _record_wait(telemetry, wait_s, "http_retry_backoff")
            await asyncio.sleep(wait_s)
            continue
        if status >= 400:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id, status="provider_error", http_status=status,
                    error_type="http", error_code=str(status),
                    error_body_summary=error_body, duration_ms=duration,
                    discarded_reason="http_error",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            response.raise_for_status()
        # success 2xx
        try:
            data = response.json()
            choice = data["choices"][0]
            finish_reason = choice.get("finish_reason")
            content = choice["message"].get("content") or ""
            reasoning_len = len(choice["message"].get("reasoning_content") or "")
        except Exception as exc:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id,
                    status="parse_error",
                    http_status=status,
                    error_type="response_parse",
                    exception_class=type(exc).__name__,
                    error_body_summary=error_body,
                    duration_ms=duration,
                    parse_status="error",
                    accepted=False,
                    discarded_reason="invalid provider response envelope",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise
        _record_completion_metadata(
            data=data, messages=messages, content=content,
            finish_reason=finish_reason, started_at=started,
        )
        completion = get_last_completion_metadata()
        complete_json = finish_reason == "length" and _is_complete_json_object(content)
        unusable_truncation = (finish_reason == "length" and not complete_json) or (
            not content.strip() and reasoning_len > 0
        )
        truncation_reason = (
            "finish_reason=length"
            if finish_reason == "length"
            else "empty_content_with_reasoning"
        )
        if att_id and telemetry is not None:
            telemetry.finalize_attempt(
                attempt_id=att_id,
                status="parse_error" if unusable_truncation else "success",
                http_status=status,
                error_type="truncated" if unusable_truncation else None,
                finish_reason=str(finish_reason) if finish_reason is not None else None,
                input_tokens=completion.input_tokens if completion else None,
                output_tokens=completion.output_tokens if completion else None,
                input_tokens_source=completion.usage_source if completion else "unknown",
                output_tokens_source=completion.usage_source if completion else "unknown",
                output_chars=len(content),
                duration_ms=duration,
                parse_status="complete_json" if complete_json else (
                    "truncated" if unusable_truncation else "unparsed"
                ),
                truncated=unusable_truncation,
                accepted=not unusable_truncation,
                discarded_reason=truncation_reason if unusable_truncation else None,
            )
        if complete_json:
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="success"
            )
            return content
        if unusable_truncation:
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMOutputTruncatedError(
                f"LLM output truncated (finish_reason={finish_reason}, reasoning_len={reasoning_len}, content_len={len(content)})",
                content=content,
            )
        _close_logical_call_if_owned(
            telemetry, logical_call_id, owned=owned, status="success"
        )
        return content
    raise LLMServerUnavailableError("LLM HTTP retry loop exited without response")


def chat_completion(
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    max_tokens: int | None = None,
    status_callback: Callable[[str], None] | None = None,
    json_schema: dict | None = None,
    *,
    logical_call_id: str | None = None,
    attempt_ordinal: int = 0,
    phase: str | None = None,
    retry_class: str | None = None,
    retry_reason: str | None = None,
    policy_decision: str | None = None,
    request_changed_fields: dict[str, Any] | None = None,
) -> str:
    """Send a chat completion request to the LLM server (sync). Returns the response text."""
    llm_settings = get_llm_settings()
    configured, reserve, requested, effective = compute_effective_output_limit(
        requested_override=max_tokens,
        known_context_limit=llm_settings.get("llm_context_window_tokens"),
        estimated_input_tokens=sum(len(item.get("content", "")) for item in messages) // 4,
    )
    known_limit = llm_settings.get("llm_context_window_tokens")

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": effective,
    }
    schema_mode = "none"
    if json_schema:
        schema_mode = _initial_schema_mode(base_url)
        if schema_mode == "strict":
            body["response_format"] = _schema_response_format(json_schema, strict=True)
        elif schema_mode == "compatible":
            body["response_format"] = _schema_response_format(json_schema, strict=False)

    telemetry = get_active_telemetry()
    owned = False
    if telemetry is not None and logical_call_id is None:
        logical_call_id = telemetry.begin_logical_call(phase=phase or "chat_completion")
        owned = True
    request_fingerprint = _request_fingerprint(messages) if telemetry else None
    input_chars = sum(len(item.get("content", "")) for item in messages)
    prompt_metadata = _prompt_metadata(messages)

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        downgrade_tries = 0
        response = None
        while downgrade_tries <= 2:
            try:
                response, att_id, duration, started = _post_attempt(
                    _get_http_client(),
                    url=url,
                    body=body,
                    headers=_auth_headers(),
                    telemetry=telemetry,
                    logical_call_id=logical_call_id,
                    ordinal=attempt_ordinal,
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
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt == _LLM_HTTP_RETRY_MAX:
                    _close_logical_call_if_owned(
                        telemetry, logical_call_id, owned=owned, status="failed"
                    )
                    raise LLMServerUnavailableError(
                        f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries"
                    )
                if status_callback:
                    status_callback(
                        f"LLM server error — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                    )
                wait_s = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                _record_wait(telemetry, wait_s, "http_retry_backoff")
                time.sleep(wait_s)
                break
            if response.status_code == 400 and json_schema:
                next_mode = _downgrade_schema_mode(
                    body, json_schema, schema_mode, status_callback,
                    status_code=400, base_url=base_url,
                )
                if next_mode is not None:
                    if att_id:
                        telemetry.finalize_attempt(  # type: ignore[union-attr]
                            attempt_id=att_id, status="provider_error",
                            http_status=400, error_type="http", error_code="400",
                            duration_ms=duration, retry_class="schema_downgrade",
                            retry_reason="server_rejected_response_format",
                        )
                    schema_mode = next_mode
                    downgrade_tries += 1
                    continue
            break
        if response is None:
            continue

        status = response.status_code
        error_body = _redacted_error_body(response)
        if _is_context_window_error(status, error_body):
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id,
                    status="provider_error",
                    http_status=status,
                    error_type="context_window",
                    error_code="context_window_exceeded",
                    error_body_summary=error_body,
                    duration_ms=duration,
                    retry_class="context_window",
                    retry_reason="provider rejected request context",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMContextWindowError(
                "LLM provider rejected the request context window",
                status_code=status,
                body=error_body,
            )
        if status >= 500:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id, status="provider_error", http_status=status,
                    error_type="http", error_code=str(status),
                    error_body_summary=error_body, duration_ms=duration,
                )
            if json_schema and "Failed to parse input" in response.text:
                next_mode = _downgrade_schema_mode(
                    body, json_schema, schema_mode, status_callback,
                    status_code=status, base_url=base_url,
                )
                if next_mode is not None:
                    schema_mode = next_mode
            if attempt == _LLM_HTTP_RETRY_MAX:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                raise LLMServerUnavailableError(
                    f"LLM server returned {status} after {_LLM_HTTP_RETRY_MAX} retries"
                )
            if status_callback:
                status_callback(
                    f"LLM server {status} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                )
            wait_s = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            _record_wait(telemetry, wait_s, "http_retry_backoff")
            time.sleep(wait_s)
            continue
        if status >= 400:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id, status="provider_error", http_status=status,
                    error_type="http", error_code=str(status),
                    error_body_summary=error_body, duration_ms=duration,
                    discarded_reason="http_error",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            response.raise_for_status()
        # success 2xx
        try:
            data = response.json()
            choice = data["choices"][0]
            finish_reason = choice.get("finish_reason")
            content = choice["message"].get("content") or ""
            reasoning_len = len(choice["message"].get("reasoning_content") or "")
        except Exception as exc:
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id,
                    status="parse_error",
                    http_status=status,
                    error_type="response_parse",
                    exception_class=type(exc).__name__,
                    error_body_summary=error_body,
                    duration_ms=duration,
                    parse_status="error",
                    accepted=False,
                    discarded_reason="invalid provider response envelope",
                )
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise
        _record_completion_metadata(
            data=data, messages=messages, content=content,
            finish_reason=finish_reason, started_at=started,
        )
        completion = get_last_completion_metadata()
        complete_json = finish_reason == "length" and _is_complete_json_object(content)
        unusable_truncation = (finish_reason == "length" and not complete_json) or (
            not content.strip() and reasoning_len > 0
        )
        truncation_reason = (
            "finish_reason=length"
            if finish_reason == "length"
            else "empty_content_with_reasoning"
        )
        if att_id and telemetry is not None:
            telemetry.finalize_attempt(
                attempt_id=att_id,
                status="parse_error" if unusable_truncation else "success",
                http_status=status,
                error_type="truncated" if unusable_truncation else None,
                finish_reason=str(finish_reason) if finish_reason is not None else None,
                input_tokens=completion.input_tokens if completion else None,
                output_tokens=completion.output_tokens if completion else None,
                input_tokens_source=completion.usage_source if completion else "unknown",
                output_tokens_source=completion.usage_source if completion else "unknown",
                output_chars=len(content),
                duration_ms=duration,
                parse_status="complete_json" if complete_json else (
                    "truncated" if unusable_truncation else "unparsed"
                ),
                truncated=unusable_truncation,
                accepted=not unusable_truncation,
                discarded_reason=truncation_reason if unusable_truncation else None,
            )
        if complete_json:
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="success"
            )
            return content
        if unusable_truncation:
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMOutputTruncatedError(
                f"LLM output truncated (finish_reason={finish_reason}, reasoning_len={reasoning_len}, content_len={len(content)})",
                content=content,
            )
        _close_logical_call_if_owned(
            telemetry, logical_call_id, owned=owned, status="success"
        )
        return content
    raise LLMServerUnavailableError("LLM HTTP retry loop exited without response")


async def outage_wait_until_recovered(
    base_url: str,
    model: str,
    progress_callback: Callable[[dict], None] | None = None,
) -> None:
    budget_s = settings.llm_outage_wall_clock_budget_s
    interval_s = settings.llm_outage_probe_interval_s
    started = time.monotonic()
    while True:
        waited = int(time.monotonic() - started)
        if waited > budget_s:
            raise LLMServerUnavailableError(f"LLM outage budget exceeded ({budget_s}s)")
        if progress_callback:
            progress_callback(
                progress_event(
                    "waiting_for_llm",
                    "running",
                    summary=f"LLM server unavailable (waited {waited}s of {budget_s}s budget)",
                )
            )
        try:
            client = await _get_async_client()
            r = await client.get(
                f"{base_url.rstrip('/')}/v1/models",
                timeout=10.0,
                headers=_auth_headers(),
            )
            if r.status_code == 200:
                ping = await client.post(
                    f"{base_url.rstrip('/')}/v1/chat/completions",
                    headers=_auth_headers(),
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": "ping"}],
                        "max_tokens": 4,
                    },
                )
                if ping.status_code < 500:
                    return
        except httpx.HTTPError, httpx.RequestError:
            pass
        await asyncio.sleep(interval_s)
