"""HTTP chat-completion client with server-outage detection and wait-for-recovery."""

from __future__ import annotations

import asyncio
import atexit
import contextvars
import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from forensia.ai.llm.attempt import _post_attempt
from forensia.ai.llm.request_metadata import (
    is_context_window_error as _is_context_window_error,
)
from forensia.ai.llm.request_metadata import prompt_metadata as _prompt_metadata
from forensia.ai.llm.request_metadata import request_fingerprint as _request_fingerprint
from forensia.ai.llm.response_metadata import (
    discarded_output_summary as _discarded_output_summary,
)
from forensia.ai.llm.response_metadata import (
    get_last_completion_metadata,
)
from forensia.ai.llm.response_metadata import (
    is_complete_json_object as _is_complete_json_object,
)
from forensia.ai.llm.response_metadata import (
    record_completion_metadata as _record_completion_metadata,
)
from forensia.ai.llm.response_metadata import (
    response_fingerprint as _response_fingerprint,
)
from forensia.ai.llm.schema_compat import (
    downgrade_schema_mode as _downgrade_schema_mode,
)
from forensia.ai.llm.schema_compat import (
    initial_schema_mode as _initial_schema_mode,
)
from forensia.ai.llm.schema_compat import (
    schema_response_format as _schema_response_format,
)
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
    "LLMRequestTimeoutError",
    "LLMOutputTruncatedError",
    "LLMContextWindowError",
    "chat_completion",
    "set_active_telemetry",
    "get_active_telemetry",
]

_TIMEOUT_KWARGS = {"connect": 5.0, "read": 300.0, "write": 30.0, "pool": 30.0}


class LLMServerUnavailableError(RuntimeError):
    """Raised when LLM server is unresponsive after call-level retries. Caller should enter outage_wait."""


class LLMRequestTimeoutError(LLMServerUnavailableError):
    """A connected provider exceeded the per-request deadline.

    This is a call/output failure, not proof of a server outage, so callers must
    not enter the outage recovery loop and replay the same expensive request.
    """


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


_LLM_HTTP_RETRY_MAX = 3
_LLM_HTTP_RETRY_BACKOFF = [2.0, 4.0, 8.0]

_CLIENT_SCOPE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "llm_client_scope", default=None
)
_SYNC_CLIENTS: dict[tuple[str | None, int], httpx.Client] = {}
_ASYNC_CLIENTS: dict[tuple[str | None, int], httpx.AsyncClient] = {}
_HTTP_CLIENTS_LOCK = threading.Lock()


def set_llm_client_scope(scope_id: str) -> contextvars.Token[str | None]:
    """Bind transport clients to one investigation lifecycle."""
    return _CLIENT_SCOPE.set(scope_id)


def reset_llm_client_scope(token: contextvars.Token[str | None]) -> None:
    _CLIENT_SCOPE.reset(token)


async def close_llm_clients(scope_id: str) -> None:
    """Close clients created by one investigation after its work has stopped."""
    with _HTTP_CLIENTS_LOCK:
        sync_clients = [
            _SYNC_CLIENTS.pop(k) for k in list(_SYNC_CLIENTS) if k[0] == scope_id
        ]
        async_clients = [
            _ASYNC_CLIENTS.pop(k) for k in list(_ASYNC_CLIENTS) if k[0] == scope_id
        ]
    for client in sync_clients:
        try:
            client.close()
        except Exception:
            logger.debug("Failed to close investigation HTTP client", exc_info=True)
    for client in async_clients:
        try:
            await client.aclose()
        except Exception:
            logger.debug("Failed to close investigation async client", exc_info=True)


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
    import httpx

    key = (_CLIENT_SCOPE.get(), threading.get_ident())
    with _HTTP_CLIENTS_LOCK:
        client = _SYNC_CLIENTS.get(key)
        if client is None:
            client = httpx.Client(timeout=httpx.Timeout(**_TIMEOUT_KWARGS))
            _SYNC_CLIENTS[key] = client
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


def _record_wait(
    telemetry: LLMTelemetry | None, duration_s: float, target: str
) -> None:
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


async def _get_async_client() -> httpx.AsyncClient:
    """Get or create a per-event-loop async HTTP client."""
    import httpx

    key = (_CLIENT_SCOPE.get(), id(asyncio.get_running_loop()))
    with _HTTP_CLIENTS_LOCK:
        client = _ASYNC_CLIENTS.get(key)
        if client is None:
            client = httpx.AsyncClient(timeout=httpx.Timeout(**_TIMEOUT_KWARGS))
            _ASYNC_CLIENTS[key] = client
        return client


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
    import httpx

    llm_settings = get_llm_settings()
    telemetry = get_active_telemetry()
    owned = False
    if telemetry is not None and logical_call_id is None:
        logical_call_id = telemetry.begin_logical_call(phase=phase or "chat_completion")
        owned = True
    try:
        configured, reserve, requested, effective = compute_effective_output_limit(
            requested_override=max_tokens,
            known_context_limit=llm_settings.get("llm_context_window_tokens"),
            estimated_input_tokens=sum(
                len(item.get("content", "")) for item in messages
            )
            // 4,
        )
    except Exception:
        _close_logical_call_if_owned(
            telemetry, logical_call_id, owned=owned, status="failed"
        )
        raise
    known_limit = llm_settings.get("llm_context_window_tokens")

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": llm_settings["temperature"],
        "max_tokens": effective,
    }
    schema_mode = "none"
    if json_schema:
        schema_mode = _initial_schema_mode(base_url)
        if schema_mode == "strict":
            body["response_format"] = _schema_response_format(json_schema, strict=True)
        elif schema_mode == "compatible":
            body["response_format"] = _schema_response_format(json_schema, strict=False)

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
            except httpx.TimeoutException as exc:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                if status_callback:
                    status_callback(
                        "LLM request timed out; not replaying it as an outage"
                    )
                raise LLMRequestTimeoutError("LLM request timed out") from exc
            except httpx.ConnectError:
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
            except Exception:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                raise
            if response.status_code == 400 and json_schema:
                next_mode = _downgrade_schema_mode(
                    body,
                    json_schema,
                    schema_mode,
                    status_callback,
                    status_code=400,
                    base_url=base_url,
                )
                if next_mode is not None:
                    if att_id:
                        telemetry.finalize_attempt(  # type: ignore[union-attr]
                            attempt_id=att_id,
                            status="provider_error",
                            http_status=400,
                            error_type="http",
                            error_code="400",
                            duration_ms=duration,
                            retry_class="schema_downgrade",
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
                    attempt_id=att_id,
                    status="provider_error",
                    http_status=status,
                    error_type="http",
                    error_code=str(status),
                    error_body_summary=error_body,
                    duration_ms=duration,
                )
            if json_schema and "Failed to parse input" in response.text:
                next_mode = _downgrade_schema_mode(
                    body,
                    json_schema,
                    schema_mode,
                    status_callback,
                    status_code=status,
                    base_url=base_url,
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
                    attempt_id=att_id,
                    status="provider_error",
                    http_status=status,
                    error_type="http",
                    error_code=str(status),
                    error_body_summary=error_body,
                    duration_ms=duration,
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
            data=data,
            messages=messages,
            content=content,
            finish_reason=finish_reason,
            started_at=started,
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
                error_body_summary=(
                    _discarded_output_summary(content, reasoning_len)
                    if unusable_truncation
                    else None
                ),
                finish_reason=str(finish_reason) if finish_reason is not None else None,
                input_tokens=completion.input_tokens if completion else None,
                output_tokens=completion.output_tokens if completion else None,
                input_tokens_source=completion.usage_source
                if completion
                else "unknown",
                output_tokens_source=completion.usage_source
                if completion
                else "unknown",
                output_chars=len(content),
                response_fingerprint=_response_fingerprint(content),
                duration_ms=duration,
                parse_status="complete_json"
                if complete_json
                else ("truncated" if unusable_truncation else "unparsed"),
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
    """Wait for the provider's model endpoint to respond to a health probe."""
    import httpx

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
                return
        except httpx.HTTPError, httpx.RequestError:
            pass
        await asyncio.sleep(interval_s)
