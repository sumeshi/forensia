"""HTTP chat-completion client with server-outage detection and wait-for-recovery."""

from __future__ import annotations

import asyncio
import atexit
import contextvars
import json
import logging
import threading
import time
from collections.abc import Callable
from copy import deepcopy
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from forensia.config import get_llm_settings, get_settings
from forensia.context.prompt_context import fit_prompt_messages
from forensia.core.control import InvestigationStopped, check_stop
from forensia.core.progress_event import progress_event
from forensia.llm.attempt import _post_attempt
from forensia.llm.request_metadata import (
    is_context_window_error as _is_context_window_error,
)
from forensia.llm.request_metadata import prompt_metadata as _prompt_metadata
from forensia.llm.request_metadata import request_fingerprint as _request_fingerprint
from forensia.llm.response_metadata import (
    discarded_output_summary as _discarded_output_summary,
)
from forensia.llm.response_metadata import (
    get_last_completion_metadata,
)
from forensia.llm.response_metadata import (
    is_complete_json_object as _is_complete_json_object,
)
from forensia.llm.response_metadata import (
    record_completion_metadata as _record_completion_metadata,
)
from forensia.llm.response_metadata import (
    response_fingerprint as _response_fingerprint,
)
from forensia.llm.schema_compat import (
    downgrade_schema_mode as _downgrade_schema_mode,
)
from forensia.llm.schema_compat import (
    schema_response_format as _schema_response_format,
)
from forensia.llm.telemetry import (
    LLMTelemetry,
    compute_effective_output_limit,
    get_active_telemetry,
    set_active_telemetry,
)

logger = logging.getLogger(__name__)

__all__ = [
    "LLMServerUnavailableError",
    "LLMRequestTimeoutError",
    "LLMOutputTruncatedError",
    "LLMContextWindowError",
    "LLMStructuredOutputError",
    "chat_completion",
    "set_active_telemetry",
    "get_active_telemetry",
]

_TIMEOUT_KWARGS = {"connect": 5.0, "read": 300.0, "write": 30.0, "pool": 30.0}


class LLMServerUnavailableError(RuntimeError):
    """Raised when LLM server is unresponsive after call-level retries. Caller should enter outage_wait."""


class LLMOutageBudgetExceededError(LLMServerUnavailableError):
    """Provider recovery exceeded its wall-clock budget; no replay is allowed."""


class LLMRequestTimeoutError(LLMServerUnavailableError):
    """A provider request exceeded its deadline and can resume after recovery."""


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


class LLMStructuredOutputError(RuntimeError):
    """The provider rejected a response schema or could not parse its output."""

    def __init__(self, *, status_code: int, error_code: str, body: str) -> None:
        reason = (
            "rejected the response schema"
            if error_code == "response_schema_rejected"
            else "could not parse generated structured output"
        )
        super().__init__(f"LLM provider {reason} (HTTP {status_code}): {body[:500]}")
        self.status_code = status_code
        self.error_code = error_code
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
    api_key = get_settings().llm_api_key
    if api_key:
        return {"Authorization": f"Bearer {api_key}"}
    return {}


def _redacted_error_body(response: httpx.Response) -> str:
    """Return a bounded provider error summary without credentials."""
    body = response.text
    api_key = get_settings().llm_api_key
    if api_key:
        body = body.replace(api_key, "[redacted]")
    return body.replace("Authorization", "[redacted]")[:500]


def _close_logical_call_if_owned(
    telemetry: LLMTelemetry | None,
    logical_call_id: str | None,
    *,
    owned: bool,
    status: str,
) -> None:
    if telemetry is not None and owned and logical_call_id is not None:
        telemetry.close_logical_call(logical_call_id=logical_call_id, status=status)  # type: ignore[arg-type]


def _check_stop_for_owned_call(
    telemetry: LLMTelemetry | None,
    logical_call_id: str | None,
    *,
    owned: bool,
) -> None:
    try:
        check_stop()
    except InvestigationStopped:
        _close_logical_call_if_owned(
            telemetry, logical_call_id, owned=owned, status="discarded"
        )
        raise


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
    attempt_ordinal: int | list[int] = 0,
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
        if json_schema is not None:
            messages = deepcopy(messages)
            serialized_schema = json.dumps(
                json_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            schema_instruction = (
                "Return exactly one JSON object matching this schema. "
                "Do not use markdown or surrounding commentary. "
                "The API response format enforces the same schema.\n"
                f"JSON Schema:\n{serialized_schema}"
            )
            if messages and messages[0].get("role") == "system":
                messages[0]["content"] = (
                    f"{messages[0].get('content', '')}\n\n{schema_instruction}"
                )
            else:
                messages.insert(0, {"role": "system", "content": schema_instruction})
        messages = (
            fit_prompt_messages(messages, max_output_tokens=max_tokens) or messages
        )
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
    if json_schema is not None:
        schema_mode = "strict"
        body["response_format"] = _schema_response_format(json_schema, strict=True)

    request_fingerprint = _request_fingerprint(messages) if telemetry else None
    ordinal = (
        attempt_ordinal if isinstance(attempt_ordinal, list) else [attempt_ordinal]
    )
    input_chars = sum(len(item.get("content", "")) for item in messages)
    prompt_metadata = _prompt_metadata(messages)

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        downgrade_tries = 0
        response = None
        while downgrade_tries <= 2:
            try:
                check_stop()
                current_ordinal = ordinal[0]
                ordinal[0] += 1
                response, att_id, duration, started = _post_attempt(
                    _get_http_client(),
                    url=url,
                    body=body,
                    headers=_auth_headers(),
                    telemetry=telemetry,
                    logical_call_id=logical_call_id,
                    ordinal=current_ordinal,
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
                try:
                    check_stop()
                except InvestigationStopped:
                    _close_logical_call_if_owned(
                        telemetry, logical_call_id, owned=owned, status="discarded"
                    )
                    raise
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                if status_callback:
                    status_callback("LLM request timed out; entering outage recovery")
                raise LLMRequestTimeoutError("LLM request timed out") from exc
            except httpx.ConnectError:
                _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
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
                until = time.monotonic() + wait_s
                try:
                    while time.monotonic() < until:
                        check_stop()
                        time.sleep(min(0.25, max(0, until - time.monotonic())))
                except InvestigationStopped:
                    _close_logical_call_if_owned(
                        telemetry, logical_call_id, owned=owned, status="discarded"
                    )
                    raise
                break
            except httpx.TransportError as exc:
                _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                if status_callback:
                    status_callback(
                        "LLM connection was interrupted; entering outage recovery"
                    )
                raise LLMServerUnavailableError(
                    f"LLM connection interrupted ({type(exc).__name__})"
                ) from exc
            except InvestigationStopped:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="discarded"
                )
                raise
            except Exception:
                _close_logical_call_if_owned(
                    telemetry, logical_call_id, owned=owned, status="failed"
                )
                raise
            if (
                response.status_code == 400
                and json_schema is not None
                and not _is_context_window_error(400, _redacted_error_body(response))
            ):
                next_mode = _downgrade_schema_mode(
                    body,
                    json_schema,
                    schema_mode,
                    status_callback,
                    status_code=400,
                    error_body=_redacted_error_body(response),
                )
                if next_mode is not None:
                    if att_id:
                        telemetry.finalize_attempt(  # type: ignore[union-attr]
                            attempt_id=att_id,
                            status="provider_error",
                            http_status=400,
                            error_type="http",
                            error_code="400",
                            error_body_summary=_redacted_error_body(response),
                            duration_ms=duration,
                            retry_class="schema_downgrade",
                            retry_reason="server_rejected_response_format",
                        )
                    schema_mode = next_mode
                    downgrade_tries += 1
                    _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
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
            _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMContextWindowError(
                "LLM provider rejected the request context window",
                status_code=status,
                body=error_body,
            )
        lowered_error = error_body.lower()
        schema_rejected = json_schema is not None and any(
            marker in lowered_error
            for marker in (
                "json schema conversion failed",
                "unable to generate parser",
                "schema unsupported",
                "response_format unsupported",
                "failed to parse grammar",
                "error parsing grammar",
            )
        )
        output_parse_failed = (
            json_schema is not None and "failed to parse input" in lowered_error
        )
        if status >= 400 and (schema_rejected or output_parse_failed):
            error_code = (
                "response_schema_rejected"
                if schema_rejected
                else "generated_output_parse_failed"
            )
            if att_id:
                telemetry.finalize_attempt(  # type: ignore[union-attr]
                    attempt_id=att_id,
                    status="provider_error",
                    http_status=status,
                    error_type="schema" if schema_rejected else "response_parse",
                    error_code=error_code,
                    error_body_summary=error_body,
                    duration_ms=duration,
                    discarded_reason=(
                        "provider rejected response schema"
                        if schema_rejected
                        else "provider could not parse generated output"
                    ),
                    retry_class=retry_class,
                    retry_reason=retry_reason,
                    policy_decision=policy_decision,
                    request_changed_fields=request_changed_fields,
                )
            _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
            _close_logical_call_if_owned(
                telemetry, logical_call_id, owned=owned, status="failed"
            )
            raise LLMStructuredOutputError(
                status_code=status, error_code=error_code, body=error_body
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
                    retry_class=retry_class,
                    retry_reason=retry_reason,
                    policy_decision=policy_decision,
                    request_changed_fields=request_changed_fields,
                )
            _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
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
                    retry_class=retry_class,
                    retry_reason=retry_reason,
                    policy_decision=policy_decision,
                    request_changed_fields=request_changed_fields,
                )
            _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
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
                    retry_class=retry_class,
                    retry_reason=retry_reason,
                    policy_decision=policy_decision,
                    request_changed_fields=request_changed_fields,
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
                input_tokens_source=completion.input_tokens_source
                if completion
                else "unknown",
                output_tokens_source=completion.output_tokens_source
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
                retry_class=retry_class,
                retry_reason=retry_reason,
                policy_decision=policy_decision,
                request_changed_fields=request_changed_fields,
            )
        _check_stop_for_owned_call(telemetry, logical_call_id, owned=owned)
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


def outage_wait_until_recovered_sync(
    base_url: str,
    status_callback: Callable[[str], None] | None = None,
    *,
    budget_s: float | None = None,
) -> None:
    """Wait for provider recovery from synchronous request paths."""
    import httpx

    settings = get_settings()
    budget_s = (
        budget_s if budget_s is not None else settings.llm_outage_wall_clock_budget_s
    )
    interval_s = settings.llm_outage_probe_interval_s
    started = time.monotonic()
    if status_callback:
        status_callback(f"LLM unavailable; waiting up to {budget_s}s for recovery")
    while True:
        check_stop()
        elapsed = time.monotonic() - started
        if elapsed >= budget_s:
            raise LLMOutageBudgetExceededError(
                f"LLM outage budget exceeded ({budget_s}s)"
            )
        try:
            response = _get_http_client().get(
                f"{base_url.rstrip('/')}/v1/models",
                timeout=min(10.0, max(0.0, budget_s - (time.monotonic() - started))),
                headers=_auth_headers(),
            )
            if response.status_code == 200:
                check_stop()
                if time.monotonic() - started >= budget_s:
                    raise LLMOutageBudgetExceededError(
                        f"LLM outage budget exceeded ({budget_s}s)"
                    )
                return
        except httpx.HTTPError:
            pass
        until = time.monotonic() + min(
            interval_s, max(0, budget_s - (time.monotonic() - started))
        )
        while time.monotonic() < until:
            check_stop()
            time.sleep(min(0.25, max(0, until - time.monotonic())))


async def outage_wait_until_recovered(
    base_url: str,
    progress_callback: Callable[[dict], None] | None = None,
    *,
    budget_s: float | None = None,
) -> None:
    """Wait for the provider's model endpoint to respond to a health probe."""
    import httpx

    settings = get_settings()
    budget_s = (
        budget_s if budget_s is not None else settings.llm_outage_wall_clock_budget_s
    )
    interval_s = settings.llm_outage_probe_interval_s
    started = time.monotonic()
    while True:
        check_stop()
        elapsed = time.monotonic() - started
        waited = int(elapsed)
        if elapsed >= budget_s:
            raise LLMOutageBudgetExceededError(
                f"LLM outage budget exceeded ({budget_s}s)"
            )
        if progress_callback:
            progress_callback(
                progress_event(
                    "llm.outage_wait",
                    "running",
                    severity="warning",
                    reason="provider_unavailable",
                    stage="waiting_for_llm",
                    summary=f"LLM server unavailable (waited {waited}s of {budget_s}s budget)",
                    waited_seconds=waited,
                    budget_seconds=budget_s,
                )
            )
        try:
            client = await _get_async_client()
            r = await client.get(
                f"{base_url.rstrip('/')}/v1/models",
                timeout=min(10.0, max(0.0, budget_s - (time.monotonic() - started))),
                headers=_auth_headers(),
            )
            if r.status_code == 200:
                check_stop()
                if time.monotonic() - started >= budget_s:
                    raise LLMOutageBudgetExceededError(
                        f"LLM outage budget exceeded ({budget_s}s)"
                    )
                return
        except httpx.HTTPError, httpx.RequestError:
            pass
        until = min(started + budget_s, time.monotonic() + interval_s)
        while time.monotonic() < until:
            check_stop()
            await asyncio.sleep(min(0.25, max(0, until - time.monotonic())))
