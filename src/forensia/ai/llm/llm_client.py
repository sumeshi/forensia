"""HTTP chat-completion client with server-outage detection and wait-for-recovery."""

from __future__ import annotations

import asyncio
import atexit
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from forensia.config import get_llm_settings, settings
from forensia.core.progress_event import progress_event


class LLMServerUnavailableError(RuntimeError):
    """Raised when LLM server is unresponsive after call-level retries. Caller should enter outage_wait."""


class LLMOutputTruncatedError(RuntimeError):
    """Raised when LLM response is truncated (finish_reason=length or empty content with non-empty reasoning)."""


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
            pass


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
) -> str:
    """Send a chat completion request to the LLM server (async). Returns the response text."""
    settings = get_llm_settings()
    resolved_max_tokens = (
        max_tokens if max_tokens is not None else settings["max_tokens"]
    ) + settings.get("reasoning_reserve_tokens", 0)

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": resolved_max_tokens,
    }
    schema_mode = "none"
    if json_schema:
        schema_mode = _initial_schema_mode(base_url)
        if schema_mode == "strict":
            body["response_format"] = _schema_response_format(json_schema, strict=True)
        elif schema_mode == "compatible":
            body["response_format"] = _schema_response_format(json_schema, strict=False)

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        try:
            client = await _get_async_client()
            response = await client.post(url, json=body)
            if response.status_code >= 500:
                if json_schema and "Failed to parse input" in response.text:
                    next_schema_mode = _downgrade_schema_mode(
                        body,
                        json_schema,
                        schema_mode,
                        status_callback,
                        status_code=response.status_code,
                        base_url=base_url,
                    )
                    if next_schema_mode is not None:
                        schema_mode = next_schema_mode
                        continue
                if attempt == _LLM_HTTP_RETRY_MAX:
                    raise LLMServerUnavailableError(
                        f"LLM server returned {response.status_code} after {_LLM_HTTP_RETRY_MAX} retries"
                    )
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(
                        f"LLM server {response.status_code} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                    )
                await asyncio.sleep(wait)
                continue
            while response.status_code == 400 and json_schema:
                next_schema_mode = _downgrade_schema_mode(
                    body,
                    json_schema,
                    schema_mode,
                    status_callback,
                    status_code=response.status_code,
                    base_url=base_url,
                )
                if next_schema_mode is not None:
                    schema_mode = next_schema_mode
                    response = await client.post(url, json=body)
                    continue
                break
            response.raise_for_status()
        except (
            httpx.HTTPStatusError,
            httpx.ConnectError,
            httpx.TimeoutException,
        ) as exc:
            if (
                isinstance(exc, httpx.HTTPStatusError)
                and exc.response.status_code < 500
            ):
                raise
            if attempt == _LLM_HTTP_RETRY_MAX:
                raise LLMServerUnavailableError(
                    f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries: {exc}"
                ) from exc
            wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            if status_callback:
                status_callback(
                    f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                )
            await asyncio.sleep(wait)
            continue
        data = response.json()
        choice = data["choices"][0]
        finish_reason = choice.get("finish_reason")
        content = choice["message"].get("content") or ""
        reasoning_len = len(choice["message"].get("reasoning_content") or "")
        if finish_reason == "length" or (not content.strip() and reasoning_len > 0):
            raise LLMOutputTruncatedError(
                f"LLM output truncated (finish_reason={finish_reason}, reasoning_len={reasoning_len}, content_len={len(content)})"
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
) -> str:
    """Send a chat completion request to the LLM server (sync). Returns the response text."""
    settings = get_llm_settings()
    resolved_max_tokens = (
        max_tokens if max_tokens is not None else settings["max_tokens"]
    ) + settings.get("reasoning_reserve_tokens", 0)

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": resolved_max_tokens,
    }
    schema_mode = "none"
    if json_schema:
        schema_mode = _initial_schema_mode(base_url)
        if schema_mode == "strict":
            body["response_format"] = _schema_response_format(json_schema, strict=True)
        elif schema_mode == "compatible":
            body["response_format"] = _schema_response_format(json_schema, strict=False)

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        try:
            response = _get_http_client().post(url, json=body)
            if response.status_code >= 500:
                if json_schema and "Failed to parse input" in response.text:
                    next_schema_mode = _downgrade_schema_mode(
                        body,
                        json_schema,
                        schema_mode,
                        status_callback,
                        status_code=response.status_code,
                        base_url=base_url,
                    )
                    if next_schema_mode is not None:
                        schema_mode = next_schema_mode
                        continue
                if attempt == _LLM_HTTP_RETRY_MAX:
                    raise LLMServerUnavailableError(
                        f"LLM server returned {response.status_code} after {_LLM_HTTP_RETRY_MAX} retries"
                    )
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(
                        f"LLM server {response.status_code} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                    )
                time.sleep(wait)
                continue
            while response.status_code == 400 and json_schema:
                next_schema_mode = _downgrade_schema_mode(
                    body,
                    json_schema,
                    schema_mode,
                    status_callback,
                    status_code=response.status_code,
                    base_url=base_url,
                )
                if next_schema_mode is not None:
                    schema_mode = next_schema_mode
                    response = _get_http_client().post(url, json=body)
                    continue
                break
            response.raise_for_status()
        except (
            httpx.HTTPStatusError,
            httpx.ConnectError,
            httpx.TimeoutException,
        ) as exc:
            if (
                isinstance(exc, httpx.HTTPStatusError)
                and exc.response.status_code < 500
            ):
                raise
            if attempt == _LLM_HTTP_RETRY_MAX:
                raise LLMServerUnavailableError(
                    f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries: {exc}"
                ) from exc
            wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            if status_callback:
                status_callback(
                    f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}"
                )
            time.sleep(wait)
            continue
        data = response.json()
        choice = data["choices"][0]
        finish_reason = choice.get("finish_reason")
        content = choice["message"].get("content") or ""
        reasoning_len = len(choice["message"].get("reasoning_content") or "")
        if finish_reason == "length" or (not content.strip() and reasoning_len > 0):
            raise LLMOutputTruncatedError(
                f"LLM output truncated (finish_reason={finish_reason}, reasoning_len={reasoning_len}, content_len={len(content)})"
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
            r = await client.get(f"{base_url.rstrip('/')}/v1/models", timeout=10.0)
            if r.status_code == 200:
                ping = await client.post(
                    f"{base_url.rstrip('/')}/v1/chat/completions",
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
