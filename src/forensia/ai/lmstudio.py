from __future__ import annotations

import atexit
from collections.abc import Callable
from typing import Any
import asyncio
import json
import threading
import time
from pathlib import Path

import os

import httpx


def _dump_failing_request(url: str, body: dict, status: int, response_text: str) -> None:
    """TEMP DIAGNOSTIC (remove after BUG investigation): persist a 5xx-triggering request for replay."""
    try:
        out = Path("/tmp/forensia-failing-prompt.json")
        existing_count = 0
        if out.exists():
            try:
                existing_count = int(json.loads(out.read_text(encoding="utf-8")).get("seq", 0))
            except Exception:
                pass
        payload = {
            "seq": existing_count + 1,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "url": url,
            "status": status,
            "response_text": response_text[:4000],
            "body": body,
        }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

from forensia.config import get_llm_settings


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
    resolved_max_tokens = (max_tokens if max_tokens is not None else settings["max_tokens"]) + settings.get("reasoning_reserve_tokens", 0)

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": resolved_max_tokens,
    }
    if json_schema:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": json_schema.get("title", "Output"), "strict": True, "schema": json_schema},
        }

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        try:
            client = await _get_async_client()
            response = await client.post(url, json=body)
            if response.status_code >= 500:
                _dump_failing_request(url, body, response.status_code, response.text)
                if json_schema and "Failed to parse input" in response.text:
                    body.pop("response_format", None)
                    if status_callback:
                        status_callback("LLM grammar violation (500) — retrying without json_schema constraint")
                    continue
                if attempt == _LLM_HTTP_RETRY_MAX:
                    raise LLMServerUnavailableError(f"LLM server returned {response.status_code} after {_LLM_HTTP_RETRY_MAX} retries")
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(f"LLM server {response.status_code} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
                await asyncio.sleep(wait)
                continue
            if response.status_code == 400 and json_schema:
                body.pop("response_format", None)
                response = await client.post(url, json=body)
            response.raise_for_status()
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500:
                raise
            if attempt == _LLM_HTTP_RETRY_MAX:
                raise LLMServerUnavailableError(f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries: {exc}") from exc
            wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            if status_callback:
                status_callback(f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
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
    resolved_max_tokens = (max_tokens if max_tokens is not None else settings["max_tokens"]) + settings.get("reasoning_reserve_tokens", 0)

    url = base_url.rstrip("/") + "/v1/chat/completions"
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": resolved_max_tokens,
    }
    if json_schema:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": json_schema.get("title", "Output"), "strict": True, "schema": json_schema},
        }

    for attempt in range(1, _LLM_HTTP_RETRY_MAX + 1):
        try:
            response = _get_http_client().post(url, json=body)
            if response.status_code >= 500:
                _dump_failing_request(url, body, response.status_code, response.text)
                if json_schema and "Failed to parse input" in response.text:
                    body.pop("response_format", None)
                    if status_callback:
                        status_callback("LLM grammar violation (500) — retrying without json_schema constraint")
                    continue
                if attempt == _LLM_HTTP_RETRY_MAX:
                    raise LLMServerUnavailableError(f"LLM server returned {response.status_code} after {_LLM_HTTP_RETRY_MAX} retries")
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(f"LLM server {response.status_code} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
                time.sleep(wait)
                continue
            if response.status_code == 400 and json_schema:
                body.pop("response_format", None)
                response = _get_http_client().post(url, json=body)
            response.raise_for_status()
        except (httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500:
                raise
            if attempt == _LLM_HTTP_RETRY_MAX:
                raise LLMServerUnavailableError(f"LLM server error after {_LLM_HTTP_RETRY_MAX} retries: {exc}") from exc
            wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
            if status_callback:
                status_callback(f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
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
    budget_s = int(os.getenv("LLM_OUTAGE_WALL_CLOCK_BUDGET_S", "28800"))
    interval_s = int(os.getenv("LLM_OUTAGE_PROBE_INTERVAL_S", "60"))
    started = time.monotonic()
    while True:
        waited = int(time.monotonic() - started)
        if waited > budget_s:
            raise LLMServerUnavailableError(f"LLM outage budget exceeded ({budget_s}s)")
        if progress_callback:
            progress_callback({"stage": "waiting_for_llm", "status": "running",
                               "summary": f"LLM server unavailable (waited {waited}s of {budget_s}s budget)"})
        try:
            client = await _get_async_client()
            r = await client.get(f"{base_url.rstrip('/')}/v1/models", timeout=10.0)
            if r.status_code == 200:
                ping = await client.post(f"{base_url.rstrip('/')}/v1/chat/completions",
                    json={"model": model, "messages": [{"role":"user","content":"ping"}], "max_tokens": 4})
                if ping.status_code < 500:
                    return
        except (httpx.HTTPError, httpx.RequestError):
            pass
        await asyncio.sleep(interval_s)
