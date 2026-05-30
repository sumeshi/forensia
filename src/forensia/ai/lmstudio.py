from __future__ import annotations

import atexit
from collections.abc import Callable
from typing import Any
import asyncio
import threading
import time

import httpx

from forensia.config import get_llm_settings

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
    resolved_max_tokens = max_tokens if max_tokens is not None else settings["max_tokens"]

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
            if attempt < _LLM_HTTP_RETRY_MAX:
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
                await asyncio.sleep(wait)
                continue
            raise
        data = response.json()
        return data["choices"][0]["message"]["content"]


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
    resolved_max_tokens = max_tokens if max_tokens is not None else settings["max_tokens"]

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
            if attempt < _LLM_HTTP_RETRY_MAX:
                wait = _LLM_HTTP_RETRY_BACKOFF[attempt - 1]
                if status_callback:
                    status_callback(f"LLM server error {exc} — retry {attempt}/{_LLM_HTTP_RETRY_MAX}")
                time.sleep(wait)
                continue
            raise
        data = response.json()
        return data["choices"][0]["message"]["content"]
