from __future__ import annotations

import atexit
from collections.abc import Callable
import asyncio
import threading

import httpx

from forensia.config import get_llm_settings

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
) -> str:
    """Send a chat completion request to the LLM server (async). Returns the response text."""
    settings = get_llm_settings()
    resolved_max_tokens = max_tokens if max_tokens is not None else settings["max_tokens"]

    url = base_url.rstrip("/") + "/v1/chat/completions"
    try:
        client = await _get_async_client()
        response = await client.post(
            url,
            json={
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": resolved_max_tokens,
            },
        )
        response.raise_for_status()
    except httpx.ConnectTimeout as exc:
        raise RuntimeError(f"Timed out while connecting to LLM server: {url}") from exc
    except httpx.ReadTimeout as exc:
        raise RuntimeError(f"Connected to LLM server, but timed out waiting for model response: {model}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"LLM server request failed: {exc}") from exc
    data = response.json()
    return data["choices"][0]["message"]["content"]


def chat_completion(
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    max_tokens: int | None = None,
    status_callback: Callable[[str], None] | None = None,
) -> str:
    """Send a chat completion request to the LLM server (sync). Returns the response text."""
    settings = get_llm_settings()
    resolved_max_tokens = max_tokens if max_tokens is not None else settings["max_tokens"]

    url = base_url.rstrip("/") + "/v1/chat/completions"
    try:
        response = _get_http_client().post(
            url,
            json={
                "model": model,
                "messages": messages,
                "temperature": 0,
                "max_tokens": resolved_max_tokens,
            },
        )
        response.raise_for_status()
    except httpx.ConnectTimeout as exc:
        raise RuntimeError(f"Timed out while connecting to LLM server: {url}") from exc
    except httpx.ReadTimeout as exc:
        raise RuntimeError(f"Connected to LLM server, but timed out waiting for model response: {model}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"LLM server request failed: {exc}") from exc
    data = response.json()
    return data["choices"][0]["message"]["content"]
