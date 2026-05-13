from __future__ import annotations

import atexit
from collections.abc import Callable
import threading

import httpx

from forensia.config import get_llm_settings

_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=30.0)
_HTTP_CLIENTS: dict[int, httpx.Client] = {}
_HTTP_CLIENTS_LOCK = threading.Lock()


def _close_http_clients() -> None:
    with _HTTP_CLIENTS_LOCK:
        clients = list(_HTTP_CLIENTS.values())
        _HTTP_CLIENTS.clear()
    for client in clients:
        client.close()


def _get_http_client() -> httpx.Client:
    thread_id = threading.get_ident()
    with _HTTP_CLIENTS_LOCK:
        client = _HTTP_CLIENTS.get(thread_id)
        if client is None:
            client = httpx.Client(timeout=_HTTP_TIMEOUT)
            _HTTP_CLIENTS[thread_id] = client
        return client


atexit.register(_close_http_clients)


def chat_completion(
    messages: list[dict[str, str]],
    model: str,
    base_url: str,
    max_tokens: int | None = None,
    status_callback: Callable[[str], None] | None = None,
) -> str:
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
