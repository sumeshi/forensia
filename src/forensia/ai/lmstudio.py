from __future__ import annotations

from collections.abc import Callable

import httpx

from forensia.config import get_llm_settings


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
    timeout = httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=30.0)
    try:
        with httpx.Client(timeout=timeout) as client:
            with client.stream(
                "POST",
                url,
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": 0,
                    "max_tokens": resolved_max_tokens,
                },
            ) as response:
                response.raise_for_status()
                payload = response.read()
    except httpx.ConnectTimeout as exc:
        raise RuntimeError(f"Timed out while connecting to LLM server: {url}") from exc
    except httpx.ReadTimeout as exc:
        raise RuntimeError(f"Connected to LLM server, but timed out waiting for model response: {model}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"LLM server request failed: {exc}") from exc
    data = httpx.Response(200, content=payload).json()
    return data["choices"][0]["message"]["content"]
