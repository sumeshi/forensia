"""OpenAI-compatible response-schema negotiation and per-endpoint downgrade cache."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

_SCHEMA_MODE_CACHE: dict[str, str] = {}
_SCHEMA_MODE_RANK = {"strict": 2, "compatible": 1, "none": 0}


def initial_schema_mode(base_url: str) -> str:
    return _SCHEMA_MODE_CACHE.get(base_url, "strict")


def _remember_schema_mode(base_url: str, mode: str) -> None:
    current = _SCHEMA_MODE_CACHE.get(base_url, "strict")
    if _SCHEMA_MODE_RANK[mode] < _SCHEMA_MODE_RANK[current]:
        _SCHEMA_MODE_CACHE[base_url] = mode


def schema_response_format(json_schema: dict, *, strict: bool) -> dict[str, Any]:
    """Build llama-server/OpenAI-compatible JSON schema response_format."""
    schema_payload: dict[str, Any] = {
        "name": json_schema.get("title", "Output"),
        "schema": json_schema,
    }
    if strict:
        schema_payload["strict"] = True
    return {"type": "json_schema", "json_schema": schema_payload}


def downgrade_schema_mode(
    body: dict[str, Any],
    json_schema: dict | None,
    schema_mode: str,
    status_callback: Callable[[str], None] | None,
    *,
    status_code: int,
    base_url: str,
) -> str | None:
    """Downgrade response_format only as far as required for compatibility."""
    if not json_schema or schema_mode == "none":
        return None
    if schema_mode == "strict":
        body["response_format"] = schema_response_format(json_schema, strict=False)
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
