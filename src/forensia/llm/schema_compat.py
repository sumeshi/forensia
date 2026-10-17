"""OpenAI-compatible response-schema negotiation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


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
    error_body: str,
) -> str | None:
    """Retry strict-schema rejection without strict mode, retaining the schema."""
    message = error_body.lower()
    explicitly_rejected_strict = (
        "strict" in message
        and ("schema" in message or "response_format" in message)
        and any(word in message for word in ("unsupported", "not supported", "reject"))
    )
    if json_schema is None or schema_mode != "strict" or not explicitly_rejected_strict:
        return None
    body["response_format"] = schema_response_format(json_schema, strict=False)
    if status_callback:
        status_callback(
            f"LLM server rejected strict json_schema ({status_code}); "
            "retrying with compatible json_schema"
        )
    return "compatible"
