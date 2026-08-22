"""Task-local completion metadata and bounded discarded-output diagnostics."""

from __future__ import annotations

import hashlib
import json
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CompletionMetadata:
    input_tokens: int
    output_tokens: int
    usage_source: str
    finish_reason: str
    latency_ms: int


_LAST_COMPLETION_METADATA: ContextVar[CompletionMetadata | None] = ContextVar(
    "last_llm_completion_metadata", default=None
)


def get_last_completion_metadata() -> CompletionMetadata | None:
    """Return task-local metadata for the most recent completion."""
    return _LAST_COMPLETION_METADATA.get()


def record_completion_metadata(
    *,
    data: dict[str, Any],
    messages: list[dict[str, str]],
    content: str,
    finish_reason: Any,
    started_at: float,
) -> None:
    """Record provider usage, falling back to a local character estimate."""
    usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    raw_input = usage.get("prompt_tokens", usage.get("input_tokens"))
    raw_output = usage.get("completion_tokens", usage.get("output_tokens"))
    measured = isinstance(raw_input, int) and isinstance(raw_output, int)
    input_tokens = (
        int(raw_input)
        if isinstance(raw_input, int)
        else max(1, sum(len(item.get("content", "")) for item in messages) // 4)
    )
    output_tokens = (
        int(raw_output) if isinstance(raw_output, int) else max(1, len(content) // 4)
    )
    _LAST_COMPLETION_METADATA.set(
        CompletionMetadata(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            usage_source="provider_actual" if measured else "local_estimate",
            finish_reason=str(finish_reason or "unknown"),
            latency_ms=max(0, int((time.monotonic() - started_at) * 1000)),
        )
    )


def is_complete_json_object(content: str) -> bool:
    """Return whether a length-finished response still contains one full object."""
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    first = text.find("{")
    last = text.rfind("}")
    if first < 0 or last <= first:
        return False
    try:
        return isinstance(json.loads(text[first : last + 1]), dict)
    except (json.JSONDecodeError, TypeError):
        return False


def discarded_output_summary(content: str, reasoning_len: int) -> str:
    """Keep a bounded diagnostic preview for unusable provider output."""
    flattened = " ".join(content.split())
    head = flattened[:300]
    tail = flattened[-120:] if len(flattened) > 300 else ""
    return (
        f"reasoning_chars={reasoning_len}; content_head={head!r}; content_tail={tail!r}"
    )


def response_fingerprint(content: str) -> str:
    """Return a stable digest for detecting repeated provider output."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:24]
