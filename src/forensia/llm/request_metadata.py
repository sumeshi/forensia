"""Pure helpers for bounded LLM request and prompt telemetry."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def is_context_window_error(status: int, body: str) -> bool:
    lowered = body.casefold()
    return status in {400, 413} and any(
        marker in lowered
        for marker in (
            "context length",
            "context window",
            "maximum context",
            "too many tokens",
            "prompt is too long",
        )
    )


def request_fingerprint(messages: list[dict[str, str]]) -> str:
    payload = json.dumps(
        messages, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def prompt_metadata(messages: list[dict[str, str]]) -> dict[str, Any]:
    """Summarize named prompt sections without persisting prompt bodies."""
    sections: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for message in messages:
        content = str(message.get("content") or "")
        for match in re.finditer(
            r"<([A-Z][A-Z0-9_:-]*)>(.*?)</\1>", content, flags=re.DOTALL
        ):
            tag, body = match.groups()
            sections.append(
                {
                    "name": tag,
                    "chars": len(body),
                    "tokens_estimate": max(1, len(body) // 4),
                }
            )
        selected_ids.update(
            re.findall(r"id=([A-Za-z0-9_.:-]+).*?\[SELECTED\]", content)
        )
    return {
        "message_count": len(messages),
        "sections": sections,
        "selected_ids": sorted(selected_ids),
        "input_chars": sum(len(str(item.get("content") or "")) for item in messages),
    }
