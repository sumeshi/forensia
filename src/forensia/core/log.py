from __future__ import annotations

import re
from typing import Literal, TypedDict

from rich import print as _rich_print
from rich.markup import escape

LogLevel = Literal["debug", "info", "success", "warning", "error"]


class StructuredLog(TypedDict):
    tag: str
    level: LogLevel
    message: str


# Colors encode outcome/severity, not arbitrary pipeline phases.
_LEVEL_STYLES: dict[LogLevel, str] = {
    "debug": "dim white",
    "info": "bold blue",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
}
_DEFAULT_TAG_LEVELS: dict[str, LogLevel] = {
    "RESOLVE": "success",
    "FALLBACK": "warning",
    "CAP": "error",
    "MEMORY": "debug",
}


def normalize_log_tag(tag: str | None) -> str:
    return str(tag or "ACTIVITY").strip().replace("-", "_").replace(" ", "_").upper()


def infer_log_level(tag: str, message: str) -> LogLevel:
    """Infer outcome severity once for persisted progress logs."""
    text = message.casefold()
    if re.search(r"\b(error|failed|failure|fatal|exception)\b", text):
        return "error"
    if re.search(
        r"\b(warn|warning|unresolved|skipped|fallback|inconclusive|blocked|retry)\b",
        text,
    ):
        return "warning"
    if (
        re.search(r"\b(done|completed|resolved|confirmed|written|success)\b", text)
        or "publishable=true" in text
    ):
        return "success"
    return _DEFAULT_TAG_LEVELS.get(tag, "info")


def structure_progress_log(message: str) -> StructuredLog:
    """Parse a legacy labelled string into the canonical progress-log shape."""
    text = str(message)
    match = re.match(r"^\[([a-z0-9_-]+)\]\s*", text, flags=re.IGNORECASE)
    tag = normalize_log_tag(match.group(1) if match else None)
    body = text[match.end() :] if match else text
    return {"tag": tag, "level": infer_log_level(tag, body), "message": body}


def format_progress_log(record: StructuredLog) -> str:
    """Keep the legacy string representation for backward-compatible clients."""
    return f"[{record['tag']}] {record['message']}"


def log(tag: str, message: str, *, level: LogLevel | None = None) -> None:
    """Print a consistently labelled, severity-colored log message."""
    normalized_tag = normalize_log_tag(tag)
    resolved_level = level or infer_log_level(normalized_tag, str(message))
    style = _LEVEL_STYLES[resolved_level]
    label = escape(f"[{normalized_tag}]")
    normalized_message = re.sub(
        r"^\[([a-z][a-z0-9_-]*)\]",
        lambda match: f"[{match.group(1).upper()}]",
        str(message),
    )
    _rich_print(f"[{style}]{label}[/{style}] {escape(normalized_message)}")
