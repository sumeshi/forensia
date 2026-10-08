from __future__ import annotations

import re
from typing import Literal, TypedDict

LogLevel = Literal["debug", "info", "success", "warning", "error"]


class StructuredLog(TypedDict):
    tag: str
    level: LogLevel
    message: str


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
    """Print a label-prefixed log line.

    Kernel output is plain text so importing the kernel never requires a
    terminal library; producers keep classifying severity explicitly via
    ``level`` and that classification reaches durable projections through
    ``structure_progress_log``/DB progress records. Terminal rendering is an
    adapter concern.
    """
    normalized_message = re.sub(
        r"^\[([a-z][a-z0-9_-]*)\]",
        lambda match: f"[{match.group(1).upper()}]",
        str(message),
    )
    print(f"[{normalize_log_tag(tag)}] {normalized_message}")
