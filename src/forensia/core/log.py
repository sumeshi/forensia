from __future__ import annotations

import re
from typing import Literal, TypedDict

LogLevel = Literal["debug", "info", "success", "warning", "error"]

_LEVELS: set[str] = {"debug", "info", "success", "warning", "error"}


class StructuredLog(TypedDict):
    tag: str
    level: LogLevel
    message: str


def normalize_log_tag(tag: str | None) -> str:
    return str(tag or "ACTIVITY").strip().replace("-", "_").replace(" ", "_").upper()


def normalize_log_level(level: LogLevel | None) -> LogLevel:
    """Return the explicitly-decided level, falling back to neutral ``info``.

    Severity is a producer decision: a call site that observes a raised or
    caught exception passes ``warning``/``error`` deliberately. Persisted
    payloads never re-classify a message by the words it happens to contain,
    so names of evidence (e.g. a *failed-logon* rule id) cannot appear as a
    processing failure.
    """
    if level in _LEVELS:
        return level
    return "info"


def structure_progress_log(
    message: str, *, level: LogLevel | None = None
) -> StructuredLog:
    """Split a tagged progress line into the structured log entry.

    ``level`` is the producer's explicit decision; when omitted the entry is
    neutral ``info``.
    """
    text = str(message)
    match = re.match(r"^\[([a-z0-9_-]+)\]\s*", text, flags=re.IGNORECASE)
    tag = normalize_log_tag(match.group(1) if match else None)
    body = text[match.end() :] if match else text
    return {"tag": tag, "level": normalize_log_level(level), "message": body}


def format_progress_log(record: StructuredLog) -> str:
    """Render-time string form derived from a structured entry."""
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
