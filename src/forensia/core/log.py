from __future__ import annotations

import re
import sys
from typing import Literal

LogLevel = Literal["debug", "info", "success", "warning", "error"]
_LEVELS = {"debug", "info", "success", "warning", "error"}


def normalize_log_tag(tag: str | None) -> str:
    return str(tag or "ACTIVITY").strip().replace("-", "_").replace(" ", "_").upper()


def log(tag: str, message: str, *, level: LogLevel | None = None) -> None:
    """Print a plain display message; durable events use core.progress_event."""
    normalized_message = re.sub(
        r"^\[([a-z][a-z0-9_-]*)\]",
        lambda match: f"[{match.group(1).upper()}]",
        str(message),
    )
    severity = level if level in _LEVELS else "info"
    output = f"[{normalize_log_tag(tag)}] [{severity.upper()}] {normalized_message}"
    encoding = getattr(sys.stdout, "encoding", None)
    if encoding:
        try:
            output.encode(encoding)
        except UnicodeEncodeError:
            output = output.encode(encoding, errors="backslashreplace").decode(encoding)
    print(output)
