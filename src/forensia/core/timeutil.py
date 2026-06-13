from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp value into a naive datetime (no tzinfo).

    Accepts:
    - ISO-8601 strings (with T, Z, +offset, or space-separated)
    - datetime objects (converted to naive)
    - float/int (treated as Unix epoch seconds -> UTC naive)
    - Strings that are float/int representations
    Returns None for empty/None/invalid input.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC).replace(tzinfo=None)
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    if not text:
        return None
    # Try ISO format first (handles Z, +offset, T)
    try:
        dt = datetime.fromisoformat(text)
        return dt.replace(tzinfo=None)
    except ValueError, TypeError:
        pass
    # Try float string
    try:
        return datetime.fromtimestamp(float(text), tz=UTC).replace(tzinfo=None)
    except ValueError, TypeError:
        pass
    # Try YYYY-MM-DD HH:MM:SS after stripping T/Z/offset
    try:
        cleaned = (
            text.replace("T", " ").split("+")[0].split("Z")[0].split(".")[0].strip()
        )
        return datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S")
    except ValueError, TypeError:
        return None


def parse_epoch_seconds(value: Any) -> float | None:
    """Parse a timestamp value to Unix epoch seconds (float).

    This preserves the return type of checker._parse_timestamp for callers
    that need epoch seconds.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError, TypeError:
        try:
            return float(text)
        except ValueError, TypeError:
            return None
