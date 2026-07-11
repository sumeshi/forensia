from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from forensia.db.database import CaseDB


def fetch_records(
    db: CaseDB, query: str, params: Sequence[Any] | None = None
) -> list[dict[str, Any]]:
    """Execute a query and return results as a list of dicts (column name → value)."""
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def normalize_value(value: Any) -> Any:
    """Normalize database values: JSON-parse stringified JSON, ISO-format datetimes, recurse into lists/dicts."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize_value(item) for key, item in value.items()}
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                return normalize_value(json.loads(stripped))
            except json.JSONDecodeError:
                return value
    return value
