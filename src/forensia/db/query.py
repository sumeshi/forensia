from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from forensia.db.database import CaseDB


def fetch_records(db: CaseDB, query: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]
