from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import duckdb

from forensia.core.case import Case
from forensia.db.schema import SCHEMA_SQL


class CaseDB:
    def __init__(self, case: Case):
        self.case = case
        self.case.db_dir.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(case.database_path))
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.execute(SCHEMA_SQL)
        self.conn.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack JSON")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'draft'")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS update_count INTEGER DEFAULT 0")

    def execute(self, query: str, params: Sequence[Any] | None = None) -> duckdb.DuckDBPyConnection:
        if params is None:
            return self.conn.execute(query)
        return self.conn.execute(query, params)

    def insert_many(self, query: str, rows: Iterable[Sequence[Any]]) -> None:
        rows = list(rows)
        if not rows:
            return
        self.conn.executemany(query, rows)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CaseDB":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
