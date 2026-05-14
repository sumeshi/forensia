from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
import re
from typing import Any

import duckdb

from forensia.core.case import Case
from forensia.db.schema import CORE_SCHEMA_SQL, TRACE_SCHEMA_SQL, TRACE_TABLES


class CaseDB:
    def __init__(self, case: Case):
        self.case = case
        self.case.db_dir.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(case.database_path))
        self.conn.execute(f"ATTACH '{case.trace_database_path.as_posix()}' AS trace")
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.execute(CORE_SCHEMA_SQL)
        self.conn.execute(TRACE_SCHEMA_SQL)
        for table_name in sorted(TRACE_TABLES):
            self.conn.execute(f"CREATE OR REPLACE TEMP VIEW {table_name} AS SELECT * FROM trace.{table_name}")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_key VARCHAR PRIMARY KEY,
                applied_at TIMESTAMP
            )
            """
        )
        self._apply_migration_once("legacy_schema_backfill", self._apply_legacy_schema_backfill)

    def _apply_migration_once(self, migration_key: str, callback: Callable[[], None]) -> None:
        existing = self.conn.execute(
            "SELECT 1 FROM schema_migrations WHERE migration_key = ? LIMIT 1",
            (migration_key,),
        ).fetchone()
        if existing is not None:
            return
        callback()
        self.conn.execute(
            "INSERT INTO schema_migrations (migration_key, applied_at) VALUES (?, now())",
            (migration_key,),
        )

    def _apply_legacy_schema_backfill(self) -> None:
        self.conn.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack JSON")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'draft'")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS update_count INTEGER DEFAULT 0")
        self.conn.execute("UPDATE report_sections SET status = 'ai_exhausted' WHERE status = 'approved'")
        legacy_verdict = "new" + "_finding"
        self.conn.execute("UPDATE trace.ai_reviews SET verdict = 'newlead' WHERE verdict = ?", (legacy_verdict,))
        self.conn.execute("UPDATE hypotheses SET verdict = 'newlead' WHERE verdict = ?", (legacy_verdict,))

    def _route_trace_write(self, query: str) -> str:
        stripped = query.lstrip()
        lowered = stripped.lower()
        if not lowered.startswith(("insert", "update", "delete")):
            return query
        for prefix in ("insert into ", "update ", "delete from "):
            if not lowered.startswith(prefix):
                continue
            for table_name in TRACE_TABLES:
                pattern = rf"(?i)\b{prefix.strip()}\s+{table_name}\b"
                if re.search(pattern, stripped):
                    return re.sub(
                        rf"(?i)\b{table_name}\b",
                        f"trace.{table_name}",
                        stripped,
                        count=1,
                    )
        return query

    def execute(self, query: str, params: Sequence[Any] | None = None) -> duckdb.DuckDBPyConnection:
        routed_query = self._route_trace_write(query)
        if params is None:
            return self.conn.execute(routed_query)
        return self.conn.execute(routed_query, params)

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
