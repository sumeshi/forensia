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
        """Connect to the case DuckDB database, attach trace DB, and initialize schema."""
        self.case = case
        self.case.db_dir.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(case.database_path))
        self.conn.execute(f"ATTACH '{case.trace_database_path.as_posix()}' AS trace")
        self.init_schema()

    def init_schema(self) -> None:
        """Apply core and trace schema SQL, then run pending migrations."""
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
        self._apply_migration_once("investigation_steps_hypothesis_id", self._apply_investigation_steps_hypothesis_id)

    def _apply_migration_once(self, migration_key: str, callback: Callable[[], None]) -> None:
        """Execute a migration callback only if it has not been applied before."""
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
        """Backfill legacy columns for evtx_events and migrate old status/verdict values."""
        self.conn.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack JSON")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'draft'")
        self.conn.execute("ALTER TABLE report_sections ADD COLUMN IF NOT EXISTS update_count INTEGER DEFAULT 0")
        for column_name, column_type in (
            ("dst_ip", "VARCHAR"),
            ("dst_port", "VARCHAR"),
            ("protocol", "VARCHAR"),
            ("process_id", "VARCHAR"),
            ("exception_code", "VARCHAR"),
            ("object_dn", "VARCHAR"),
            ("attribute", "VARCHAR"),
            ("target_server", "VARCHAR"),
            ("target_group", "VARCHAR"),
            ("task_name", "VARCHAR"),
            ("session_id", "VARCHAR"),
            ("share_name", "VARCHAR"),
            ("access_mask", "VARCHAR"),
            ("normalized_src_ip", "VARCHAR"),
            ("normalized_target_user", "VARCHAR"),
            ("parent_process", "VARCHAR"),
            ("parent_process_id", "VARCHAR"),
            ("parent_cmd", "VARCHAR"),
            ("child_process", "VARCHAR"),
            ("child_process_id", "VARCHAR"),
            ("child_cmd", "VARCHAR"),
            ("parent_guid", "VARCHAR"),
            ("child_guid", "VARCHAR"),
            ("clear_time", "TIMESTAMP"),
            ("clear_event_id", "INTEGER"),
            ("reason", "VARCHAR"),
        ):
            self.conn.execute(f"ALTER TABLE evtx_events ADD COLUMN IF NOT EXISTS {column_name} {column_type}")
        self.conn.execute("UPDATE report_sections SET status = 'ai_exhausted' WHERE status = 'approved'")
        legacy_verdict = "new" + "_finding"
        self.conn.execute("UPDATE trace.ai_reviews SET verdict = 'newlead' WHERE verdict = ?", (legacy_verdict,))
        self.conn.execute("UPDATE hypotheses SET verdict = 'newlead' WHERE verdict = ?", (legacy_verdict,))

    def _apply_investigation_steps_hypothesis_id(self) -> None:
        """Add hypothesis_id column to the investigation_steps trace table."""
        self.conn.execute("ALTER TABLE trace.investigation_steps ADD COLUMN IF NOT EXISTS hypothesis_id VARCHAR")

    def _route_trace_write(self, query: str) -> str:
        """Rewrite unqualified INSERT/UPDATE/DELETE to use the trace schema prefix."""
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
        """Execute a SQL query, routing trace writes automatically."""
        routed_query = self._route_trace_write(query)
        if params is None:
            return self.conn.execute(routed_query)
        return self.conn.execute(routed_query, params)

    def insert_many(self, query: str, rows: Iterable[Sequence[Any]]) -> None:
        """Execute a parameterized INSERT for multiple rows using executemany."""
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
