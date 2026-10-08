from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import duckdb

from forensia.core.case import Case
from forensia.db.schema import (
    CORE_SCHEMA_SQL,
    SCHEMA_VERSION,
    TRACE_SCHEMA_SQL,
    TRACE_TABLES,
)

_CASE_CONNECTION_LOCKS: dict[str, threading.RLock] = {}
_CASE_CONNECTION_LOCKS_GUARD = threading.Lock()


def _case_connection_lock(case: Case) -> threading.RLock:
    key = str(case.database_path.resolve())
    with _CASE_CONNECTION_LOCKS_GUARD:
        return _CASE_CONNECTION_LOCKS.setdefault(key, threading.RLock())


class CaseDB:
    def __init__(self, case: Case):
        """Open a current case or initialize a new core/trace pair."""
        self.case = case
        self._connection_lock = _case_connection_lock(case)
        self._connection_lock.acquire()
        self._closed = False
        conn = None
        try:
            core_exists = case.database_path.exists()
            trace_exists = case.trace_database_path.exists()
            if core_exists != trace_exists:
                raise ValueError(
                    "Incomplete case database pair; preserve the case and ingest "
                    "the original artifacts into a new case directory."
                )
            case.db_dir.mkdir(parents=True, exist_ok=True)
            conn = self.conn = duckdb.connect(str(case.database_path))
            if core_exists:
                self._check_schema_version("main")
            trace_path = case.trace_database_path.as_posix().replace("'", "''")
            conn.execute(f"ATTACH '{trace_path}' AS trace")
            if trace_exists:
                self._check_schema_version("trace")
            else:
                conn.execute(CORE_SCHEMA_SQL)
                conn.execute(TRACE_SCHEMA_SQL)
                for catalog in ("trace", "main"):
                    conn.execute(
                        f"CREATE TABLE {catalog}.forensia_schema (version INTEGER NOT NULL)"
                    )
                    conn.execute(
                        f"INSERT INTO {catalog}.forensia_schema VALUES (?)",
                        [SCHEMA_VERSION],
                    )
            for table_name in sorted(TRACE_TABLES):
                conn.execute(
                    f"CREATE TEMP VIEW {table_name} AS SELECT * FROM trace.{table_name}"
                )
        except Exception:
            if conn is not None:
                conn.close()
            self._closed = True
            self._connection_lock.release()
            raise

    def _check_schema_version(self, catalog: str) -> None:
        """Reject unsupported databases before executing any persistent DDL/DML."""
        try:
            versions = self.conn.execute(
                f"SELECT version FROM {catalog}.forensia_schema"
            ).fetchall()
        except duckdb.CatalogException:
            versions = []
        if versions != [(SCHEMA_VERSION,)]:
            path = (
                self.case.trace_database_path
                if catalog == "trace"
                else self.case.database_path
            )
            raise ValueError(
                f"Unsupported case schema: {path} (expected {SCHEMA_VERSION}). "
                "Preserve the case and ingest the original artifacts into a new "
                "case directory; automatic migration is not supported."
            )

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

    def execute(
        self, query: str, params: Sequence[Any] | None = None
    ) -> duckdb.DuckDBPyConnection:
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

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit a group of writes atomically, rolling back on failure."""
        self.conn.execute("BEGIN TRANSACTION")
        try:
            yield
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    @contextmanager
    def bulk_load_mode(self) -> Iterator[None]:
        """Bound memory during wide JSON loads, then restore connection settings."""
        previous_threads = int(
            self.conn.execute("SELECT current_setting('threads')").fetchone()[0]
        )
        previous_order = bool(
            self.conn.execute(
                "SELECT current_setting('preserve_insertion_order')"
            ).fetchone()[0]
        )
        self.conn.execute("SET threads = 1")
        self.conn.execute("SET preserve_insertion_order = false")
        try:
            yield
        finally:
            self.conn.execute(f"SET threads = {previous_threads}")
            self.conn.execute(
                "SET preserve_insertion_order = "
                + ("true" if previous_order else "false")
            )

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.conn.close()
        finally:
            self._closed = True
            self._connection_lock.release()

    def __enter__(self) -> CaseDB:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
