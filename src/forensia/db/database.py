from __future__ import annotations

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
)

_CASE_CONNECTION_LOCKS: dict[str, threading.RLock] = {}
_CASE_CONNECTION_LOCKS_GUARD = threading.Lock()


def _case_connection_lock(case: Case) -> threading.RLock:
    key = str(case.database_path.resolve())
    with _CASE_CONNECTION_LOCKS_GUARD:
        return _CASE_CONNECTION_LOCKS.setdefault(key, threading.RLock())


class CaseDB:
    def __init__(self, case: Case, *, read_only: bool = False):
        """Open a current case or initialize a new case database."""
        self.case = case
        self.read_only = read_only
        self._connection_lock = _case_connection_lock(case)
        self._connection_lock.acquire()
        self._thread_connections = threading.local()
        self._cursors: list[duckdb.DuckDBPyConnection] = []
        self._closed = False
        conn = None
        try:
            database_exists = case.database_path.exists()
            legacy_trace_path = case.db_dir / "trace.duckdb"
            if legacy_trace_path.exists():
                raise ValueError(
                    "Unsupported split case databases; preserve the case and ingest "
                    "the original artifacts into a new case directory."
                )
            if read_only and not database_exists:
                raise FileNotFoundError(
                    f"Case database not found: {case.database_path}"
                )
            if not read_only:
                case.db_dir.mkdir(parents=True, exist_ok=True)
            conn = self._root_connection = duckdb.connect(
                str(case.database_path), read_only=read_only
            )
            if database_exists:
                self._check_schema_version(conn)
            if not database_exists:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("CREATE SCHEMA IF NOT EXISTS trace")
                conn.execute(CORE_SCHEMA_SQL)
                conn.execute(TRACE_SCHEMA_SQL)
                conn.execute("CREATE TABLE forensia_schema (version INTEGER NOT NULL)")
                conn.execute("INSERT INTO forensia_schema VALUES (?)", [SCHEMA_VERSION])
                conn.execute("COMMIT")
        except Exception:
            if conn is not None:
                conn.close()
            self._closed = True
            self._connection_lock.release()
            raise
        self._connection_lock.release()

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        """Each thread owns its result cursor; the case lock serializes writes."""
        with self._connection_lock:
            if self._closed:
                raise RuntimeError("CaseDB is closed")
            connection = getattr(self._thread_connections, "connection", None)
            if connection is None:
                connection = self._root_connection.cursor()
                self._thread_connections.connection = connection
                self._cursors.append(connection)
            return connection

    def _check_schema_version(self, conn: duckdb.DuckDBPyConnection) -> None:
        """Reject unsupported databases before executing any persistent DDL/DML."""
        try:
            versions = conn.execute("SELECT version FROM forensia_schema").fetchall()
        except duckdb.CatalogException:
            versions = []
        if versions != [(SCHEMA_VERSION,)]:
            raise ValueError(
                f"Unsupported case schema: {self.case.database_path} (expected {SCHEMA_VERSION}). "
                "Preserve the case and ingest the original artifacts into a new "
                "case directory; automatic migration is not supported."
            )

    def execute(
        self, query: str, params: Sequence[Any] | None = None
    ) -> duckdb.DuckDBPyConnection:
        """Execute SQL against the unified case database."""
        with self._connection_lock:
            if params is None:
                return self.conn.execute(query)
            return self.conn.execute(query, params)

    def insert_many(self, query: str, rows: Iterable[Sequence[Any]]) -> None:
        """Execute a parameterized INSERT for multiple rows using executemany."""
        rows = list(rows)
        if not rows:
            return
        if self.read_only:
            raise PermissionError("Cannot write through a read-only CaseDB")
        with self._connection_lock:
            self.conn.executemany(query, rows)

    @contextmanager
    def read_snapshot(self) -> Iterator[None]:
        """Keep a derived view consistent with one durable event position."""
        with self._connection_lock:
            yield

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit a group of writes atomically, rolling back on failure."""
        if self.read_only:
            raise PermissionError("Cannot write through a read-only CaseDB")
        with self._connection_lock:
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
        if self.read_only:
            raise PermissionError(
                "Cannot change write settings through a read-only CaseDB"
            )
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
        with self._connection_lock:
            if self._closed:
                return
            for cursor in self._cursors:
                cursor.close()
            self._root_connection.close()
            self._closed = True

    def __enter__(self) -> CaseDB:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
