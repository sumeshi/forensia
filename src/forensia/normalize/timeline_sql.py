"""Shared SQL builders for artifact timeline ingestion (prefetch, MFT).

The *2es tools' timeline_mode emits ECS-shaped JSON; ingest enriches the
records with forensia-flat fields at the top level (timeline_id,
evidence_id, etc.). Each artifact stages rows into a temp table, deletes
previously ingested rows for the same evidence, then inserts.
"""

from __future__ import annotations

from pathlib import Path


def duckdb_path_literal(path: Path) -> str:
    """Escape a filesystem path for embedding in a DuckDB string literal."""
    return path.as_posix().replace("'", "''")


def build_timeline_stage_sql(
    stage_table: str,
    path_sql: str,
    columns: list[tuple[str, str]],
) -> str:
    """Return SQL creating `stage_table` from an ndjson file.

    `columns` is a list of (column_name, select_expression) pairs.
    """
    select_lines = ",\n".join(
        f"            {expr} AS {name}" for name, expr in columns
    )
    return f"""
        CREATE OR REPLACE TEMP TABLE {stage_table} AS
        WITH raw AS (
            SELECT json
            FROM read_ndjson_objects('{path_sql}')
        )
        SELECT
{select_lines}
        FROM raw
        WHERE json_extract_string(json, '$.timeline_id') IS NOT NULL
    """


def insert_timeline_sql(
    target_table: str,
    stage_table: str,
    column_names: list[str],
) -> str:
    """Return SQL copying all staged rows into `target_table`."""
    cols = ", ".join(column_names)
    return f"""
        INSERT INTO {target_table} (
            {cols}
        )
        SELECT
            {cols}
        FROM {stage_table}
    """


def delete_existing_timeline_entries_sql(
    target_table: str,
    stage_table: str,
) -> str:
    """Return SQL removing rows for evidence that is being re-ingested."""
    return (
        f"DELETE FROM {target_table} WHERE evidence_id IN "
        f"(SELECT DISTINCT evidence_id FROM {stage_table} "
        "WHERE evidence_id IS NOT NULL)"
    )
