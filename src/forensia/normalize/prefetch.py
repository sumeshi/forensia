from __future__ import annotations

from collections.abc import Collection

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize import select_source_paths
from forensia.normalize.timeline_sql import (
    build_timeline_stage_sql,
    delete_existing_timeline_entries_sql,
    duckdb_path_literal,
    insert_timeline_sql,
)

_TIMELINE_COLUMNS: list[tuple[str, str]] = [
    ("timeline_id", "json_extract_string(json, '$.timeline_id')"),
    ("evidence_id", "json_extract_string(json, '$.evidence_id')"),
    ("executable_name", "json_extract_string(json, '$.executable_name')"),
    ("prefetch_hash", "json_extract_string(json, '$.prefetch_hash')"),
    (
        "exec_time",
        "try_cast(nullif(json_extract_string(json, '$.exec_time'), '') AS TIMESTAMP)",
    ),
    (
        "exec_index",
        "try_cast(nullif(json_extract_string(json, '$.exec_index'), '') AS INTEGER)",
    ),
    ("source_file", "json_extract_string(json, '$.source_file')"),
    ("tags", "CAST('[]' AS JSON)"),
]


def normalize_prefetch(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> tuple[int, int]:
    inserted = 0
    entry_paths = select_source_paths(
        case.raw_dir.glob("prefetch-entries-*.jsonl"), source_keys
    )
    for path in entry_paths:
        path_sql = duckdb_path_literal(path)
        db.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE prefetch_execution_stage AS
            SELECT
                json_extract_string(json, '$.evidence_id')            AS evidence_id,
                json_extract_string(json, '$.source_file')            AS source_file,
                json_extract_string(json, '$.name')                   AS executable_name,
                TRY_CAST(json_extract_string(json, '$.exec_count') AS INTEGER) AS exec_count,
                TRY_CAST(json_extract_string(json, '$.last_exec_times[0]') AS TIMESTAMP) AS last_exec_time,
                json_extract(json, '$.last_exec_times')               AS exec_times,
                json_extract_string(json, '$.prefetch_hash')          AS prefetch_hash,
                json_extract(json, '$.filenames')                     AS filenames,
                json_extract(json, '$.volumes')                       AS volumes,
                json                                                   AS raw_json,
                json_extract(json, '$.tags')                          AS tags,
                NULL                                                   AS severity
            FROM read_ndjson_objects('{path_sql}')
            """
        )
        row_count = int(
            db.execute("SELECT COUNT(*) FROM prefetch_execution_stage").fetchone()[0]
        )
        if row_count == 0:
            continue
        with db.transaction():
            db.execute(
                """
                DELETE FROM prefetch_executions
                WHERE source_file IN (
                    SELECT DISTINCT source_file
                    FROM prefetch_execution_stage
                    WHERE source_file IS NOT NULL
                )
                """
            )
            db.execute(
                """
                INSERT INTO prefetch_executions (
                    evidence_id, source_file, executable_name, exec_count,
                    last_exec_time, exec_times, prefetch_hash,
                    filenames, volumes, raw_json, tags, severity
                )
                SELECT * FROM prefetch_execution_stage
                """
            )
        inserted += row_count

    total_timeline = 0
    timeline_paths = select_source_paths(
        case.raw_dir.glob("prefetch-timeline-*.jsonl"), source_keys
    )
    for path in timeline_paths:
        path_sql = duckdb_path_literal(path)
        db.execute(
            build_timeline_stage_sql(
                "prefetch_timeline_stage", path_sql, _TIMELINE_COLUMNS
            )
        )
        with db.transaction():
            db.execute(
                delete_existing_timeline_entries_sql(
                    "prefetch_timeline", "prefetch_timeline_stage"
                )
            )
            db.execute(
                insert_timeline_sql(
                    "prefetch_timeline",
                    "prefetch_timeline_stage",
                    [name for name, _ in _TIMELINE_COLUMNS],
                )
            )
            total_timeline += db.execute(
                "SELECT COUNT(*) FROM prefetch_timeline_stage"
            ).fetchone()[0]

    return inserted, total_timeline
