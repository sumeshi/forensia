from __future__ import annotations

from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB


def _duckdb_path_literal(path: Path) -> str:
    return path.as_posix().replace("'", "''")


def _build_timeline_stage_sql(path_sql: str) -> str:
    # prefetch2es timeline_mode emits ECS-shaped JSON; ingest enriches the records
    # with forensia-flat fields at the top level (timeline_id, evidence_id, etc.).
    return f"""
        CREATE OR REPLACE TEMP TABLE prefetch_timeline_stage AS
        WITH raw AS (
            SELECT json
            FROM read_ndjson_objects('{path_sql}')
        )
        SELECT
            json_extract_string(json, '$.timeline_id')      AS timeline_id,
            json_extract_string(json, '$.evidence_id')      AS evidence_id,
            json_extract_string(json, '$.executable_name')  AS executable_name,
            json_extract_string(json, '$.prefetch_hash')    AS prefetch_hash,
            try_cast(nullif(json_extract_string(json, '$.exec_time'), '') AS TIMESTAMP) AS exec_time,
            try_cast(nullif(json_extract_string(json, '$.exec_index'), '') AS INTEGER) AS exec_index,
            json_extract_string(json, '$.source_file')      AS source_file,
            CAST('[]' AS JSON)                              AS tags
        FROM raw
        WHERE json_extract_string(json, '$.timeline_id') IS NOT NULL
    """


def _insert_timeline_sql() -> str:
    return """
        INSERT INTO prefetch_timeline (
            timeline_id, evidence_id, executable_name, prefetch_hash,
            exec_time, exec_index, source_file, tags
        )
        SELECT
            timeline_id, evidence_id, executable_name, prefetch_hash,
            exec_time, exec_index, source_file, tags
        FROM prefetch_timeline_stage
    """


def _delete_existing_timeline_entries() -> str:
    return "DELETE FROM prefetch_timeline WHERE evidence_id IN (SELECT DISTINCT evidence_id FROM prefetch_timeline_stage WHERE evidence_id IS NOT NULL)"


def normalize_prefetch(case: Case, db: CaseDB) -> tuple[int, int]:
    inserted = 0
    for path in sorted(case.raw_dir.glob("prefetch-entries-*.jsonl")):
        source_file = db.execute(
            """
            SELECT json_extract_string(json, '$.source_file')
            FROM read_ndjson_objects(?)
            LIMIT 1
            """,
            (str(path),),
        ).fetchone()
        if source_file and source_file[0]:
            db.execute("DELETE FROM prefetch_executions WHERE source_file = ?", (source_file[0],))

        row_count = db.execute("SELECT COUNT(*) FROM read_ndjson_objects(?)", (str(path),)).fetchone()[0]
        db.execute(
            """
            INSERT INTO prefetch_executions (
                evidence_id, source_file, executable_name, exec_count,
                last_exec_time, exec_times, prefetch_hash,
                filenames, volumes, raw_json, tags, severity
            )
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
            FROM read_ndjson_objects(?)
            """,
            (str(path),),
        )
        inserted += int(row_count)

    total_timeline = 0
    for path in sorted(case.raw_dir.glob("prefetch-timeline-*.jsonl")):
        path_sql = _duckdb_path_literal(path)
        db.execute(_build_timeline_stage_sql(path_sql))
        db.execute(_delete_existing_timeline_entries())
        db.execute(_insert_timeline_sql())
        total_timeline += db.execute("SELECT COUNT(*) FROM prefetch_timeline_stage").fetchone()[0]

    return inserted, total_timeline
