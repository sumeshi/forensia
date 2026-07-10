from __future__ import annotations

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize.timeline_sql import (
    build_timeline_stage_sql,
    delete_existing_timeline_entries_sql,
    duckdb_path_literal,
    insert_timeline_sql,
)

_TIMELINE_COLUMNS: list[tuple[str, str]] = [
    ("timeline_id", "json_extract_string(json, '$.timeline_id')"),
    ("evidence_id", "json_extract_string(json, '$.evidence_id')"),
    (
        "record_number",
        "try_cast(nullif(json_extract_string(json, '$.record_number'), '') AS BIGINT)",
    ),
    ("file_path", "json_extract_string(json, '$.file_path')"),
    ("file_name", "json_extract_string(json, '$.file_name')"),
    (
        "timestamp",
        "try_cast(nullif(json_extract_string(json, '$.timestamp'), '') AS TIMESTAMP)",
    ),
    ("timestamp_type", "json_extract_string(json, '$.timestamp_type')"),
    ("source_file", "json_extract_string(json, '$.source_file')"),
]


def _build_stage_table_sql(path_sql: str) -> str:
    return f"""
            CREATE OR REPLACE TEMP TABLE mft_stage AS
            WITH raw AS (
                SELECT json
                FROM read_ndjson_objects('{path_sql}')
            )
            SELECT
                json_extract_string(json, '$.evidence_id') AS evidence_id,
                json_extract_string(json, '$.source_file') AS source_file,
                try_cast(nullif(json_extract_string(json, '$.header.record_number'), '') AS BIGINT) AS record_number,
                json_extract_string(json, '$.attributes.FileName.data.path') AS file_path,
                regexp_extract(json_extract_string(json, '$.attributes.FileName.data.path'), '[^/\\\\]+$') AS file_name,
                json_extract_string(json, '$.attributes.FileName.data.name') AS fn_name,
                nullif(
                    regexp_extract(
                        regexp_extract(json_extract_string(json, '$.attributes.FileName.data.path'), '[^/\\\\]+$'),
                        '\\.([^./]+)$',
                        1
                    ),
                    ''
                ) AS extension,
                CASE
                    WHEN json_extract(json, '$.header.is_directory') IS NULL THEN NULL
                    ELSE lower(coalesce(json_extract_string(json, '$.header.is_directory'), '')) IN ('1', 'true', 'yes')
                END AS is_directory,
                CASE
                    WHEN json_extract(json, '$.header.flags') IS NULL THEN NULL
                    ELSE lower(coalesce(json_extract_string(json, '$.header.flags'), '')) NOT LIKE '%allocated%'
                END AS is_deleted,
                try_cast(
                    nullif(
                        CASE
                            WHEN json_extract(json, '$.header.allocated_size') IS NULL THEN json_extract_string(json, '$.header.size')
                            WHEN json_type(json_extract(json, '$.header.allocated_size')) IN ('BIGINT', 'UBIGINT', 'DOUBLE')
                                AND try_cast(json_extract_string(json, '$.header.allocated_size') AS DOUBLE) = 0
                                THEN json_extract_string(json, '$.header.size')
                            ELSE json_extract_string(json, '$.header.allocated_size')
                        END,
                        ''
                    ) AS BIGINT
                ) AS size,
                try_cast(nullif(json_extract_string(json, '$.attributes.StandardInformation.data.created'), '') AS TIMESTAMP) AS si_created,
                try_cast(nullif(json_extract_string(json, '$.attributes.StandardInformation.data.modified'), '') AS TIMESTAMP) AS si_modified,
                try_cast(nullif(json_extract_string(json, '$.attributes.StandardInformation.data.accessed'), '') AS TIMESTAMP) AS si_accessed,
                try_cast(nullif(json_extract_string(json, '$.attributes.StandardInformation.data.mft_modified'), '') AS TIMESTAMP) AS si_mft_modified,
                try_cast(nullif(json_extract_string(json, '$.attributes.FileName.data.created'), '') AS TIMESTAMP) AS fn_created,
                try_cast(nullif(json_extract_string(json, '$.attributes.FileName.data.modified'), '') AS TIMESTAMP) AS fn_modified,
                try_cast(nullif(json_extract_string(json, '$.attributes.FileName.data.accessed'), '') AS TIMESTAMP) AS fn_accessed,
                try_cast(nullif(json_extract_string(json, '$.attributes.FileName.data.mft_modified'), '') AS TIMESTAMP) AS fn_mft_modified,
                json AS raw_json
            FROM raw
    """


def _delete_existing_entries_sql() -> str:
    return """
            DELETE FROM mft_entries
            WHERE source_file = (
                SELECT source_file
                FROM mft_stage
                WHERE source_file IS NOT NULL
                LIMIT 1
            )
    """


def _insert_entries_sql() -> str:
    return """
            INSERT INTO mft_entries (
                evidence_id, source_file, record_number, file_path, file_name, fn_name, extension,
                is_directory, is_deleted, size, si_created, si_modified, si_accessed,
                si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified,
                raw_json, tags, severity
            )
            SELECT
                evidence_id,
                source_file,
                record_number,
                file_path,
                file_name,
                fn_name,
                extension,
                is_directory,
                is_deleted,
                size,
                si_created,
                si_modified,
                si_accessed,
                si_mft_modified,
                fn_created,
                fn_modified,
                fn_accessed,
                fn_mft_modified,
                raw_json,
                CAST('[]' AS JSON),
                NULL
            FROM mft_stage
    """


def normalize_mft(case: Case, db: CaseDB) -> tuple[int, int]:
    entry_paths = sorted({*case.raw_dir.glob("mft-entries-*.jsonl")})
    timeline_paths = sorted({*case.raw_dir.glob("mft-timeline-*.jsonl")})
    if not entry_paths and not timeline_paths:
        return 0, 0
    total_entries = 0
    total_timeline = 0
    for path in entry_paths:
        path_sql = duckdb_path_literal(path)
        db.execute(_build_stage_table_sql(path_sql))
        db.execute(_delete_existing_entries_sql())
        db.execute(_insert_entries_sql())
        total_entries += db.execute("SELECT COUNT(*) FROM mft_stage").fetchone()[0]
    for path in timeline_paths:
        path_sql = duckdb_path_literal(path)
        db.execute(
            build_timeline_stage_sql("mft_timeline_stage", path_sql, _TIMELINE_COLUMNS)
        )
        db.execute(
            delete_existing_timeline_entries_sql("mft_timeline", "mft_timeline_stage")
        )
        db.execute(
            insert_timeline_sql(
                "mft_timeline",
                "mft_timeline_stage",
                [name for name, _ in _TIMELINE_COLUMNS],
            )
        )
        total_timeline += db.execute(
            "SELECT COUNT(*) FROM mft_timeline_stage"
        ).fetchone()[0]
    return total_entries, total_timeline
