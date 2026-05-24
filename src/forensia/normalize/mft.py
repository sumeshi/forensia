from __future__ import annotations

from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB


def _duckdb_path_literal(path: Path) -> str:
    return path.as_posix().replace("'", "''")


def normalize_mft(case: Case, db: CaseDB) -> tuple[int, int]:
    paths = sorted({*case.raw_dir.glob("mft.jsonl"), *case.raw_dir.glob("mft-*.jsonl")})
    if not paths:
        return 0, 0

    total_entries = 0
    total_timeline = 0
    for path in paths:
        path_sql = _duckdb_path_literal(path)
        db.execute(
            f"""
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
                    WHEN json_extract(json, '$.header.is_deleted') IS NULL THEN NULL
                    ELSE lower(coalesce(json_extract_string(json, '$.header.is_deleted'), '')) IN ('1', 'true', 'yes')
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
        )
        db.execute(
            """
            CREATE OR REPLACE TEMP TABLE mft_stage_timeline AS
            SELECT
                coalesce(evidence_id, 'None') || '-' || lower(timestamp_type) AS timeline_id,
                evidence_id,
                record_number,
                file_path,
                timestamp,
                timestamp_type,
                timestamp_type || ' for ' || coalesce(file_path, file_name, 'unknown') AS description,
                CAST('[]' AS JSON) AS tags
            FROM (
                SELECT evidence_id, record_number, file_path, file_name, si_created AS timestamp, 'SI_CREATED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, si_modified AS timestamp, 'SI_MODIFIED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, si_accessed AS timestamp, 'SI_ACCESSED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, si_mft_modified AS timestamp, 'SI_MFT_MODIFIED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, fn_created AS timestamp, 'FN_CREATED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, fn_modified AS timestamp, 'FN_MODIFIED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, fn_accessed AS timestamp, 'FN_ACCESSED' AS timestamp_type
                FROM mft_stage
                UNION ALL
                SELECT evidence_id, record_number, file_path, file_name, fn_mft_modified AS timestamp, 'FN_MFT_MODIFIED' AS timestamp_type
                FROM mft_stage
            ) AS expanded
            WHERE timestamp IS NOT NULL
            """
        )

        db.execute(
            """
            DELETE FROM mft_entries
            WHERE source_file = (
                SELECT source_file
                FROM mft_stage
                WHERE source_file IS NOT NULL
                LIMIT 1
            )
            """
        )
        db.execute(
            """
            DELETE FROM mft_timeline
            WHERE evidence_id IN (
                SELECT DISTINCT evidence_id
                FROM mft_stage
                WHERE evidence_id IS NOT NULL AND evidence_id <> ''
            )
            """
        )

        db.execute(
            """
            INSERT INTO mft_entries (
                evidence_id, source_file, record_number, file_path, file_name, extension,
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
        )
        db.execute(
            """
            INSERT INTO mft_timeline (
                timeline_id, evidence_id, record_number, file_path, timestamp,
                timestamp_type, description, tags
            )
            SELECT
                timeline_id,
                evidence_id,
                record_number,
                file_path,
                timestamp,
                timestamp_type,
                description,
                tags
            FROM mft_stage_timeline
            """
        )

        total_entries += db.execute("SELECT COUNT(*) FROM mft_stage").fetchone()[0]
        total_timeline += db.execute("SELECT COUNT(*) FROM mft_stage_timeline").fetchone()[0]
    return total_entries, total_timeline
