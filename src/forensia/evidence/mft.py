from __future__ import annotations

from collections.abc import Callable, Collection
from pathlib import Path

from mft2es.presenters.Mft2jsonPresenter import Mft2jsonPresenter

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.jsonl import duckdb_path_literal, export_jsonl, raw_source_hash
from forensia.evidence.normalize import select_source_paths


def ingest_mft_file(
    case: Case,
    mft_path: str | Path,
    source_sha: str,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """Write native MFT parser JSONL unchanged, publishing only complete output."""
    mft_path = Path(mft_path)
    entries_path = case.raw_dir / f"mft-entries-{source_sha}.jsonl"
    if progress_callback:
        progress_callback(f"Parsing MFT records from {mft_path}")
    export_jsonl(
        Mft2jsonPresenter,
        mft_path,
        entries_path,
        multiprocess=False,
        chunk_size=500,
        timeline_mode=False,
    )
    if progress_callback:
        progress_callback(f"Wrote JSONL: {entries_path}")
    return entries_path


def _build_entries_select_sql(path_sql: str, source_sha: str) -> str:
    return f"""
            WITH raw AS (SELECT json FROM read_ndjson_objects('{path_sql}'))
            SELECT
                'mft-' || '{source_sha}' || '-' ||
                    printf('%012d', coalesce(try_cast(json_extract_string(json, '$.header.record_number') AS BIGINT), error('MFT record_number missing or invalid'))) || '-' ||
                    printf('%02d', coalesce(try_cast(json_extract_string(json, '$.header.sequence') AS INTEGER), error('MFT sequence missing or invalid'))) AS evidence_id,
                '{source_sha}' AS source_file,
                try_cast(nullif(json_extract_string(json, '$.header.record_number'), '') AS BIGINT) AS record_number,
                json_extract_string(json, '$.attributes.FileName.data.path') AS file_path,
                regexp_extract(json_extract_string(json, '$.attributes.FileName.data.path'), '[^/\\\\]+$') AS file_name,
                json_extract_string(json, '$.attributes.FileName.data.name') AS fn_name,
                nullif(regexp_extract(regexp_extract(json_extract_string(json, '$.attributes.FileName.data.path'), '[^/\\\\]+$'), '\\.([^./]+)$', 1), '') AS extension,
                CASE WHEN json_extract(json, '$.header.flags') IS NULL THEN NULL
                    ELSE regexp_matches(json_extract_string(json, '$.header.flags'), '(^|[^A-Z_])INDEX_PRESENT([^A-Z_]|$)') END AS is_directory,
                CASE WHEN json_extract(json, '$.header.flags') IS NULL THEN NULL
                    ELSE NOT regexp_matches(json_extract_string(json, '$.header.flags'), '(^|[^A-Z_])ALLOCATED([^A-Z_]|$)') END AS is_deleted,
                try_cast(json_extract_string(json, '$.attributes.FileName.data.logical_size') AS BIGINT) AS size,
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


def _insert_entries_sql(path_sql: str, source_sha: str) -> str:
    return f"""
        INSERT INTO mft_entries (
            evidence_id, source_file, record_number, file_path, file_name, fn_name, extension,
            is_directory, is_deleted, size, si_created, si_modified, si_accessed,
            si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified,
            raw_json, tags, severity
        )
        SELECT evidence_id, source_file, record_number, file_path, file_name, fn_name, extension,
            is_directory, is_deleted, size, si_created, si_modified, si_accessed,
            si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified,
            raw_json, CAST('[]' AS JSON), NULL
        FROM ({_build_entries_select_sql(path_sql, source_sha)}) AS projected_entries
    """


def _insert_timeline_from_entries(db: CaseDB, source_file: str) -> int:
    db.execute(
        """
        INSERT INTO mft_timeline (
            timeline_id, evidence_id, record_number, file_path, file_name,
            timestamp, timestamp_type, source_file, description, tags
        )
        SELECT evidence_id || '-' || timestamp_type, evidence_id, record_number, file_path,
            file_name, timestamp, timestamp_type, source_file, NULL, CAST('[]' AS JSON)
        FROM mft_entries
        CROSS JOIN LATERAL (VALUES
            ('SI_CREATED', si_created), ('SI_MODIFIED', si_modified),
            ('SI_ACCESSED', si_accessed), ('SI_MFT_MODIFIED', si_mft_modified),
            ('FN_CREATED', fn_created), ('FN_MODIFIED', fn_modified),
            ('FN_ACCESSED', fn_accessed), ('FN_MFT_MODIFIED', fn_mft_modified)
        ) AS timestamps(timestamp_type, timestamp)
        WHERE source_file = ? AND timestamp IS NOT NULL
    """,
        (source_file,),
    )
    return int(
        db.execute(
            "SELECT COUNT(*) FROM mft_timeline WHERE source_file = ?", (source_file,)
        ).fetchone()[0]
    )


def _normalize_mft_selected(
    case: Case, db: CaseDB, source_keys: Collection[str] | None = None
) -> tuple[int, int]:
    paths = select_source_paths(case.raw_dir.glob("mft-entries-*.jsonl"), source_keys)
    total_entries = total_timeline = 0
    for path in paths:
        source_sha = raw_source_hash(path)
        path_sql = duckdb_path_literal(path)
        with db.transaction():
            db.execute("DELETE FROM mft_entries WHERE source_file = ?", (source_sha,))
            db.execute("DELETE FROM mft_timeline WHERE source_file = ?", (source_sha,))
            db.execute(_insert_entries_sql(path_sql, source_sha))
            total_entries += int(
                db.execute(
                    "SELECT COUNT(*) FROM mft_entries WHERE source_file = ?",
                    (source_sha,),
                ).fetchone()[0]
            )
            total_timeline += _insert_timeline_from_entries(db, source_sha)
    return total_entries, total_timeline


def normalize_mft(
    case: Case, db: CaseDB, source_keys: Collection[str] | None = None
) -> tuple[int, int]:
    with db.bulk_load_mode():
        return _normalize_mft_selected(case, db, source_keys=source_keys)
