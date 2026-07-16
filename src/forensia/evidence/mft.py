from __future__ import annotations

import json
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from pathlib import Path

from mft2es.models.Mft2es import Mft2es

from forensia.core.case import Case
from forensia.core.evidence import make_mft_evidence_id
from forensia.db.database import CaseDB
from forensia.evidence.normalize import select_source_paths
from forensia.evidence.timeline_sql import (
    build_timeline_stage_sql,
    delete_existing_timeline_entries_sql,
    duckdb_path_literal,
    insert_timeline_sql,
)


def ingest_mft_file(
    case: Case,
    mft_path: str | Path,
    source_sha: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[Path, Path | None]:
    mft_path = Path(mft_path)
    sha_prefix = (source_sha or "unknown")[:12]
    entries_path = case.raw_dir / f"mft-entries-{sha_prefix}.jsonl"
    timeline_path = case.raw_dir / f"mft-timeline-{sha_prefix}.jsonl"
    ingested_at = datetime.now(UTC).isoformat()

    if progress_callback:
        progress_callback(f"Parsing MFT records from {mft_path}")
    parser = Mft2es(mft_path)
    record_count = 0
    with entries_path.open("w", encoding="utf-8") as handle:
        for chunk in parser.gen_timeline_records(
            multiprocess=False, chunk_size=500, timeline_mode=False
        ):
            for record in chunk:
                header = record.get("header", {})
                record_number = int(header.get("record_number") or 0)
                sequence_number = int(header.get("sequence_number") or 0)
                enriched = {
                    **record,
                    "source_type": "mft",
                    # Stable source identity; display paths live in evidence_sources.
                    "source_file": source_sha or str(mft_path),
                    "parser": "mft2es",
                    "ingested_at": ingested_at,
                    "evidence_id": make_mft_evidence_id(record_number, sequence_number),
                }
                handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                record_count += 1
    if progress_callback:
        progress_callback(f"Parsed {record_count} MFT records from {mft_path}")
    if progress_callback:
        progress_callback(f"Wrote JSONL: {entries_path}")

    # Timeline rows are derived from the eight timestamp columns while loading
    # entries into DuckDB.  The old second parser pass produced a much larger
    # duplicate JSONL (1.16 GB for the CFReDS sample).
    timeline_path.unlink(missing_ok=True)
    return entries_path, None


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


def _build_entries_select_sql(path_sql: str) -> str:
    return f"""
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


def _insert_entries_sql(path_sql: str) -> str:
    return f"""
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
            FROM ({_build_entries_select_sql(path_sql)}) AS projected_entries
    """


def _insert_timeline_from_entries(db: CaseDB, source_file: str) -> int:
    """Derive MFT timeline rows from entries inserted for one source."""
    db.execute(
        """
        INSERT INTO mft_timeline (
            timeline_id, evidence_id, record_number, file_path, file_name,
            timestamp, timestamp_type, source_file, description, tags
        )
        SELECT
            evidence_id || '-' || timestamp_type AS timeline_id,
            evidence_id,
            record_number,
            file_path,
            file_name,
            timestamp,
            timestamp_type,
            source_file,
            NULL AS description,
            CAST('[]' AS JSON) AS tags
        FROM mft_entries
        CROSS JOIN LATERAL (
            VALUES
                ('SI_CREATED', si_created),
                ('SI_MODIFIED', si_modified),
                ('SI_ACCESSED', si_accessed),
                ('SI_MFT_MODIFIED', si_mft_modified),
                ('FN_CREATED', fn_created),
                ('FN_MODIFIED', fn_modified),
                ('FN_ACCESSED', fn_accessed),
                ('FN_MFT_MODIFIED', fn_mft_modified)
        ) AS timestamps(timestamp_type, timestamp)
        WHERE source_file = ? AND timestamp IS NOT NULL
        """,
        (source_file,),
    )
    return int(
        db.execute(
            "SELECT COUNT(*) FROM mft_timeline WHERE source_file = ?",
            (source_file,),
        ).fetchone()[0]
    )


def _normalize_mft_selected(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> tuple[int, int]:
    entry_paths = select_source_paths(
        case.raw_dir.glob("mft-entries-*.jsonl"), source_keys
    )
    timeline_paths = select_source_paths(
        case.raw_dir.glob("mft-timeline-*.jsonl"), source_keys
    )
    if not entry_paths and not timeline_paths:
        return 0, 0
    total_entries = 0
    total_timeline = 0
    entry_keys: set[str] = set()
    for path in entry_paths:
        entry_keys.add(path.name.removeprefix("mft-entries-").removesuffix(".jsonl"))
        path_sql = duckdb_path_literal(path)
        source_row = db.execute(
            """
            SELECT json_extract_string(json, '$.source_file')
            FROM read_ndjson_objects(?)
            WHERE json_extract_string(json, '$.source_file') IS NOT NULL
            LIMIT 1
            """,
            (str(path),),
        ).fetchone()
        if not source_row:
            continue
        source_file = str(source_row[0])
        with db.transaction():
            db.execute("DELETE FROM mft_entries WHERE source_file = ?", (source_file,))
            db.execute("DELETE FROM mft_timeline WHERE source_file = ?", (source_file,))
            db.execute(_insert_entries_sql(path_sql))
            total_entries += db.execute(
                "SELECT COUNT(*) FROM mft_entries WHERE source_file = ?", (source_file,)
            ).fetchone()[0]
            total_timeline += _insert_timeline_from_entries(db, source_file)
    for path in timeline_paths:
        timeline_key = path.name.removeprefix("mft-timeline-").removesuffix(".jsonl")
        if timeline_key in entry_keys:
            continue
        path_sql = duckdb_path_literal(path)
        db.execute(
            build_timeline_stage_sql("mft_timeline_stage", path_sql, _TIMELINE_COLUMNS)
        )
        with db.transaction():
            db.execute(
                delete_existing_timeline_entries_sql(
                    "mft_timeline", "mft_timeline_stage"
                )
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


def normalize_mft(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> tuple[int, int]:
    # Parallel JSON materialization multiplies buffers for MFT's wide raw_json
    # rows. One DuckDB worker is faster and substantially leaner here.
    with db.bulk_load_mode():
        return _normalize_mft_selected(case, db, source_keys=source_keys)
