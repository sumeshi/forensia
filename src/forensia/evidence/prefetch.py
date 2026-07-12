from __future__ import annotations

import json
import os
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

from prefetch2es.models.Prefetch2es import Prefetch2es

from forensia.core.case import Case
from forensia.core.evidence import make_prefetch_evidence_id
from forensia.db.database import CaseDB
from forensia.evidence.normalize import select_source_paths
from forensia.evidence.timeline_sql import (
    build_timeline_stage_sql,
    delete_existing_timeline_entries_sql,
    duckdb_path_literal,
    insert_timeline_sql,
)


def ingest_prefetch_file(
    case: Case,
    prefetch_path: str | Path,
    source_sha: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> tuple[Path, Path | None]:
    prefetch_path = Path(prefetch_path)
    sha_prefix = (source_sha or "unknown")[:12]
    entries_path = case.raw_dir / f"prefetch-entries-{sha_prefix}.jsonl"
    timeline_path = case.raw_dir / f"prefetch-timeline-{sha_prefix}.jsonl"
    ingested_at = datetime.now(UTC).isoformat()

    parser = Prefetch2es(prefetch_path)
    records = list(
        chain.from_iterable(parser.gen_records(multiprocess=False, chunk_size=500))
    )
    if not records:
        if progress_callback:
            progress_callback(
                f"WARNING: prefetch parser returned 0 records for {prefetch_path}"
            )
        return None, None

    with entries_path.open("w", encoding="utf-8") as handle:
        for record in records:
            executable_name = str(record.get("name") or "")
            prefetch_hash = str(record.get("prefetch_hash") or "")
            enriched = {
                **record,
                "source_type": "prefetch",
                "ingested_at": ingested_at,
                "evidence_id": make_prefetch_evidence_id(
                    executable_name, prefetch_hash
                ),
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")

    timeline_parser = Prefetch2es(prefetch_path)
    timeline_records = list(
        chain.from_iterable(
            timeline_parser.gen_timeline_records(multiprocess=False, chunk_size=500)
        )
    )
    # Records are returned in descending exec_time order per file (most recent first).
    with timeline_path.open("w", encoding="utf-8") as handle:
        for idx, record in enumerate(timeline_records):
            # prefetch2es timeline_mode emits ECS-shaped records (@timestamp,
            # process.name, windows.prefetch.*). Enrich with forensia-flat fields
            # at the top level so normalize/prefetch.py can json_extract_string('$.x') them.
            process_obj = record.get("process", {}) or {}
            win_prefetch = (record.get("windows", {}) or {}).get("prefetch", {}) or {}
            hash_obj = win_prefetch.get("hash", {}) or {}
            executable_name = str(process_obj.get("name") or "")
            prefetch_hash = str(hash_obj.get("prefetch") or "")
            evidence_id = make_prefetch_evidence_id(executable_name, prefetch_hash)
            enriched = {
                **record,
                "source_type": "prefetch",
                "source_file": os.path.basename(str(prefetch_path)),
                "ingested_at": ingested_at,
                # Forensia-flat fields consumed by normalize/prefetch.py
                "timeline_id": f"{evidence_id}-{idx:02d}",
                "evidence_id": evidence_id,
                "executable_name": executable_name,
                "prefetch_hash": prefetch_hash,
                "exec_time": record.get("@timestamp"),
                "exec_index": idx,
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    if not timeline_records:
        if progress_callback:
            progress_callback(
                f"WARNING: prefetch timeline parser returned 0 records for {prefetch_path}"
            )
    if progress_callback:
        progress_callback(f"Wrote JSONL: {timeline_path}")

    return entries_path, timeline_path


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
