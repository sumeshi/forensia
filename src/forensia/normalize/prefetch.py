from __future__ import annotations

from forensia.core.case import Case
from forensia.db.database import CaseDB


def normalize_prefetch(case: Case, db: CaseDB) -> int:
    inserted = 0
    for path in sorted(case.raw_dir.glob("prefetch-*.jsonl")):
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
    return inserted
