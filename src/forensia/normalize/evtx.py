from __future__ import annotations

from collections.abc import Collection

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.normalize import select_source_paths
from forensia.normalize.timeline_sql import duckdb_path_literal


def normalize_evtx(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> int:
    """Load EVTX JSONL files into the evtx_events database table.

    Deletes existing rows for each source_file before insert so re-ingestion
    replaces rather than duplicates data. Returns total rows inserted.
    """
    inserted = 0
    paths = select_source_paths(
        {*case.raw_dir.glob("evtx.jsonl"), *case.raw_dir.glob("evtx-*.jsonl")},
        source_keys,
    )
    for path in paths:
        path_sql = duckdb_path_literal(path)
        db.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE evtx_stage AS
            SELECT
                json_extract_string(json, '$.evidence_id') AS evidence_id,
                json_extract_string(json, '$.source_file') AS source_file,
                coalesce(
                    json_extract_string(json, '$.winlog.channel'),
                    json_extract_string(json, '$.channel')
                ) AS channel,
                try_cast(json_extract_string(json, '$.winlog.event_id') AS INTEGER) AS event_id,
                try_cast(json_extract_string(json, '$.winlog.record_id') AS BIGINT) AS record_id,
                try_cast(json_extract_string(json, '$.\"@timestamp\"') AS TIMESTAMP) AS timestamp,
                json_extract_string(json, '$.winlog.computer_name') AS computer,
                json_extract_string(json, '$.winlog.user.name') AS user_name,
                json_extract_string(json, '$.winlog.event_data.TargetUserName') AS target_user,
                json_extract_string(json, '$.winlog.event_data.SubjectUserName') AS subject_user,
                json_extract_string(json, '$.winlog.event_data.IpAddress') AS src_ip,
                nullif(json_extract_string(json, '$.winlog.event_data.LogonType'), '') AS logon_type,
                coalesce(
                    json_extract_string(json, '$.winlog.event_data.NewProcessName'),
                    json_extract_string(json, '$.winlog.event_data.ProcessName'),
                    json_extract_string(json, '$.winlog.event_data.Image')
                ) AS process_name,
                json_extract_string(json, '$.winlog.event_data.CommandLine') AS command_line,
                json_extract_string(json, '$.winlog.event_data.ServiceName') AS service_name,
                coalesce(
                    json_extract_string(json, '$.winlog.event_data.Message'),
                    json_extract_string(json, '$.userdata.Message')
                ) AS message,
                json AS raw_json,
                json_extract(json, '$.tags') AS tags,
                NULL AS severity
            FROM read_ndjson_objects('{path_sql}')
            """
        )
        row_count = int(db.execute("SELECT COUNT(*) FROM evtx_stage").fetchone()[0])
        if row_count == 0:
            continue
        with db.transaction():
            db.execute(
                """
                DELETE FROM evtx_events
                WHERE source_file IN (
                    SELECT DISTINCT source_file FROM evtx_stage WHERE source_file IS NOT NULL
                )
                """
            )
            db.execute(
                """
                INSERT INTO evtx_events (
                    evidence_id, source_file, channel, event_id, record_id, timestamp,
                    computer, user_name, target_user, subject_user, src_ip, logon_type,
                    process_name, command_line, service_name, message, raw_json, tags, severity
                )
                SELECT
                    evidence_id, source_file, channel, event_id, record_id, timestamp,
                    computer, user_name, target_user, subject_user, src_ip, logon_type,
                    process_name, command_line, service_name, message, raw_json, tags, severity
                FROM evtx_stage
                """
            )
        inserted += row_count
    return inserted
