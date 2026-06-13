from __future__ import annotations

from forensia.core.case import Case
from forensia.db.database import CaseDB


def normalize_evtx(case: Case, db: CaseDB) -> int:
    """Load EVTX JSONL files into the evtx_events database table.

    Deletes existing rows for each source_file before insert so re-ingestion
    replaces rather than duplicates data. Returns total rows inserted.
    """
    inserted = 0
    for path in sorted(
        {*case.raw_dir.glob("evtx.jsonl"), *case.raw_dir.glob("evtx-*.jsonl")}
    ):
        source_file = db.execute(
            """
            SELECT json_extract_string(json, '$.source_file')
            FROM read_ndjson_objects(?)
            LIMIT 1
            """,
            (str(path),),
        ).fetchone()
        if source_file and source_file[0]:
            db.execute(
                "DELETE FROM evtx_events WHERE source_file = ?", (source_file[0],)
            )

        row_count = db.execute(
            "SELECT COUNT(*) FROM read_ndjson_objects(?)", (str(path),)
        ).fetchone()[0]
        db.execute(
            """
            INSERT INTO evtx_events (
                evidence_id, source_file, channel, event_id, record_id, timestamp,
                computer, user_name, target_user, subject_user, src_ip, logon_type,
                process_name, command_line, service_name, message, raw_json, tags, severity
            )
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
                -- Severity is assigned later by rule-based findings, not by raw event rows.
                NULL AS severity
            FROM read_ndjson_objects(?)
            """,
            (str(path),),
        )
        inserted += int(row_count)
    return inserted
