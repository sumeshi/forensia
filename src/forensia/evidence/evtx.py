from __future__ import annotations

from collections.abc import Callable, Collection
from pathlib import Path

from evtx2es.presenters.Evtx2jsonPresenter import Evtx2jsonPresenter

from forensia.core.case import Case
from forensia.core.textutil import strict_slugify
from forensia.db.database import CaseDB
from forensia.evidence.jsonl import duckdb_path_literal, export_jsonl, raw_source_hash
from forensia.evidence.normalize import select_source_paths


def ingest_evtx_file(
    case: Case,
    evtx_path: str | Path,
    source_sha: str,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """Write the parser's records unchanged as atomically published JSONL."""
    evtx_path = Path(evtx_path)
    output_path = case.raw_dir / f"evtx-{source_sha}-records.jsonl"
    if progress_callback:
        progress_callback(f"Parsing EVTX records from {evtx_path}")
    export_jsonl(
        Evtx2jsonPresenter,
        evtx_path,
        output_path,
        shift="0",
        multiprocess=False,
        chunk_size=500,
    )
    if progress_callback:
        progress_callback(f"Wrote JSONL: {output_path}")
    return output_path


def normalize_evtx(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> int:
    """Load native EVTX JSONL, assigning source identity during projection."""
    inserted = 0
    paths = select_source_paths(case.raw_dir.glob("evtx-*.jsonl"), source_keys)
    for path in paths:
        source_sha = raw_source_hash(path)
        path_sql = duckdb_path_literal(path)
        channel_rows = db.execute(
            f"SELECT DISTINCT json_extract_string(json, '$.winlog.channel') "
            f"FROM read_ndjson_objects('{path_sql}')"
        ).fetchall()
        channels = {row[0] for row in channel_rows if row[0] is not None}
        slug_cases = " ".join(
            f"WHEN channel_value = '{channel.replace(chr(39), chr(39) * 2)}' "
            f"THEN '{strict_slugify(channel)}'"
            for channel in sorted(channels)
        )
        slug_expression = (
            f"CASE {slug_cases} ELSE 'unknown' END" if slug_cases else "'unknown'"
        )
        db.execute(
            f"""
            CREATE OR REPLACE TEMP TABLE evtx_stage AS
            WITH extracted AS (
                SELECT json,
                    json_extract_string(json, '$.winlog.channel') AS channel_value
                FROM read_ndjson_objects('{path_sql}')
            )
            SELECT
                'evtx-' || '{source_sha}' || '-' ||
                    ({slug_expression}) || '-' ||
                    printf('%012d', coalesce(try_cast(json_extract_string(json, '$.winlog.record_id') AS BIGINT), error('EVTX record_id missing or invalid'))) AS evidence_id,
                '{source_sha}' AS source_file,
                json_extract_string(json, '$.winlog.channel') AS channel,
                try_cast(json_extract_string(json, '$.winlog.event_id') AS INTEGER) AS event_id,
                try_cast(json_extract_string(json, '$.winlog.record_id') AS BIGINT) AS record_id,
                try_cast(json_extract_string(json, '$."@timestamp"') AS TIMESTAMP) AS timestamp,
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
                json_extract_string(json, '$.winlog.event_data.Message') AS message,
                json AS raw_json,
                json_extract(json, '$.tags') AS tags,
                NULL AS severity
            FROM extracted
            """
        )
        row_count = int(db.execute("SELECT COUNT(*) FROM evtx_stage").fetchone()[0])
        with db.transaction():
            db.execute("DELETE FROM evtx_events WHERE source_file = ?", (source_sha,))
            db.execute(
                """
                INSERT INTO evtx_events (
                    evidence_id, source_file, channel, event_id, record_id, timestamp,
                    computer, user_name, target_user, subject_user, src_ip, logon_type,
                    process_name, command_line, service_name, message, raw_json, tags, severity
                )
                SELECT evidence_id, source_file, channel, event_id, record_id, timestamp,
                    computer, user_name, target_user, subject_user, src_ip, logon_type,
                    process_name, command_line, service_name, message, raw_json, tags, severity
                FROM evtx_stage
                """
            )
        inserted += row_count
    return inserted
