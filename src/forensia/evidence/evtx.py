from __future__ import annotations

import json
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

from evtx2es.models.Evtx2es import Evtx2es

from forensia.core.case import Case
from forensia.core.evidence import make_evtx_evidence_id
from forensia.db.database import CaseDB
from forensia.evidence.normalize import select_source_paths
from forensia.evidence.timeline_sql import duckdb_path_literal


def ingest_evtx_file(
    case: Case,
    evtx_path: str | Path,
    source_sha: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """Parse an EVTX file with evtx2es, enrich records with metadata, and write as JSONL.

    Each record gets a unique evidence_id derived from channel and record_id, plus
    source tracking and ingestion timestamp. The output filename encodes the channel
    name and source hash for traceability.
    """
    evtx_path = Path(evtx_path)
    ingested_at = datetime.now(UTC).isoformat()

    if progress_callback:
        progress_callback(f"Parsing EVTX records from {evtx_path}")
    parser = Evtx2es(evtx_path)
    records = list(
        chain.from_iterable(
            parser.gen_records(shift="0", multiprocess=False, chunk_size=500)
        )
    )
    if progress_callback:
        progress_callback(f"Parsed {len(records)} EVTX records from {evtx_path}")

    # Use channel from first record to name the output file; fall back to stem
    first_channel = (
        records[0].get("winlog", {}).get("channel", evtx_path.stem)
        if records
        else evtx_path.stem
    )
    safe_name = (
        first_channel.lower().replace("/", "_").replace(" ", "_").replace("\\", "_")
    )
    sha_prefix = (source_sha or "unknown")[:12]
    output_path = case.raw_dir / f"evtx-{sha_prefix}-{safe_name}.jsonl"

    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            winlog = record.get("winlog", {})
            channel = winlog.get("channel", first_channel)
            record_id = int(winlog.get("record_id") or 0)
            enriched = {
                **record,
                "source_type": "evtx",
                "source_file": str(evtx_path),
                "channel": channel,
                "parser": "evtx2es",
                "ingested_at": ingested_at,
                "evidence_id": make_evtx_evidence_id(channel, record_id),
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    if progress_callback:
        progress_callback(f"Wrote JSONL: {output_path}")

    return output_path


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
