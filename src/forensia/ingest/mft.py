from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path

from mft2es.models.Mft2es import Mft2es

from forensia.core.case import Case
from forensia.core.evidence import make_mft_evidence_id


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
    records = list(
        chain.from_iterable(
            parser.gen_timeline_records(
                multiprocess=False, chunk_size=500, timeline_mode=False
            )
        )
    )
    if progress_callback:
        progress_callback(f"Parsed {len(records)} MFT records from {mft_path}")

    with entries_path.open("w", encoding="utf-8") as handle:
        for record in records:
            header = record.get("header", {})
            record_number = int(header.get("record_number") or 0)
            sequence_number = int(header.get("sequence_number") or 0)
            enriched = {
                **record,
                "source_type": "mft",
                "source_file": str(mft_path),
                "parser": "mft2es",
                "ingested_at": ingested_at,
                "evidence_id": make_mft_evidence_id(record_number, sequence_number),
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    if progress_callback:
        progress_callback(f"Wrote JSONL: {entries_path}")

    if progress_callback:
        progress_callback(f"Parsing MFT timeline records from {mft_path}")
    timeline_parser = Mft2es(mft_path)
    timeline_records = list(
        chain.from_iterable(
            timeline_parser.gen_timeline_records(
                multiprocess=False, chunk_size=500, timeline_mode=True
            )
        )
    )
    with timeline_path.open("w", encoding="utf-8") as handle:
        for record in timeline_records:
            # mft2es timeline_mode=True emits ECS-shaped records (@timestamp, event.action,
            # windows.mft.record.*). Add forensia-flat fields at the top level so the normalize
            # SQL can json_extract_string('$.field') directly.
            mft_rec = (record.get("windows", {}) or {}).get("mft", {}) or {}
            rec_meta = mft_rec.get("record", {}) or {}
            header = mft_rec.get("header", {}) or {}
            record_number = int(rec_meta.get("number") or 0)
            sequence_number = int(header.get("sequence") or 0)
            event_action = str((record.get("event", {}) or {}).get("action") or "")
            timestamp_type = _TIMESTAMP_TYPE_MAP.get(event_action, event_action)
            evidence_id = make_mft_evidence_id(record_number, sequence_number)
            timeline_id = (
                f"{evidence_id}-{timestamp_type}" if timestamp_type else evidence_id
            )
            file_path = rec_meta.get("path") or ""
            file_name = rec_meta.get("name") or ""
            enriched = {
                **record,
                "source_type": "mft",
                "source_file": str(mft_path),
                "parser": "mft2es",
                "ingested_at": ingested_at,
                # Forensia-flat fields consumed by normalize/mft.py
                "timeline_id": timeline_id,
                "evidence_id": evidence_id,
                "record_number": record_number,
                "file_path": file_path,
                "file_name": file_name,
                "timestamp": record.get("@timestamp"),
                "timestamp_type": timestamp_type,
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    if progress_callback:
        progress_callback(f"Wrote JSONL: {timeline_path}")

    return entries_path, timeline_path


# Maps mft2es ECS event.action → forensia timestamp_type constants. The trailing
# letter encodes the timestamp kind (c=created, m=modified, a=accessed, b=mft_modified).
_TIMESTAMP_TYPE_MAP = {
    "mft-standardinformation-c": "SI_CREATED",
    "mft-standardinformation-m": "SI_MODIFIED",
    "mft-standardinformation-a": "SI_ACCESSED",
    "mft-standardinformation-b": "SI_MFT_MODIFIED",
    "mft-filename-c": "FN_CREATED",
    "mft-filename-m": "FN_MODIFIED",
    "mft-filename-a": "FN_ACCESSED",
    "mft-filename-b": "FN_MFT_MODIFIED",
}
