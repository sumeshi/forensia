from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
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
                    "source_file": str(mft_path),
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
