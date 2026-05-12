from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import Callable

from mft2es.models.Mft2es import Mft2es

from forensia.core.case import Case
from forensia.core.evidence import make_mft_evidence_id


def ingest_mft_file(
    case: Case,
    mft_path: str | Path,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    mft_path = Path(mft_path)
    output_path = case.raw_dir / "mft.jsonl"
    ingested_at = datetime.now(UTC).isoformat()

    if progress_callback:
        progress_callback(f"Parsing MFT records from {mft_path}")
    parser = Mft2es(mft_path)
    records = list(chain.from_iterable(
        parser.gen_timeline_records(multiprocess=False, chunk_size=500, timeline_mode=False)
    ))
    if progress_callback:
        progress_callback(f"Parsed {len(records)} MFT records from {mft_path}")

    with output_path.open("w", encoding="utf-8") as handle:
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
        progress_callback(f"Wrote JSONL: {output_path}")

    return output_path
