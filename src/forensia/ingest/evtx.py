from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import Callable

from evtx2es.models.Evtx2es import Evtx2es

from forensia.core.case import Case
from forensia.core.evidence import make_evtx_evidence_id


def ingest_evtx_file(
    case: Case,
    evtx_path: str | Path,
    source_sha: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    evtx_path = Path(evtx_path)
    ingested_at = datetime.now(UTC).isoformat()

    if progress_callback:
        progress_callback(f"Parsing EVTX records from {evtx_path}")
    parser = Evtx2es(evtx_path)
    records = list(chain.from_iterable(
        parser.gen_records(shift="0", multiprocess=False, chunk_size=500)
    ))
    if progress_callback:
        progress_callback(f"Parsed {len(records)} EVTX records from {evtx_path}")

    # Use channel from first record to name the output file; fall back to stem
    first_channel = records[0].get("winlog", {}).get("channel", evtx_path.stem) if records else evtx_path.stem
    safe_name = first_channel.lower().replace("/", "_").replace(" ", "_").replace("\\", "_")
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
