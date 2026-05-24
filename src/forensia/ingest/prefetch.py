from __future__ import annotations

import json
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import Callable

from prefetch2es.models.Prefetch2es import Prefetch2es

from forensia.core.case import Case
from forensia.core.evidence import make_prefetch_evidence_id


def ingest_prefetch_file(
    case: Case,
    prefetch_path: str | Path,
    source_sha: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> Path | None:
    prefetch_path = Path(prefetch_path)
    sha_prefix = (source_sha or "unknown")[:12]
    output_path = case.raw_dir / f"prefetch-{sha_prefix}.jsonl"
    ingested_at = datetime.now(UTC).isoformat()

    parser = Prefetch2es(prefetch_path)
    records = list(chain.from_iterable(
        parser.gen_records(multiprocess=False, chunk_size=500)
    ))
    if not records:
        return None

    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            executable_name = str(record.get("name") or "")
            prefetch_hash = str(record.get("prefetch_hash") or "")
            enriched = {
                **record,
                "source_type": "prefetch",
                "ingested_at": ingested_at,
                "evidence_id": make_prefetch_evidence_id(executable_name, prefetch_hash),
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")

    return output_path
