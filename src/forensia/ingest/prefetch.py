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
) -> tuple[Path, Path | None]:
    prefetch_path = Path(prefetch_path)
    sha_prefix = (source_sha or "unknown")[:12]
    entries_path = case.raw_dir / f"prefetch-entries-{sha_prefix}.jsonl"
    timeline_path = case.raw_dir / f"prefetch-timeline-{sha_prefix}.jsonl"
    ingested_at = datetime.now(UTC).isoformat()

    parser = Prefetch2es(prefetch_path)
    records = list(chain.from_iterable(
        parser.gen_records(multiprocess=False, chunk_size=500)
    ))
    if not records:
        if progress_callback:
            progress_callback(f"WARNING: prefetch parser returned 0 records for {prefetch_path}")
        return None, None

    with entries_path.open("w", encoding="utf-8") as handle:
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

    timeline_parser = Prefetch2es(prefetch_path)
    timeline_records = list(chain.from_iterable(
        timeline_parser.gen_timeline_records(multiprocess=False, chunk_size=500)
    ))
    # Records are returned in descending exec_time order per file (most recent first).
    with timeline_path.open("w", encoding="utf-8") as handle:
        for idx, record in enumerate(timeline_records):
            # prefetch2es timeline_mode emits ECS-shaped records (@timestamp,
            # process.name, windows.prefetch.*). Enrich with forensia-flat fields
            # at the top level so normalize/prefetch.py can json_extract_string('$.x') them.
            process_obj = record.get("process", {}) or {}
            win_prefetch = (record.get("windows", {}) or {}).get("prefetch", {}) or {}
            hash_obj = win_prefetch.get("hash", {}) or {}
            executable_name = str(process_obj.get("name") or "")
            prefetch_hash = str(hash_obj.get("prefetch") or "")
            evidence_id = make_prefetch_evidence_id(executable_name, prefetch_hash)
            enriched = {
                **record,
                "source_type": "prefetch",
                "source_file": str(prefetch_path),
                "ingested_at": ingested_at,
                # Forensia-flat fields consumed by normalize/prefetch.py
                "timeline_id": f"{evidence_id}-{idx:02d}",
                "evidence_id": evidence_id,
                "executable_name": executable_name,
                "prefetch_hash": prefetch_hash,
                "exec_time": record.get("@timestamp"),
                "exec_index": idx,
            }
            handle.write(json.dumps(enriched, ensure_ascii=False) + "\n")
    if not timeline_records:
        if progress_callback:
            progress_callback(f"WARNING: prefetch timeline parser returned 0 records for {prefetch_path}")
    if progress_callback:
        progress_callback(f"Wrote JSONL: {timeline_path}")

    return entries_path, timeline_path
