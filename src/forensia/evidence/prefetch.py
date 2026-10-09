from __future__ import annotations

import json
from collections.abc import Callable, Collection, Iterator
from pathlib import Path
from typing import Any

from prefetch2es.presenters.Prefetch2jsonPresenter import Prefetch2jsonPresenter

from forensia.core.case import Case
from forensia.core.evidence import make_prefetch_evidence_id
from forensia.db.database import CaseDB
from forensia.evidence.jsonl import export_jsonl, raw_source_hash
from forensia.evidence.normalize import select_source_paths


def ingest_prefetch_file(
    case: Case,
    prefetch_path: str | Path,
    source_sha: str,
    progress_callback: Callable[[str], None] | None = None,
) -> Path:
    """Publish the parser's native Prefetch JSONL as the authoritative raw source."""
    prefetch_path = Path(prefetch_path)
    entries_path = case.raw_dir / f"prefetch-entries-{source_sha}.jsonl"
    export_jsonl(
        Prefetch2jsonPresenter,
        prefetch_path,
        entries_path,
        require_records=True,
        timeline_mode=False,
        multiprocess=False,
        chunk_size=500,
    )
    if progress_callback:
        progress_callback(f"Wrote JSONL: {entries_path}")
    return entries_path


def _read_records(path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            yield line.rstrip("\r\n"), value


def normalize_prefetch(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> tuple[int, int]:
    """Normalize native entries and derive executions from their timestamp arrays."""
    inserted = total_timeline = 0
    paths = select_source_paths(
        case.raw_dir.glob("prefetch-entries-*.jsonl"), source_keys
    )
    for path in paths:
        source_sha = raw_source_hash(path)
        entry_count = timeline_count = 0
        with db.transaction():
            db.execute(
                "DELETE FROM prefetch_executions WHERE source_file = ?", [source_sha]
            )
            db.execute(
                "DELETE FROM prefetch_timeline WHERE source_file = ?", [source_sha]
            )
            for raw_line, record in _read_records(path):
                name = record["name"]
                prefetch_hash = record["prefetch_hash"]
                evidence_id = make_prefetch_evidence_id(source_sha, name, prefetch_hash)
                exec_times = record["last_exec_times"]
                if not isinstance(exec_times, list):
                    raise ValueError(f"{path}: last_exec_times must be an array")
                tags = json.dumps(record.get("tags", []), ensure_ascii=False)
                db.execute(
                    """INSERT INTO prefetch_executions (
                        evidence_id, source_file, executable_name, exec_count,
                        last_exec_time, exec_times, prefetch_hash, filenames,
                        volumes, raw_json, tags, severity
                    ) VALUES (
                        ?, ?, ?, ?, TRY_CAST(? AS TIMESTAMP), CAST(? AS JSON), ?,
                        CAST(? AS JSON), CAST(? AS JSON), CAST(? AS JSON), CAST(? AS JSON), NULL
                    )""",
                    [
                        evidence_id,
                        source_sha,
                        name,
                        record["exec_count"],
                        exec_times[0] if exec_times else None,
                        json.dumps(exec_times),
                        prefetch_hash,
                        json.dumps(record.get("filenames", []), ensure_ascii=False),
                        json.dumps(record.get("volumes", []), ensure_ascii=False),
                        raw_line,
                        tags,
                    ],
                )
                entry_count += 1
                for exec_index, exec_time in enumerate(exec_times):
                    db.execute(
                        """INSERT INTO prefetch_timeline (
                            timeline_id, evidence_id, executable_name, prefetch_hash,
                            exec_time, exec_index, source_file, tags
                        ) VALUES (?, ?, ?, ?, TRY_CAST(? AS TIMESTAMP), ?, ?, CAST(? AS JSON))""",
                        [
                            f"{evidence_id}-{exec_index:02d}",
                            evidence_id,
                            name,
                            prefetch_hash,
                            exec_time,
                            exec_index,
                            source_sha,
                            tags,
                        ],
                    )
                    timeline_count += 1
            if not entry_count:
                raise ValueError(f"prefetch parser output is empty: {path}")
        inserted += entry_count
        total_timeline += timeline_count
    return inserted, total_timeline
