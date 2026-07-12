from __future__ import annotations

from collections.abc import Collection, Iterable
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.artifacts import get_artifact_adapters


def select_source_paths(
    paths: Iterable[Path], source_keys: Collection[str] | None
) -> list[Path]:
    """Return all raw paths, or only paths produced by this ingest run."""
    ordered = sorted(set(paths))
    if source_keys is None:
        return ordered
    keys = {str(key) for key in source_keys if key}
    return [path for path in ordered if any(key in path.name for key in keys)]


def normalize_all(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> dict[str, int]:
    counts = {
        "evtx_rows": 0,
        "mft_entries": 0,
        "mft_timeline_rows": 0,
        "prefetch_executions": 0,
        "prefetch_timeline": 0,
    }
    for adapter in get_artifact_adapters():
        result = adapter.normalize(case, db, source_keys=source_keys)
        if result.source_kind == "evtx":
            counts["evtx_rows"] = result.rows
        elif result.source_kind == "mft":
            counts["mft_entries"] = result.rows
            counts["mft_timeline_rows"] = result.aux_rows
        elif result.source_kind == "prefetch":
            counts["prefetch_executions"] = result.rows
            counts["prefetch_timeline"] = result.aux_rows
    return counts
