from __future__ import annotations

from forensia.artifacts import get_artifact_adapters
from forensia.core.case import Case
from forensia.db.database import CaseDB


def normalize_all(case: Case, db: CaseDB) -> dict[str, int]:
    counts = {
        "evtx_rows": 0,
        "mft_entries": 0,
        "mft_timeline_rows": 0,
        "prefetch_executions": 0,
    }
    for adapter in get_artifact_adapters():
        result = adapter.normalize(case, db)
        if result.source_kind == "evtx":
            counts["evtx_rows"] = result.rows
        elif result.source_kind == "mft":
            counts["mft_entries"] = result.rows
            counts["mft_timeline_rows"] = result.aux_rows
        elif result.source_kind == "prefetch":
            counts["prefetch_executions"] = result.rows
    return counts
