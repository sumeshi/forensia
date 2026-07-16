from __future__ import annotations

from collections.abc import Collection, Iterable
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
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
        try:
            result = adapter.normalize(case, db, source_keys=source_keys)
        except Exception as exc:
            if source_keys:
                for key in source_keys:
                    rows = db.execute(
                        "SELECT sha256, path FROM ingested_files "
                        "WHERE sha256 LIKE ? AND source_kind = ?",
                        [f"{key}%", adapter.name],
                    ).fetchall()
                    for source_id, path in rows:
                        register_evidence_source(
                            db,
                            source_id=source_id,
                            artifact_family=adapter.name,
                            display_path=Path(path).name,
                            ingest_status="failed",
                            parser_name=adapter.name,
                            error_code="normalize_failed",
                            error_summary=str(exc),
                        )
            raise
        if result.source_kind == "evtx":
            counts["evtx_rows"] = result.rows
        elif result.source_kind == "mft":
            counts["mft_entries"] = result.rows
            counts["mft_timeline_rows"] = result.aux_rows
        elif result.source_kind == "prefetch":
            counts["prefetch_executions"] = result.rows
            counts["prefetch_timeline"] = result.aux_rows

    if source_keys:
        _update_source_status(db, source_keys, counts)

    return counts


def _update_source_status(
    db: CaseDB,
    source_keys: Collection[str],
    counts: dict[str, int],
) -> None:
    """Best-effort update of evidence_sources rows after normalization."""
    for key in source_keys:
        if not key:
            continue
        try:
            rows = db.execute(
                "SELECT sha256, source_kind FROM ingested_files WHERE sha256 LIKE ?",
                (f"{key}%",),
            ).fetchall()
            for row in rows:
                sha256: str = row[0]
                source_kind: str = row[1]
                source_row = db.execute(
                    "SELECT path FROM ingested_files WHERE sha256 = ?", [sha256]
                ).fetchone()
                source_path = str(source_row[0] or "") if source_row else ""
                lookup_path = (
                    Path(source_path).name
                    if source_kind == "prefetch"
                    else source_path
                )
                table = {
                    "evtx": "evtx_events",
                    "mft": "mft_entries",
                    "prefetch": "prefetch_executions",
                }.get(source_kind)
                if table is None:
                    continue
                metadata = db.execute(
                    "SELECT COUNT(*), MIN(timestamp), MAX(timestamp), "
                    "list(DISTINCT computer), list(DISTINCT channel) "
                    "FROM evtx_events WHERE source_file = ?"
                    if source_kind == "evtx"
                    else (
                        f"SELECT COUNT(*), NULL, NULL, [], [] FROM {table} "
                        "WHERE source_file = ?"
                    ),
                    [lookup_path],
                ).fetchone()
                row_count = int(metadata[0] or 0)
                hosts = [str(item) for item in (metadata[3] or []) if item]
                channels = [str(item) for item in (metadata[4] or []) if item]
                min_time = metadata[1]
                max_time = metadata[2]
                if source_kind in {"mft", "prefetch"}:
                    timeline_table = (
                        "mft_timeline"
                        if source_kind == "mft"
                        else "prefetch_timeline"
                    )
                    timestamp_column = (
                        "timestamp" if source_kind == "mft" else "exec_time"
                    )
                    time_row = db.execute(
                        f"SELECT MIN({timestamp_column}), MAX({timestamp_column}) "
                        f"FROM {timeline_table} WHERE source_file = ?",
                        [lookup_path],
                    ).fetchone()
                    min_time, max_time = time_row if time_row else (None, None)
                register_evidence_source(
                    db,
                    source_id=sha256,
                    artifact_family=source_kind,
                    display_path="",
                    ingest_status="normalized",
                    parser_name=source_kind,
                    row_count=row_count,
                    channel=channels[0] if len(channels) == 1 else "",
                    hosts=hosts,
                    min_time=min_time,
                    max_time=max_time,
                )
        except Exception:
            pass
