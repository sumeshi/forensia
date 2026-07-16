from __future__ import annotations

import logging
from collections.abc import Collection, Iterable
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.evidence.artifacts import get_artifact_adapters

logger = logging.getLogger(__name__)


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

    _update_source_status(db, source_keys, counts)

    return counts


def _resolve_source_path(db: CaseDB, sha256: str, source_kind: str) -> str:
    """Resolve the source_file path used in normalized tables for a given ingested file.

    Tries multiple path formats: absolute path from ingested_files,
    relative path from case root, and basename (for prefetch).
    Returns the path that matches rows in the normalized table.
    """
    source_row = db.execute(
        "SELECT path FROM ingested_files WHERE sha256 = ?", [sha256]
    ).fetchone()
    if not source_row:
        return ""
    abs_path = str(source_row[0] or "")
    if not abs_path:
        return ""

    table = {
        "evtx": "evtx_events",
        "mft": "mft_entries",
        "prefetch": "prefetch_executions",
    }.get(source_kind)
    if table is None:
        return abs_path

    # Current raw records use the ingested SHA-256 as their durable source
    # identity.  Path matching below is retained only for legacy case data.
    count_row = db.execute(
        f"SELECT COUNT(*) FROM {table} WHERE source_file = ?", [sha256]
    ).fetchone()
    if count_row and int(count_row[0] or 0) > 0:
        return sha256

    # Legacy absolute path.
    count_row = db.execute(
        f"SELECT COUNT(*) FROM {table} WHERE source_file = ?", [abs_path]
    ).fetchone()
    if count_row and int(count_row[0] or 0) > 0:
        return abs_path

    # Try relative path (strip common prefixes)
    p = Path(abs_path)
    for parent_len in range(1, len(p.parts)):
        relative = str(Path(*p.parts[parent_len:]))
        count_row = db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE source_file = ?", [relative]
        ).fetchone()
        if count_row and int(count_row[0] or 0) > 0:
            return relative

    # Try basename (for prefetch or when path was stored differently)
    basename = p.name
    count_row = db.execute(
        f"SELECT COUNT(*) FROM {table} WHERE source_file = ?", [basename]
    ).fetchone()
    if count_row and int(count_row[0] or 0) > 0:
        return basename

    # Fallback: return absolute path (will result in 0 count, logged below)
    logger.warning(
        "Source path resolution failed for %s (sha256=%s): no match in %s",
        abs_path,
        sha256,
        table,
    )
    return abs_path


def _update_source_status(
    db: CaseDB,
    source_keys: Collection[str] | None,
    counts: dict[str, int],
) -> None:
    """Best-effort update of evidence_sources rows after normalization.

    When source_keys is None, updates all sources that have ingested_files entries.
    """
    if source_keys:
        keys = [k for k in source_keys if k]
    else:
        rows = db.execute(
            "SELECT DISTINCT SUBSTR(sha256, 1, 12) FROM ingested_files"
        ).fetchall()
        keys = [str(row[0]) for row in rows if row[0]]

    for key in keys:
        try:
            rows = db.execute(
                "SELECT sha256, source_kind FROM ingested_files WHERE sha256 LIKE ?",
                (f"{key}%",),
            ).fetchall()
            for row in rows:
                sha256: str = row[0]
                source_kind: str = row[1]
                lookup_path = _resolve_source_path(db, sha256, source_kind)
                if not lookup_path:
                    continue
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
                        "mft_timeline" if source_kind == "mft" else "prefetch_timeline"
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
                status = "normalized" if row_count > 0 else "empty"
                register_evidence_source(
                    db,
                    source_id=sha256,
                    artifact_family=source_kind,
                    display_path="",
                    ingest_status=status,
                    parser_name=source_kind,
                    row_count=row_count,
                    channel=channels[0] if len(channels) == 1 else "",
                    hosts=hosts,
                    min_time=min_time,
                    max_time=max_time,
                )
        except Exception as exc:
            logger.warning("Failed to update source status for key %s: %s", key, exc)
