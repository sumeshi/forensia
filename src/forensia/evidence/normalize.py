from __future__ import annotations

import logging
import re
from collections.abc import Collection, Iterable
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.evidence.artifacts import get_artifact_adapters
from forensia.evidence.invalidation import (
    fetch_referenced_evidence_fingerprints,
    invalidate_removed_evidence,
)
from forensia.evidence.timestamp_policy import (
    configured_timestamp_policy,
    timestamp_year_range_sql,
)

logger = logging.getLogger(__name__)


def select_source_paths(
    paths: Iterable[Path], source_keys: Collection[str] | None
) -> list[Path]:
    """Return all raw paths, or only paths produced by this ingest run."""
    ordered = sorted(set(paths))
    if source_keys is None:
        return ordered
    keys = {str(key) for key in source_keys if key}
    invalid = [key for key in keys if re.fullmatch(r"[0-9a-f]{64}", key) is None]
    if invalid:
        raise ValueError("source_keys must contain full lowercase SHA-256 identities")
    return [path for path in ordered if any(key in path.name for key in keys)]


def normalize_all(
    case: Case,
    db: CaseDB,
    source_keys: Collection[str] | None = None,
) -> dict[str, int]:
    if source_keys is None:
        active_source_keys = tuple(
            str(row[0])
            for row in db.execute(
                "SELECT sha256 FROM ingested_files ORDER BY sha256"
            ).fetchall()
            if row[0]
        )
    else:
        active_source_keys = tuple(
            dict.fromkeys(str(key) for key in source_keys if key)
        )
    counts = {
        "evtx_rows": 0,
        "mft_entries": 0,
        "mft_timeline_rows": 0,
        "prefetch_executions": 0,
        "prefetch_timeline": 0,
        "registry_artifacts": 0,
    }
    for adapter in get_artifact_adapters():
        ids_before, fingerprints_before = fetch_referenced_evidence_fingerprints(
            db, adapter.name
        )
        try:
            result = adapter.normalize(case, db, source_keys=active_source_keys)
        except Exception as exc:
            if active_source_keys:
                for key in active_source_keys:
                    rows = db.execute(
                        "SELECT sha256, path FROM ingested_files "
                        "WHERE sha256 = ? AND source_kind = ?",
                        [key, adapter.name],
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
        ids_after, fingerprints_after = fetch_referenced_evidence_fingerprints(
            db, adapter.name
        )
        invalidate_removed_evidence(db, ids_before - ids_after)
        # Same-ID content change under the same source identity: dependents
        # must be re-evaluated; link history is kept and the read-time
        # currentness check additionally refuses the changed rows as support.
        content_changed = {
            evidence_id
            for evidence_id in ids_before & ids_after
            if fingerprints_before.get(evidence_id)
            != fingerprints_after.get(evidence_id)
        }
        if content_changed:
            invalidate_removed_evidence(
                db,
                content_changed,
                reason=(
                    "Assessed evidence content changed under the same source "
                    "identity; re-evaluation required"
                ),
            )
        if result.source_kind == "evtx":
            counts["evtx_rows"] = result.rows
        elif result.source_kind == "mft":
            counts["mft_entries"] = result.rows
            counts["mft_timeline_rows"] = result.aux_rows
        elif result.source_kind == "prefetch":
            counts["prefetch_executions"] = result.rows
            counts["prefetch_timeline"] = result.aux_rows
        elif result.source_kind == "registry":
            counts["registry_artifacts"] = result.rows

    _update_source_status(db, active_source_keys, counts, raw_dir=case.raw_dir)

    return counts


def _raw_source_state(raw_dir: Path, source_kind: str, key: str) -> str:
    """Return ``empty``, ``nonempty``, or ``missing`` for one raw source."""
    patterns = {
        "evtx": f"evtx-{key}-*.jsonl",
        "mft": f"mft-entries-{key}.jsonl",
        "prefetch": f"prefetch-entries-{key}.jsonl",
    }
    pattern = patterns.get(source_kind)
    if not pattern:
        return "missing"
    paths = list(raw_dir.glob(pattern))
    if not paths:
        return "missing"
    return "nonempty" if any(path.stat().st_size > 0 for path in paths) else "empty"


def _update_source_status(
    db: CaseDB,
    source_keys: Collection[str] | None,
    counts: dict[str, int],
    *,
    raw_dir: Path | None = None,
) -> None:
    """Best-effort update of evidence_sources rows after normalization.

    When source_keys is None, updates all sources that have ingested_files entries.
    """
    if source_keys is not None:
        keys = [k for k in source_keys if k]
    else:
        rows = db.execute("SELECT DISTINCT sha256 FROM ingested_files").fetchall()
        keys = [str(row[0]) for row in rows if row[0]]

    timestamp_policy = configured_timestamp_policy()
    for key in keys:
        try:
            rows = db.execute(
                "SELECT sha256, source_kind FROM ingested_files WHERE sha256 = ?",
                (key,),
            ).fetchall()
            for row in rows:
                sha256: str = row[0]
                source_kind: str = row[1]
                table = {
                    "evtx": "evtx_events",
                    "mft": "mft_entries",
                    "prefetch": "prefetch_executions",
                }.get(source_kind)
                if table is None:
                    continue
                evtx_eligible = timestamp_year_range_sql("timestamp", timestamp_policy)
                # Normalized rows carry the ingested SHA-256 as their durable
                # source identity; the raw JSONL writers store it verbatim.
                metadata = db.execute(
                    "SELECT COUNT(*), "
                    f"MIN(timestamp) FILTER (WHERE {evtx_eligible}), "
                    f"MAX(timestamp) FILTER (WHERE {evtx_eligible}), "
                    "list(DISTINCT computer), list(DISTINCT channel) "
                    "FROM evtx_events WHERE source_file = ?"
                    if source_kind == "evtx"
                    else (
                        f"SELECT COUNT(*), NULL, NULL, [], [] FROM {table} "
                        "WHERE source_file = ?"
                    ),
                    [sha256],
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
                    eligible_time = timestamp_year_range_sql(
                        timestamp_column, timestamp_policy
                    )
                    time_row = db.execute(
                        f"SELECT "
                        f"MIN({timestamp_column}) FILTER (WHERE {eligible_time}), "
                        f"MAX({timestamp_column}) FILTER (WHERE {eligible_time}) "
                        f"FROM {timeline_table} WHERE source_file = ?",
                        [sha256],
                    ).fetchone()
                    min_time, max_time = time_row if time_row else (None, None)
                status = "normalized" if row_count > 0 else "empty"
                error_code = ""
                error_summary = ""
                if row_count == 0 and raw_dir is not None:
                    raw_state = _raw_source_state(raw_dir, source_kind, sha256)
                    if raw_state != "empty":
                        status = "failed"
                        error_code = "normalized_rows_missing"
                        error_summary = (
                            "Raw parser output was non-empty but no normalized rows "
                            "were found"
                            if raw_state == "nonempty"
                            else "Raw parser output file is missing"
                        )
                        logger.error(
                            "Normalization output missing for %s (sha256=%s): %s",
                            source_kind,
                            sha256,
                            error_summary,
                        )
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
                    error_code=error_code,
                    error_summary=error_summary,
                )
        except Exception as exc:
            logger.warning("Failed to update source status for key %s: %s", key, exc)
