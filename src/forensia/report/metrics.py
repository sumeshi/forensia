"""Deterministic case metrics shared by report tables and LLM projections.

DuckDB is the authority for these values.  Report prose must consume this
projection rather than independently counting rows (or asking the model to
count them), so a metric such as the number of 4648 events has one meaning in
every section.
"""

from __future__ import annotations

from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import event_context_eligible, load_event_id_hints


def query_case_metrics(db: CaseDB) -> dict[str, Any]:
    """Return compact, deterministic metrics for report generation.

    Host identity is canonicalized as ``UPPER(TRIM(computer))``.  The
    canonical key is used for counts and grouping; ``display_names`` retains
    observed spellings without pretending they are separate systems.
    Artifact counts are read from their authoritative normalized tables, while
    ``artifact_source_coverage`` records the ingested source families and
    statuses when available.
    """

    counts = fetch_records(
        db,
        """
        SELECT event_id, COUNT(*) AS count
        FROM evtx_events
        WHERE event_id IS NOT NULL
        GROUP BY event_id
        ORDER BY event_id
        """,
    )
    event_counts = {
        str(int(row["event_id"])): int(row["count"] or 0)
        for row in counts
        if row.get("event_id") is not None
    }
    # Numeric event counts remain raw telemetry.  Semantic counts are derived
    # generically from the YAML catalog's channel/provider constraints, so an
    # unrelated provider reusing an event ID cannot borrow its meaning.
    hints = load_event_id_hints()
    constrained_ids = sorted(
        event_id
        for event_id, hint in hints.items()
        if hint.get("channels") or hint.get("providers")
    )
    semantic_event_counts: dict[str, int] = {}
    semantic_event_metadata: dict[str, dict[str, Any]] = {}
    if constrained_ids:
        placeholders = ", ".join("?" for _ in constrained_ids)
        semantic_rows = fetch_records(
            db,
            f"""
            WITH contextual AS (
              SELECT event_id,
                     LOWER(COALESCE(channel, json_extract_string(raw_json, '$.winlog.channel'), '')) AS channel,
                     LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) AS provider
              FROM evtx_events
              WHERE event_id IN ({placeholders})
            )
            SELECT event_id, channel, provider, COUNT(*) AS count
            FROM contextual
            GROUP BY event_id, channel, provider
            """,
            tuple(constrained_ids),
        )
        for row in semantic_rows:
            event_id = int(row["event_id"])
            if not event_context_eligible(
                event_id,
                channel=row.get("channel"),
                provider=row.get("provider"),
            ):
                continue
            key = str(event_id)
            semantic_event_counts[key] = semantic_event_counts.get(key, 0) + int(
                row["count"] or 0
            )
    for event_id in constrained_ids:
        hint = hints[event_id]
        key = str(event_id)
        semantic_event_metadata[key] = {
            "event_id": event_id,
            "count": semantic_event_counts.get(key, 0),
            "catalog_title": hint.get("title", ""),
            "catalog_channels": list(hint.get("channels") or []),
            "catalog_providers": list(hint.get("providers") or []),
        }

    host_rows = fetch_records(
        db,
        """
        WITH grouped AS (
          SELECT
            UPPER(TRIM(computer)) AS canonical,
            TRIM(computer) AS display_name,
            COUNT(*) AS event_count
          FROM evtx_events
          WHERE COALESCE(TRIM(computer), '') != ''
          GROUP BY UPPER(TRIM(computer)), TRIM(computer)
        )
        ,ranked AS (
          SELECT *, ROW_NUMBER() OVER (
            PARTITION BY canonical ORDER BY event_count DESC, display_name ASC
          ) AS display_rank
          FROM grouped
        )
        SELECT
          canonical,
          MAX(display_name) FILTER (WHERE display_rank = 1) AS display_name,
          SUM(event_count) AS event_count,
          COUNT(*) AS observed_spellings
        FROM ranked
        GROUP BY canonical
        ORDER BY canonical
        """,
    )

    artifact_counts: dict[str, int] = {}
    for family, table in (
        ("evtx", "evtx_events"),
        ("mft", "mft_entries"),
        ("prefetch", "prefetch_executions"),
    ):
        row = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        artifact_counts[family] = int(row[0] or 0) if row else 0

    source_coverage: list[dict[str, Any]] = []
    try:
        source_rows = fetch_records(
            db,
            """
            SELECT artifact_family, COUNT(*) AS source_count,
                   SUM(COALESCE(row_count, 0)) AS source_rows,
                   STRING_AGG(DISTINCT COALESCE(ingest_status, 'unknown'), ', ' ORDER BY COALESCE(ingest_status, 'unknown')) AS statuses
            FROM evidence_sources
            GROUP BY artifact_family
            ORDER BY artifact_family
            """,
        )
    except Exception:
        # Older in-memory test databases may only contain normalized tables.
        source_rows = []
    for row in source_rows:
        source_coverage.append(
            {
                "artifact_family": row.get("artifact_family"),
                "source_count": int(row.get("source_count") or 0),
                "source_rows": int(row.get("source_rows") or 0),
                "statuses": str(row.get("statuses") or "unknown"),
            }
        )

    return {
        "authority": "DuckDB normalized evidence; use these values instead of recounting in prose",
        "event_counts": event_counts,
        "semantic_event_counts": semantic_event_counts,
        "semantic_event_metadata": semantic_event_metadata,
        "normalized_host_count": len(host_rows),
        "hosts": [
            {
                "canonical": row.get("canonical"),
                "display_name": row.get("display_name"),
                "event_count": int(row.get("event_count") or 0),
                "observed_spellings": int(row.get("observed_spellings") or 0),
            }
            for row in host_rows
        ],
        "artifact_row_counts": artifact_counts,
        "artifact_source_coverage": source_coverage,
    }
