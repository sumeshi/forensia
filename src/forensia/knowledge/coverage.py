"""Evidence coverage tracking and capability declaration reader.

Reads artifact_capabilities.yaml and evidence_sufficiency.yaml,
and provides deterministic coverage computation from evidence_sources.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from forensia.db.database import CaseDB
from forensia.evidence.timestamp_policy import TimestampPolicy
from forensia.knowledge.resources import schema_dir

logger = logging.getLogger(__name__)


_TIMESTAMP_TABLES = {
    "evtx": ("evtx_events", "timestamp"),
    "mft": ("mft_timeline", "timestamp"),
    "prefetch": ("prefetch_timeline", "exec_time"),
}


def _source_file_values(db: CaseDB, source_ids: list[str]) -> list[str]:
    """Return current stable IDs plus paths used by legacy normalized rows."""
    if not source_ids:
        return []
    placeholders = ", ".join("?" for _ in source_ids)
    legacy_paths = db.execute(
        f"SELECT path FROM ingested_files WHERE sha256 IN ({placeholders})",
        source_ids,
    ).fetchall()
    return list(
        dict.fromkeys([*source_ids, *(str(row[0]) for row in legacy_paths if row[0])])
    )


def _case_evidence_window(
    sources_by_family: dict[str, list[dict[str, Any]]],
    reference_families: list[str],
) -> tuple[datetime, datetime] | None:
    """Derive the case window from higher-confidence timestamp families."""
    starts: list[datetime] = []
    ends: list[datetime] = []
    for family in reference_families:
        for source in sources_by_family.get(family, []):
            if source["ingest_status"] not in {"normalized", "parsed"}:
                continue
            if source.get("min_time"):
                starts.append(source["min_time"])
            if source.get("max_time"):
                ends.append(source["max_time"])
    if not starts or not ends:
        return None
    return min(starts), max(ends)


def _timestamp_stats(
    db: CaseDB,
    family: str,
    source_ids: list[str],
    policy: TimestampPolicy,
    evidence_window: tuple[datetime, datetime] | None,
) -> tuple[datetime | None, datetime | None, dict[str, int]]:
    """Aggregate eligible bounds and exclusions from normalized rows.

    The raw timestamp remains in its normalized artifact row; this projection is
    used only for analysis coverage.  Querying rows here avoids promoting a
    source-level raw MIN/MAX and reports the number of excluded observations.
    """
    table_spec = _TIMESTAMP_TABLES.get(family)
    if table_spec is None or not source_ids:
        return None, None, {}
    table, column = table_spec
    source_values = _source_file_values(db, source_ids)
    placeholders = ", ".join("?" for _ in source_values)

    absolute = (
        f"EXTRACT(year FROM {column}) BETWEEN "
        f"{policy.minimum_year} AND {policy.maximum_year}"
    )
    eligible = absolute
    select_params: list[Any] = []
    outside_expression = "0"
    if evidence_window is not None:
        margin = timedelta(days=policy.case_window_margin_days)
        lower = evidence_window[0] - margin
        upper = evidence_window[1] + margin
        eligible = f"({absolute}) AND {column} BETWEEN ? AND ?"
        outside_expression = (
            f"COUNT(*) FILTER (WHERE ({absolute}) AND NOT ({column} BETWEEN ? AND ?))"
        )
        # ``eligible`` appears in both MIN and MAX, then the outside-window
        # expression contributes the third pair of placeholders.
        select_params.extend([lower, upper, lower, upper, lower, upper])

    row = db.execute(
        f"""
        SELECT
            MIN({column}) FILTER (WHERE {eligible}),
            MAX({column}) FILTER (WHERE {eligible}),
            COUNT(*) FILTER (WHERE {column} IS NULL),
            COUNT(*) FILTER (
                WHERE {column} IS NOT NULL
                  AND EXTRACT(year FROM {column}) <= {policy.sentinel_max_year}
            ),
            COUNT(*) FILTER (
                WHERE EXTRACT(year FROM {column}) > {policy.sentinel_max_year}
                  AND EXTRACT(year FROM {column}) < {policy.minimum_year}
            ),
            COUNT(*) FILTER (
                WHERE EXTRACT(year FROM {column}) > {policy.maximum_year}
            ),
            {outside_expression}
        FROM {table}
        WHERE source_file IN ({placeholders})
        """,
        [*select_params, *source_values],
    ).fetchone()
    if row is None:
        return None, None, {}
    reason_names = (
        "parser-invalid",
        "sentinel",
        "pre-analysis-epoch",
        "overflow",
        "outside-analysis-window",
    )
    excluded = {
        reason: int(count)
        for reason, count in zip(reason_names, row[2:], strict=True)
        if int(count or 0) > 0
    }
    return row[0], row[1], excluded


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and return its contents."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_artifact_capabilities() -> dict[str, Any]:
    """Load artifact capability declarations from _schema/artifact_capabilities.yaml."""
    path = schema_dir() / "artifact_capabilities.yaml"
    if not path.exists():
        logger.warning("artifact_capabilities.yaml not found at %s", path)
        return {}
    return _load_yaml(path)


def load_evidence_sufficiency_policy() -> dict[str, Any]:
    """Load evidence sufficiency policy from _schema/evidence_sufficiency.yaml."""
    path = schema_dir() / "evidence_sufficiency.yaml"
    if not path.exists():
        logger.warning("evidence_sufficiency.yaml not found at %s", path)
        return {}
    return _load_yaml(path)


def _check_row_count_invariant(
    db: CaseDB,
    sources_by_family: dict[str, list[dict[str, Any]]],
) -> None:
    """Check that normalized sources with row_count=0 actually have 0 rows in the table.

    Logs a warning for invariant violations (source marked normalized but table
    has rows while row_count says 0). This indicates a path resolution failure
    in _update_source_status.
    """
    table_map = {
        "evtx": "evtx_events",
        "mft": "mft_entries",
        "prefetch": "prefetch_executions",
    }
    for family, sources in sources_by_family.items():
        table = table_map.get(family)
        if not table:
            continue
        for source in sources:
            if source["ingest_status"] not in {"normalized", "empty", "parsed"}:
                continue
            # New normalized rows carry the stable SHA source identity.  The
            # path subquery is retained for legacy case databases.
            try:
                actual = db.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE source_file = ? OR source_file IN "
                    "(SELECT path FROM ingested_files WHERE sha256 = ?)",
                    [source["source_id"], source["source_id"]],
                ).fetchone()
                actual_count = int(actual[0] or 0) if actual else 0
                expected_count = int(source["row_count"] or 0)
                if actual_count != expected_count:
                    logger.warning(
                        "Coverage invariant violation: source %s (%s) records "
                        "row_count=%d but %s contains %d rows",
                        source["source_id"][:12],
                        family,
                        expected_count,
                        table,
                        actual_count,
                    )
            except Exception as exc:
                logger.warning(
                    "Coverage invariant check failed for source %s: %s",
                    source["source_id"][:12],
                    exc,
                )


def compute_evidence_coverage(db: CaseDB) -> list[dict[str, Any]]:
    """Compute evidence coverage from evidence_sources and artifact capabilities.

    Returns a list of coverage entries for the evidence_coverage table.
    """
    capabilities = load_artifact_capabilities()
    families = capabilities.get("families", {})
    timestamp_config = capabilities.get("timestamp_policy", {})
    timestamp_policy = TimestampPolicy.from_mapping(timestamp_config)

    rows = db.execute(
        "SELECT source_id, artifact_family, ingest_status, channel, hosts, "
        "min_time, max_time, row_count FROM evidence_sources"
    ).fetchall()

    sources_by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        source = {
            "source_id": row[0],
            "artifact_family": row[1],
            "ingest_status": row[2],
            "channel": row[3],
            "hosts": (
                json.loads(row[4])
                if isinstance(row[4], str)
                else row[4]
                if isinstance(row[4], list)
                else []
            ),
            "min_time": row[5],
            "max_time": row[6],
            "row_count": row[7],
        }
        family = source["artifact_family"]
        sources_by_family.setdefault(family, []).append(source)

    # Invariant check: normalized sources with row_count=0 but table has rows
    _check_row_count_invariant(db, sources_by_family)
    evidence_window = _case_evidence_window(
        sources_by_family,
        [str(item) for item in timestamp_config.get("reference_families", [])],
    )

    coverage_entries: list[dict[str, Any]] = []
    now = datetime.now(UTC)

    for family, family_config in families.items():
        caps = family_config.get("capabilities", {})
        sources = sources_by_family.get(family, [])

        for cap_name, cap_config in caps.items():
            if not sources:
                coverage_entries.append(
                    {
                        "capability": cap_name,
                        "host": "",
                        "channel": cap_config.get("channel", ""),
                        "source_family": family,
                        "state": "unavailable",
                        "reason_code": "artifact_not_collected",
                        "source_ids": [],
                        "start_time": None,
                        "end_time": None,
                        "confidence": 0.0,
                        "derived_at": now,
                    }
                )
                continue

            scoped_sources = sources
            required_channel = str(cap_config.get("channel") or "")
            channel_reason = ""
            if family == "evtx" and required_channel:
                matching = [
                    source
                    for source in sources
                    if str(source.get("channel") or "").lower()
                    == required_channel.lower()
                ]
                unknown_channel = [
                    source for source in sources if not source.get("channel")
                ]
                if matching:
                    scoped_sources = matching
                elif unknown_channel:
                    scoped_sources = unknown_channel
                    channel_reason = "source_channel_unknown"
                else:
                    scoped_sources = []
                    channel_reason = "required_channel_not_collected"

            normalized = [
                s
                for s in scoped_sources
                if s["ingest_status"] in ("normalized", "parsed")
            ]
            failed = [s for s in scoped_sources if s["ingest_status"] == "failed"]
            empty = [s for s in scoped_sources if s["ingest_status"] == "empty"]

            if not normalized and not empty:
                if failed:
                    state = "degraded"
                    reason_code = "ingest_failed"
                elif channel_reason:
                    state = "unavailable" if not scoped_sources else "partial"
                    reason_code = channel_reason
                else:
                    state = "unavailable"
                    reason_code = "artifact_not_collected"
            elif normalized:
                total_rows = sum(s["row_count"] for s in normalized)
                if total_rows == 0:
                    state = "partial"
                    reason_code = "empty_parser_result"
                else:
                    state = "available"
                    reason_code = ""
            else:
                state = "partial"
                reason_code = "empty_parser_result"

            if channel_reason and normalized:
                state = "partial"
                reason_code = channel_reason

            event_ids = [int(item) for item in cap_config.get("event_ids", [])]
            if family == "evtx" and normalized and event_ids and not channel_reason:
                event_placeholders = ", ".join("?" for _ in event_ids)
                source_values = _source_file_values(
                    db, [str(source["source_id"]) for source in normalized]
                )
                source_placeholders = ", ".join("?" for _ in source_values)
                event_count = int(
                    db.execute(
                        f"SELECT COUNT(*) FROM evtx_events WHERE lower(channel) = lower(?) "
                        f"AND event_id IN ({event_placeholders}) "
                        f"AND source_file IN ({source_placeholders})",
                        [required_channel, *event_ids, *source_values],
                    ).fetchone()[0]
                )
                if event_count == 0:
                    state = "partial"
                    reason_code = "recording_configuration_unknown"

            all_hosts: set[str] = set()
            all_source_ids: list[str] = []

            for s in normalized + empty:
                all_source_ids.append(s["source_id"])
                for h in s.get("hosts", []):
                    if h:
                        all_hosts.add(h)

            min_t, max_t, excluded_timestamps = _timestamp_stats(
                db,
                family,
                [s["source_id"] for s in normalized],
                timestamp_policy,
                evidence_window,
            )

            for s in failed:
                all_source_ids.append(s["source_id"])

            host_val = "" if len(all_hosts) != 1 else next(iter(all_hosts))

            coverage_entries.append(
                {
                    "capability": cap_name,
                    "host": host_val,
                    "channel": cap_config.get("channel", ""),
                    "source_family": family,
                    "state": state,
                    "reason_code": reason_code,
                    "source_ids": all_source_ids,
                    "start_time": min_t,
                    "end_time": max_t,
                    "excluded_timestamps": excluded_timestamps,
                    "confidence": 0.9
                    if state == "available"
                    else 0.5
                    if state == "partial"
                    else 0.1,
                    "derived_at": now,
                }
            )

    return coverage_entries


def refresh_evidence_coverage(db: CaseDB) -> int:
    """Recompute and persist evidence_coverage table. Returns number of entries."""
    entries = compute_evidence_coverage(db)
    db.execute("DELETE FROM evidence_coverage")
    if not entries:
        return 0
    db.insert_many(
        """
        INSERT INTO evidence_coverage (
            capability, host, channel, source_family, state, reason_code,
            source_ids, start_time, end_time, excluded_timestamps, confidence, derived_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            [
                e["capability"],
                e["host"],
                e["channel"],
                e["source_family"],
                e["state"],
                e["reason_code"],
                e["source_ids"],
                e["start_time"],
                e["end_time"],
                e.get("excluded_timestamps", {}),
                e["confidence"],
                e["derived_at"],
            ]
            for e in entries
        ],
    )
    return len(entries)


def get_coverage_summary(db: CaseDB) -> dict[str, Any]:
    """Get a summary of current evidence coverage for prompts/UI."""
    rows = db.execute(
        "SELECT capability, state, reason_code, source_family, source_ids FROM evidence_coverage"
    ).fetchall()
    summary: dict[str, dict[str, Any]] = {}
    for cap, state, reason, family, source_ids in rows:
        key = f"{family}:{cap}"
        # Parse source_ids if it's a JSON string
        parsed_ids = source_ids
        if isinstance(source_ids, str):
            try:
                import json

                parsed_ids = json.loads(source_ids)
            except Exception:
                parsed_ids = []
        summary[key] = {
            "state": state,
            "reason": reason or "",
            "family": family,
            "source_ids": parsed_ids or [],
        }
    return summary


def get_capability_for_table(table_name: str) -> list[str]:
    """Return capability names that use the given table."""
    capabilities = load_artifact_capabilities()
    result = []
    for family_config in capabilities.get("families", {}).values():
        if table_name in family_config.get("tables", []):
            for cap_name in family_config.get("capabilities", {}):
                result.append(cap_name)
    return result


def infer_capabilities(text: str) -> list[str]:
    """Infer relevant capabilities from known tables and declared Event IDs."""
    normalized = text.lower()
    numeric_tokens = {
        int(item)
        for item in re.findall(
            r"(?<![a-z0-9])([1-9][0-9]{2,4})(?![a-z0-9])", normalized
        )
    }
    declarations = load_artifact_capabilities().get("families", {})
    inferred: set[str] = set()
    for family_config in declarations.values():
        if not any(
            str(table).lower() in normalized
            for table in family_config.get("tables", [])
        ):
            continue
        capabilities = family_config.get("capabilities", {})
        event_matches = {
            name
            for name, config in capabilities.items()
            if numeric_tokens & {int(item) for item in config.get("event_ids", [])}
        }
        inferred.update(event_matches or capabilities.keys())
    return sorted(inferred)
