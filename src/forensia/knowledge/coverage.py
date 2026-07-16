"""Evidence coverage tracking and capability declaration reader.

Reads artifact_capabilities.yaml and evidence_sufficiency.yaml,
and provides deterministic coverage computation from evidence_sources.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from forensia.db.database import CaseDB
from forensia.knowledge.resources import schema_dir

logger = logging.getLogger(__name__)


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


def compute_evidence_coverage(db: CaseDB) -> list[dict[str, Any]]:
    """Compute evidence coverage from evidence_sources and artifact capabilities.

    Returns a list of coverage entries for the evidence_coverage table.
    """
    capabilities = load_artifact_capabilities()
    families = capabilities.get("families", {})

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
                placeholders = ", ".join("?" for _ in event_ids)
                event_count = int(
                    db.execute(
                        f"SELECT COUNT(*) FROM evtx_events WHERE lower(channel) = lower(?) "
                        f"AND event_id IN ({placeholders})",
                        [required_channel, *event_ids],
                    ).fetchone()[0]
                )
                if event_count == 0:
                    state = "partial"
                    reason_code = "recording_configuration_unknown"

            all_hosts: set[str] = set()
            all_source_ids: list[str] = []
            min_t: datetime | None = None
            max_t: datetime | None = None

            for s in normalized + empty:
                all_source_ids.append(s["source_id"])
                for h in s.get("hosts", []):
                    if h:
                        all_hosts.add(h)
                t_min = s.get("min_time")
                t_max = s.get("max_time")
                if t_min and (min_t is None or t_min < min_t):
                    min_t = t_min
                if t_max and (max_t is None or t_max > max_t):
                    max_t = t_max

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
            source_ids, start_time, end_time, confidence, derived_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        "SELECT capability, state, reason_code, source_family FROM evidence_coverage"
    ).fetchall()
    summary: dict[str, dict[str, str]] = {}
    for cap, state, reason, family in rows:
        key = f"{family}:{cap}"
        summary[key] = {"state": state, "reason": reason or "", "family": family}
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
