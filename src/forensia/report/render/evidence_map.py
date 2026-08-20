"""Build an evidence_id -> source-record reference map for the rendered report.

Derived from the final report body (one-directional: section writers never see
it), so it adds no coupling into the ai/ layer. The map feeds the Evidence
References appendix in report.md and the hover/anchor links in report.html.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN


def _summarize_evtx_row(row: dict[str, Any]) -> str:
    parts = []
    if row.get("event_id"):
        parts.append(str(row["event_id"]))
    if row.get("channel"):
        parts.append(str(row["channel"]))
    user = row.get("target_user") or row.get("subject_user")
    computer = row.get("computer")
    if user and computer:
        parts.append(f"{user}@{computer}")
    elif computer:
        parts.append(str(computer))
    src = str(row.get("src_ip") or "")
    if src and src not in ("-", "::1", "127.0.0.1"):
        parts.append(f"src={src}")
    if row.get("service_name"):
        parts.append(f"service={row['service_name']}")
    return " ".join(parts) or "evtx event"


def _summarize_mft_row(row: dict[str, Any]) -> str:
    parts = []
    if row.get("file_path"):
        parts.append(str(row["file_path"]))
    elif row.get("file_name"):
        parts.append(str(row["file_name"]))
    if row.get("si_modified"):
        parts.append(f"modified={row['si_modified']}")
    return " ".join(parts) or "mft entry"


def _summarize_prefetch_row(row: dict[str, Any]) -> str:
    parts = []
    if row.get("executable_name"):
        parts.append(str(row["executable_name"]))
    if row.get("exec_count"):
        parts.append(f"runs={row['exec_count']}")
    if row.get("last_exec_time"):
        parts.append(f"last={row['last_exec_time']}")
    elif row.get("exec_time"):
        parts.append(f"at={row['exec_time']}")
    return " ".join(parts) or "prefetch execution"


def _summarize_registry_row(row: dict[str, Any]) -> str:
    parts = [
        value
        for value in (row.get("plugin"), row.get("hive"), row.get("key_path"))
        if value
    ]
    if row.get("value_name"):
        parts.append(f"value={row['value_name']}")
    return " ".join(str(part) for part in parts) or "registry artifact"


def _pick_timestamp(row: dict[str, Any]) -> str:
    for key in ("timestamp", "last_exec_time", "exec_time", "si_modified"):
        val = row.get(key)
        if val:
            return str(val)
    return ""


def _summarize_row(row: dict[str, Any], source: str) -> str:
    if source == "evtx_events":
        return _summarize_evtx_row(row)
    if source == "mft_entries":
        return _summarize_mft_row(row)
    if source in ("prefetch_executions", "prefetch_timeline"):
        return _summarize_prefetch_row(row)
    if source == "registry_artifacts":
        return _summarize_registry_row(row)
    return ""


def build_evidence_map(db: CaseDB, body: str) -> dict[str, dict[str, str]]:
    """Scan body for evidence IDs and resolve each to {source, timestamp, summary}."""
    ids = sorted(set(EVIDENCE_ID_PATTERN.findall(body)))
    if not ids:
        return {}

    records = fetch_evidence_records(db, ids)
    found: dict[str, dict[str, str]] = {}

    for eid, row in records.items():
        source = row.get("_source", "unknown")
        found[eid] = {
            "source": source,
            "timestamp": _pick_timestamp(row),
            "summary": _summarize_row(row, source),
        }

    for eid in ids:
        if eid not in found:
            found[eid] = {
                "source": "unresolved",
                "timestamp": "",
                "summary": "ID not found in evidence tables",
            }

    return found


def write_evidence_map(
    db: CaseDB, body: str, output_dir: Path
) -> dict[str, dict[str, str]]:
    """Build, persist (reports/evidence_map.json), and return the evidence map."""
    evidence_map = build_evidence_map(db, body)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence_map.json").write_text(
        json.dumps(evidence_map, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return evidence_map


def render_evidence_references(evidence_map: dict[str, dict[str, str]]) -> str:
    """Render the evidence map as a `## Evidence References` markdown section."""
    if not evidence_map:
        return ""
    lines = ["## Evidence References", ""]
    for eid, info in sorted(evidence_map.items()):
        ref_parts = [f"`{eid}`"]
        if info.get("timestamp"):
            ref_parts.append(str(info["timestamp"]))
        if info.get("source") and info["source"] != "unresolved":
            ref_parts.append(str(info["source"]))
        if info.get("summary"):
            ref_parts.append(f"— {info['summary']}")
        lines.append("- " + " ".join(ref_parts))
    return "\n".join(lines)
