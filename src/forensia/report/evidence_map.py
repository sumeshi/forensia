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
from forensia.db.query import fetch_records
from forensia.report.keypoints import EVIDENCE_ID_PATTERN


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


# Per-table lookup: (sql with {placeholders}, timestamp key, summarizer).
_TABLE_LOOKUPS: list[tuple[str, str, Any]] = [
    (
        "SELECT evidence_id, timestamp, event_id, channel, computer, target_user, subject_user, src_ip, service_name "
        "FROM evtx_events WHERE evidence_id IN ({placeholders})",
        "evtx_events",
        _summarize_evtx_row,
    ),
    (
        "SELECT evidence_id, si_modified AS timestamp, file_name, file_path, si_modified "
        "FROM mft_entries WHERE evidence_id IN ({placeholders})",
        "mft_entries",
        _summarize_mft_row,
    ),
    (
        "SELECT evidence_id, last_exec_time AS timestamp, executable_name, exec_count, last_exec_time "
        "FROM prefetch_executions WHERE evidence_id IN ({placeholders})",
        "prefetch_executions",
        _summarize_prefetch_row,
    ),
    (
        "SELECT evidence_id, exec_time AS timestamp, executable_name, exec_time "
        "FROM prefetch_timeline WHERE evidence_id IN ({placeholders})",
        "prefetch_timeline",
        _summarize_prefetch_row,
    ),
]


def build_evidence_map(db: CaseDB, body: str) -> dict[str, dict[str, str]]:
    """Scan body for evidence IDs and resolve each to {source, timestamp, summary}."""
    ids = sorted(set(EVIDENCE_ID_PATTERN.findall(body)))
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    found: dict[str, dict[str, str]] = {}
    for sql_template, source, summarizer in _TABLE_LOOKUPS:
        rows = fetch_records(db, sql_template.format(placeholders=placeholders), tuple(ids))
        for row in rows:
            eid = str(row.get("evidence_id") or "")
            if not eid or eid in found:
                continue
            found[eid] = {
                "source": source,
                "timestamp": str(row.get("timestamp") or ""),
                "summary": summarizer(row),
            }
    for eid in ids:
        if eid not in found:
            found[eid] = {"source": "unresolved", "timestamp": "", "summary": "ID not found in evidence tables"}
    return found


def write_evidence_map(db: CaseDB, body: str, output_dir: Path) -> dict[str, dict[str, str]]:
    """Build, persist (reports/evidence_map.json), and return the evidence map."""
    evidence_map = build_evidence_map(db, body)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence_map.json").write_text(
        json.dumps(evidence_map, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
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
