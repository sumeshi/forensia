from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dateutil import parser as dt_parser

from forensia.core.case import Case
from forensia.db.database import CaseDB


# mft2es standard format: attributes.StandardInformation.data / attributes.FileName.data
# Timestamp field names in mft2es output (MACB: created/modified/mft_modified/accessed)
SI_FIELDS = {
    "SI_CREATED": "created",
    "SI_MODIFIED": "modified",
    "SI_ACCESSED": "accessed",
    "SI_MFT_MODIFIED": "mft_modified",
}
FN_FIELDS = {
    "FN_CREATED": "created",
    "FN_MODIFIED": "modified",
    "FN_ACCESSED": "accessed",
    "FN_MFT_MODIFIED": "mft_modified",
}


def _parse_ts(value: Any) -> Any:
    if not value:
        return None
    try:
        return dt_parser.parse(str(value)).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}


def normalize_mft(case: Case, db: CaseDB) -> tuple[int, int]:
    paths = sorted({*case.raw_dir.glob("mft.jsonl"), *case.raw_dir.glob("mft-*.jsonl")})
    if not paths:
        return 0, 0

    total_entries = 0
    total_timeline = 0
    for path in paths:
        source_file = None
        evidence_ids: set[str] = set()
        entry_rows = []
        timeline_rows = []

        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                source_file = source_file or record.get("source_file")

                header = record.get("header") or {}
                attrs = record.get("attributes") or {}
                si = (attrs.get("StandardInformation") or {}).get("data") or {}
                fn = (attrs.get("FileName") or {}).get("data") or {}

                record_number = _safe_int(header.get("record_number"))
                file_path = fn.get("path")
                file_name = Path(file_path).name if file_path else None

                entry_rows.append((
                    record.get("evidence_id"),
                    record.get("source_file"),
                    record_number,
                    file_path,
                    file_name,
                    Path(file_name).suffix.lstrip(".") if file_name else None,
                    _safe_bool(header.get("is_directory")),
                    _safe_bool(header.get("is_deleted")),
                    _safe_int(header.get("allocated_size") or header.get("size")),
                    _parse_ts(si.get("created")),
                    _parse_ts(si.get("modified")),
                    _parse_ts(si.get("accessed")),
                    _parse_ts(si.get("mft_modified")),
                    _parse_ts(fn.get("created")),
                    _parse_ts(fn.get("modified")),
                    _parse_ts(fn.get("accessed")),
                    _parse_ts(fn.get("mft_modified")),
                    json.dumps(record, ensure_ascii=False),
                    json.dumps([], ensure_ascii=False),
                    None,
                ))

                evidence_id = record.get("evidence_id")
                if evidence_id:
                    evidence_ids.add(str(evidence_id))
                for ts_type, field in {**SI_FIELDS, **FN_FIELDS}.items():
                    src = si if ts_type.startswith("SI_") else fn
                    ts = _parse_ts(src.get(field))
                    if ts is None:
                        continue
                    timeline_rows.append((
                        f"{evidence_id}-{ts_type.lower()}",
                        evidence_id,
                        record_number,
                        file_path,
                        ts,
                        ts_type,
                        f"{ts_type} for {file_path or file_name or 'unknown'}",
                        json.dumps([], ensure_ascii=False),
                    ))

        if source_file:
            db.execute("DELETE FROM mft_entries WHERE source_file = ?", (source_file,))
        if evidence_ids:
            placeholders = ", ".join("?" for _ in evidence_ids)
            db.execute(f"DELETE FROM mft_timeline WHERE evidence_id IN ({placeholders})", tuple(sorted(evidence_ids)))

        db.insert_many(
            """
            INSERT INTO mft_entries (
                evidence_id, source_file, record_number, file_path, file_name, extension,
                is_directory, is_deleted, size, si_created, si_modified, si_accessed,
                si_mft_modified, fn_created, fn_modified, fn_accessed, fn_mft_modified,
                raw_json, tags, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            entry_rows,
        )
        db.insert_many(
            """
            INSERT INTO mft_timeline (
                timeline_id, evidence_id, record_number, file_path, timestamp,
                timestamp_type, description, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            timeline_rows,
        )
        total_entries += len(entry_rows)
        total_timeline += len(timeline_rows)
    return total_entries, total_timeline
