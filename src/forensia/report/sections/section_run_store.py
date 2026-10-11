"""Report projection receipts and evidence links."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from forensia.db.database import CaseDB
from forensia.report.evidence_refs import _extract_evidence_ids_from_value


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _store_section_run(
    db: CaseDB,
    *,
    section_key: str,
    block_heading: str,
    iteration: int | None,
    phase: str,
    payload: dict[str, Any],
    verdict: str | None = None,
) -> None:
    """Append one deterministic report projection or generation receipt."""
    if verdict is not None:
        from forensia.core.verdicts import assert_valid_verdict

        assert_valid_verdict(verdict, "section_verdict")
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    run_id = hashlib.sha256(
        f"{section_key}\0{block_heading}\0{iteration}\0{phase}\0{serialized}".encode()
    ).hexdigest()[:24]
    db.execute(
        """
        INSERT INTO section_runs (
            run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (run_id) DO NOTHING
        """,
        (
            run_id,
            section_key,
            block_heading,
            iteration,
            phase,
            serialized,
            verdict,
            _now(),
        ),
    )


def load_section_signature(db: CaseDB, section_key: str) -> str | None:
    """Return the most recently recorded current-input signature for a section."""
    row = db.execute(
        """
        SELECT payload
        FROM section_runs
        WHERE section_key = ? AND phase = 'projection'
        ORDER BY created_at DESC, run_id DESC
        LIMIT 1
        """,
        [section_key],
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except TypeError, ValueError:
        return None
    signature = payload.get("input_signature") if isinstance(payload, dict) else None
    return str(signature) if signature else None


def replace_section_evidence(
    db: CaseDB,
    section_key: str,
    evidence_results: list[dict[str, Any]],
) -> None:
    """Replace current section evidence links from the freshly rendered recipes."""
    db.execute("DELETE FROM section_evidence WHERE section_key = ?", [section_key])
    rows: list[tuple[Any, ...]] = []
    seen: set[tuple[str, str, str]] = set()
    now = _now()
    for result in evidence_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        heading = str(result.get("block_heading") or "")
        source_ref = str(
            result.get("source_ref") or result.get("keypoint") or "report_projection"
        )
        evidence_ids: list[str] = []
        for evidence_id in result.get("evidence_ids") or []:
            value = str(evidence_id or "").strip()
            if value:
                evidence_ids.append(value)
        for key in ("sample_rows", "head_rows", "tail_rows"):
            for row in result.get(key) or []:
                evidence_ids.extend(_extract_evidence_ids_from_value(row))
        for evidence_id in evidence_ids:
            key = (heading, source_ref, evidence_id)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                (
                    section_key,
                    heading,
                    evidence_id,
                    "observed",
                    source_ref,
                    now,
                )
            )
    if rows:
        db.insert_many(
            """
            INSERT INTO section_evidence (
                section_key, block_heading, evidence_id, role, source_query, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            """,
            rows,
        )
