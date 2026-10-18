from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from forensia.core.progress_event import ProgressEvent, validate_progress_event_fields
from forensia.db.database import CaseDB


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def record_progress_event(db: CaseDB, event: ProgressEvent) -> int:
    """Append one compact semantic event; its index orders the case history."""
    kind = event.get("kind")
    status = event.get("status")
    severity = event.get("severity")
    validate_progress_event_fields(
        str(kind or ""), str(status or ""), str(severity or "")
    )
    # The case Runtime is the single writer, so MAX+1 is a stable append cursor.
    event_index = int(
        db.execute(
            "SELECT COALESCE(MAX(event_index), 0) + 1 FROM trace.progress_events"
        ).fetchone()[0]
    )
    created_at = datetime.now(UTC).replace(tzinfo=None)
    db.execute(
        """
        INSERT INTO trace.progress_events (
            event_index, session_id, kind, severity, reason, refs, stage, status,
            iteration, summary, payload, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_index,
            event.get("session_id"),
            kind,
            severity,
            event.get("reason"),
            _json(event.get("refs", {})),
            event.get("stage"),
            status,
            event.get("iteration"),
            event.get("summary"),
            _json(event.get("attributes", {})),
            created_at,
        ),
    )
    return event_index


def list_progress_events(
    db: CaseDB, after_index: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    """Read durable case events after a cursor, in append order."""
    if after_index < 0 or limit < 1:
        raise ValueError("after_index must be nonnegative and limit must be positive")
    result = db.execute(
        """
        SELECT event_index, session_id, kind, severity, reason, refs, stage, status,
               iteration, summary, payload, created_at
        FROM trace.progress_events
        WHERE event_index > ?
        ORDER BY event_index
        LIMIT ?
        """,
        (after_index, limit),
    )
    columns = [item[0] for item in result.description]
    rows = [dict(zip(columns, row, strict=False)) for row in result.fetchall()]
    for row in rows:
        for key in ("refs", "payload"):
            value = row.get(key)
            if isinstance(value, str):
                row[key] = json.loads(value)
        if row.get("created_at") is not None:
            row["created_at"] = row["created_at"].isoformat()
    return rows
