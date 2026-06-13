from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from forensia.db.database import CaseDB

MAX_PROGRESS_EVENTS = 1000


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def clear_progress_events(db: CaseDB) -> None:
    """Remove all progress events from the database."""
    db.execute("DELETE FROM progress_events")


def record_progress_event(db: CaseDB, payload: dict[str, Any]) -> int:
    """Insert a progress event and enforce the event count cap (oldest are pruned)."""
    event_index = int(
        db.execute(
            "SELECT COALESCE(MAX(event_index), 0) + 1 FROM progress_events"
        ).fetchone()[0]
    )
    created_at = datetime.now(UTC).replace(tzinfo=None)
    db.execute(
        """
        INSERT INTO progress_events (
            event_index, stage, status, iteration, current_query, summary, payload, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_index,
            payload.get("stage"),
            payload.get("status"),
            payload.get("iteration"),
            payload.get("current_query"),
            payload.get("summary"),
            _json(payload),
            created_at,
        ),
    )
    db.execute(
        """
        DELETE FROM progress_events
        WHERE event_index <= (
            SELECT COALESCE(MAX(event_index), 0) - ?
            FROM progress_events
        )
        """,
        (MAX_PROGRESS_EVENTS,),
    )
    return event_index


def list_progress_events(
    db: CaseDB, after_index: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    """Return progress events after a given index, with parsed payload JSON."""
    result = db.execute(
        """
        SELECT event_index, stage, status, iteration, current_query, summary, payload, created_at
        FROM progress_events
        WHERE event_index > ?
        ORDER BY event_index
        LIMIT ?
        """,
        (after_index, limit),
    )
    columns = [item[0] for item in result.description]
    rows = [dict(zip(columns, row, strict=False)) for row in result.fetchall()]
    for row in rows:
        payload = row.get("payload")
        if isinstance(payload, str):
            row["payload"] = json.loads(payload)
        row["created_at"] = (
            row.get("created_at").isoformat() if row.get("created_at") else None
        )
    return rows
