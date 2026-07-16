"""Investigation state management in the case database."""

from __future__ import annotations

import json
import logging
from typing import Any

from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)


def ensure_investigation_state(
    db: CaseDB,
    *,
    objective: str = "",
    status: str = "active",
    termination_policy: dict[str, Any] | None = None,
) -> None:
    """Ensure the investigation_state singleton exists. Insert only if absent."""
    existing = db.execute(
        "SELECT 1 FROM investigation_state WHERE state_id = 'case' LIMIT 1"
    ).fetchone()
    if existing is not None:
        if objective:
            db.execute(
                "UPDATE investigation_state SET objective = ? "
                "WHERE state_id = 'case' AND COALESCE(objective, '') = ''",
                [objective],
            )
        return
    db.execute(
        "INSERT INTO investigation_state (state_id, objective, status, termination_policy, created_at, updated_at) "
        "VALUES ('case', ?, ?, ?, now(), now())",
        [
            objective,
            status,
            json.dumps(termination_policy) if termination_policy else None,
        ],
    )


def save_stop_reason(
    db: CaseDB,
    *,
    status: str,
    stop_reason_code: str = "",
    stop_reason: str = "",
) -> None:
    """Save the investigation stop reason to investigation_state."""
    db.execute(
        "UPDATE investigation_state SET status = ?, stop_reason_code = ?, stop_reason = ?, updated_at = now() "
        "WHERE state_id = 'case'",
        [status, stop_reason_code, stop_reason],
    )


def mark_investigation_started(db: CaseDB) -> None:
    """Mark a resumed or new investigation as active without changing its objective."""
    db.execute(
        "UPDATE investigation_state SET status = 'active', stop_reason_code = NULL, "
        "stop_reason = NULL, updated_at = now() WHERE state_id = 'case'"
    )


def load_investigation_state(db: CaseDB) -> dict[str, Any] | None:
    """Load the investigation state singleton."""
    row = db.execute(
        "SELECT state_id, objective, status, termination_policy, "
        "stop_reason_code, stop_reason, updated_at FROM investigation_state "
        "WHERE state_id = 'case'"
    ).fetchone()
    if not row:
        return None
    return {
        "state_id": row[0],
        "objective": row[1] or "",
        "status": row[2] or "active",
        "termination_policy": (
            row[3]
            if isinstance(row[3], dict)
            else json.loads(row[3])
            if isinstance(row[3], str)
            else None
        ),
        "stop_reason_code": row[4] or "",
        "stop_reason": row[5] or "",
        "updated_at": row[6],
    }
