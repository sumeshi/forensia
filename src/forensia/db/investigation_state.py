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


def set_preferred_hypothesis(db: CaseDB, hypothesis_id: str) -> None:
    """Save an unresolved hypothesis preference without changing eligibility."""
    row = db.execute(
        "SELECT status FROM hypotheses WHERE hypothesis_id = ?", [hypothesis_id]
    ).fetchone()
    if row is None:
        raise ValueError("hypothesis_not_found")
    if row[0] not in {"active", "deferred", "blocked", "needs_review", "untestable"}:
        raise ValueError("hypothesis_already_settled")
    ensure_investigation_state(db)
    db.execute(
        "UPDATE investigation_state SET preferred_hypothesis_id = ?, updated_at = now() "
        "WHERE state_id = 'case'",
        [hypothesis_id],
    )


def save_stop_reason(
    db: CaseDB,
    *,
    status: str,
    stop_reason_code: str = "",
    stop_reason: str = "",
    stop_summary: dict[str, int] | None = None,
) -> None:
    """Save the investigation stop reason to investigation_state."""
    db.execute(
        "UPDATE investigation_state SET status = ?, stop_reason_code = ?, "
        "stop_reason = ?, stop_summary = ?, updated_at = now() "
        "WHERE state_id = 'case'",
        [status, stop_reason_code, stop_reason, json.dumps(stop_summary or {})],
    )


def mark_investigation_started(db: CaseDB) -> None:
    """Mark a resumed or new investigation as active without changing its objective."""
    db.execute(
        "UPDATE investigation_state SET status = 'active', stop_reason_code = NULL, "
        "stop_reason = NULL, stop_summary = NULL, updated_at = now() "
        "WHERE state_id = 'case'"
    )


def load_investigation_state(db: CaseDB) -> dict[str, Any] | None:
    """Load the investigation state singleton."""
    row = db.execute(
        "SELECT state_id, objective, preferred_hypothesis_id, status, termination_policy, "
        "stop_reason_code, stop_reason, stop_summary, updated_at FROM investigation_state "
        "WHERE state_id = 'case'"
    ).fetchone()
    if not row:
        return None
    return {
        "state_id": row[0],
        "objective": row[1] or "",
        "preferred_hypothesis_id": row[2] or "",
        "status": row[3] or "active",
        "termination_policy": (
            row[4]
            if isinstance(row[4], dict)
            else json.loads(row[4])
            if isinstance(row[4], str)
            else None
        ),
        "stop_reason_code": row[5] or "",
        "stop_reason": row[6] or "",
        "stop_summary": (
            row[7]
            if isinstance(row[7], dict)
            else json.loads(row[7])
            if isinstance(row[7], str) and row[7]
            else {}
        ),
        "updated_at": row[8],
    }
