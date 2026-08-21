"""Hypothesis relationship management: validation, cycle detection, propagation."""

from __future__ import annotations

import logging
from typing import Any

from forensia.ai.hypotheses.hypothesis_model import (
    _description_has_material_unknown,
)
from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)

VALID_RELATION_TYPES = frozenset(
    [
        "parent_of",
        "prerequisite_for",
        "derived_from",
        "contradicts",
        "alternative_to",
        "supersedes",
    ]
)

SYMMETRIC_RELATION_TYPES = frozenset(["contradicts", "alternative_to"])

CONFLICTING_PAIRS = [
    ("parent_of", "parent_of"),
    ("prerequisite_for", "alternative_to"),
    ("supersedes", "supersedes"),
]


def validate_relation(
    *,
    from_id: str,
    to_id: str,
    relation_type: str,
    existing_relations: list[tuple[str, str, str]],
) -> str | None:
    """Validate a proposed relation. Returns error message or None if valid."""
    if relation_type not in VALID_RELATION_TYPES:
        return f"Invalid relation type: {relation_type}"
    if from_id == to_id:
        return "Self-edge not allowed"
    if not from_id or not to_id:
        return "Both from_id and to_id required"

    for pair in CONFLICTING_PAIRS:
        if relation_type == pair[0]:
            reverse = (to_id, from_id, pair[1])
            if reverse in existing_relations:
                return f"Conflicting: {pair[0]} conflicts with existing {pair[1]}"

    for ef, et, ert in existing_relations:
        if ef == from_id and et == to_id and ert == relation_type:
            return "Duplicate relation"
        if relation_type in SYMMETRIC_RELATION_TYPES:
            if ef == to_id and et == from_id and ert == relation_type:
                return "Duplicate symmetric relation"

    return None


def check_cycle(
    db: CaseDB,
    *,
    from_id: str,
    to_id: str,
    relation_type: str,
) -> bool:
    """Check if adding this relation would create a cycle.

    Returns True if a cycle would be created.
    """
    if relation_type in SYMMETRIC_RELATION_TYPES:
        return False

    visited: set[str] = set()
    queue = [to_id]
    while queue:
        next_queue = []
        for current in queue:
            if current == from_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            rows = db.execute(
                "SELECT to_hypothesis_id FROM hypothesis_relations "
                "WHERE from_hypothesis_id = ? AND relation_type IN ('parent_of', 'prerequisite_for', 'derived_from', 'supersedes')",
                [current],
            ).fetchall()
            for r in rows:
                if r[0] not in visited:
                    next_queue.append(r[0])
        queue = next_queue
    return False


def insert_relation(
    db: CaseDB,
    *,
    from_id: str,
    to_id: str,
    relation_type: str,
    origin: str = "code",
    confidence: float = 1.0,
    rationale: str = "",
    created_session: str = "",
) -> bool:
    """Insert a validated relation. Returns True if inserted."""
    known = {
        str(row[0])
        for row in db.execute(
            "SELECT hypothesis_id FROM hypotheses WHERE hypothesis_id IN (?, ?)",
            [from_id, to_id],
        ).fetchall()
    }
    if known != {from_id, to_id}:
        logger.warning("Relation rejected: unknown hypothesis reference")
        return False
    existing = db.execute(
        "SELECT from_hypothesis_id, to_hypothesis_id, relation_type FROM hypothesis_relations"
    ).fetchall()

    error = validate_relation(
        from_id=from_id,
        to_id=to_id,
        relation_type=relation_type,
        existing_relations=existing,
    )
    if error:
        logger.warning("Relation rejected: %s", error)
        return False

    if check_cycle(db, from_id=from_id, to_id=to_id, relation_type=relation_type):
        logger.warning(
            "Relation rejected: would create cycle from %s to %s", from_id, to_id
        )
        return False

    if relation_type in SYMMETRIC_RELATION_TYPES and from_id > to_id:
        from_id, to_id = to_id, from_id

    db.execute(
        """
        INSERT INTO hypothesis_relations (
            from_hypothesis_id, to_hypothesis_id, relation_type,
            origin, confidence, rationale, created_session, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, now())
        ON CONFLICT (from_hypothesis_id, to_hypothesis_id, relation_type) DO NOTHING
        """,
        [from_id, to_id, relation_type, origin, confidence, rationale, created_session],
    )
    return True


def get_relations_for_hypothesis(
    db: CaseDB, hypothesis_id: str
) -> list[dict[str, Any]]:
    """Get all relations involving a hypothesis."""
    rows = db.execute(
        "SELECT from_hypothesis_id, to_hypothesis_id, relation_type, "
        "origin, confidence, rationale FROM hypothesis_relations "
        "WHERE from_hypothesis_id = ? OR to_hypothesis_id = ?",
        [hypothesis_id, hypothesis_id],
    ).fetchall()
    return [
        {
            "from_hypothesis_id": r[0],
            "to_hypothesis_id": r[1],
            "relation_type": r[2],
            "origin": r[3],
            "confidence": r[4],
            "rationale": r[5],
        }
        for r in rows
    ]


def get_adjacent_hypotheses(
    db: CaseDB, hypothesis_id: str, relation_type: str | None = None
) -> list[str]:
    """Get directly adjacent hypothesis IDs."""
    if relation_type:
        rows = db.execute(
            "SELECT to_hypothesis_id FROM hypothesis_relations "
            "WHERE from_hypothesis_id = ? AND relation_type = ? "
            "UNION "
            "SELECT from_hypothesis_id FROM hypothesis_relations "
            "WHERE to_hypothesis_id = ? AND relation_type = ?",
            [hypothesis_id, relation_type, hypothesis_id, relation_type],
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT to_hypothesis_id FROM hypothesis_relations WHERE from_hypothesis_id = ? "
            "UNION "
            "SELECT from_hypothesis_id FROM hypothesis_relations WHERE to_hypothesis_id = ?",
            [hypothesis_id, hypothesis_id],
        ).fetchall()
    return [r[0] for r in rows]


def propagate_verdict(
    db: CaseDB,
    *,
    hypothesis_id: str,
    verdict: str,
    created_session: str = "",
) -> list[dict[str, Any]]:
    """Propagate verdict effects to adjacent hypotheses (bounded).

    Returns a list of propagation actions taken (for trace logging).
    """
    actions: list[dict[str, Any]] = []
    relations = get_relations_for_hypothesis(db, hypothesis_id)

    for rel in relations:
        from_id = rel["from_hypothesis_id"]
        to_id = rel["to_hypothesis_id"]
        rel_type = rel["relation_type"]
        adjacent_id = to_id if from_id == hypothesis_id else from_id

        if rel_type == "parent_of" and from_id == hypothesis_id:
            if verdict == "refuted":
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'needs_review', "
                    "human_review_required = TRUE WHERE hypothesis_id = ?",
                    [adjacent_id],
                )
                actions.append(
                    {
                        "action": "re_evaluate",
                        "target": adjacent_id,
                        "reason": f"Parent {hypothesis_id} refuted",
                    }
                )

        elif rel_type == "prerequisite_for" and from_id == hypothesis_id:
            if verdict in ("confirmed", "sufficient"):
                db.execute(
                    "UPDATE hypotheses SET blocked_reason = NULL, next_eligible_at = NULL "
                    "WHERE hypothesis_id = ?",
                    [adjacent_id],
                )
                actions.append(
                    {
                        "action": "unblock",
                        "target": adjacent_id,
                        "reason": f"Prerequisite {hypothesis_id} confirmed",
                    }
                )
            elif verdict == "refuted":
                db.execute(
                    "UPDATE hypotheses SET blocked_reason = ? WHERE hypothesis_id = ? "
                    "AND status = 'active'",
                    [f"prerequisite_refuted:{hypothesis_id}", adjacent_id],
                )
                actions.append(
                    {
                        "action": "re_evaluate",
                        "target": adjacent_id,
                        "reason": f"Prerequisite {hypothesis_id} refuted",
                    }
                )
            elif verdict == "inconclusive":
                db.execute(
                    "UPDATE hypotheses SET blocked_reason = ? WHERE hypothesis_id = ? "
                    "AND status = 'active'",
                    [f"prerequisite_inconclusive:{hypothesis_id}", adjacent_id],
                )

        elif rel_type == "contradicts":
            if verdict in ("confirmed",):
                db.execute(
                    "UPDATE hypotheses SET sufficiency_status = 'needs_review', "
                    "human_review_required = TRUE WHERE hypothesis_id = ?",
                    [adjacent_id],
                )
                actions.append(
                    {
                        "action": "flag_contradiction",
                        "target": adjacent_id,
                        "reason": f"Contradicting hypothesis {hypothesis_id} confirmed",
                    }
                )

        elif rel_type == "supersedes" and from_id == hypothesis_id:
            if verdict in ("confirmed", "sufficient"):
                db.execute(
                    "UPDATE hypotheses SET blocked_reason = ?, "
                    "sufficiency_reason = ? WHERE hypothesis_id = ? AND status = 'active'",
                    [
                        f"superseded_by:{hypothesis_id}",
                        f"Superseded by {hypothesis_id}",
                        adjacent_id,
                    ],
                )
                actions.append(
                    {
                        "action": "supersede",
                        "target": adjacent_id,
                        "reason": f"Superseded by {hypothesis_id}",
                    }
                )

    return actions


def relation_involves_unknown_claim(
    from_description: str | None, to_description: str | None
) -> bool:
    """Return True if either endpoint description names a material-unknown value.

    Used by the runner before ``insert_relation`` so a relation is never drawn
    from/to a hypothesis that admits an unresolved ``unknown src_ip`` / ``None``
    / placeholder claim.  Relations are only meaningful between durable, bounded
    claims.
    """
    return _description_has_material_unknown(
        from_description or ""
    ) or _description_has_material_unknown(to_description or "")
