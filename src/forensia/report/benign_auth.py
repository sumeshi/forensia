"""Benign local authentication detection and tagging.

This module provides deterministic (no-LLM) detection of benign local
authentication patterns — loopback auth, machine account self-auth, and
local UAC/credential dialog processes — and tags findings accordingly.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records

_LOOPBACK_VALUES: set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "-",
    "",
    "none",
}

# Hardcoded fallback used when schema loading fails.
_FALLBACK_AUTH_EVENT_IDS: frozenset[str] = frozenset({"4624", "4648"})


@lru_cache(maxsize=1)
def _load_auth_event_ids() -> frozenset[str]:
    """Return the set of logon/auth event IDs from event_ids.yaml.

    Reads the ``event_classes`` section and collects all event IDs from
    classes whose name contains ``logon``, ``auth``, or ``credential``
    (case-insensitive). Falls back to the hardcoded set if schema loading
    fails.
    """
    try:
        from forensia.knowledge import load_event_class_definitions

        classes = load_event_class_definitions()
        ids: set[str] = set()
        for class_name, class_def in classes.items():
            name = class_name.lower()
            if "logon" in name or "auth" in name or "credential" in name:
                for eid in class_def.get("event_ids", []):
                    ids.add(str(eid))
        if ids:
            return frozenset(ids)
    except Exception:
        pass
    return _FALLBACK_AUTH_EVENT_IDS


def clear_benign_auth_caches() -> None:
    """Clear cached schema loads in this module. Call in test teardowns."""
    _load_auth_event_ids.cache_clear()


def _normalise_ip(value: Any) -> str:
    """Normalise an IP / host value to a lowercase string for comparison."""
    if value is None:
        return ""
    s = str(value).strip().lower()
    return s


def is_benign_local_auth(evidence_row: dict) -> bool:
    """Return True if the evidence row represents benign local authentication.

    True if ANY of:
    - src_ip is loopback (127.0.0.1, ::1, localhost, -, '', none)
      AND event_id is 4624 or 4648 (logon type)
    - subject_user ends with "$" (machine account) AND src_ip is loopback
      AND computer matches the machine account's hostname

    Cross-host machine account auth over loopback (e.g. OTHER-PC$ on HOST-A)
    is NOT benign — it indicates potential lateral movement.
    """
    src_ip = _normalise_ip(evidence_row.get("src_ip"))
    subject_user = str(evidence_row.get("subject_user") or "").strip()
    event_id = str(evidence_row.get("event_id") or "").strip()

    # Only meaningful for logon events
    if not event_id or event_id not in _load_auth_event_ids():
        return False

    is_loopback = src_ip in _LOOPBACK_VALUES
    computer = str(evidence_row.get("computer") or evidence_row.get("host", "")).strip()

    # Machine account on loopback: verify same-host, reject cross-host
    if is_loopback and subject_user.endswith("$"):
        # No computer field — can't verify host, assume same-host → benign
        if not computer or subject_user.rstrip("$").lower() == computer.lower():
            return True
        return False

    # Bare loopback (no subject or non-machine account) → benign
    if is_loopback:
        return True

    return False


def tag_benign_local_auth_findings(db: CaseDB) -> int:
    """Scan findings table, tag findings where ALL evidence rows are benign.

    For each finding where every evidence row satisfies ``is_benign_local_auth``,
    append ``benign-context:loopback-local-auth`` to the ``tags`` JSON array.
    Preserves existing tags, avoids duplicates.

    Returns the count of findings tagged.
    """
    tagged = 0
    rows = fetch_records(
        db.conn,
        "SELECT finding_id, evidence, tags FROM findings WHERE evidence IS NOT NULL",
    )
    for row in rows:
        finding_id = str(row["finding_id"])
        evidence_raw = row.get("evidence")
        if not evidence_raw:
            continue
        try:
            evidence_list = (
                json.loads(evidence_raw)
                if isinstance(evidence_raw, str)
                else evidence_raw
            )
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(evidence_list, list):
            continue
        if not evidence_list:
            continue

        if not all(is_benign_local_auth(entry) for entry in evidence_list):
            continue

        # All evidence rows are benign — tag the finding
        current_tags: list[str] = []
        tags_raw = row.get("tags")
        if tags_raw:
            try:
                current_tags = (
                    json.loads(tags_raw)
                    if isinstance(tags_raw, str)
                    else (list(tags_raw) if isinstance(tags_raw, (list, tuple)) else [])
                )
            except (json.JSONDecodeError, TypeError):
                current_tags = []

        tag = "benign-context:loopback-local-auth"
        if tag not in current_tags:
            current_tags.append(tag)
            db.conn.execute(
                "UPDATE findings SET tags = ? WHERE finding_id = ?",
                [json.dumps(current_tags), finding_id],
            )
            tagged += 1

    return tagged
