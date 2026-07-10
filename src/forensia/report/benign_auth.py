"""Benign local authentication detection and tagging.

This module provides deterministic (no-LLM) detection of benign local
authentication patterns — loopback auth, machine account self-auth, and
local UAC/credential dialog processes — and tags findings accordingly.
"""

from __future__ import annotations

import json
import re
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


def _normalise_ip(value: Any) -> str:
    """Normalise an IP / host value to a lowercase string for comparison."""
    if value is None:
        return ""
    s = str(value).strip().lower()
    return s


def finding_is_auth_scoped(rule_id: Any, title: Any) -> bool:
    """Return True when a finding is scoped to authentication events.

    Rule queries commonly filter on an auth event ID (``WHERE event_id =
    4648``) without SELECTing the column, so the evidence rows carry no
    ``event_id``. The finding's rule_id / title still name the event
    (``windows-security-4648-...``, ``... (4648): ...``), which lets the
    benign predicate apply to such rows.
    """
    blob = f"{rule_id or ''} {title or ''}"
    if not blob.strip():
        return False
    return any(
        re.search(rf"(?<!\d){re.escape(eid)}(?!\d)", blob)
        for eid in _load_auth_event_ids()
    )


def is_benign_local_auth(
    evidence_row: dict, *, assume_auth_event: bool = False
) -> bool:
    """Return True if the evidence row represents benign local authentication.

    Benign when the event is an authentication event (4624 / 4648, or an
    auth-scoped finding via ``assume_auth_event``) AND ``src_ip`` is loopback
    (127.0.0.1 / ::1 / localhost / empty). Loopback means the authentication
    originated on the local machine, so it is local system activity — not
    lateral movement, which cannot present as a loopback source.

    Non-loopback authentication is not treated as benign here.

    ``assume_auth_event`` lets callers that already know the row comes from
    an authentication-scoped finding (see :func:`finding_is_auth_scoped`)
    apply the predicate to rows whose SELECT did not include ``event_id``.
    A present-but-non-auth event_id is still rejected.
    """
    src_ip = _normalise_ip(evidence_row.get("src_ip"))
    event_id = str(evidence_row.get("event_id") or "").strip()

    # Only meaningful for logon events
    if event_id:
        if event_id not in _load_auth_event_ids():
            return False
    elif not assume_auth_event:
        return False

    is_loopback = src_ip in _LOOPBACK_VALUES

    # Loopback (127.0.0.1 / ::1) means the authentication originated on the
    # local machine itself. Lateral movement from another host cannot present
    # as a loopback source, so any subject over loopback — including a machine
    # account whose name differs from the current hostname (a renamed host or
    # base-image account authenticating to itself) — is benign local activity.
    # Distinguishing a former self-name from a foreign machine account would
    # require rename history (entity unification), which is out of scope; the
    # safe default is benign, since this only demotes ranking, never deletes.
    if is_loopback:
        return True

    # Non-loopback: not benign here. A different host's machine account over a
    # real IP is a lateral-movement signal; genuine same-host machine self-auth
    # over a real interface is left to other gates rather than blanket-cleared.
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
        "SELECT finding_id, rule_id, title, evidence, tags FROM findings"
        " WHERE evidence IS NOT NULL",
    )
    for row in rows:
        finding_id = str(row["finding_id"])
        assume_auth = finding_is_auth_scoped(row.get("rule_id"), row.get("title"))
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

        if not all(
            is_benign_local_auth(entry, assume_auth_event=assume_auth)
            for entry in evidence_list
        ):
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
