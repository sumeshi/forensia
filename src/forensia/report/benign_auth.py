"""Benign local authentication detection.

This module provides deterministic (no-LLM) detection of benign local
authentication patterns — loopback auth, machine account self-auth, and
local UAC/credential dialog processes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from forensia.knowledge.catalog import (
    event_context_eligible,
    event_context_from_row,
)
from forensia.knowledge.resources import schema_dir


@dataclass(frozen=True, slots=True)
class BenignAuthPolicy:
    """Hold externally managed local-auth classification policy."""

    local_source_values: frozenset[str]
    auth_event_class_terms: tuple[str, ...]
    fallback_auth_event_ids: frozenset[str]


@lru_cache(maxsize=1)
def _load_benign_auth_policy() -> BenignAuthPolicy:
    """Load and validate local-auth policy from benign_auth.yaml."""
    import yaml

    path = schema_dir() / "benign_auth.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"{path}: version must be 1")
    policy = data.get("local_auth")
    if not isinstance(policy, dict):
        raise ValueError(f"{path}: local_auth must be a mapping")

    def _strings(name: str) -> tuple[str, ...]:
        values = policy.get(name)
        if not isinstance(values, list) or not all(
            isinstance(value, (str, int)) for value in values
        ):
            raise ValueError(f"{path}: local_auth.{name} must be a list")
        return tuple(str(value).strip().lower() for value in values)

    return BenignAuthPolicy(
        local_source_values=frozenset(_strings("local_source_values")),
        auth_event_class_terms=_strings("auth_event_class_terms"),
        fallback_auth_event_ids=frozenset(_strings("fallback_auth_event_ids")),
    )


@lru_cache(maxsize=1)
def _load_auth_event_ids() -> frozenset[str]:
    """Return the set of logon/auth event IDs from event_ids.yaml.

    Reads the ``event_classes`` section and collects all event IDs from
    classes whose name contains ``logon``, ``auth``, or ``credential``
    (case-insensitive). Falls back to the hardcoded set if schema loading
    fails.
    """
    from forensia.knowledge.catalog import load_event_class_definitions

    policy = _load_benign_auth_policy()
    classes = load_event_class_definitions()
    ids = {
        str(event_id)
        for class_name, class_def in classes.items()
        if any(term in class_name.lower() for term in policy.auth_event_class_terms)
        for event_id in class_def.get("event_ids", [])
    }
    return frozenset(ids) or policy.fallback_auth_event_ids


def normalise_ip(value: Any) -> str:
    """Normalise an IP / host value to a lowercase string for comparison."""
    if value is None:
        return ""
    s = str(value).strip().lower()
    return s


def finding_is_auth_scoped(rule_id: Any, title: Any) -> bool:
    """Return True when a finding is scoped to authentication events.

    This is a routing hint only. It cannot qualify evidence without the row's
    event ID, channel, and provider.
    """
    blob = f"{rule_id or ''} {title or ''}"
    if not blob.strip():
        return False
    return any(
        re.search(rf"(?<!\d){re.escape(eid)}(?!\d)", blob)
        for eid in _load_auth_event_ids()
    )


def is_benign_local_auth(evidence_row: dict) -> bool:
    """Return True if the evidence row represents benign local authentication.

    Benign when the row contains a catalog-qualified authentication event AND ``src_ip`` is loopback
    (127.0.0.1 / ::1 / localhost / empty). Loopback means the authentication
    originated on the local machine, so it is local system activity — not
    lateral movement, which cannot present as a loopback source.

    Non-loopback authentication is not treated as benign here.

    """
    src_ip = normalise_ip(evidence_row.get("src_ip"))
    event_id = str(evidence_row.get("event_id") or "").strip()

    # Only meaningful for logon events
    if not event_id or event_id not in _load_auth_event_ids():
        return False
    channel, provider = event_context_from_row(evidence_row)
    if not event_context_eligible(event_id, channel=channel, provider=provider):
        return False

    is_loopback = src_ip in _load_benign_auth_policy().local_source_values

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
