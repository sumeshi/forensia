"""Stable identifiers for concepts shared across domain boundaries."""

from __future__ import annotations

import hashlib


def gap_hypothesis_id(
    description: str,
    *,
    section_key: str | None = None,
    block_heading: str | None = None,
) -> str:
    """Generate a deterministic hypothesis ID, optionally scoped to a report block."""
    identity = description
    if section_key is not None or block_heading is not None:
        identity = "\0".join((section_key or "", block_heading or "", description))
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]
    return f"gap-{digest}"


def report_gap_id(
    description: str,
    *,
    section_key: str | None = None,
    block_heading: str | None = None,
) -> str:
    """Generate a deterministic report gap ID, optionally scoped to a report block."""
    identity = description
    if section_key is not None or block_heading is not None:
        identity = "\0".join((section_key or "", block_heading or "", description))
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"GAP-{digest}"
