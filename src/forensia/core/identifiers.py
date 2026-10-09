"""Stable identifiers for concepts shared across domain boundaries."""

from __future__ import annotations

import hashlib


def gap_hypothesis_id(description: str) -> str:
    """Generate a deterministic hypothesis ID from a gap description."""
    digest = hashlib.sha1(description.encode("utf-8")).hexdigest()[:10]
    return f"gap-{digest}"


def report_gap_id(description: str) -> str:
    """Generate a deterministic report gap ID from its exact description."""
    digest = hashlib.sha256(description.encode("utf-8")).hexdigest()[:16]
    return f"GAP-{digest}"
