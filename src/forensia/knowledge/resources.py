"""Canonical filesystem locations for packaged knowledge data.

All code must resolve knowledge paths through these helpers instead
of Path(__file__) arithmetic, so the physical layout can change in one place.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_KNOWLEDGE_ROOT = files("forensia.knowledge")


def rulepacks_dir() -> Path:
    """Directory containing the packaged detection rulepacks (YAML)."""
    return Path(_KNOWLEDGE_ROOT.joinpath("rulepacks"))


def schema_dir() -> Path:
    """Directory containing schema cards, catalogs, and playbook data."""
    return Path(_KNOWLEDGE_ROOT.joinpath("rulepacks", "_schema"))
