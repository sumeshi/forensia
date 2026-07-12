"""Canonical filesystem locations for packaged knowledge data.

All code must resolve rulepacks/profiles paths through these helpers instead
of Path(__file__) arithmetic, so the physical layout can change in one place.
"""

from __future__ import annotations

from pathlib import Path

_KNOWLEDGE_ROOT = Path(__file__).resolve().parent


def rulepacks_dir() -> Path:
    """Directory containing the packaged detection rulepacks (YAML)."""
    return _KNOWLEDGE_ROOT / "rulepacks"


def schema_dir() -> Path:
    """Directory containing schema cards, catalogs, and playbook data."""
    return rulepacks_dir() / "_schema"


def profiles_dir() -> Path:
    """Directory containing the packaged investigation profiles (YAML)."""
    return _KNOWLEDGE_ROOT / "profiles"


def profile_path(profile_name: str) -> Path:
    """Path of one packaged profile YAML by name (may not exist)."""
    return profiles_dir() / f"{profile_name}.yaml"
