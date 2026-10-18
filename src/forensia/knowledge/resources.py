"""Canonical filesystem locations for packaged knowledge data.

All code must resolve knowledge paths through these helpers instead
of Path(__file__) arithmetic, so the physical layout can change in one place.
"""

from __future__ import annotations

import os
from importlib.resources import files
from pathlib import Path

_DATA_ROOT = files("forensia").joinpath("data")


def rules_dir() -> Path:
    """Directory containing the packaged detection rules (YAML)."""
    return Path(_DATA_ROOT.joinpath("rules"))


def schema_dir() -> Path:
    """Directory containing schema cards and catalogs."""
    return Path(_DATA_ROOT.joinpath("schema"))


def playbook_dir() -> Path:
    """Directory containing the packaged investigation playbook."""
    return Path(_DATA_ROOT.joinpath("playbook"))


def sigma_bundle_path() -> Path:
    """User-installed Sigma rules, separate from the Python distribution."""
    from importlib.metadata import version

    root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return root / "forensia" / "sigma" / version("forensia") / "sigma_bundle.json"
