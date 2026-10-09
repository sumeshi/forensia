"""Canonical filesystem locations for packaged knowledge data.

All code must resolve knowledge paths through these helpers instead
of Path(__file__) arithmetic, so the physical layout can change in one place.
"""

from __future__ import annotations

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
    """Path to the generated, admitted Sigma executable bundle."""
    return Path(_DATA_ROOT.joinpath("sigma", "sigma_bundle.json"))


def sigma_license_path() -> Path:
    """Path to the bundled SigmaHQ license and attribution notice."""
    return Path(_DATA_ROOT.joinpath("sigma", "SIGMA_LICENSE.txt"))
