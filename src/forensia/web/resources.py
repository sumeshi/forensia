"""Canonical filesystem locations for packaged web data.

All code must resolve the packaged SPA/static directory through these helpers
instead of Path(__file__) arithmetic, so the physical layout can change in
one place. (Same policy as forensia.knowledge.resources.)
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_WEB_ROOT = files("forensia.web")


def static_dir() -> Path:
    """Directory containing the packaged SPA static files."""
    return Path(_WEB_ROOT.joinpath("static"))
