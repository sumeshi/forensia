"""Canonical filesystem locations for packaged report data.

All code must resolve packaged report template paths through these helpers
instead of Path(__file__) arithmetic, so the physical layout can change in
one place. (Same policy as forensia.knowledge.resources.)
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_DATA_ROOT = files("forensia").joinpath("data")


def report_templates_dir() -> Path:
    """Directory containing the packaged Markdown section templates."""
    return Path(_DATA_ROOT.joinpath("report"))


def report_formats_path() -> Path:
    """Packaged report wording/format policy (`_formats/report.yaml`)."""
    return Path(_DATA_ROOT.joinpath("report", "_formats", "report.yaml"))


def render_templates_dir() -> Path:
    """Directory containing the Jinja templates for the HTML report page."""
    return Path(_DATA_ROOT.joinpath("render"))
