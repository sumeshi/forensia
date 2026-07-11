"""Load user-editable Markdown report wording and format policy."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@lru_cache(maxsize=16)
def load_report_formats(template_dir: str | Path | None = None) -> dict[str, Any]:
    """Load packaged formats, merged with `_formats/report.yaml` when present."""
    packaged = resources.files("forensia").joinpath(
        "report_template/_formats/report.yaml"
    )
    base = yaml.safe_load(packaged.read_text(encoding="utf-8")) or {}
    if not isinstance(base, dict) or base.get("version") != 1:
        raise ValueError("packaged report format must be a version 1 mapping")
    if not template_dir:
        return base
    override_path = Path(template_dir) / "_formats" / "report.yaml"
    if not override_path.exists():
        return base
    override = yaml.safe_load(override_path.read_text(encoding="utf-8")) or {}
    if not isinstance(override, dict):
        raise ValueError(f"{override_path}: expected a mapping")
    if override.get("version", 1) != 1:
        raise ValueError(f"{override_path}: version must be 1")
    return _merge(base, override)
