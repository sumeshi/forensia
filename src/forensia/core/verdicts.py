from __future__ import annotations

from pathlib import Path
from typing import Any

_taxonomy_path: Path | None = None
_taxonomy_cache: dict[str, Any] | None = None


def set_taxonomy_path(path: Path) -> None:
    """Set the path to the verdict taxonomy YAML (called at startup)."""
    global _taxonomy_path, _taxonomy_cache
    _taxonomy_path = path
    _taxonomy_cache = None


def _load_taxonomy() -> dict[str, Any]:
    """Load the verdict taxonomy YAML file (cached after first call).

    Raises ``RuntimeError`` if ``set_taxonomy_path`` was never called, and
    ``FileNotFoundError`` / ``yaml.YAMLError`` on read failures.  Validation is
    fail-closed: if the taxonomy cannot be loaded, verdicts are rejected.
    """
    global _taxonomy_cache
    if _taxonomy_cache is not None:
        return _taxonomy_cache

    if _taxonomy_path is None:
        raise RuntimeError(
            "verdict taxonomy path not set; call set_taxonomy_path() at startup"
        )
    if not _taxonomy_path.exists():  # type: ignore[union-attr]
        raise FileNotFoundError(f"verdict taxonomy not found: {_taxonomy_path}")
    import yaml

    data = yaml.safe_load(_taxonomy_path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
    if not isinstance(data, dict):
        raise ValueError(f"verdict taxonomy must be a mapping: {_taxonomy_path}")
    _taxonomy_cache = data
    return _taxonomy_cache


def valid_verdicts(category: str) -> list[str]:
    """Return the list of allowed verdict values for a given category."""
    tax = _load_taxonomy()
    cat = tax.get(category, {})
    values = cat.get("values", []) if isinstance(cat, dict) else []
    return [str(v) for v in values]


def assert_valid_verdict(verdict: str, category: str) -> None:
    """Raise ValueError if the verdict is not in the allowed set for the category."""
    allowed = valid_verdicts(category)
    if allowed and verdict not in allowed:
        raise ValueError(
            f"Invalid verdict '{verdict}' for {category}. Allowed: {allowed}"
        )
