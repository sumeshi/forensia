from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any


@lru_cache(maxsize=1)
def _load_taxonomy() -> dict[str, Any]:
    """Load the verdict taxonomy YAML file (cached after first call)."""
    path = (
        Path(__file__).parent.parent / "knowledge" / "rulepacks" / "_schema" / "verdict_taxonomy.yaml"
    )
    if not path.exists():
        return {}
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


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
