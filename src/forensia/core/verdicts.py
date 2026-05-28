from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any


@lru_cache(maxsize=1)
def _load_taxonomy() -> dict[str, Any]:
    path = Path(__file__).parent.parent / "rulepacks" / "_schema" / "verdict_taxonomy.yaml"
    if not path.exists():
        return {}
    import yaml
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def valid_verdicts(category: str) -> list[str]:
    tax = _load_taxonomy()
    cat = tax.get(category, {})
    values = cat.get("values", []) if isinstance(cat, dict) else []
    return [str(v) for v in values]


def assert_valid_verdict(verdict: str, category: str) -> None:
    allowed = valid_verdicts(category)
    if allowed and verdict not in allowed:
        raise ValueError(f"Invalid verdict '{verdict}' for {category}. Allowed: {allowed}")


def map_verdict(verdict: str, mapping_name: str) -> str | None:
    tax = _load_taxonomy()
    mapping = tax.get("mapping", {})
    table = mapping.get(mapping_name, {})
    if not isinstance(table, dict):
        return None
    return table.get(verdict)


def hypothesis_to_section(verdict: str) -> str | None:
    return map_verdict(verdict, "hypothesis_to_section")


def section_to_benchmark(verdict: str) -> str | None:
    return map_verdict(verdict, "section_to_benchmark")


def benchmark_to_claim(verdict: str) -> str | None:
    return map_verdict(verdict, "benchmark_to_claim")
