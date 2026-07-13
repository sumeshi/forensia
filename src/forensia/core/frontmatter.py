"""Shared YAML frontmatter parser for templates and knowledge files."""

from __future__ import annotations


def parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter dict from text starting with ---."""
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return {}
    import yaml

    try:
        meta = yaml.safe_load(parts[1])
    except Exception:
        meta = {}
    return meta if isinstance(meta, dict) else {}
