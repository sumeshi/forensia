"""Shared test fixtures for forensia test suite."""

from __future__ import annotations

from forensia.core.verdicts import set_taxonomy_path
from forensia.knowledge.resources import schema_dir

set_taxonomy_path(schema_dir() / "verdict_taxonomy.yaml")
