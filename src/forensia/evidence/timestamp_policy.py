"""Shared policy values and SQL predicate for analysis-eligible timestamps."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from importlib.resources import files
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class TimestampPolicy:
    """Declarative bounds used by normalization and coverage SQL."""

    minimum_year: int = 1980
    maximum_year: int = 2200
    sentinel_max_year: int = 1970
    case_window_margin_days: int = 3650

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> TimestampPolicy:
        value = value or {}
        defaults = cls()
        return cls(
            minimum_year=int(value.get("minimum_year", defaults.minimum_year)),
            maximum_year=int(value.get("maximum_year", defaults.maximum_year)),
            sentinel_max_year=int(
                value.get("sentinel_max_year", defaults.sentinel_max_year)
            ),
            case_window_margin_days=int(
                value.get("case_window_margin_days", defaults.case_window_margin_days)
            ),
        )

    @property
    def case_window_margin(self) -> timedelta:
        return timedelta(days=self.case_window_margin_days)


def timestamp_year_range_sql(column: str, policy: TimestampPolicy) -> str:
    """Return the shared SQL predicate for absolute timestamp eligibility."""
    return (
        f"EXTRACT(year FROM {column}) BETWEEN "
        f"{policy.minimum_year} AND {policy.maximum_year}"
    )


def load_artifact_capabilities_config() -> dict[str, Any]:
    """Load the required capability catalog as a YAML mapping."""
    path = files("forensia").joinpath(
        "knowledge", "rulepacks", "_schema", "artifact_capabilities.yaml"
    )
    if not path.is_file():
        raise FileNotFoundError(f"required policy file is missing: {path}")
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        actual_type = "null" if config is None else type(config).__name__
        raise TypeError(
            f"required policy file must contain a YAML mapping: {path} "
            f"(got {actual_type})"
        )
    return config


def configured_timestamp_policy() -> TimestampPolicy:
    """Load shared timestamp bounds from the packaged capability catalog."""
    config = load_artifact_capabilities_config()
    return TimestampPolicy.from_mapping(config.get("timestamp_policy", {}))
