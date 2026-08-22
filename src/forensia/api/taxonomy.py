"""Canonical API projections of the YAML-backed status taxonomy.

The vocabulary in ``knowledge/rulepacks/_schema/verdict_taxonomy.yaml`` is the
only authority. Application entry points configure ``core.verdicts`` before
these projections are evaluated; missing or malformed taxonomy data fails
closed instead of silently falling back to duplicated Python constants.
"""

from __future__ import annotations

from typing import Any

from forensia.core.verdicts import taxonomy_block


def _strings(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"taxonomy field {field} must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"taxonomy field {field} must contain non-empty strings")
    normalized = [item.strip() for item in value]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"taxonomy field {field} contains duplicate values")
    return normalized


def _normalized_block(category: str, group_names: tuple[str, ...]) -> dict[str, Any]:
    raw = taxonomy_block(category)
    values = _strings(raw.get("values"), field=f"{category}.values")
    raw_groups = raw.get("groups")
    if not isinstance(raw_groups, dict):
        raise ValueError(f"taxonomy field {category}.groups must be a mapping")
    groups = {
        name: _strings(raw_groups.get(name), field=f"{category}.groups.{name}")
        for name in group_names
    }
    grouped_values = [value for members in groups.values() for value in members]
    grouped = set(grouped_values)
    if len(grouped_values) != len(grouped):
        raise ValueError(f"taxonomy groups for {category} overlap")
    unknown = grouped - set(values)
    if unknown:
        raise ValueError(
            f"taxonomy groups for {category} contain unknown values: {sorted(unknown)}"
        )
    ungrouped = set(values) - grouped
    if ungrouped:
        raise ValueError(
            f"taxonomy values for {category} are not grouped: {sorted(ungrouped)}"
        )
    result: dict[str, Any] = {
        "values": values,
        "groups": groups,
        "description": str(raw.get("description") or ""),
    }
    if isinstance(raw.get("kpi"), dict):
        result["kpi"] = dict(raw["kpi"])
    return result


def get_hypothesis_taxonomy() -> dict[str, Any]:
    """Return the authoritative hypothesis lifecycle taxonomy."""
    return _normalized_block("hypothesis_status", ("active", "resolved"))


def get_report_status_taxonomy() -> dict[str, Any]:
    """Return the authoritative report-section completion taxonomy."""
    return _normalized_block(
        "report_section_status", ("draft", "stable", "reviewed")
    )


def hypothesis_status_group(status: str | None) -> str:
    """Return the YAML-defined active/resolved group for a status."""
    groups = get_hypothesis_taxonomy()["groups"]
    if status in groups["active"]:
        return "active"
    if status in groups["resolved"]:
        return "resolved"
    raise ValueError(f"unknown hypothesis status: {status!r}")
