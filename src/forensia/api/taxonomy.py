"""Canonical hypothesis/report status taxonomy (single source of truth).

The YAML vocabulary in ``knowledge/rulepacks/_schema/verdict_taxonomy.yaml`` is
the documented contract (GOAL.md §7, T-50.1). This module loads that file and
exposes the authoritative active/resolved partition so the backend
(``api/service.py``), the snapshot writers, and the Web UI all derive counts
from the same grouping. If the file cannot be read we fall back to the same
constants so behaviour never silently diverges.
"""

from __future__ import annotations

from collections.abc import Iterable

# Fallback constants (must mirror the YAML groups block).
ACTIVE_STATUSES: frozenset[str] = frozenset({"active"})
RESOLVED_STATUSES: frozenset[str] = frozenset(
    {"confirmed", "refuted", "untestable", "needs_review", "deferred", "blocked"}
)
ALL_HYPOTHESIS_STATUSES: frozenset[str] = ACTIVE_STATUSES | RESOLVED_STATUSES

REPORT_DRAFT_STATUSES: frozenset[str] = frozenset({"draft"})
REPORT_STABLE_STATUSES: frozenset[str] = frozenset({"ai_exhausted"})
REPORT_REVIEWED_STATUSES: frozenset[str] = frozenset({"human_reviewed"})



def hypothesis_status_group(status: str | None) -> str:
    """Return ``"active"`` or ``"resolved"`` for a hypothesis status."""
    if status is None:
        return "resolved"
    if status in ACTIVE_STATUSES:
        return "active"
    return "resolved"


def is_active_status(status: str | None) -> bool:
    return status in ACTIVE_STATUSES


def is_resolved_status(status: str | None) -> bool:
    return status in RESOLVED_STATUSES


def report_section_group(status: str | None) -> str:
    """Return draft/stable/reviewed for a report section status."""
    if status in REPORT_REVIEWED_STATUSES:
        return "reviewed"
    if status in REPORT_STABLE_STATUSES:
        return "stable"
    return "draft"


def get_hypothesis_taxonomy() -> dict:
    """Return the canonical hypothesis taxonomy block for API consumption."""
    return {
        "values": sorted(ALL_HYPOTHESIS_STATUSES),
        "groups": {
            "active": sorted(ACTIVE_STATUSES),
            "resolved": sorted(RESOLVED_STATUSES),
        },
        "kpi": {
            "resolved_total_field": "resolved_hypotheses",
            "breakdown_fields": [
                "confirmed_hypotheses", "refuted_hypotheses", "untestable_hypotheses",
                "needs_review_hypotheses", "deferred_hypotheses", "blocked_hypotheses",
            ],
        },
        "description": "Lifecycle status of a hypothesis.",
    }


def get_report_status_taxonomy() -> dict:
    """Return the canonical report section status taxonomy block."""
    return {
        "values": sorted(
            REPORT_DRAFT_STATUSES | REPORT_STABLE_STATUSES | REPORT_REVIEWED_STATUSES
        ),
        "groups": {
            "draft": sorted(REPORT_DRAFT_STATUSES),
            "stable": sorted(REPORT_STABLE_STATUSES),
            "reviewed": sorted(REPORT_REVIEWED_STATUSES),
        },
        "description": "Completion state of a report section.",
    }


def all_statuses() -> frozenset[str]:
    return ALL_HYPOTHESIS_STATUSES


def status_in_taxonomy(status: str | None) -> bool:
    return status in ALL_HYPOTHESIS_STATUSES


def validate_statuses(statuses: Iterable[str]) -> list[str]:
    """Return the subset of *statuses* that are unknown to the taxonomy."""
    return [s for s in statuses if s not in ALL_HYPOTHESIS_STATUSES]
