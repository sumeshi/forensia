"""Timestamp plausibility policy for evidence coverage and timeline.

R8-03: Separates raw timestamps from analysis-eligible timestamps.
Raw values are preserved for forensic integrity, but coverage/timeline
aggregation only uses timestamps that pass plausibility checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any


@dataclass(frozen=True, slots=True)
class TimestampPolicy:
    """Declarative bounds used to decide whether a timestamp is analysable."""

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


@dataclass(frozen=True, slots=True)
class TimestampClassification:
    """Classification of a timestamp value."""

    is_plausible: bool
    reason: str


@dataclass(frozen=True, slots=True)
class TimestampBounds:
    """Plausible timestamp bounds for a set of timestamps."""

    min_time: datetime | None
    max_time: datetime | None
    excluded_count: int
    excluded_reasons: dict[str, int]  # reason -> count


def classify_timestamp(
    ts: datetime | None,
    policy: TimestampPolicy | None = None,
    evidence_window: tuple[datetime, datetime] | None = None,
) -> TimestampClassification:
    """Classify a timestamp as plausible or sentinel/overflow.

    Returns TimestampClassification with is_plausible flag and reason.
    """
    policy = policy or TimestampPolicy()
    if ts is None:
        return TimestampClassification(is_plausible=False, reason="null")

    try:
        year = ts.year
    except AttributeError, ValueError:
        return TimestampClassification(is_plausible=False, reason="invalid")

    # Windows epoch 1601 sentinel (NTFS "never" value)
    if year <= policy.sentinel_max_year:
        return TimestampClassification(is_plausible=False, reason="sentinel_1601")

    # Pre-DOS epoch (before 1980)
    if year < policy.minimum_year:
        return TimestampClassification(is_plausible=False, reason="pre_dos_epoch")

    # Far-future overflow (NTFS int64-MAX misinterpretation)
    if year > policy.maximum_year:
        return TimestampClassification(is_plausible=False, reason="overflow")

    if evidence_window is not None:
        lower, upper = evidence_window
        margin = timedelta(days=policy.case_window_margin_days)
        if ts < lower - margin or ts > upper + margin:
            return TimestampClassification(
                is_plausible=False, reason="outside-analysis-window"
            )

    return TimestampClassification(is_plausible=True, reason="valid")


def filter_plausible_timestamps(
    timestamps: list[datetime | None],
    policy: TimestampPolicy | None = None,
    evidence_window: tuple[datetime, datetime] | None = None,
) -> tuple[list[datetime], dict[str, int]]:
    """Filter timestamps to only plausible ones.

    Returns (plausible_timestamps, excluded_reasons).
    """
    plausible: list[datetime] = []
    excluded: dict[str, int] = {}

    for ts in timestamps:
        cls = classify_timestamp(ts, policy, evidence_window)
        if cls.is_plausible and ts is not None:
            plausible.append(ts)
        else:
            excluded[cls.reason] = excluded.get(cls.reason, 0) + 1

    return plausible, excluded


def compute_plausible_bounds(
    timestamps: list[datetime | None],
    policy: TimestampPolicy | None = None,
    evidence_window: tuple[datetime, datetime] | None = None,
) -> TimestampBounds:
    """Compute plausible min/max bounds from a list of timestamps.

    Returns TimestampBounds with min/max of plausible timestamps only,
    plus exclusion metadata.
    """
    plausible, excluded = filter_plausible_timestamps(
        timestamps, policy, evidence_window
    )

    if not plausible:
        return TimestampBounds(
            min_time=None,
            max_time=None,
            excluded_count=sum(excluded.values()),
            excluded_reasons=excluded,
        )

    return TimestampBounds(
        min_time=min(plausible),
        max_time=max(plausible),
        excluded_count=sum(excluded.values()),
        excluded_reasons=excluded,
    )


def is_plausible_timestamp(
    ts: datetime | None, policy: TimestampPolicy | None = None
) -> bool:
    """Quick check if a timestamp is plausible for analysis."""
    return classify_timestamp(ts, policy).is_plausible
