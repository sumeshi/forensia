from __future__ import annotations

from typing import Any, Literal, TypedDict

EventStatus = Literal[
    "running",
    "completed",
    "skipped",
    "failed",
    "interrupted",
    "stopped",
    "cancelled",
    "abandoned",
]
EventSeverity = Literal["info", "success", "warning", "error"]

_STATUSES = {
    "running",
    "completed",
    "skipped",
    "failed",
    "interrupted",
    "stopped",
    "cancelled",
    "abandoned",
}
_SEVERITIES = {"info", "success", "warning", "error"}


class ProgressEvent(TypedDict, total=False):
    kind: str
    status: EventStatus
    severity: EventSeverity
    reason: str | None
    refs: dict[str, Any]
    stage: str | None
    iteration: int | None
    summary: str | None
    session_id: str | None
    attributes: dict[str, Any]


def progress_event(
    kind: str,
    status: EventStatus,
    *,
    severity: EventSeverity = "info",
    reason: str | None = None,
    refs: dict[str, Any] | None = None,
    stage: str | None = None,
    iteration: int | None = None,
    summary: str | None = None,
    session_id: str | None = None,
    **attributes: Any,
) -> ProgressEvent:
    """Build one compact, producer-classified trace event."""
    validate_progress_event_fields(kind, status, severity)
    event: ProgressEvent = {
        "kind": kind,
        "status": status,
        "severity": severity,
    }
    if reason is not None:
        event["reason"] = reason
    if refs:
        event["refs"] = refs
    if stage is not None:
        event["stage"] = stage
    if iteration is not None:
        event["iteration"] = iteration
    if summary is not None:
        event["summary"] = summary
    if session_id is not None:
        event["session_id"] = session_id
    if attributes:
        event["attributes"] = attributes
    return event


def validate_progress_event_fields(kind: str, status: str, severity: str) -> None:
    """Validate the persisted event vocabulary at producer and storage boundaries."""
    if not kind.strip():
        raise ValueError("event kind must not be empty")
    if status not in _STATUSES:
        raise ValueError(f"unsupported progress event status: {status}")
    if severity not in _SEVERITIES:
        raise ValueError(f"unsupported progress event severity: {severity}")
