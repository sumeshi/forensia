from typing import Any


def progress_event(
    stage: str,
    status: str,
    *,
    iteration: int | None = None,
    summary: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    event: dict[str, Any] = {"stage": stage, "status": status}
    if iteration is not None:
        event["iteration"] = iteration
    if summary is not None:
        event["summary"] = summary
    event.update(extra)
    return event
