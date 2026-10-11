"""Cooperative stop at existing execution boundaries."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Event

_STOP: ContextVar[Event | None] = ContextVar("forensia_stop", default=None)


class InvestigationStopped(Exception):
    """The operator requested a safe stop, not a failed investigation."""


def is_stopped() -> bool:
    event = _STOP.get()
    return event is not None and event.is_set()


def check_stop() -> None:
    if is_stopped():
        raise InvestigationStopped("operator requested stop")


@contextmanager
def stop_scope(event: Event | None) -> Iterator[None]:
    token = _STOP.set(event)
    try:
        yield
    finally:
        _STOP.reset(token)
