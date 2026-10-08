"""Invariants of the trace progress_events store (db.progress, formerly api.progress)."""

from __future__ import annotations

import tempfile

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.progress import (
    MAX_PROGRESS_EVENTS,
    list_progress_events,
    record_progress_event,
)


def test_progress_events_are_capped() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            total = MAX_PROGRESS_EVENTS + 105
            for index in range(total):
                record_progress_event(
                    db,
                    {
                        "stage": "investigate/check",
                        "status": "running",
                        "iteration": index,
                        "summary": f"event-{index}",
                    },
                )
            count = db.execute("SELECT COUNT(*) FROM trace.progress_events").fetchone()[0]
            assert count == MAX_PROGRESS_EVENTS
            events = list_progress_events(db, after_index=0, limit=100)
            # Oldest events are pruned; listing starts at the surviving tail.
            assert events[0]["event_index"] == total - count + 1


def test_progress_events_store_lives_in_trace_database() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            record_progress_event(db, {"stage": "init", "status": "running"})
            row = db.execute(
                "SELECT stage, status FROM trace.progress_events LIMIT 1"
            ).fetchone()
            assert row == ("init", "running")
            assert case.trace_database_path.exists()
