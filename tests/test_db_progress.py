"""Invariants of the durable semantic trace event feed."""

from __future__ import annotations

import tempfile

import pytest

from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import list_progress_events, record_progress_event


def test_progress_events_append_page_and_preserve_structured_fields() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            first = record_progress_event(
                db,
                progress_event(
                    "finding.created",
                    "completed",
                    session_id="session-a",
                    severity="success",
                    reason="rule_match",
                    refs={"finding_ids": ["F-1"], "evidence_ids": ["E-1"]},
                    summary="Finding created",
                    rule_id="R-1",
                ),
            )
            second = record_progress_event(
                db,
                progress_event(
                    "investigation.stopped",
                    "stopped",
                    session_id="session-b",
                    reason="operator_stop",
                    summary="Stopped at a safe boundary",
                ),
            )
            assert second == first + 1

            page = list_progress_events(db, after_index=first - 1, limit=1)
            assert len(page) == 1
            assert page[0]["event_index"] == first
            assert page[0]["session_id"] == "session-a"
            assert page[0]["kind"] == "finding.created"
            assert page[0]["severity"] == "success"
            assert page[0]["status"] == "completed"
            assert page[0]["reason"] == "rule_match"
            assert page[0]["refs"] == {
                "finding_ids": ["F-1"],
                "evidence_ids": ["E-1"],
            }
            assert page[0]["payload"] == {"rule_id": "R-1"}
            assert page[0]["created_at"]
            assert (
                list_progress_events(db, after_index=first, limit=10)[0]["event_index"]
                == second
            )


def test_progress_events_are_not_pruned_after_one_thousand_rows() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            db.execute(
                """
                INSERT INTO trace.progress_events (
                    event_index, kind, status, severity, refs, payload, summary
                ) SELECT i, 'pipeline.stage', 'completed', 'info', '{}', '{}',
                         'stage ' || CAST(i AS VARCHAR)
                  FROM range(1, 1002) AS r(i)
                """
            )
            record_progress_event(
                db,
                progress_event(
                    "pipeline.stage.completed",
                    "completed",
                    session_id="session-b",
                    summary="after the seeded history",
                ),
            )
            count = db.execute("SELECT COUNT(*) FROM trace.progress_events").fetchone()[
                0
            ]
            assert count == 1002
            first = list_progress_events(db, limit=1)[0]
            assert first["event_index"] == 1
            assert first["summary"] == "stage 1"


def test_storage_rejects_unknown_event_vocabulary() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with CaseDB(case) as db:
            with pytest.raises(ValueError, match="status"):
                record_progress_event(
                    db,
                    {
                        "kind": "investigation.error",
                        "status": "error",
                        "severity": "error",
                    },  # type: ignore[arg-type]
                )
