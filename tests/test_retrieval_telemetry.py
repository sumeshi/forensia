from __future__ import annotations

import json

from forensia.ai.retrieval_telemetry import record_retrieval_event
from forensia.core.case import Case
from forensia.db.database import CaseDB


def test_retrieval_event_is_written_to_attached_trace_db(tmp_path) -> None:
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        record_retrieval_event(
            db,
            session_id="S-1",
            scope_kind="hypothesis",
            scope_id="H-A",
            phase="read_more",
            source_kind="memory",
            query_terms=["event", "1102"],
            candidate_count=2,
            selected_refs=["entities/host/A.md"],
            rejected_refs=["scratch/H-B/tasks.md"],
            selected_chars=321,
            budget=1024,
        )
        row = db.execute(
            """
            SELECT scope_id, query_terms, selected_refs, rejected_refs,
                   selected_chars, budget
            FROM retrieval_events
            """
        ).fetchone()

    assert row is not None
    assert row[0] == "H-A"
    assert json.loads(row[1]) == ["event", "1102"]
    assert json.loads(row[2]) == ["entities/host/A.md"]
    assert json.loads(row[3]) == ["scratch/H-B/tasks.md"]
    assert row[4:] == (321, 1024)
