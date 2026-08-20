from __future__ import annotations

import json

import pytest

from forensia.ai.retrieval_telemetry import (
    RetrievalEvaluation,
    ToolReceipt,
    evaluate_retrieval,
    record_retrieval_event,
)
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


def test_empty_sql_receipt_is_not_negative_evidence_or_support(tmp_path) -> None:
    receipt = ToolReceipt(
        receipt_id="r-1",
        call_id="H-1-q1",
        session_id="S-1",
        hypothesis_id="H-1",
        phase="do",
        tool_id="sql.query",
        arguments={"normalized_sql": "SELECT 1"},
        coverage_snapshot={"status": "unknown"},
        cache={"status": "not_applicable"},
        returned_count=0,
        sampled_count=0,
        truncated=False,
        result_refs={"evidence_ids": []},
        status="empty",
        reason="no rows returned",
    )

    evaluation = evaluate_retrieval(receipt, required_fields=["normalized_sql"])

    assert isinstance(evaluation, RetrievalEvaluation)
    assert evaluation.outcome == "partial"
    assert evaluation.empty_semantics == "unknown"
    assert "supporting" not in receipt.model_dump()
    error = receipt.model_copy(
        update={
            "status": "error",
            "returned_count": None,
            "sampled_count": None,
            "truncated": None,
        }
    )
    error_eval = evaluate_retrieval(error, required_fields=["normalized_sql"])
    assert error_eval.outcome == "unavailable"
    assert error_eval.empty_semantics == "not_empty"
    observable = receipt.model_copy(
        update={
            "coverage_snapshot": {
                "status": "observed",
                "capabilities": {"evtx:security_logon": {"state": "available"}},
            }
        }
    )
    observable_eval = evaluate_retrieval(
        observable,
        required_fields=["normalized_sql"],
        required_capabilities=["security_logon"],
    )
    assert observable_eval.empty_semantics == "observable"
    unrelated_eval = evaluate_retrieval(
        observable,
        required_fields=["normalized_sql"],
        required_capabilities=["registry_users"],
    )
    assert unrelated_eval.empty_semantics == "unknown"
    with pytest.raises(ValueError):
        ToolReceipt.model_validate({**receipt.model_dump(), "supporting": True})
    with pytest.raises(ValueError):
        ToolReceipt.model_validate(
            {**receipt.model_dump(), "result_refs": {"supporting": ["e-1"]}}
        )
