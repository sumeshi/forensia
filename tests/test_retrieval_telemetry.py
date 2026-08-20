from __future__ import annotations

import json

import pytest

from forensia.ai.hypotheses.execution import build_sql_receipt
from forensia.ai.retrieval_telemetry import (
    RetrievalEvaluation,
    ToolReceipt,
    evaluate_retrieval,
    record_retrieval_event,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery
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


def test_memory_retrieval_evaluation_distinguishes_empty_from_rejected_scope() -> None:
    memory_receipt = ToolReceipt(
        receipt_id="memory-1",
        call_id="memory-call-1",
        phase="read_more",
        tool_id="memory.read_more",
        arguments={"paths": ["entities/host-A.md"]},
        returned_count=0,
        status="empty",
    )
    assert (
        evaluate_retrieval(
            memory_receipt, required_fields=["paths"], scope_status="valid"
        ).outcome
        == "needs-pivot"
    )
    assert (
        evaluate_retrieval(
            memory_receipt, required_fields=["paths"], scope_status="rejected"
        ).outcome
        == "invalid"
    )


def test_fallback_receipt_keeps_pre_limit_count_and_truncation() -> None:
    receipt = build_sql_receipt(
        db=object(),
        session_id="S-1",
        plan_cycle=1,
        query_index=1,
        hypothesis=Hypothesis(id="H-1", description="test"),
        planned_query=PlannedQuery(
            query_id="H-1-q1",
            hypothesis_id="H-1",
            purpose="test",
            sql="SELECT 1",
        ),
        query_hash="qhash",
        duration_ms=1,
        rows=[{"event_id": i} for i in range(20)],
        original_row_count=0,
        fallback_info={
            "phase": "artifact_table",
            "original_row_count": 24,
            "truncated": True,
        },
    )
    assert receipt.arguments["fallback_row_count"] == 24
    assert receipt.returned_count == 20
    assert receipt.truncated is True
