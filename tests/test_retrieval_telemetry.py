from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from forensia.context.retrieval import (
    RetrievalEvaluation,
    ToolReceipt,
    evaluate_retrieval,
    record_retrieval_event,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.investigation.hypotheses.execution import build_sql_receipt
from forensia.investigation.hypotheses.hypothesis_runner import (
    _build_settlement_input,
    _canonical_evidence_rows,
    _canonical_query_summary,
    _evidence_scope_fingerprint,
    _finding_ids_by_evidence,
    _phase_check,
    _phase_execute,
)
from forensia.investigation.planner import _materialize_planned_query
from forensia.investigation.verification.assessment import assess_evidence_group
from forensia.investigation.verification.settlement import decide_settlement


def test_retrieval_event_is_written_to_trace_schema(tmp_path) -> None:
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        record_retrieval_event(
            db,
            session_id="S-1",
            scope_kind="hypothesis",
            scope_id="H-A",
            phase="hypothesis-plan",
            source_kind="org_knowledge",
            query_terms=["event", "1102"],
            candidate_count=2,
            selected_refs=["registry.md#overview"],
            rejected_refs=[],
            selected_chars=321,
            budget=1024,
        )
        row = db.execute(
            """
            SELECT scope_id, query_terms, selected_refs, rejected_refs,
                   selected_chars, budget
            FROM trace.retrieval_events
            """
        ).fetchone()

    assert row is not None
    assert row[0] == "H-A"
    assert json.loads(row[1]) == ["event", "1102"]
    assert json.loads(row[2]) == ["registry.md#overview"]
    assert json.loads(row[3]) == []
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


def test_assessment_hydrates_and_deduplicates_canonical_evidence(tmp_path) -> None:
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, channel, event_id, raw_json) "
            "VALUES ('evtx-real', 'source-hash', 'Security', 4624, '{\"canonical\":true}')"
        )
        db.execute(
            "INSERT INTO findings (finding_id, evidence) "
            "VALUES ('F-CANONICAL', '[{\"evidence_id\":\"evtx-real\"}]')"
        )
        rows, evidence_ids, content_fingerprints = _canonical_evidence_rows(
            db,
            [
                {
                    "evidence_id": "evtx-real",
                    "event_id": 9999,
                    "source_family": "mft",
                    "computer": "forged-host",
                },
                {
                    "artifact_id": "evtx-real",
                    "event_id": 4624,
                    "artifact_family": "mft",
                },
                {"evidence_id": "evtx-missing", "event_id": 4624},
            ],
        )
        finding_ids_by_evidence = _finding_ids_by_evidence(db, evidence_ids)

    assert evidence_ids == ["evtx-real"]
    assert len(rows) == 1
    assert rows[0]["event_id"] == 4624
    assert rows[0]["source_family"] == "evtx"
    assert content_fingerprints["evtx-real"].startswith("cf-")
    assert finding_ids_by_evidence == {"evtx-real": "F-CANONICAL"}
    assert rows[0]["computer"] is None
    assert rows[0]["raw_json"] == {"canonical": True}

    hypothesis = Hypothesis(
        id="H-duplicate-query-row",
        description="Two logons were observed",
        confirm_when={"co_observed_event_ids": [4624], "min_count": 2},
    )
    duplicate = assess_evidence_group(
        hypothesis=hypothesis,
        rows=rows,
        evidence_ids=evidence_ids,
    )
    assert duplicate.role == "contextual"
    assert duplicate.evidence_ids == ()
    assert duplicate.contextual_evidence_ids == ("evtx-real",)


def test_phase_check_trace_persists_assessment_content_fingerprints(tmp_path) -> None:
    case = Case.init(tmp_path)
    hypothesis = Hypothesis(
        id="H-TRACE-ASSESSMENT",
        description="A successful logon was observed",
        confirm_when={"co_observed_event_ids": [4624]},
    )
    assessment = assess_evidence_group(
        hypothesis=hypothesis,
        rows=[{"evidence_id": "evtx-real", "event_id": 4624}],
        evidence_ids=["evtx-real"],
        retrieval_outcome="partial",
        content_fingerprints={"evtx-real": "cf-canonical-content"},
    )
    rs = SimpleNamespace(
        hypothesis=hypothesis,
        state=SimpleNamespace(history=[]),
        ctx=SimpleNamespace(progress_callback=None),
        base_url="http://localhost",
        model="test",
        plan_cycle=1,
        session_id="S-TRACE-ASSESSMENT",
        case=case,
        emit_fn=None,
        llm_status_fn=None,
        query_index=1,
        candidates=[],
        planned_query=SimpleNamespace(
            query_id="Q-1",
            template_id="",
            params={},
            purpose="test",
            model_dump=lambda: {"query_id": "Q-1"},
        ),
        result_summary={"evidence_ids": ["evtx-real"], "observed_row_count": 1},
        fallback_info=None,
        rows=[{"evidence_id": "evtx-real", "event_id": 4624}],
        observed_evidence_ids=["evtx-real"],
        canonical_evidence_ids=["evtx-real"],
        finding_ids_by_evidence={},
        retrieval_evaluation=SimpleNamespace(outcome="partial"),
        evidence_assessment=assessment,
        canonicalization_error="",
        attempt_ref="R-1",
    )
    check_result = SimpleNamespace(
        verdict="inconclusive",
        report_text="checked",
        raw_response={},
        new_hypotheses=[],
        progress=False,
    )

    with CaseDB(case) as db:
        rs.db = db
        with patch(
            "forensia.investigation.hypotheses.hypothesis_runner.check_query_result",
            return_value=check_result,
        ):
            assert asyncio.run(_phase_check(rs)) == "ok"
        output_row = db.execute(
            "SELECT output_json FROM trace.investigation_steps WHERE phase = 'check'"
        ).fetchone()

    assert output_row is not None
    payload = json.loads(output_row[0])
    assert payload["assessment"]["content_fingerprints"] == {
        "evtx-real": "cf-canonical-content"
    }


def test_checker_sample_prioritizes_witness_outside_default_sample() -> None:
    rows = [
        {
            "evidence_id": f"evtx-{index:02d}",
            "event_id": 4624 if index == 10 else 4625,
        }
        for index in range(20)
    ]
    evidence_ids = [row["evidence_id"] for row in rows]
    hypothesis = Hypothesis(
        id="H-sample-witness",
        description="A successful logon was observed",
        confirm_when={"co_observed_event_ids": [4624]},
    )

    assessment = assess_evidence_group(
        hypothesis=hypothesis,
        rows=rows,
        evidence_ids=evidence_ids,
        retrieval_outcome="adequate",
    )
    summary = _canonical_query_summary(
        rows,
        assessment,
        observed_row_count=23,
    )

    assert summary["row_count"] == 20
    assert summary["observed_row_count"] == 23
    assert len(summary["sample_rows"]) == 10
    assert "evtx-10" in summary["evidence_ids"]
    assert summary["evidence_ids"] == [
        row["evidence_id"] for row in summary["sample_rows"]
    ]


def test_evidence_scope_tracks_normalizer_receipt_and_source_changes(tmp_path):
    from forensia.pipeline import _record_stage_receipt

    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        source = {
            "source_id": "source-a",
            "artifact_family": "evtx",
            "display_path": "Security.evtx",
            "ingest_status": "normalized",
            "parser_name": "evtx-normalizer",
            "parser_version": "1",
            "row_count": 3,
            "channel": "Security",
            "hosts": ["WS-1"],
        }
        register_evidence_source(db, **source)
        _record_stage_receipt(
            db,
            "pipeline-normalize",
            "normalized-revision-a",
            "3 sources normalized",
            details={"parser_revision": "parser-revision-a"},
        )
        sql = "SELECT evidence_id FROM evtx_events"
        initial = _evidence_scope_fingerprint(db, sql)

        register_evidence_source(db, **source)
        assert _evidence_scope_fingerprint(db, sql) == initial

        receipt = db.execute(
            "SELECT step_id, output_json FROM trace.investigation_steps "
            "WHERE phase = 'pipeline-normalize'"
        ).fetchone()
        payload = json.loads(receipt[1])
        payload["revision"] = "normalized-revision-b"
        payload["parser_revision"] = "parser-revision-b"
        db.execute(
            "UPDATE trace.investigation_steps SET output_json = ? WHERE step_id = ?",
            [json.dumps(payload), receipt[0]],
        )
        assert _evidence_scope_fingerprint(db, sql) != initial

        register_evidence_source(db, **{**source, "source_id": "source-b"})
        assert _evidence_scope_fingerprint(db, sql) != initial


@pytest.mark.parametrize(
    ("state", "sql", "expected"),
    [
        (
            "available",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 LIMIT 20",
            "refuted",
        ),
        (
            "partial",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 LIMIT 20",
            "untestable",
        ),
        (
            "unknown",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 LIMIT 20",
            "untestable",
        ),
        (
            "unavailable",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 LIMIT 20",
            "untestable",
        ),
        (
            "available",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 AND computer = 'WS-X' LIMIT 20",
            "untestable",
        ),
        (
            "available",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4624 LIMIT 20",
            "untestable",
        ),
        (
            "available",
            "SELECT evidence_id FROM evtx_events TABLESAMPLE SYSTEM(0 PERCENT) WHERE event_id = 4688 LIMIT 20",
            "untestable",
        ),
        (
            "available",
            "SELECT unnest([]) FROM evtx_events WHERE event_id = 4688 LIMIT 20",
            "untestable",
        ),
        (
            "available",
            "SELECT evidence_id FROM evtx_events WHERE event_id = 4688 LIMIT 10 PERCENT",
            "untestable",
        ),
    ],
)
def test_runner_empty_sql_reaches_only_observable_refutation(
    tmp_path, state, sql, expected
):
    from forensia.investigation.investigation_session import Ctx

    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        # Other artifact families cannot veto or prove the EVTX lookup.
        db.execute(
            "INSERT INTO evidence_coverage (capability, host, channel, source_family, state, source_ids) "
            "VALUES ('process_execution', '', 'Security', 'evtx', ?, '[]'), "
            "('process_execution', '', '', 'mft', 'unavailable', '[]')",
            [state],
        )
        hypothesis = Hypothesis(
            id="H-absence",
            description="Process execution",
            confirm_when={"co_observed_event_ids": [4688]},
            refute_when={"zero_rows": True},
        )
        query = _materialize_planned_query(
            {
                "query_id": "Q-absence",
                "hypothesis_id": hypothesis.id,
                "purpose": "verify absence",
                "sql": sql,
            },
            db,
        )
        rs = SimpleNamespace(
            hypothesis=hypothesis,
            ctx=Ctx(),
            state=SessionState(session_id="S-test"),
            db=db,
            session_id="S-test",
            plan_cycle=1,
            query_index=0,
            emit_fn=None,
            focus_sections={},
            hypothesis_plan=SimpleNamespace(query=query),
            tracker=SimpleNamespace(
                record=lambda *a, **k: None,
                zero_row_inconclusive_count=3,
                consecutive_same_missing=0,
            ),
            missing_checks_raw=[],
            sufficiency_result=None,
            check_result=SimpleNamespace(verdict="inconclusive", report_text="empty"),
        )
        with patch(
            "forensia.investigation.hypotheses.hypothesis_runner.resolve_zero_row_fallbacks",
            side_effect=lambda **kwargs: (kwargs["rows"], None),
        ):
            assert _phase_execute(rs) == "ok"
        si = _build_settlement_input(rs)
        assert decide_settlement(si, links=[], coverage={}).verdict == expected
        if expected == "refuted":
            assert rs.retrieval_evaluation.scope_status == "valid"
            assert rs.retrieval_evaluation.coverage_status == "available"
            assert si.absence_scope == "observable"
        payload = db.execute(
            "SELECT output_json FROM trace.investigation_steps WHERE phase = 'do'"
        ).fetchone()[0]
        assert (
            json.loads(payload)["retrieval_evaluation"]
            == rs.retrieval_evaluation.model_dump()
        )
