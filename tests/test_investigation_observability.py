"""Actual investigation producers retain evidence and causal stage identities."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from forensia.context.sql_templates import render_query_template
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.db.investigation_state import ensure_investigation_state
from forensia.investigation.hypotheses import execution
from forensia.investigation.hypotheses import hypothesis_runner as runner
from forensia.investigation.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.investigation.investigation_cycle import _run_cycle_body
from forensia.investigation.investigation_session import Ctx
from forensia.investigation.planner import HypothesisPlanResult
from forensia.investigation.verification.check_normalize import CheckResult
from forensia.knowledge.coverage import canonical_observation_claim
from forensia.llm.telemetry import (
    LLMTelemetry,
    get_active_telemetry,
    reset_active_telemetry,
    set_active_telemetry,
)

SESSION = "session-observability"
SQL = (
    "SELECT evidence_id, file_name, is_deleted FROM mft_entries "
    "WHERE evidence_id = 'mft-alpha'"
)


@pytest.fixture()
def observation_case(tmp_path):
    case = Case.init(tmp_path / "case")
    spec = VerificationSpec(
        support_conditions={
            "observation": {
                "family": "mft",
                "capability": "file_activity",
                "field": "is_deleted",
                "operator": "equals",
                "value": True,
                "evidence_ids": ["mft-alpha"],
            }
        }
    )
    hypothesis = Hypothesis(
        id="H-deletion",
        description=canonical_observation_claim(spec),
        verification_spec=spec,
    )
    with CaseDB(case) as db:
        ensure_investigation_state(db, objective="verify the canonical deletion flag")
        _upsert_hypothesis(db, hypothesis, "test", SESSION)
        db.execute(
            "INSERT INTO mft_entries (evidence_id, source_file, file_name, is_deleted) "
            "VALUES ('mft-alpha', 'volume.mft', 'ALPHA.EXE', true)"
        )
        db.execute(
            "INSERT INTO evidence_sources (source_id, artifact_family, ingest_status, "
            "parser_name, parser_version, row_count) "
            "VALUES ('source-mft', 'mft', 'normalized', 'mft2es', 'test', 1)"
        )
        db.execute(
            "INSERT INTO evidence_coverage (capability, source_family, state) "
            "VALUES ('file_activity', 'mft', 'available')"
        )
    return case, hypothesis


def _plan(hypothesis: Hypothesis, **query_fields) -> HypothesisPlanResult:
    return HypothesisPlanResult(
        query=PlannedQuery(
            query_id="Q-deletion",
            hypothesis_id=hypothesis.id,
            purpose="Read the deletion flag on the specified MFT record",
            **({"sql": SQL} | query_fields),
        ),
        stop_reason=None,
        raw_response={"action": {"intent": "read the canonical deletion flag"}},
    )


def _run(case, hypothesis, db, events, *, cycle=False):
    state = SessionState(
        session_id=SESSION, iteration=1, active_hypotheses=[hypothesis]
    )
    ctx = Ctx(progress_callback=events.append)
    shared = dict(
        case=case,
        db=db,
        state=state,
        ctx=ctx,
        session_id=SESSION,
        base_url="http://llm.invalid",
        model="offline-test",
        plan_cycle=1,
        max_queries_per_hypothesis=1,
    )
    if cycle:
        return asyncio.run(
            _run_cycle_body(
                **shared,
                progress_callback=events.append,
                max_iter=1,
                report_only=False,
            )
        )
    return asyncio.run(
        runner._investigate_one_hypothesis(
            **shared, hypothesis=hypothesis, query_limit=1
        )
    )


def _steps(db):
    return [
        {
            "id": step_id,
            "phase": phase,
            "input": json.loads(step_input),
            "output": json.loads(step_output),
        }
        for step_id, phase, step_input, step_output in db.execute(
            "SELECT step_id, phase, input_json, output_json "
            "FROM trace.investigation_steps WHERE session_id = ? "
            "ORDER BY created_at, step_id",
            [SESSION],
        ).fetchall()
    ]


def _stage(steps, phase):
    return next(step for step in steps if step["phase"] == phase)


def _assert_chain(steps):
    plan = _stage(steps, "plan-hypothesis")
    execution = _stage(steps, "query-execution")
    terminal = _stage(steps, "do")
    check = _stage(steps, "check")
    sufficiency = _stage(steps, "sufficiency")
    settlement = _stage(steps, "settlement")
    act = _stage(steps, "act")
    attempt_ref = execution["input"]["attempt_ref"]
    assert execution["input"]["plan_step_id"] == plan["id"]
    for stage in (terminal, check, sufficiency, settlement, act):
        assert stage["input"]["plan_step_id"] == plan["id"]
        assert stage["input"]["execution_step_id"] == execution["id"]
    assert terminal["output"]["attempt"]["attempt_ref"] == attempt_ref
    for stage in (check, sufficiency, settlement, act):
        assert stage["input"]["attempt_ref"] == attempt_ref
        assert stage["input"]["do_step_id"] == terminal["id"]
    assert sufficiency["input"]["check_step_id"] == check["id"]
    assert act["input"]["sufficiency_step_id"] == sufficiency["id"]
    assert act["output"]["settlement_ref"] == settlement["id"]
    assert plan["output"]["materialized_query"]["sql"] == SQL
    return attempt_ref


def test_cycle_events_and_reopened_trace_follow_the_actual_stage_chain(
    observation_case, monkeypatch
):
    case, hypothesis = observation_case
    monkeypatch.setattr(runner, "plan_hypothesis_query", lambda **_: _plan(hypothesis))
    events = []
    with CaseDB(case) as db:
        _run(case, hypothesis, db, events, cycle=True)

    with CaseDB(case, read_only=True) as db:
        steps = _steps(db)
        attempt_ref = _assert_chain(steps)
        assert _stage(steps, "act")["output"]["verdict"] == "confirmed"
        by_id = {step["id"]: step for step in steps}
        emitted = {event["kind"]: event for event in events}
        expected = {
            "query.planned": "plan-hypothesis",
            "hypothesis.check_completed": "check",
            "hypothesis.verdict_applied": "act",
            "investigation.sufficiency": "sufficiency",
            "investigation.settlement": "settlement",
        }
        for kind, phase in expected.items():
            event = emitted[kind]
            assert by_id[event["refs"]["step_id"]]["phase"] == phase
            assert event["refs"]["attempt_ref"] == attempt_ref
            audit = event["attributes"]["audit"]
            assert audit["version"] == "1"
            assert audit["origin"] in {"planner", "host", "checker"}
            assert audit["purpose"]
            assert audit["test_intent"] == "primary_verification"
        verdict = emitted["hypothesis.verdict_applied"]
        assert verdict["refs"]["check_step_id"] == _stage(steps, "check")["id"]
        assert verdict["refs"]["settlement_ref"] == _stage(steps, "settlement")["id"]


def test_revisiting_same_query_index_keeps_both_complete_stage_chains(
    observation_case, monkeypatch
):
    case, hypothesis = observation_case
    hypothesis.verification_spec.evidence_requirements = {"min_count": 2}
    monkeypatch.setattr(runner, "plan_hypothesis_query", lambda **_: _plan(hypothesis))
    with CaseDB(case) as db:
        _upsert_hypothesis(db, hypothesis, "test", SESSION)
        _run(case, hypothesis, db, [])
        first = _steps(db)
        first_ids = {step["id"] for step in first}
        db.execute("UPDATE evidence_sources SET parser_version = 'test-revised'")
        _run(case, hypothesis, db, [])

    with CaseDB(case, read_only=True) as db:
        all_steps = _steps(db)
        second = [step for step in all_steps if step["id"] not in first_ids]
        assert _assert_chain(first) != _assert_chain(second)
        for phase in (
            "plan-hypothesis",
            "query-execution",
            "do",
            "check",
            "sufficiency",
            "act",
        ):
            assert len([step for step in all_steps if step["phase"] == phase]) == 2
        assert {step["id"] for step in _steps(db)} >= first_ids


def test_failed_execution_then_retry_retains_both_attempts_at_the_same_index(
    observation_case, monkeypatch
):
    case, hypothesis = observation_case
    monkeypatch.setattr(runner, "plan_hypothesis_query", lambda **_: _plan(hypothesis))
    fetch = runner.fetch_bounded_records

    def failing_fetch(*args, **kwargs):
        raise RuntimeError("database is locked")

    with CaseDB(case) as db:
        monkeypatch.setattr(runner, "fetch_bounded_records", failing_fetch)
        _run(case, hypothesis, db, [])
        failed = _steps(db)
        failed_ids = {step["id"] for step in failed}
        monkeypatch.setattr(runner, "fetch_bounded_records", fetch)
        _run(case, hypothesis, db, [])

    with CaseDB(case, read_only=True) as db:
        steps = _steps(db)
        successful = [step for step in steps if step["id"] not in failed_ids]
        _assert_chain(successful)
        error = _stage(failed, "do")
        start = _stage(failed, "query-execution")
        assert error["input"]["execution_step_id"] == start["id"]
        assert error["input"]["plan_step_id"] == _stage(failed, "plan-hypothesis")["id"]
        assert error["output"]["tool_receipt"]["status"] == "error"
        assert "database is locked" in error["output"]["attempt"]["error"]
        assert error["id"] != _stage(successful, "do")["id"]
        assert start["input"]["query_index"] == 1
        assert _stage(successful, "query-execution")["input"]["query_index"] == 1


def test_process_interruption_retains_materialized_template_and_execution_start(
    observation_case, monkeypatch
):
    case, hypothesis = observation_case
    template_id = "q_registry_timeline_recent"
    rendered = render_query_template(template_id, {})
    plan = _plan(hypothesis, sql=rendered, template_id=template_id)
    plan.raw_response = {"action": {"template_id": template_id, "params": {}}}
    monkeypatch.setattr(runner, "plan_hypothesis_query", lambda **_: plan)

    class ProcessInterrupted(BaseException):
        pass

    def interrupted_fetch(db, sql, **kwargs):
        steps = _steps(db)
        persisted = _stage(steps, "plan-hypothesis")
        assert persisted["id"] == plan.step_id
        assert persisted["output"]["materialized_query"]["sql"] == rendered
        assert persisted["output"]["materialized_query"]["template_id"] == template_id
        assert _stage(steps, "query-execution")["input"]["host_executed_sql"] == sql
        raise ProcessInterrupted()

    monkeypatch.setattr(runner, "fetch_bounded_records", interrupted_fetch)
    with CaseDB(case) as db, pytest.raises(ProcessInterrupted):
        _run(case, hypothesis, db, [])

    with CaseDB(case, read_only=True) as db:
        steps = _steps(db)
        execution = _stage(steps, "query-execution")
        assert execution["input"]["plan_step_id"] == plan.step_id
        assert execution["output"] == {"status": "running"}
        assert not any(step["phase"] in {"do", "check", "act"} for step in steps)


def test_same_index_visits_bind_planning_and_checker_calls_to_exact_saved_actions(
    observation_case, monkeypatch
):
    case, hypothesis = observation_case
    hypothesis.description = "Review file activity with independent corroboration"
    hypothesis.verification_spec = VerificationSpec(
        required_capabilities=["file_activity"],
        evidence_requirements={"min_count": 2},
    )

    def logical_call(phase):
        telemetry = get_active_telemetry()
        assert telemetry is not None
        call_id = telemetry.begin_logical_call(phase=phase)
        telemetry.close_logical_call(logical_call_id=call_id, status="success")

    def plan(**kwargs):
        logical_call("hypothesis-plan")
        return _plan(hypothesis)

    def check(**kwargs):
        for phase in ("check-verdict", "check-finding-extract"):
            logical_call(phase)
        return CheckResult(
            query_id=kwargs["planned_query"].query_id,
            verdict="inconclusive",
            finding_updates=[],
            suspicious_evidence=[],
            new_hypotheses=[],
            report_text="Independent corroboration is still required.",
            raw_response={},
        )

    monkeypatch.setattr(runner, "plan_hypothesis_query", plan)
    monkeypatch.setattr(runner, "check_query_result", check)
    with CaseDB(case) as db:
        _upsert_hypothesis(db, hypothesis, "test", SESSION)
        token = set_active_telemetry(LLMTelemetry(db, SESSION))
        try:
            _run(case, hypothesis, db, [])
            db.execute("UPDATE evidence_sources SET parser_version = 'test-revised'")
            _run(case, hypothesis, db, [])
        finally:
            reset_active_telemetry(token)

    with CaseDB(case, read_only=True) as db:
        steps = _steps(db)
        plans = [step for step in steps if step["phase"] == "plan-hypothesis"]
        checks = [step for step in steps if step["phase"] == "check"]
        assert len(plans) == len(checks) == 2
        assert len({step["input"]["action_id"] for step in plans}) == 2
        assert {step["input"]["query_index"] for step in plans} == {1}
        for step in plans + checks:
            action_id = step["input"]["action_id"]
            calls = db.execute(
                "SELECT phase, status, iteration FROM trace.llm_logical_calls "
                "WHERE action_id = ? AND session_id = ? AND hypothesis_id = ?",
                [action_id, SESSION, hypothesis.id],
            ).fetchall()
            expected = (
                {"hypothesis-plan"}
                if step["phase"] == "plan-hypothesis"
                else {"check-verdict", "check-finding-extract"}
            )
            assert {phase for phase, _, _ in calls} == expected
            assert len(calls) == len(expected)
            assert {(status, iteration) for _, status, iteration in calls} == {
                ("success", 1)
            }
            if step["phase"] == "check":
                assert action_id == f"{step['input']['attempt_ref']}:check"
        assert db.execute(
            "SELECT COUNT(*) FROM trace.llm_logical_calls"
        ).fetchone() == (6,)
        assert db.execute(
            "SELECT COUNT(*) FROM trace.llm_provider_attempts"
        ).fetchone() == (0,)


@pytest.mark.parametrize("outcome", ["empty", "match", "sqlerror"])
def test_fallback_sql_receipts_survive_reopen_and_keep_the_primary_parent(
    observation_case, monkeypatch, outcome
):
    case, hypothesis = observation_case
    hypothesis.source_rule_ids = ["rule-mft-fallback"]
    declared = {"phase": "artifact_table", "table": " MFT_ENTRIES "}
    rule = SimpleNamespace(fallback_search=[declared])
    monkeypatch.setattr(execution, "load_rule_by_id", lambda rule_id: rule)
    primary_sql = "SELECT evidence_id FROM evtx_events WHERE event_id = 99999"
    monkeypatch.setattr(
        runner, "plan_hypothesis_query", lambda **_: _plan(hypothesis, sql=primary_sql)
    )
    with CaseDB(case) as db:
        _upsert_hypothesis(db, hypothesis, "test", SESSION)
        if outcome == "empty":
            db.execute("DELETE FROM mft_entries")
        elif outcome == "sqlerror":
            fetch_primary = runner.fetch_bounded_records

            def remove_fallback_table(database, sql, **kwargs):
                result = fetch_primary(database, sql, **kwargs)
                database.execute("DROP TABLE mft_entries")
                return result

            monkeypatch.setattr(runner, "fetch_bounded_records", remove_fallback_table)
        _run(case, hypothesis, db, [])

    with CaseDB(case, read_only=True) as db:
        steps = _steps(db)
        primary = _stage(steps, "query-execution")
        start = _stage(steps, "fallback-query")
        result = _stage(steps, "fallback-query-result")
        terminal = _stage(steps, "do")
        for fallback in (start, result):
            inputs = fallback["input"]
            assert inputs["execution_step_id"] == primary["id"]
            assert inputs["plan_step_id"] == primary["input"]["plan_step_id"]
            assert inputs["attempt_ref"] == primary["input"]["attempt_ref"]
            assert inputs["sql"] == "SELECT * FROM mft_entries LIMIT 100"
            assert inputs["params"] == []
            assert inputs["source_rule_id"] == hypothesis.source_rule_ids[0]
            assert inputs["declared_fallback"] == declared
            assert inputs["resolved_config"] == {
                "phase": "artifact_table",
                "table": "mft_entries",
                "limit": 100,
            }
        assert result["input"]["fallback_start_step_id"] == start["id"]
        assert (
            result["input"]["fallback_query_ref"]
            == start["input"]["fallback_query_ref"]
        )
        assert start["output"]["status"] == "running"
        fallback_ids = [start["id"], result["id"]]
        assert terminal["input"]["fallback_step_ids"] == fallback_ids
        receipt = terminal["output"]["tool_receipt"]
        assert receipt["arguments"]["fallback_step_ids"] == fallback_ids
        assert receipt["receipt_id"] == primary["input"]["attempt_ref"]
        assert terminal["input"]["execution_step_id"] == primary["id"]
        assert steps.index(primary) < steps.index(start) < steps.index(result)
        assert steps.index(result) < steps.index(terminal)
        if outcome == "sqlerror":
            assert result["output"]["status"] == "failed"
            assert result["output"]["error_type"] == "CatalogException"
            assert receipt["status"] == "error"
            assert not any(step["phase"] == "check" for step in steps)
        else:
            assert result["output"]["status"] == "completed"
            assert result["output"]["returned_count"] == int(outcome == "match")
            assert receipt["status"] == ("partial" if outcome == "match" else "empty")
            if outcome == "match":
                assert (
                    terminal["output"]["retrieval_evaluation"]["outcome"] == "partial"
                )
                assert (
                    _stage(steps, "sufficiency")["output"]["machine_status"]
                    != "sufficient"
                )
            assert _stage(steps, "act")["output"]["verdict"] != "confirmed"
