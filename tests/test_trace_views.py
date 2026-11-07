"""Read-only trace navigation keeps historical records and current data distinct."""

from __future__ import annotations

import json

import pytest

from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.db.views import DETAIL_KINDS, case_detail


@pytest.fixture
def db(tmp_path):
    with CaseDB(Case.init(tmp_path / "case")) as case_db:
        yield case_db


def _step(
    db,
    step_id,
    *,
    hypothesis_id="H-1",
    session_id="session-1",
    phase="do",
    step_input=None,
    step_output=None,
    created_at="2026-01-01 00:00:00",
):
    db.execute(
        "INSERT INTO trace.investigation_steps "
        "(step_id, hypothesis_id, session_id, phase, input_json, output_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            step_id,
            hypothesis_id,
            session_id,
            phase,
            json.dumps(step_input or {}),
            json.dumps(step_output or {}),
            created_at,
        ),
    )


def _link_ids(detail):
    return {(link["kind"], link["id"]) for link in detail["related_records"]}


def test_timeline_pages_recorded_hypothesis_ownership_across_sessions(db):
    _step(
        db,
        "do-1",
        step_output={
            "tool_receipt": {
                "receipt_id": "receipt-1",
                "status": "ok",
                "returned_count": 2,
            }
        },
    )
    _step(
        db,
        "check-1",
        phase="check",
        created_at="2026-01-01 00:00:02",
        step_output={
            "attempt_ref": "receipt-1",
            "assessment": {"assessment_id": "assessment-1"},
        },
    )
    _step(db, "do-2", session_id="session-2", created_at="2026-01-02 00:00:00")
    _step(db, "unrelated", hypothesis_id="H-2", created_at="2026-01-01 00:00:01")
    db.execute(
        "INSERT INTO trace.llm_logical_calls "
        "(logical_call_id, hypothesis_id, session_id, phase, status, created_at) "
        "VALUES ('call-1', 'H-1', 'session-1', 'query-plan', 'success', '2026-01-01 00:00:01')"
    )
    db.execute(
        "INSERT INTO trace.llm_provider_attempts (attempt_id, logical_call_id) "
        "VALUES ('provider-1', 'call-1')"
    )
    db.execute(
        "INSERT INTO trace.hypothesis_reasoning "
        "(entry_id, hypothesis_id, session_id, phase, body, created_at) "
        "VALUES ('reason-1', 'H-1', 'session-2', 'check', 'model claim not a fact', '2026-01-02 00:00:01')"
    )
    first = case_detail(db, "timeline", "H-1", limit=2)
    assert first["total_items"] == 5
    assert [item["id"] for item in first["items"]] == ["do-1", "call-1"]
    assert first["next_offset"] == 2
    assert ("llm_attempt", "provider-1") in _link_ids(first["items"][1])
    assert "success" in first["items"][1]["summary"]
    second = case_detail(db, "timeline", "H-1", limit=2, offset=2)
    assert [item["id"] for item in second["items"]] == ["check-1", "do-2"]
    assert [item["session_id"] for item in second["items"]] == [
        "session-1",
        "session-2",
    ]
    assert ("query_receipt", "receipt-1") in _link_ids(second["items"][0])
    last = case_detail(db, "timeline", "H-1", limit=2, offset=4)
    assert last["next_offset"] is None
    assert "model claim" not in json.dumps(last)
    assert "timeline" in DETAIL_KINDS


def test_timeline_is_bounded_and_ties_use_stable_identity(db):
    db.execute(
        "INSERT INTO trace.investigation_steps "
        "(step_id, hypothesis_id, phase, input_json, output_json, created_at) "
        "SELECT 'step-' || lpad(CAST(i AS VARCHAR), 3, '0'), 'H-1', 'check', '{}', '{}', now() "
        "FROM range(60) r(i)"
    )
    page = case_detail(db, "timeline", "H-1", limit=100)
    assert len(page["items"]) == 50
    assert page["next_offset"] == 50
    assert [item["id"] for item in page["items"]] == [f"step-{i:03}" for i in range(50)]
    assert all(item["correlation_status"] == "unknown" for item in page["items"])
    assert len(case_detail(db, "timeline", "H-1", offset=50)["items"]) == 10
    assert case_detail(db, "timeline", "missing") is None
    assert case_detail(db, "timeline", "H-1", offset=999)["items"] == []
    with pytest.raises(ValueError, match="offset"):
        case_detail(db, "timeline", "H-1", offset=-1)


def test_timeline_does_not_join_reused_query_labels_or_expand_model_prose(db):
    secret_prose = "CHECKER_CLAIM_NOT_A_HOST_FACT"
    _step(
        db,
        "do-1",
        step_input={"planned_query": {"query_id": "Q-1", "purpose": "Verify target"}},
        step_output={"tool_receipt": {"receipt_id": "r-1", "returned_count": 0}},
    )
    _step(
        db,
        "legacy-check",
        phase="check",
        session_id="session-2",
        step_input={"planned_query": {"query_id": "Q-1"}},
        step_output={"check_summary": secret_prose, "raw_response": secret_prose},
    )
    page = case_detail(db, "timeline", "H-1")
    legacy = next(item for item in page["items"] if item["id"] == "legacy-check")
    assert legacy["correlation_status"] == "unknown"
    assert ("query_receipt", "r-1") not in _link_ids(legacy)
    assert secret_prose not in json.dumps(page)
    assert "Verify target" in json.dumps(page)


def test_timeline_session_provenance_uses_exact_session_reference(db):
    _step(
        db,
        "execution-start",
        phase="query-execution",
        step_input={"planned_query": {"purpose": "Check a host"}},
    )
    _step(db, "provenance", phase="runtime-provenance", hypothesis_id=None)
    _step(db, "settings", phase="session-settings", hypothesis_id=None)
    _step(
        db,
        "other-provenance",
        phase="runtime-provenance",
        hypothesis_id=None,
        session_id="other-session",
    )
    page = case_detail(db, "timeline", "H-1")
    assert page["total_items"] == 1
    assert "started (historical event)" in page["items"][0]["summary"]
    assert _link_ids(page) == {
        ("hypothesis", "H-1"),
        ("step", "provenance"),
        ("step", "settings"),
    }


def test_event_navigation_uses_explicit_refs_and_survives_large_detail_pages(db):
    event_id = record_progress_event(
        db,
        progress_event(
            "query.completed",
            "completed",
            refs={
                "hypothesis_id": "H-1",
                "plan_step_id": "plan-1",
                "execution_step_id": "execute-1",
                "receipt_id": "receipt-1",
                "settlement_ref": "settle-1",
            },
            summary="step-forged and call-forged occur only in text",
            audit={"normalized_sql": "SELECT 'step-fake'"},
            long_value="x" * 20000,
        ),
    )
    detail = case_detail(db, "event", str(event_id))
    expected = {
        ("hypothesis", "H-1"),
        ("step", "plan-1"),
        ("step", "execute-1"),
        ("query_receipt", "receipt-1"),
        ("step", "settle-1"),
    }
    assert _link_ids(detail) == expected
    assert detail["next_offset"] is not None
    next_page = case_detail(db, "event", str(event_id), offset=detail["next_offset"])
    assert _link_ids(next_page) == expected


def test_step_navigation_retains_contract_result_and_assessment_references(db):
    _step(
        db,
        "do-1",
        step_output={
            "tool_receipt": {
                "receipt_id": "r-1",
                "result_refs": {"evidence_ids": ["e-1"]},
            }
        },
    )
    _step(
        db,
        "settle-1",
        phase="settlement",
        step_output={
            "settlement": {
                "hypothesis_id": "H-1",
                "attempt_ref": "r-1",
                "task_contract_refs": {"task-1": "contract-1"},
                "assessment_ids": ["assessment-1"],
                "evidence_ids": ["e-1"],
            }
        },
    )
    detail = case_detail(db, "step", "settle-1")
    assert {
        ("hypothesis", "H-1"),
        ("query_receipt", "r-1"),
        ("task", "task-1"),
        ("step", "contract-1"),
        ("assessment", "assessment-1"),
        ("evidence", "e-1"),
    } <= _link_ids(detail)
    evidence_link = next(
        link for link in detail["related_records"] if link["kind"] == "evidence"
    )
    assert "current record" in evidence_link["label"]


def test_receipt_keeps_recorded_observation_separate_from_current_evidence(db):
    evidence_id = "evtx-" + "a" * 64 + "-security-000000000001"
    db.execute(
        "INSERT INTO evtx_events (evidence_id, event_id) VALUES (?, 99)",
        (evidence_id,),
    )
    _step(
        db,
        "do-1",
        step_output={
            "tool_receipt": {
                "receipt_id": "r-1",
                "result_refs": {"evidence_ids": [evidence_id]},
            },
            "sample_rows": [{"evidence_id": evidence_id, "event_id": 1}],
        },
    )
    detail = case_detail(db, "query_receipt", "r-1")
    assert detail["output_json"]["sample_rows"][0]["event_id"] == 1
    assert detail["evidence"][0]["event_id"] == 99
    assert detail["evidence_view"]["historical_result"] is False
    assert detail["evidence_view"]["origin"] == "current_case_records"


def test_timeline_reads_accepted_plan_purpose_and_explicit_causal_steps(db):
    causal_refs = {
        "plan_step_id": "plan-1",
        "execution_step_id": "execution-1",
        "do_step_id": "do-1",
        "check_step_id": "check-1",
        "sufficiency_step_id": "sufficiency-1",
    }
    _step(
        db,
        "settle-1",
        phase="query-plan",
        step_input=causal_refs,
        step_output={"materialized_query": {"purpose": "Verify accepted plan"}},
    )
    item = case_detail(db, "timeline", "H-1")["items"][0]
    assert "Verify accepted plan" in item["summary"]
    assert {("step", step_id) for step_id in causal_refs.values()} <= _link_ids(item)
    assert item["correlation_status"] == "recorded"


def test_navigation_and_timeline_do_not_change_case_or_trace(db):
    _step(db, "do-1", step_output={"tool_receipt": {"receipt_id": "r-1"}})
    before = db.execute(
        "SELECT * FROM trace.investigation_steps ORDER BY step_id"
    ).fetchall()
    case_detail(db, "timeline", "H-1")
    case_detail(db, "step", "do-1")
    case_detail(db, "query_receipt", "r-1")
    assert (
        db.execute(
            "SELECT * FROM trace.investigation_steps ORDER BY step_id"
        ).fetchall()
        == before
    )
    assert db.execute("SELECT count(*) FROM trace.progress_events").fetchone()[0] == 0


def test_timeline_exposes_failure_classification_and_host_gate_without_raw_error(db):
    _step(
        db,
        "failed-check",
        phase="check",
        step_output={
            "status": "failed",
            "error_type": "timeout",
            "error": "PRIVATE_RAW_EXCEPTION",
        },
    )
    _step(
        db,
        "settlement",
        phase="settlement",
        step_input={"planned_query": {"purpose": "long purpose " * 100}},
        step_output={"settlement": {"verdict": "inconclusive", "allowed": False}},
    )
    page = case_detail(db, "timeline", "H-1")
    summaries = {item["id"]: item["summary"] for item in page["items"]}
    assert "failed" in summaries["failed-check"]
    assert "timeout" in summaries["failed-check"]
    assert "host verdict inconclusive; allowed=false" in summaries["settlement"]
    assert "PRIVATE_RAW_EXCEPTION" not in json.dumps(page)
    assert all(len(summary) <= 320 for summary in summaries.values())


def test_action_navigation_requires_exact_action_session_and_hypothesis(db):
    _step(db, "plan-1", phase="query-plan", step_input={"action_id": "action-1"})
    _step(
        db,
        "other-session",
        session_id="session-2",
        step_input={"action_id": "action-1"},
    )
    _step(
        db,
        "other-hypothesis",
        hypothesis_id="H-2",
        step_input={"action_id": "action-1"},
    )
    db.execute(
        "INSERT INTO trace.llm_logical_calls (logical_call_id, action_id, session_id, hypothesis_id) VALUES "
        "('call-1', 'action-1', 'session-1', 'H-1'), "
        "('call-wrong-session', 'action-1', 'session-2', 'H-1'), "
        "('call-wrong-hypothesis', 'action-1', 'session-1', 'H-2'), "
        "('call-wrong-action', 'action-2', 'session-1', 'H-1')"
    )
    step_links = _link_ids(case_detail(db, "step", "plan-1"))
    assert {link for link in step_links if link[0] == "llm_call"} == {
        ("llm_call", "call-1")
    }
    call_links = _link_ids(case_detail(db, "llm_call", "call-1"))
    assert {link for link in call_links if link[0] == "step"} == {("step", "plan-1")}
    timeline = case_detail(db, "timeline", "H-1")
    plan = next(item for item in timeline["items"] if item["id"] == "plan-1")
    assert ("llm_call", "call-1") in _link_ids(plan)
    assert ("llm_call", "call-wrong-session") not in _link_ids(plan)


def test_case_wide_action_owner_null_is_not_a_wildcard(db):
    _step(
        db, "case-wide-plan", hypothesis_id=None, step_input={"action_id": "action-1"}
    )
    _step(db, "hypothesis-plan", step_input={"action_id": "action-1"})
    db.execute(
        "INSERT INTO trace.llm_logical_calls (logical_call_id, action_id, session_id, hypothesis_id) VALUES "
        "('case-wide-call', 'action-1', 'session-1', NULL), "
        "('hypothesis-call', 'action-1', 'session-1', 'H-1')"
    )
    links = _link_ids(case_detail(db, "llm_call", "case-wide-call"))
    assert ("step", "case-wide-plan") in links
    assert ("step", "hypothesis-plan") not in links


def test_large_evidence_fanout_preserves_causal_contract_and_assessment_links(db):
    _step(db, "do-1", step_output={"tool_receipt": {"receipt_id": "receipt-1"}})
    _step(
        db,
        "settle-1",
        step_output={
            "evidence_ids": [f"evidence-{i}" for i in range(100)],
            "settlement": {
                "attempt_ref": "receipt-1",
                "assessment_ids": ["assessment-1"],
                "task_contract_refs": {"task-1": "contract-1"},
            },
        },
    )
    detail = case_detail(db, "step", "settle-1")
    links = _link_ids(detail)
    assert {
        ("query_receipt", "receipt-1"),
        ("assessment", "assessment-1"),
        ("task", "task-1"),
        ("step", "contract-1"),
    } <= links
    assert len(detail["related_records"]) == 50


def test_step_navigation_follows_explicit_branches_within_recorded_owner(db):
    _step(db, "plan-1", phase="query-plan")
    _step(
        db,
        "execution-1",
        phase="query-execution",
        step_input={"plan_step_id": "plan-1"},
    )
    _step(
        db,
        "execution-branch",
        phase="query-execution",
        step_input={"plan_step_id": "plan-1"},
        created_at="2025-01-01 00:00:00",
    )
    _step(
        db,
        "wrong-session",
        session_id="session-2",
        step_input={"plan_step_id": "plan-1"},
    )
    _step(
        db,
        "wrong-hypothesis",
        hypothesis_id="H-2",
        step_input={"plan_step_id": "plan-1"},
    )
    _step(db, "unlinked-same-time", phase="query-execution")
    links = _link_ids(case_detail(db, "step", "plan-1"))
    assert {link for link in links if link[0] == "step"} == {
        ("step", "execution-1"),
        ("step", "execution-branch"),
    }
    assert ("step", "plan-1") in _link_ids(case_detail(db, "step", "execution-1"))
    timeline = case_detail(db, "timeline", "H-1")
    item = next(item for item in timeline["items"] if item["id"] == "plan-1")
    assert ("step", "execution-branch") in _link_ids(item)


def test_fallback_start_and_receipt_argument_refs_are_typed_steps(db):
    _step(db, "fallback-start", phase="fallback-query")
    _step(
        db,
        "fallback-result",
        phase="fallback-query-result",
        step_input={"fallback_start_step_id": "fallback-start"},
    )
    _step(
        db,
        "do-1",
        step_output={
            "tool_receipt": {
                "receipt_id": "receipt-1",
                "arguments": {
                    "fallback_step_ids": ["fallback-start", "fallback-result"]
                },
            }
        },
    )
    links = _link_ids(case_detail(db, "query_receipt", "receipt-1"))
    assert {("step", "fallback-start"), ("step", "fallback-result")} <= links
    assert ("step", "fallback-result") in _link_ids(
        case_detail(db, "step", "fallback-start")
    )
