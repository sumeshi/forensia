"""Task completion must refer to current, host-settled evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from forensia.context.retrieval import RetrievalEvaluation
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records
from forensia.evidence.content_identity import bulk_evidence_content_fingerprints
from forensia.evidence.links import verification_spec_fingerprint
from forensia.investigation import task_contracts
from forensia.investigation.hypotheses.execution import (
    _evidence_scope_fingerprint,
    build_sql_receipt,
)
from forensia.investigation.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.investigation.progress import query_fingerprint
from forensia.investigation.task_contracts import (
    ensure_task_contract,
    evaluate_task_completion,
    load_task_contract,
    record_settlement_receipt,
    record_task_completion,
    task_contract_summary,
)
from forensia.investigation.verification.assessment import assess_evidence_group
from forensia.investigation.verification.settlement import (
    SettlementInput,
    judge_absence_scope,
    settle_hypothesis,
)
from forensia.investigation.verification.sufficiency import (
    assess_and_persist_sufficiency,
    create_hypothesis_evidence_link,
)
from forensia.knowledge.coverage import canonical_observation_claim


@dataclass
class TaskCase:
    case: Case
    db: CaseDB
    hypothesis: Hypothesis
    task_id: str = "TASK-check-deletion"


@pytest.fixture
def task_case(tmp_path):
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
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
        _upsert_hypothesis(db, hypothesis, "test", "session-task")
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
        task = TaskCase(case, db, hypothesis)
        db.execute(
            "INSERT INTO investigation_tasks (task_id, kind, description, status, "
            "hypothesis_id, required_capability, required_source, owner_phase, "
            "created_at, updated_at) VALUES (?, 'needs_review', ?, 'in_progress', "
            "?, 'file_activity', 'mft', 'investigation', now(), now())",
            [task.task_id, hypothesis.description, hypothesis.id],
        )
        yield task


def save_search(
    task,
    *,
    attempt_ref="receipt-deletion",
    hypothesis_id=None,
    receipt_hypothesis_id=None,
    sql=None,
    rows=None,
):
    """Persist a real host receipt, without pretending that it is a conclusion."""
    db, hypothesis = task.db, task.hypothesis
    query = PlannedQuery(
        query_id="Q-deletion",
        hypothesis_id=hypothesis_id or hypothesis.id,
        purpose="Read the deletion flag on the specified MFT record",
        sql=sql
        or "SELECT evidence_id FROM mft_entries WHERE evidence_id = 'mft-alpha' LIMIT 1",
    )
    rows = [{"evidence_id": "mft-alpha"}] if rows is None else rows
    receipt = build_sql_receipt(
        db=db,
        session_id="session-task",
        plan_cycle=1,
        query_index=1,
        hypothesis=hypothesis,
        planned_query=query,
        query_hash=query_fingerprint(query.sql),
        duration_ms=1,
        rows=rows,
        original_row_count=len(rows),
    ).model_copy(update={"receipt_id": attempt_ref})
    if receipt_hypothesis_id is not None:
        receipt = receipt.model_copy(update={"hypothesis_id": receipt_hypothesis_id})
    db.execute(
        "INSERT INTO trace.investigation_steps VALUES "
        "(?, 'session-task', ?, 1, 'do', ?, ?, now())",
        [
            "do-" + attempt_ref,
            hypothesis_id or hypothesis.id,
            json.dumps({"planned_query": query.model_dump(mode="json")}),
            json.dumps(
                {
                    "tool_receipt": receipt.model_dump(mode="json"),
                    "attempt": {
                        "attempt_ref": attempt_ref,
                        "query_fingerprint": query_fingerprint(query.sql),
                        "verification_spec_fingerprint": verification_spec_fingerprint(
                            hypothesis.verification_spec
                        ),
                        "evidence_scope_fingerprint": _evidence_scope_fingerprint(
                            db, query.sql
                        ),
                        "status": receipt.status,
                        "evidence_ids": [row["evidence_id"] for row in rows],
                    },
                }
            ),
        ],
    )
    return attempt_ref


def settle_deletion(task):
    """Use the production assessment and settlement gates, rather than a mock verdict."""
    db, hypothesis = task.db, task.hypothesis
    records = fetch_evidence_records(db, ["mft-alpha"])
    rows = [{**record, "source_family": "mft"} for record in records.values()]
    assessment = assess_evidence_group(
        hypothesis=hypothesis,
        rows=rows,
        evidence_ids=["mft-alpha"],
        retrieval_outcome="adequate",
        content_fingerprints=bulk_evidence_content_fingerprints(db, ["mft-alpha"]),
    )
    assert assessment.role == "supporting"
    create_hypothesis_evidence_link(
        db,
        hypothesis_id=hypothesis.id,
        evidence_id="mft-alpha",
        source_family="mft",
        query_id="Q-deletion",
        assessment_id=assessment.assessment_id,
        assessment_reason=assessment.reason,
        matched_conditions=assessment.matched_conditions,
        strength="strong",
    )
    sufficient, _, _ = assess_and_persist_sufficiency(
        db,
        hypothesis_id=hypothesis.id,
        verification_spec=hypothesis.verification_spec,
        evidence_requirements=hypothesis.verification_spec.evidence_requirements,
        session_id="session-task",
    )
    decision = settle_hypothesis(
        db,
        SettlementInput(
            hypothesis=hypothesis,
            checker_verdict="inconclusive",
            check_summary="The host assesses the observed deletion flag",
            sample_rows=rows,
            sufficiency_result=sufficient,
        ),
    )
    assert decision.allowed and decision.verdict == "confirmed"
    return decision


def complete_deletion(task, *, task_contract_refs=None):
    attempt_ref = save_search(task)
    decision = settle_deletion(task)
    settlement_ref = record_settlement_receipt(
        task.db,
        hypothesis_id=task.hypothesis.id,
        decision=decision,
        attempt_ref=attempt_ref,
        session_id="session-task",
        iteration=1,
        task_contract_refs=task_contract_refs,
    )
    task.db.execute(
        "UPDATE hypotheses SET status = ?, verdict = ? WHERE hypothesis_id = ?",
        [decision.verdict, decision.verdict, task.hypothesis.id],
    )
    return settlement_ref


def test_current_settlement_completes_task_and_survives_case_reopen(task_case):
    task = task_case
    contract = ensure_task_contract(task.db, task.task_id, session_id="session-task")
    settlement_ref = complete_deletion(task)

    completion = evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    )
    assert completion.status == "completed"
    assert completion.contract_ref == contract.ref
    assert completion.settlement_ref == settlement_ref
    completion_ref = record_task_completion(
        task.db, completion, session_id="session-task"
    )
    assert task.db.execute(
        "SELECT 1 FROM trace.investigation_steps WHERE step_id = ?",
        [completion_ref],
    ).fetchone() == (1,)
    # The work-state owner, rather than a Trace recorder, owns the status write.
    assert task.db.execute(
        "SELECT status FROM investigation_tasks WHERE task_id = ?", [task.task_id]
    ).fetchone() == ("in_progress",)

    task.db.close()
    with CaseDB(task.case, read_only=True) as reopened:
        assert load_task_contract(reopened, task.task_id).ref == contract.ref
        assert (
            evaluate_task_completion(
                reopened, task.task_id, settlement_ref=settlement_ref
            ).status
            == "completed"
        )


def test_successful_search_does_not_complete_parent_work(task_case):
    task = task_case
    ensure_task_contract(task.db, task.task_id)
    save_search(task)

    completion = evaluate_task_completion(task.db, task.task_id)
    assert completion.status == "blocked"
    assert task.db.execute(
        "SELECT status, verdict FROM hypotheses WHERE hypothesis_id = ?",
        [task.hypothesis.id],
    ).fetchone() == ("active", None)
    assert task.db.execute(
        "SELECT status FROM investigation_tasks WHERE task_id = ?", [task.task_id]
    ).fetchone() == ("in_progress",)


def test_parent_settlement_cannot_substitute_for_external_task_owner(task_case):
    task = task_case
    task.db.execute(
        "UPDATE investigation_tasks SET kind = 'evidence_acquisition' WHERE task_id = ?",
        [task.task_id],
    )
    ensure_task_contract(task.db, task.task_id)
    settlement_ref = complete_deletion(task)

    completion = evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    )
    assert completion.status == "blocked"
    assert completion.reason == "external_owner_result_required"


@pytest.mark.parametrize(
    "change", ["specification", "coverage", "content", "support_strength"]
)
def test_completion_rejects_changed_inputs_or_assessed_material(task_case, change):
    task = task_case
    ensure_task_contract(task.db, task.task_id)
    settlement_ref = complete_deletion(task)
    assert (
        evaluate_task_completion(
            task.db, task.task_id, settlement_ref=settlement_ref
        ).status
        == "completed"
    )

    if change == "specification":
        spec = task.hypothesis.verification_spec.model_copy(
            update={"required_capabilities": ["file_activity", "persistence"]}
        )
        task.db.execute(
            "UPDATE hypotheses SET verification_spec = ? WHERE hypothesis_id = ?",
            [spec.model_dump_json(), task.hypothesis.id],
        )
    elif change == "coverage":
        task.db.execute(
            "UPDATE evidence_coverage SET state = 'unavailable' "
            "WHERE capability = 'file_activity'"
        )
    elif change == "content":
        # Leave source identity and row count unchanged: material currentness matters.
        task.db.execute(
            "UPDATE mft_entries SET is_deleted = false WHERE evidence_id = 'mft-alpha'"
        )
    else:
        # A formerly sufficient supporting group must not retain its old acceptance.
        task.db.execute(
            "UPDATE hypothesis_evidence SET strength = 'weak' WHERE hypothesis_id = ?",
            [task.hypothesis.id],
        )

    assert (
        evaluate_task_completion(
            task.db, task.task_id, settlement_ref=settlement_ref
        ).status
        == "stale"
    )


def test_old_run_cannot_complete_task_after_new_input_contract_is_adopted(task_case):
    task = task_case
    previous = ensure_task_contract(task.db, task.task_id)
    old_mapping = {task.task_id: previous.ref}
    attempt_ref = save_search(task)
    decision = settle_deletion(task)

    task.db.execute(
        "UPDATE evidence_sources SET parser_version = 'new-parser' "
        "WHERE source_id = 'source-mft'"
    )
    renewed = ensure_task_contract(task.db, task.task_id, session_id="session-resumed")
    assert renewed.ref != previous.ref
    settlement_ref = record_settlement_receipt(
        task.db,
        hypothesis_id=task.hypothesis.id,
        decision=decision,
        attempt_ref=attempt_ref,
        session_id="session-task",
        iteration=1,
        task_contract_refs=old_mapping,
    )
    task.db.execute(
        "UPDATE hypotheses SET status = 'confirmed', verdict = 'confirmed' "
        "WHERE hypothesis_id = ?",
        [task.hypothesis.id],
    )

    assert evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    ).status in {"stale", "blocked"}
    assert load_task_contract(task.db, task.task_id).ref == renewed.ref
    assert task.db.execute(
        "SELECT status FROM investigation_tasks WHERE task_id = ?", [task.task_id]
    ).fetchone() == ("in_progress",)


def test_task_status_updates_do_not_invalidate_their_own_input_snapshot(task_case):
    task = task_case
    contract = ensure_task_contract(task.db, task.task_id)
    settlement_ref = complete_deletion(task)
    task.db.execute(
        "UPDATE investigation_tasks SET status = 'resolved', updated_at = now() "
        "WHERE task_id = ?",
        [task.task_id],
    )
    assert ensure_task_contract(task.db, task.task_id).ref == contract.ref
    assert (
        evaluate_task_completion(
            task.db, task.task_id, settlement_ref=settlement_ref
        ).status
        == "completed"
    )


def test_saved_completion_is_presented_as_stale_after_evidence_changes(task_case):
    task = task_case
    ensure_task_contract(task.db, task.task_id)
    settlement_ref = complete_deletion(task)
    completion = evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    )
    completion_ref = record_task_completion(task.db, completion)
    assert (
        task_contract_summary(task.db, task.task_id)["result"]["status"] == "completed"
    )

    task.db.execute(
        "UPDATE mft_entries SET is_deleted = false WHERE evidence_id = 'mft-alpha'"
    )

    summary = task_contract_summary(task.db, task.task_id)
    assert summary["result"]["ref"] == completion_ref
    assert summary["result"]["status"] == "stale"


def test_existing_task_without_contract_is_unknown_and_not_retroactively_completed(
    task_case,
):
    task = task_case
    save_search(task)
    assert load_task_contract(task.db, task.task_id) is None
    completion = evaluate_task_completion(task.db, task.task_id)
    assert completion.status == "blocked"
    assert "contract" in completion.reason.lower()
    assert (
        task_contract_summary(task.db, task.task_id)["input_currentness"] == "unknown"
    )
    # A read must not silently invent a dispatch-time contract for old work.
    assert load_task_contract(task.db, task.task_id) is None


@pytest.mark.parametrize("mismatch", ["trace_parent", "typed_receipt_parent"])
def test_receipt_for_another_hypothesis_cannot_complete_this_task(task_case, mismatch):
    task = task_case
    ensure_task_contract(task.db, task.task_id)
    attempt_ref = save_search(
        task,
        hypothesis_id="H-unrelated" if mismatch == "trace_parent" else None,
        receipt_hypothesis_id="H-unrelated"
        if mismatch == "typed_receipt_parent"
        else None,
    )
    decision = settle_deletion(task)
    settlement_ref = record_settlement_receipt(
        task.db,
        hypothesis_id=task.hypothesis.id,
        decision=decision,
        attempt_ref=attempt_ref,
        session_id="session-task",
        iteration=1,
    )
    task.db.execute(
        "UPDATE hypotheses SET status = 'confirmed', verdict = 'confirmed' "
        "WHERE hypothesis_id = ?",
        [task.hypothesis.id],
    )

    assert evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    ).status in {"blocked", "stale"}


def test_completion_receipt_rolls_back_with_its_enclosing_state_transition(task_case):
    task = task_case
    ensure_task_contract(task.db, task.task_id)
    settlement_ref = complete_deletion(task)
    completion = evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    )
    assert completion.status == "completed"
    before = task.db.execute(
        "SELECT count(*) FROM trace.investigation_steps"
    ).fetchone()

    with pytest.raises(RuntimeError, match="abort work transition"):
        with task.db.transaction():
            record_task_completion(task.db, completion, session_id="session-task")
            task.db.execute(
                "UPDATE investigation_tasks SET status = 'resolved' WHERE task_id = ?",
                [task.task_id],
            )
            raise RuntimeError("abort work transition")

    assert (
        task.db.execute("SELECT count(*) FROM trace.investigation_steps").fetchone()
        == before
    )
    assert task.db.execute(
        "SELECT status FROM investigation_tasks WHERE task_id = ?", [task.task_id]
    ).fetchone() == ("in_progress",)


def test_latest_contract_is_the_latest_adoption_within_one_transaction(
    task_case, monkeypatch
):
    task = task_case
    # References are opaque identities; lexical UUID order cannot decide a revision.
    ids = iter([SimpleNamespace(hex="f" * 32), SimpleNamespace(hex="0" * 32)])
    monkeypatch.setattr(task_contracts, "uuid4", lambda: next(ids))

    with task.db.transaction():
        earlier = ensure_task_contract(task.db, task.task_id)
        task.db.execute(
            "UPDATE investigation_tasks SET description = 'Review the deletion result' "
            "WHERE task_id = ?",
            [task.task_id],
        )
        latest = ensure_task_contract(task.db, task.task_id)
        assert latest.ref != earlier.ref
        assert load_task_contract(task.db, task.task_id).ref == latest.ref

    assert load_task_contract(task.db, task.task_id).ref == latest.ref


def test_normalization_revision_invalidates_completed_observable_empty_search(
    task_case,
):
    from forensia.investigation.work_state import reconcile_completed_task_inputs

    task = task_case
    hypothesis = Hypothesis(
        id=task.hypothesis.id,
        description="Security logs contain an authentication event",
        verification_spec=VerificationSpec(
            support_conditions={"co_observed_event_ids": [4624]},
            refute_conditions={"zero_rows": True},
            required_capabilities=["authentication"],
        ),
    )
    task.hypothesis = hypothesis
    _upsert_hypothesis(task.db, hypothesis, "test", "session-task")
    task.db.execute(
        "UPDATE investigation_tasks SET description = ?, "
        "required_capability = 'authentication', required_source = 'evtx' "
        "WHERE task_id = ?",
        [hypothesis.description, task.task_id],
    )
    task.db.execute(
        "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
        "VALUES ('evtx-auth', 'Security.evtx', 4634)"
    )
    task.db.execute(
        "INSERT INTO evidence_sources (source_id, artifact_family, ingest_status, "
        "parser_name, parser_version, row_count) "
        "VALUES ('source-evtx', 'evtx', 'normalized', 'evtx2es', 'unchanged', 1)"
    )
    task.db.execute(
        "INSERT INTO evidence_coverage (capability, source_family, state) "
        "VALUES ('authentication', 'evtx', 'available')"
    )

    def save_normalize_revision(revision):
        task.db.execute(
            "INSERT INTO trace.investigation_steps VALUES "
            "(?, 'session-task', NULL, 1, 'pipeline-normalize', '{}', ?, now())",
            [
                "normalize-" + revision,
                json.dumps(
                    {
                        "status": "completed",
                        "revision": revision,
                        "parser_revision": revision,
                    }
                ),
            ],
        )

    save_normalize_revision("old")
    ensure_task_contract(task.db, task.task_id)
    attempt_ref = save_search(
        task,
        sql="SELECT evidence_id FROM evtx_events WHERE event_id = 4624 LIMIT 10",
        rows=[],
    )
    absence_scope, _ = judge_absence_scope(
        task.db,
        hypothesis,
        RetrievalEvaluation(
            receipt_id=attempt_ref,
            outcome="adequate",
            scope_status="valid",
            coverage_status="available",
            empty_semantics="observable",
        ),
        source_families=["evtx"],
    )
    assert absence_scope == "observable"
    decision = settle_hypothesis(
        task.db,
        SettlementInput(
            hypothesis=hypothesis,
            checker_verdict="inconclusive",
            check_summary="Repeated empty retrieval over an observable scope",
            consecutive_zero_row_inconclusive=3,
            has_rule_refute_when_zero_rows=True,
            absence_scope=absence_scope,
        ),
    )
    assert decision.allowed and decision.verdict == "refuted"
    settlement_ref = record_settlement_receipt(
        task.db,
        hypothesis_id=hypothesis.id,
        decision=decision,
        attempt_ref=attempt_ref,
        session_id="session-task",
        iteration=1,
    )
    task.db.execute(
        "UPDATE hypotheses SET status = 'refuted', verdict = 'refuted' "
        "WHERE hypothesis_id = ?",
        [hypothesis.id],
    )
    completion = evaluate_task_completion(
        task.db, task.task_id, settlement_ref=settlement_ref
    )
    assert completion.status == "completed"
    record_task_completion(task.db, completion, session_id="session-task")
    task.db.execute(
        "UPDATE investigation_tasks SET status = 'resolved' WHERE task_id = ?",
        [task.task_id],
    )

    # A normalizer fix can change the records without changing source IDs or counts.
    task.db.execute(
        "UPDATE evtx_events SET event_id = 4624 WHERE evidence_id = 'evtx-auth'"
    )
    save_normalize_revision("new")

    assert (
        evaluate_task_completion(
            task.db, task.task_id, settlement_ref=settlement_ref
        ).status
        == "stale"
    )
    assert reconcile_completed_task_inputs(task.db) == [hypothesis.id]
    assert task.db.execute(
        "SELECT status, verdict FROM hypotheses WHERE hypothesis_id = ?",
        [hypothesis.id],
    ).fetchone() == ("active", None)
    assert task.db.execute(
        "SELECT status FROM investigation_tasks WHERE task_id = ?", [task.task_id]
    ).fetchone() == ("in_progress",)
    assert reconcile_completed_task_inputs(task.db) == []
