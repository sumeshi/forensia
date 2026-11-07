"""Task contracts and bounded result projections over existing Case / Trace.

This module records references and judges whether they still describe the
current work. Task and Gap state writes remain with their existing owners.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlglot.errors import SqlglotError

from forensia.core.task import TaskCompletion, TaskContract, TaskSettlementReceipt
from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.evidence.links import load_evidence_links, verification_spec_fingerprint
from forensia.investigation.hypotheses.execution import _evidence_scope_fingerprint
from forensia.investigation.verification.settlement import SettlementDecision
from forensia.investigation.work_judgment import (
    EXTERNAL_TASK_KINDS,
    spec_capabilities,
    work_progress_snapshot,
)


@dataclass(frozen=True)
class TaskContractRecord:
    ref: str
    contract: TaskContract


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical_spec(value: Any) -> VerificationSpec:
    payload = _object(value)
    if not payload:
        raise ValueError("Task input has no canonical VerificationSpec")
    return VerificationSpec.model_validate(payload)


def _input_fingerprint(db: CaseDB, work_identity: str) -> str:
    return _fingerprint(
        {
            "work_inputs": work_identity,
            "source_revision": _evidence_scope_fingerprint(db, ""),
        }
    )


def _current_contract(db: CaseDB, task_id: str) -> TaskContract:
    row = db.execute(
        "SELECT kind, description, gap_id, hypothesis_id, required_capability, "
        "required_source FROM investigation_tasks WHERE task_id = ?",
        [task_id],
    ).fetchone()
    if row is None:
        raise ValueError(f"Task not found: {task_id}")
    kind, description, raw_gap_id, raw_hypothesis_id, raw_caps, raw_sources = row
    gap_id, hypothesis_id = str(raw_gap_id or ""), str(raw_hypothesis_id or "")
    gap_fingerprint = ""
    if gap_id:
        gap = db.execute(
            "SELECT description, block_heading, section_key FROM report_gaps WHERE gap_id = ?",
            [gap_id],
        ).fetchone()
        if gap is None:
            raise ValueError(f"Task parent Gap not found: {gap_id}")
        gap_fingerprint = _fingerprint(gap)
    capabilities = {item for item in str(raw_caps or "").split(",") if item}
    spec_fingerprint = ""
    hypothesis_fingerprint = ""
    if hypothesis_id:
        hypothesis = db.execute(
            "SELECT verification_spec, description FROM hypotheses WHERE hypothesis_id = ?",
            [hypothesis_id],
        ).fetchone()
        if hypothesis is None:
            raise ValueError(f"Task parent hypothesis not found: {hypothesis_id}")
        spec = _canonical_spec(hypothesis[0])
        spec_fingerprint = verification_spec_fingerprint(spec)
        hypothesis_fingerprint = _fingerprint(str(hypothesis[1] or ""))
        capabilities.update(
            spec_capabilities(spec.model_dump(mode="json"), hypothesis_id=hypothesis_id)
        )
        snapshot = work_progress_snapshot(db, hypothesis_id)
        if snapshot is None:
            raise ValueError(f"Task input unavailable: {hypothesis_id}")
        input_identity = snapshot["identity"]
    else:
        # Imported lazily: report admission already depends on work_state.
        from forensia.investigation.report_gap import evaluation_snapshot

        input_identity = evaluation_snapshot(db)["identity"]
    input_identity = _input_fingerprint(db, input_identity)
    external = str(kind or "") in EXTERNAL_TASK_KINDS or not hypothesis_id
    return TaskContract(
        task_id=task_id,
        task_kind=str(kind or ""),
        purpose=str(description or task_id),
        gap_id=gap_id,
        gap_fingerprint=gap_fingerprint,
        hypothesis_id=hypothesis_id,
        hypothesis_fingerprint=hypothesis_fingerprint,
        input_identity=input_identity,
        verification_spec_fingerprint=spec_fingerprint,
        required_capabilities=tuple(sorted(capabilities)),
        required_sources=tuple(
            sorted({item for item in str(raw_sources or "").split(",") if item})
        ),
        expected_output="external_result" if external else "hypothesis_settlement",
        completion_condition="external_owner_result"
        if external
        else "current_settlement",
    )


def _latest_task_step(db: CaseDB, task_id: str, phase: str) -> tuple | None:
    return db.execute(
        "SELECT step_id, hypothesis_id, input_json, output_json "
        "FROM trace.investigation_steps WHERE phase = ? "
        "AND json_extract_string(input_json, '$.task_id') = ? "
        "ORDER BY created_at DESC, step_id DESC LIMIT 1",
        [phase, task_id],
    ).fetchone()


def _record_step(
    db: CaseDB,
    *,
    phase: str,
    hypothesis_id: str,
    session_id: str,
    iteration: int = 0,
    step_input: dict[str, Any],
    step_output: dict[str, Any],
) -> str:
    ref = f"{phase}-{uuid4().hex}"
    db.execute(
        "INSERT INTO trace.investigation_steps "
        "(step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ref,
            session_id,
            hypothesis_id or None,
            iteration,
            phase,
            json.dumps(step_input, ensure_ascii=False),
            json.dumps(step_output, ensure_ascii=False),
            datetime.now(UTC).replace(tzinfo=None),
        ],
    )
    return ref


def load_task_contract(db: CaseDB, task_id: str) -> TaskContractRecord | None:
    """Read only the latest contract; an invalid latest entry cannot revive an old one."""
    row = _latest_task_step(db, task_id, "task-contract")
    if row is None:
        return None
    try:
        contract = TaskContract.model_validate(_object(row[3]).get("contract"))
    except ValidationError:
        return None
    if contract.task_id != task_id or (row[1] or "") != contract.hypothesis_id:
        return None
    return TaskContractRecord(str(row[0]), contract)


def ensure_task_contract(
    db: CaseDB, task_id: str, *, session_id: str = ""
) -> TaskContractRecord:
    """Freeze current inputs at admission or dispatch, retaining earlier versions."""
    contract = _current_contract(db, task_id)
    previous = load_task_contract(db, task_id)
    if previous is not None and previous.contract == contract:
        return previous
    ref = _record_step(
        db,
        phase="task-contract",
        hypothesis_id=contract.hypothesis_id,
        session_id=session_id,
        step_input={"task_id": task_id},
        step_output={"contract": contract.model_dump(mode="json")},
    )
    return TaskContractRecord(ref, contract)


def prepare_hypothesis_task_contracts(
    db: CaseDB, hypothesis_id: str, *, session_id: str = ""
) -> tuple[TaskContractRecord, ...]:
    rows = db.execute(
        "SELECT task_id FROM investigation_tasks WHERE hypothesis_id = ? "
        "AND status IN ('open', 'in_progress') ORDER BY task_id",
        [hypothesis_id],
    ).fetchall()
    return tuple(
        ensure_task_contract(db, str(row[0]), session_id=session_id) for row in rows
    )


def _assessed_artifacts(db: CaseDB, hypothesis_id: str) -> dict[str, Any]:
    links = [
        link
        for link in load_evidence_links(db, hypothesis_id, current_only=True)
        if link.assessment_id
        and link.role in {"supporting", "corroborating", "contradictory"}
    ]
    payload = sorted(
        (
            link.link_id,
            link.evidence_id,
            link.assessment_id,
            link.role,
            link.content_fingerprint,
            link.verification_spec_fingerprint,
            link.strength,
            link.derivation_group,
            link.source_family,
            link.source_file,
            link.matched_conditions,
        )
        for link in links
    )
    return {
        "fingerprint": _fingerprint(payload),
        "assessment_ids": tuple(sorted({link.assessment_id for link in links})),
        "evidence_ids": tuple(sorted({link.evidence_id for link in links})),
        "roles": {link.role for link in links},
    }


def record_settlement_receipt(
    db: CaseDB,
    *,
    hypothesis_id: str,
    decision: SettlementDecision,
    attempt_ref: str,
    session_id: str,
    iteration: int,
    task_contract_refs: dict[str, str] | None = None,
    causal_refs: dict[str, str] | None = None,
) -> str:
    """Record the existing host decision before its transaction applies a verdict."""
    row = db.execute(
        "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchone()
    snapshot = work_progress_snapshot(db, hypothesis_id)
    if row is None or snapshot is None:
        raise ValueError(f"Settlement parent hypothesis not found: {hypothesis_id}")
    spec = _canonical_spec(row[0])
    artifacts = _assessed_artifacts(db, hypothesis_id)
    if task_contract_refs is None:
        task_contract_refs = {}
        for (task_id,) in db.execute(
            "SELECT task_id FROM investigation_tasks WHERE hypothesis_id = ? "
            "AND status IN ('open', 'in_progress')",
            [hypothesis_id],
        ).fetchall():
            record = load_task_contract(db, str(task_id))
            if record is not None:
                task_contract_refs[str(task_id)] = record.ref
    receipt = TaskSettlementReceipt(
        hypothesis_id=hypothesis_id,
        attempt_ref=attempt_ref,
        input_identity=_input_fingerprint(db, snapshot["identity"]),
        verification_spec_fingerprint=verification_spec_fingerprint(spec),
        assessed_links_fingerprint=artifacts["fingerprint"],
        task_contract_refs=dict(task_contract_refs),
        verdict=decision.verdict,
        allowed=decision.allowed,
        reason=decision.reason or "",
        gates_passed=tuple(decision.gates_passed),
        gates_failed=tuple(decision.gates_failed),
        assessment_ids=artifacts["assessment_ids"],
        evidence_ids=artifacts["evidence_ids"],
    )
    return _record_step(
        db,
        phase="settlement",
        hypothesis_id=hypothesis_id,
        session_id=session_id,
        iteration=iteration,
        step_input={
            **{
                key: value
                for key, value in (causal_refs or {}).items()
                if key
                in {
                    "plan_step_id",
                    "execution_step_id",
                    "do_step_id",
                    "check_step_id",
                    "sufficiency_step_id",
                }
                and value
            },
            "hypothesis_id": hypothesis_id,
            "attempt_ref": attempt_ref,
        },
        step_output={"settlement": receipt.model_dump(mode="json")},
    )


def evaluate_task_completion(
    db: CaseDB, task_id: str, *, settlement_ref: str | None = None
) -> TaskCompletion:
    """Judge a host result against frozen and current inputs without writing state."""
    record = load_task_contract(db, task_id)
    completion = {
        "task_id": task_id,
        "contract_ref": record.ref if record else "",
        "settlement_ref": settlement_ref or "",
    }

    def result(status: str, reason: str, **kwargs: Any) -> TaskCompletion:
        return TaskCompletion(**completion, status=status, reason=reason, **kwargs)

    if record is None:
        return result("blocked", "task_contract_unrecorded")
    contract = record.contract
    try:
        current = _current_contract(db, task_id)
    except ValueError:
        return result("stale", "task_inputs_unavailable")
    if current != contract:
        return result("stale", "task_inputs_changed")
    if contract.completion_condition == "external_owner_result":
        return result("blocked", "external_owner_result_required")
    hypothesis_id = contract.hypothesis_id
    row = db.execute(
        "SELECT status, verdict, sufficiency_status FROM hypotheses WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchone()
    if row is None or row[0] not in {"confirmed", "refuted"} or row[0] != row[1]:
        return result("blocked", "hypothesis_not_settled")
    if settlement_ref is None:
        latest = db.execute(
            "SELECT step_id FROM trace.investigation_steps "
            "WHERE phase = 'settlement' AND hypothesis_id = ? "
            "ORDER BY created_at DESC, step_id DESC LIMIT 1",
            [hypothesis_id],
        ).fetchone()
        settlement_ref = str(latest[0]) if latest else ""
        completion["settlement_ref"] = settlement_ref
    settlement = db.execute(
        "SELECT hypothesis_id, input_json, output_json FROM trace.investigation_steps "
        "WHERE step_id = ? AND phase = 'settlement'",
        [settlement_ref],
    ).fetchone()
    if settlement is None:
        return result("blocked", "host_settlement_unrecorded")
    try:
        receipt = TaskSettlementReceipt.model_validate(
            _object(settlement[2]).get("settlement")
        )
    except ValidationError:
        return result("blocked", "host_settlement_invalid")
    step_input = _object(settlement[1])
    if (
        settlement[0] != hypothesis_id
        or receipt.hypothesis_id != hypothesis_id
        or step_input.get("hypothesis_id") != hypothesis_id
        or step_input.get("attempt_ref") != receipt.attempt_ref
    ):
        return result("blocked", "settlement_identity_mismatch")
    if receipt.task_contract_refs.get(task_id) != record.ref:
        return result("stale", "settlement_contract_changed")
    if (
        receipt.input_identity != contract.input_identity
        or receipt.verification_spec_fingerprint
        != contract.verification_spec_fingerprint
    ):
        return result("stale", "settlement_inputs_changed")
    if not receipt.allowed or receipt.gates_failed or receipt.verdict != row[0]:
        return result("blocked", "settlement_not_conclusive")
    attempt = db.execute(
        "SELECT input_json, output_json FROM trace.investigation_steps "
        "WHERE phase = 'do' AND hypothesis_id = ? AND "
        "(json_extract_string(output_json, '$.attempt.attempt_ref') = ? OR "
        "json_extract_string(output_json, '$.tool_receipt.receipt_id') = ?) "
        "ORDER BY created_at DESC, step_id DESC LIMIT 1",
        [hypothesis_id, receipt.attempt_ref, receipt.attempt_ref],
    ).fetchone()
    if not receipt.attempt_ref or attempt is None:
        return result("blocked", "settlement_attempt_unrecorded")
    attempt_input, attempt_output = _object(attempt[0]), _object(attempt[1])
    query = _object(attempt_input.get("planned_query"))
    attempt_record = _object(attempt_output.get("attempt"))
    tool_receipt = _object(attempt_output.get("tool_receipt"))
    if (
        query.get("hypothesis_id", hypothesis_id) != hypothesis_id
        or attempt_record.get("attempt_ref", receipt.attempt_ref) != receipt.attempt_ref
        or tool_receipt.get("receipt_id", receipt.attempt_ref) != receipt.attempt_ref
        or tool_receipt.get("hypothesis_id") != hypothesis_id
    ):
        return result("blocked", "settlement_attempt_identity_mismatch")
    if (
        attempt_record.get("verification_spec_fingerprint")
        != contract.verification_spec_fingerprint
    ):
        return result("stale", "settlement_attempt_spec_changed")
    sql = str(
        query.get("sql")
        or _object(tool_receipt.get("arguments")).get("normalized_sql")
        or attempt_record.get("normalized_sql")
        or ""
    )
    scope_fingerprint = attempt_record.get("evidence_scope_fingerprint")
    if not sql or not scope_fingerprint:
        return result("blocked", "settlement_source_revision_unrecorded")
    try:
        current_scope_fingerprint = _evidence_scope_fingerprint(db, sql)
    except ValueError, SqlglotError:
        return result("blocked", "settlement_query_unverifiable")
    if scope_fingerprint != current_scope_fingerprint:
        return result("stale", "settlement_source_revision_changed")
    artifacts = _assessed_artifacts(db, hypothesis_id)
    if receipt.assessed_links_fingerprint != artifacts["fingerprint"]:
        return result("stale", "settlement_evidence_changed")
    if row[0] == "confirmed" and (
        row[2] != "sufficient" or "supporting" not in artifacts["roles"]
    ):
        return result("blocked", "current_support_required")
    if row[0] == "refuted" and not (
        "contradictory" in artifacts["roles"]
        or "auto_refute_zero_rows" in receipt.gates_passed
    ):
        return result("blocked", "current_refutation_required")
    output_refs = (
        str(settlement_ref),
        f"hypothesis:{hypothesis_id}",
        *(f"assessment:{ref}" for ref in receipt.assessment_ids),
        *(f"evidence:{ref}" for ref in receipt.evidence_ids),
    )
    return result("completed", "current_settlement_recorded", output_refs=output_refs)


def record_task_completion(
    db: CaseDB, completion: TaskCompletion, *, session_id: str = ""
) -> str:
    """Record an evaluation; the caller owns its atomic Task / Gap transition."""
    latest = _latest_task_step(db, completion.task_id, "task-completion")
    payload = completion.model_dump(mode="json")
    if latest is not None and _object(latest[3]).get("completion") == payload:
        return str(latest[0])
    record = load_task_contract(db, completion.task_id)
    return _record_step(
        db,
        phase="task-completion",
        hypothesis_id=record.contract.hypothesis_id if record else "",
        session_id=session_id,
        step_input={
            "task_id": completion.task_id,
            "contract_ref": completion.contract_ref,
        },
        step_output={"completion": payload},
    )


def task_contract_summary(db: CaseDB, task_id: str) -> dict[str, Any]:
    """Read a bounded handoff; historical completion never overrides current inputs."""
    record = load_task_contract(db, task_id)
    if record is None:
        return {"input_currentness": "unknown", "reason": "task_contract_unrecorded"}
    try:
        currentness = (
            "current" if _current_contract(db, task_id) == record.contract else "stale"
        )
    except ValueError:
        currentness = "unknown"
    contract = record.contract
    summary: dict[str, Any] = {
        "ref": record.ref,
        "input_revision": contract.input_identity,
        "input_currentness": currentness,
        "hypothesis_id": contract.hypothesis_id,
        "gap_id": contract.gap_id,
        "expected_output": contract.expected_output,
        "completion_condition": contract.completion_condition,
        "required_capabilities": list(contract.required_capabilities[:8]),
    }
    latest = _latest_task_step(db, task_id, "task-completion")
    if latest is not None:
        try:
            previous = TaskCompletion.model_validate(
                _object(latest[3]).get("completion")
            )
        except ValidationError:
            summary["result"] = {"status": "unknown", "reason": "task_result_invalid"}
            return summary
        if (
            previous.task_id != task_id
            or (latest[1] or "") != contract.hypothesis_id
            or _object(latest[2]).get("contract_ref") != previous.contract_ref
        ):
            summary["result"] = {
                "status": "unknown",
                "reason": "task_result_identity_mismatch",
            }
            return summary
        if previous.contract_ref != record.ref:
            summary["result"] = {"status": "stale", "reason": "task_contract_changed"}
            return summary
        current = evaluate_task_completion(
            db, task_id, settlement_ref=previous.settlement_ref or None
        )
        if current.status == "completed" and previous.status != "completed":
            current = previous
        summary["result"] = {
            "ref": str(latest[0]),
            "status": current.status,
            "reason": current.reason,
            "settlement_ref": current.settlement_ref,
            "output_refs": list(current.output_refs[:8]),
            "omitted_output_count": max(0, len(current.output_refs) - 8),
        }
    return summary
