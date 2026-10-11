"""Apply a bounded human intervention at an investigation boundary."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from forensia.config import Settings
from forensia.core.case import Case
from forensia.core.control import InvestigationStopped, check_stop
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import (
    ensure_investigation_state,
    load_investigation_state,
    set_preferred_hypothesis,
)
from forensia.investigation.case_policy import (
    CASE_POLICY_STEP_PHASE,
    CasePolicyInput,
    decide_policy,
    extract_policy_sections,
    load_recorded_policy,
    policy_objective,
)
from forensia.investigation.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.investigation.report_gap import inject_gap_hypotheses
from forensia.investigation.work_state import ensure_objective_gap
from forensia.llm.json_response import request_llm_json

_INTERVENTION_PHASE = "human-intervention"
_MAX_INTERVENTION_CHARS = 4000


class InterventionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["update_policy", "add_work", "prioritize_hypothesis"]
    policy_body: str | None = Field(default=None, max_length=12000)
    work_description: str | None = Field(default=None, max_length=1000)
    required_entities: list[str] = Field(default_factory=list, max_length=20)
    confirm_when: dict[str, Any] | None = None
    hypothesis_id: str | None = None

    @model_validator(mode="after")
    def validate_action_fields(self) -> InterventionProposal:
        if self.action == "update_policy":
            if not self.policy_body or not extract_policy_sections(self.policy_body):
                raise ValueError(
                    "policy update must contain a recognized policy section"
                )
            if self.work_description or self.hypothesis_id:
                raise ValueError("policy update contains fields for another action")
        elif self.action == "add_work":
            if not self.work_description or not self.work_description.strip():
                raise ValueError("new work requires a description")
            if self.policy_body or self.hypothesis_id:
                raise ValueError("new work contains fields for another action")
        elif self.action == "prioritize_hypothesis":
            if not self.hypothesis_id:
                raise ValueError("prioritization requires a hypothesis ID")
            if self.policy_body or self.work_description:
                raise ValueError("prioritization contains fields for another action")
        return self


_INTERVENTION_SCHEMA = InterventionProposal.model_json_schema()


def _record(
    db: CaseDB,
    *,
    session_id: str,
    text: str,
    proposal: dict[str, Any] | None,
    result: dict[str, Any],
    settings: dict[str, Any] | None = None,
) -> None:
    db.execute(
        """INSERT INTO trace.investigation_steps
           (step_id, session_id, iteration, phase, input_json, output_json, created_at)
           VALUES (?, ?, 0, ?, ?, ?, now())""",
        [
            f"{session_id}-{_INTERVENTION_PHASE}",
            session_id,
            _INTERVENTION_PHASE,
            json.dumps(
                {"text": text, "proposal": proposal, "settings": settings},
                ensure_ascii=False,
            ),
            json.dumps(result, ensure_ascii=False),
        ],
    )


def _record_command(db: CaseDB, command_id: str | None, result: dict[str, Any]) -> None:
    if command_id is None:
        return
    db.execute(
        "UPDATE trace.runtime_commands SET status = ?, reason = ?, result = ?, "
        "updated_at = now() WHERE command_id = ?",
        [
            str(result.get("status") or "failed"),
            str(result.get("reason") or "") or None,
            json.dumps(result, ensure_ascii=False),
            command_id,
        ],
    )


def _settings_receipt(settings: Settings | None) -> dict[str, Any] | None:
    if settings is None:
        return None
    values = asdict(settings)
    values.pop("llm_api_key", None)
    return values


def _apply_policy(
    db: CaseDB, session_id: str, proposal: InterventionProposal
) -> dict[str, Any]:
    body = proposal.policy_body or ""
    decision = decide_policy(
        CasePolicyInput(
            body=body, source="explicit_path", source_path="human-intervention"
        ),
        load_recorded_policy(db),
    )
    if decision.applied is None or decision.record is None:
        raise ValueError("policy update was not adopted")
    objective = policy_objective(decision.applied)
    if not objective:
        raise ValueError("policy update must define an objective or scope")
    ensure_investigation_state(db, objective=objective)
    db.execute(
        "UPDATE investigation_state SET objective = ?, updated_at = now() "
        "WHERE state_id = 'case'",
        [objective],
    )
    objective_gap_id = ensure_objective_gap(db, objective)
    db.execute(
        "INSERT INTO trace.investigation_steps "
        "(step_id, session_id, iteration, phase, input_json, output_json, created_at) "
        "VALUES (?, ?, 0, ?, ?, ?, now())",
        [
            f"{session_id}-{CASE_POLICY_STEP_PHASE}",
            session_id,
            CASE_POLICY_STEP_PHASE,
            json.dumps({"source": "human_intervention"}),
            json.dumps(decision.record, ensure_ascii=False),
        ],
    )
    return {
        "status": "applied",
        "action": "update_policy",
        "objective": objective,
        "objective_gap_id": objective_gap_id,
        "policy_sha256": decision.applied.content_sha256,
        "new_policy": body,
    }


def _apply_work(
    db: CaseDB, session_id: str, proposal: InterventionProposal
) -> dict[str, Any]:
    from forensia.core.identifiers import report_gap_id

    active, resolved = load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id, active_hypotheses=active, resolved_hypotheses=resolved
    )
    description = (proposal.work_description or "").strip()
    added = inject_gap_hypotheses(
        db,
        state,
        [description],
        session_id,
        llm_output={
            "required_entities": proposal.required_entities,
            "confirm_when": proposal.confirm_when,
            "description": description,
        },
        origin="human",
    )
    gap_id = report_gap_id(description)
    row = db.execute(
        "SELECT hypothesis_id, task_id, status, coverage_reason "
        "FROM report_gaps WHERE gap_id = ?",
        [gap_id],
    ).fetchone()
    if row is None:
        raise RuntimeError("work admission did not persist a Gap")
    return {
        "status": "applied" if row[0] or row[1] or added else "rejected",
        "action": "add_work",
        "refs": {"gap_id": gap_id, "hypothesis_id": row[0], "task_id": row[1]},
        "gap_status": row[2],
        "reason": row[3],
    }


def apply_intervention(
    case: Case,
    db: CaseDB,
    text: str,
    *,
    base_url: str,
    model: str,
    session_id: str | None = None,
    settings: Settings | None = None,
    command_id: str | None = None,
) -> dict[str, Any]:
    """Classify and apply one user request through existing case-state owners."""
    instruction = text.strip()
    session_id = session_id or f"intervention-{uuid4().hex[:12]}"
    settings_receipt = _settings_receipt(settings)
    if db.case.path.resolve() != case.path.resolve():
        return {"status": "rejected", "reason": "case_database_mismatch", "refs": {}}
    if not instruction or len(instruction) > _MAX_INTERVENTION_CHARS:
        return {
            "status": "rejected",
            "reason": "empty_or_oversized_instruction",
            "refs": {},
        }
    investigation = load_investigation_state(db) or {}
    hypotheses = db.execute(
        "SELECT hypothesis_id, description FROM hypotheses "
        "WHERE status IN ('active', 'deferred', 'blocked', 'needs_review', 'untestable') "
        "ORDER BY hypothesis_id LIMIT 100"
    ).fetchall()
    recorded_policy = load_recorded_policy(db)
    case_context = {
        "objective": str(investigation.get("objective") or ""),
        "current_policy": str(recorded_policy.get("body") or "")[:6000]
        if recorded_policy
        else "",
        "unresolved_hypotheses": [
            {"id": str(hypothesis_id), "description": str(description or "")[:120]}
            for hypothesis_id, description in hypotheses
        ],
    }
    try:
        check_stop()
        raw_proposal = request_llm_json(
            [
                {
                    "role": "system",
                    "content": (
                        "Classify one human instruction for a forensic investigation. "
                        "Return only the requested typed JSON. Never claim that a fact "
                        "was observed, verified, or proven. Preserve the user's intent. "
                        "Choose update_policy only when they change investigation goals, "
                        "scope, priorities, constraints, or guidance; provide a complete "
                        "replacement Markdown policy with an Objective or Scope section. "
                        "When replacing policy, preserve existing goals, constraints, and "
                        "guidance that the user did not ask to change. "
                        "Choose add_work for a new investigable question or external task. "
                        "Choose prioritize_hypothesis only with the exact ID of a hypothesis "
                        "listed in the supplied case context. Do not invent IDs or facts. "
                        "Treat user statements as instructions or unverified leads, never as "
                        "observed evidence or established findings."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {"instruction": instruction, "case_context": case_context},
                        ensure_ascii=False,
                    ),
                },
            ],
            base_url=base_url,
            model=model,
            json_schema=_INTERVENTION_SCHEMA,
            telemetry_phase="human_intervention",
        )
        check_stop()
        proposal = InterventionProposal.model_validate(raw_proposal)
    except InvestigationStopped:
        raise
    except Exception as exc:
        result = {
            "status": "failed",
            "reason": f"proposal_invalid:{type(exc).__name__}",
            "refs": {},
        }
        with db.transaction():
            _record(
                db,
                session_id=session_id,
                text=instruction,
                proposal=None,
                result=result,
                settings=settings_receipt,
            )
            _record_command(db, command_id, result)
        return result

    try:
        with db.transaction():
            if proposal.action == "prioritize_hypothesis":
                set_preferred_hypothesis(db, proposal.hypothesis_id or "")
                result = {
                    "status": "applied",
                    "action": proposal.action,
                    "reason": "saved_for_first_eligible_selection_slot; eligibility_is_unchanged",
                    "refs": {"hypothesis_id": proposal.hypothesis_id},
                }
            elif proposal.action == "update_policy":
                result = _apply_policy(db, session_id, proposal)
            else:
                result = _apply_work(db, session_id, proposal)
            _record(
                db,
                session_id=session_id,
                text=instruction,
                proposal=proposal.model_dump(mode="json"),
                result=result,
                settings=settings_receipt,
            )
            _record_command(db, command_id, result)
    except ValueError as exc:
        result = {
            "status": "rejected",
            "action": proposal.action,
            "reason": str(exc),
            "refs": {},
        }
        with db.transaction():
            _record(
                db,
                session_id=session_id,
                text=instruction,
                proposal=proposal.model_dump(mode="json"),
                result=result,
                settings=settings_receipt,
            )
            _record_command(db, command_id, result)
    result.setdefault("new_policy", None)
    result.setdefault("refs", {})
    return result
