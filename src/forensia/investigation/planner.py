"""Hypothesis query planning: one SQL decision plus deterministic host validation."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from forensia.context.case_profile import CaseEvidenceProfile
from forensia.context.prompt_context import (
    _build_schema_guidance,
)
from forensia.context.sql_templates import (
    MAX_SQL_ROWS,
    query_referenced_tables,
    query_template_catalog_for_tables,
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import canonical_record_table
from forensia.evidence.links import verification_spec_fingerprint
from forensia.investigation.hypotheses.execution import (
    _evidence_scope_fingerprint,
    _repeat_gate_decision,
)
from forensia.investigation.hypotheses.hypothesis_store import load_hypothesis_attempts
from forensia.investigation.progress import query_fingerprint
from forensia.investigation.prompts import (
    build_query_intent_messages,
)
from forensia.investigation.verification.assessment import _observation_value_matches
from forensia.knowledge.coverage import (
    derive_required_capabilities,
    disclosure_tables_for_spec,
    load_artifact_capabilities,
    observation_catalog,
    observation_condition_error,
)
from forensia.llm import json_response
from forensia.llm.schemas import (
    QUERY_INTENT_SCHEMA,
    QueryIntentResponse,
    SQLQueryAction,
    query_intent_schema_for_catalog,
)

logger = logging.getLogger(__name__)


def normalize_query_intent_action(
    payload: dict[str, Any],
) -> tuple[SQLQueryAction | None, str | None]:
    """Validate the single action envelope emitted by the current planner."""
    if not isinstance(payload, dict):
        return None, "action payload is not an object"

    try:
        action = QueryIntentResponse.model_validate(payload).action
    except ValidationError as exc:
        errors = exc.errors(include_url=False, include_input=False)
        return None, "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'action'}: "
            f"{error['type']} — {error['msg']}"
            for error in errors[:3]
        )[:500]

    return action, None


def _materialize_planned_query(
    payload: dict[str, Any],
    db: CaseDB | None = None,
    eligible_tables: tuple[str, ...] | None = None,
) -> PlannedQuery:
    planned_query = PlannedQuery.model_validate(payload)
    tid = planned_query.template_id
    if tid:
        planned_query.sql = render_query_template(tid, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    used_tables = query_referenced_tables(planned_query.sql)
    target = str(payload.get("target_table") or "").casefold()
    if target not in used_tables:
        raise ValueError("target_table must name a table used by the query")
    if eligible_tables is not None:
        allowed = {str(table).casefold() for table in eligible_tables}
        if not used_tables or not used_tables <= allowed:
            rejected = ", ".join(sorted(used_tables - allowed)) or "no artifact table"
            raise ValueError(
                f"query table is outside this work's eligible catalog: {rejected}"
            )
    if db is not None:
        planned_query.sql = validate_select_sql_with_dryrun(planned_query.sql, db)
    return planned_query


def _typed_observation_query(
    *,
    hypothesis: Hypothesis,
    spec_payload: dict[str, Any] | None,
    query_index: int,
    db: CaseDB | None,
) -> PlannedQuery | None:
    """Build the first bounded query directly from an admitted typed observation."""
    if query_index != 1 or not isinstance(spec_payload, dict):
        return None
    conditions = spec_payload.get("support_conditions") or {}
    observation = (
        conditions.get("observation") if isinstance(conditions, dict) else None
    )
    if observation is None:
        return None
    if (
        observation_condition_error(conditions)
        or spec_payload.get("scope")
        or spec_payload.get("correlation")
    ):
        return None
    family = str(observation["family"]).strip().lower()
    capability = str(observation["capability"]).strip()
    field = str(observation["field"]).strip()
    operator = str(observation["operator"]).strip()
    expected = observation["value"]
    table = canonical_record_table(family)
    catalog = observation_catalog().get(family)
    if not table or not catalog or capability not in catalog["capabilities"]:
        return None
    if field not in catalog["fields"]:
        return None

    if db is None:
        return None
    id_column = "artifact_id" if family == "registry" else "evidence_id"
    matching_ids: list[str] = []
    targets = observation.get("evidence_ids") or []
    target_filter = (
        f" WHERE {id_column} IN ({', '.join('?' for _ in targets)})" if targets else ""
    )
    cursor = db.execute(
        f"SELECT {id_column}, {field} FROM {table}{target_filter} ORDER BY {id_column}",
        targets,
    )
    while batch := cursor.fetchmany(512):
        for evidence_id, value in batch:
            if _observation_value_matches(value, operator, expected):
                matching_ids.append(str(evidence_id))
                if len(matching_ids) == MAX_SQL_ROWS:
                    break
        if len(matching_ids) == MAX_SQL_ROWS:
            break
    id_filter = ", ".join(
        "'" + evidence_id.replace("'", "''") + "'" for evidence_id in matching_ids
    )
    predicate = f"{id_column} IN ({id_filter})" if matching_ids else "FALSE"
    sql = (
        f"SELECT {id_column} AS evidence_id FROM {table} WHERE {predicate} "
        f"ORDER BY {id_column} LIMIT {MAX_SQL_ROWS}"
    )
    return PlannedQuery(
        query_id=f"{hypothesis.id}-q{query_index}",
        hypothesis_id=hypothesis.id,
        purpose=(
            f"primary verification: {family}.{field} "
            f"{observation['operator']} {observation['value']}"
        ),
        sql=sql,
        test_intent="primary_verification",
    )


@dataclass(slots=True)
class _QueryIntentResult:
    """Keep host validation and selected context separate from raw model output."""

    action: SQLQueryAction | None
    raw_response: dict[str, Any]
    error: str | None = None


@dataclass(slots=True)
class HypothesisPlanResult:
    query: PlannedQuery | None
    stop_reason: str | None
    raw_response: dict[str, Any]
    #: Deterministic disclosure this planner attempt adopted (V2-08): selected
    #: schema cards, playbook artifact tables, and executable template ids.
    #: Knowledge sections are recorded per prompt in the Trace retrieval
    #: events; this rides the existing plan step payload.
    disclosure: dict[str, Any] | None = None
    test_intent: str | None = None


def _eligible_planner_tables(
    spec_payload: dict[str, Any] | None,
    disclosed_tables: tuple[str, ...],
    *,
    include_corroboration: bool,
) -> tuple[str, ...] | None:
    if not isinstance(spec_payload, dict):
        return None
    support_conditions = spec_payload.get("support_conditions") or {}
    if not disclosed_tables and not (
        spec_payload.get("required_capabilities") or support_conditions
    ):
        return None
    tables = dict.fromkeys(disclosed_tables)
    if include_corroboration:
        capabilities = derive_required_capabilities(
            list(spec_payload.get("required_capabilities") or []), support_conditions
        )
        catalog = load_artifact_capabilities()
        families = catalog.get("families") or {}
        for capability in capabilities:
            cross = (catalog.get("cross_artifact_corroboration") or {}).get(
                capability, {}
            )
            for family in cross.get("preferred_families") or []:
                for table in (families.get(family) or {}).get("tables") or []:
                    tables.setdefault(str(table), None)
    return tuple(tables)


def persist_hypothesis_plan_result(
    *,
    db: CaseDB,
    session_id: str,
    iteration: int,
    hypothesis: Hypothesis,
    query_index: int,
    plan: HypothesisPlanResult,
    state: SessionState,
    attempt_number: int = 1,
    correction_budget: list[int] | None = None,
    emit: Callable[..., None] | None = None,
) -> str:
    """Persist query planning without changing the admitted hypothesis."""
    from forensia.investigation.investigation_session import (
        _save_step,
        append_hypothesis_reasoning,
    )
    from forensia.investigation.work_judgment import work_progress_snapshot

    work = work_progress_snapshot(db, hypothesis.id)
    retry_available = bool(
        plan.stop_reason
        and plan.stop_reason.startswith("invalid_action:")
        and correction_budget is not None
        and correction_budget[0] > 0
    )
    step_suffix = f"{hypothesis.id}-{query_index:02d}-{attempt_number:02d}"
    step_id = f"{session_id}-{iteration:02d}-plan-hypothesis-{step_suffix}"
    output = dict(plan.raw_response)
    output["_plan_status"] = {
        "query_materialized": plan.query is not None,
        "stop_reason": plan.stop_reason,
        "retry_available": retry_available,
        "work_identity": work["identity"] if work is not None else None,
        "test_intent": (
            plan.query.test_intent
            if plan.query is not None
            else plan.test_intent or plan.raw_response.get("test_intent")
        ),
    }
    if plan.disclosure is not None:
        output["_disclosure"] = plan.disclosure
    _save_step(
        db=db,
        session_id=session_id,
        iteration=iteration,
        phase="plan-hypothesis",
        hypothesis_id=hypothesis.id,
        input_json={
            "hypothesis": hypothesis.model_dump(),
            "query_index": query_index,
            "attempt_number": attempt_number,
        },
        output_json=output,
        suffix=step_suffix,
    )
    if plan.query:
        return "ok"
    if not plan.stop_reason:
        return "break"
    reason = str(plan.stop_reason)
    append_hypothesis_reasoning(
        db=db,
        hypothesis_id=hypothesis.id,
        session_id=session_id,
        iteration=iteration,
        phase="plan",
        body=f"[planner-validation] {reason}",
    )
    # This is consumed by the next query-intent call; no SQL ran here.
    state.last_planner_error = {
        "hypothesis_id": hypothesis.id,
        "reason": reason[:500],
        "step_id": step_id,
        "rejected_action": json.dumps(
            plan.raw_response, ensure_ascii=False, default=str
        )[:500],
    }
    if emit:
        emit(
            "investigate/plan",
            f"[plan] planner rejected {hypothesis.id}: {reason}",
            iteration=iteration,
            kind="hypothesis.plan_rejected",
            status="failed",
            severity="error" if reason == "planner_failed" else "warning",
            reason="planner_validation_failed"
            if reason.startswith("invalid_action:")
            else reason.split(":", 1)[0],
            hypothesis_id=hypothesis.id,
            step_id=step_id,
        )
    logger.warning("%s planner validation rejected the plan: %s", hypothesis.id, reason)
    return "continue" if retry_available else "break"


def request_query_intent(
    messages: list[dict[str, str]],
    *,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    json_schema: dict[str, Any] = QUERY_INTENT_SCHEMA,
    correction_budget: list[int] | None = None,
) -> _QueryIntentResult:
    """Make one bounded query decision from the supplied Case/Trace context."""
    parsed = json_response.request_llm_json(
        messages=messages,
        model=model,
        base_url=base_url,
        json_schema=json_schema,
        telemetry_phase="hypothesis-plan",
        status_callback=status_callback,
        correction_budget=correction_budget,
    )
    action, error = normalize_query_intent_action(parsed)
    return _QueryIntentResult(action, parsed, error)


def _compute_uncovered_keypoints(
    observed: list[str],
    active: list[Hypothesis],
    resolved: list[Hypothesis],
) -> list[dict[str, str]]:
    """Compute uncovered keypoints using round-robin across families.

    A keypoint is considered covered (excluded from output) when:
    - Any active/resolved hypothesis has target_keypoint_id == keypoint name (exact match)
    - It is already targeted by current active/resolved work.

    Remaining candidates are grouped by family (first underscore token) and
    selected round-robin across families up to 8 items.
    """
    if not observed:
        return []

    covered: set[str] = set()
    for hyp in list(active) + list(resolved):
        if hyp.target_keypoint_id:
            covered.add(hyp.target_keypoint_id.strip().lower())

    groups: dict[str, list[str]] = {}
    for item in observed:
        name = (
            item.split(" (")[0].strip().lower()
            if " (" in item
            else item.strip().lower()
        )
        if not name or name in covered:
            continue
        family = name.split("_")[0] if "_" in name else name
        groups.setdefault(family, []).append(name)

    result: list[dict[str, str]] = []
    families = sorted(groups.keys())
    indices = {f: 0 for f in families}
    while len(result) < 8 and families:
        advanced = False
        for family in families:
            if indices[family] < len(groups[family]):
                advanced = True
                result.append({"name": groups[family][indices[family]]})
                indices[family] += 1
                if len(result) >= 8:
                    break
        if not advanced:
            break
    return result


def _build_hypothesis_history(
    state: SessionState,
    hypothesis: Hypothesis,
    db: CaseDB | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Build chronological attempt history without deduplicating display IDs."""
    if db is not None:
        attempts = load_hypothesis_attempts(db, hypothesis.id)
        return attempts[-limit:] if limit > 0 else attempts
    return [
        item.model_dump()
        for item in state.history
        if item.hypothesis_id == hypothesis.id
    ][-limit:]


def _build_working_state_block(db: CaseDB | None, hypothesis_id: str) -> str:
    """Build the current bounded Case/Trace prompt block on demand."""
    if db is None or not hypothesis_id:
        return ""
    from forensia.investigation.working_state import (
        build_working_state,
        render_working_state,
    )

    return render_working_state(build_working_state(db, hypothesis_id=hypothesis_id))


def _load_prior_check_feedback(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Summarize recent sufficiency/settlement gate feedback for this hypothesis.

    Free text is a supplement only — the structured attempt history
    (``<PRIOR_ATTEMPTS>`` in the intent prompt) carries the signal, including
    the per-check reasoning bodies.  This feedback therefore reads only the
    gate phases that ``<PRIOR_ATTEMPTS>`` does not already show, so the same
    Trace reasoning row is not delivered through two prompt layers (V2-07).
    """
    if db is None or not hypothesis.id:
        return ""
    recent_checks = db.execute(
        """
        SELECT phase, body FROM (
            SELECT phase, body, created_at, entry_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY phase ORDER BY created_at DESC, entry_id DESC
                   ) AS phase_rank
            FROM trace.hypothesis_reasoning
            WHERE hypothesis_id = ?
              AND phase IN ('sufficiency', 'settlement')
        ) recent
        WHERE phase_rank = 1
        ORDER BY created_at DESC, entry_id DESC
    """,
        (hypothesis.id,),
    ).fetchall()
    if not recent_checks:
        return ""
    return "\n".join(
        f"- [{str(row[0] or 'feedback')}] {str(row[1] or '')[:120]}"
        for row in recent_checks
        if str(row[1] or "").strip()
    )


def _consume_execution_error_block(state: SessionState) -> str:
    """Format (and clear) the last SQL execution error as a prompt block."""
    if not state.last_execution_error:
        return ""
    block = (
        f"\n<EXECUTION_ERROR>\n"
        f"The previous SQL failed at execute time. Do NOT repeat the same SQL.\n"
        f"query_id: {state.last_execution_error['query_id']}\n"
        f"failing_sql: {state.last_execution_error['sql']}\n"
        f"error: {state.last_execution_error['error']}\n"
        f"</EXECUTION_ERROR>\n"
    )
    state.last_execution_error = None
    return block


def _consume_planner_error_block(state: SessionState, hypothesis_id: str) -> str:
    """Format and clear host planner validation feedback for the next call."""
    if (
        not state.last_planner_error
        or state.last_planner_error.get("hypothesis_id") != hypothesis_id
    ):
        return ""
    block = (
        f"\n<PLANNER_VALIDATION_ERROR>\n"
        "The previous planner action was rejected by host validation. "
        "Correct the action before trying again; do not repeat the rejected payload.\n"
        f"reason: {state.last_planner_error.get('reason', 'unknown validation error')}\n"
        f"rejected_action: {state.last_planner_error.get('rejected_action', '(not recorded)')}\n"
        "</PLANNER_VALIDATION_ERROR>\n"
    )
    state.last_planner_error = None
    return block


def plan_hypothesis_query(
    state: SessionState,
    hypothesis: Hypothesis,
    base_url: str,
    model: str,
    db: CaseDB | None = None,
    status_callback: Callable[[str], None] | None = None,
    query_index: int = 1,
    time_range: dict[str, str] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
    correction_budget: list[int] | None = None,
) -> HypothesisPlanResult:
    """Plan the next query for a single hypothesis.

    Collapsed to a single SQL decision plus deterministic host validation (T-20):
    the query_intent_planner makes one model decision choosing a recipe
    (template_id+params) or a bounded fallback SELECT; the host then validates
    table/column/SELECT-only/allow-list/row-limit/dry-run before execution.

    The former second "schema-readiness" LLM self-check call was removed."""
    hypothesis_history = _build_hypothesis_history(state, hypothesis, db, limit=10)
    # V2-08 single disclosure pathway: one spec/capability correspondence
    # (the artifact capability catalog shared with Coverage and the work
    # judgment) selects the schema cards, playbook artifact gating, and the
    # executable template subset disclosed in the intent prompt. The db
    # canonical spec is authoritative when a row exists; otherwise the
    # in-session hypothesis spec is used (same contract, admission seam).
    if db is not None and hypothesis.id:
        row = db.execute(
            "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
            [hypothesis.id],
        ).fetchone()
    else:
        row = None
    if row is not None and row[0]:
        spec_payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    else:
        spec_obj = getattr(hypothesis, "verification_spec", None)
        spec_payload = (
            spec_obj.model_dump(mode="json") if spec_obj is not None else None
        )
    from forensia.core.verification import VerificationSpec
    from forensia.knowledge.coverage import observation_claim_scope_error

    if spec_payload:
        scope_error = observation_claim_scope_error(
            hypothesis.description, VerificationSpec.model_validate(spec_payload)
        )
        if scope_error:
            return HypothesisPlanResult(
                query=None, raw_response={}, stop_reason=scope_error
            )
    declared_conditions = (
        spec_payload.get("support_conditions")
        if isinstance(spec_payload, dict)
        else None
    )
    if (
        isinstance(declared_conditions, dict)
        and "observation" in declared_conditions
        and (condition_error := observation_condition_error(declared_conditions))
    ):
        return HypothesisPlanResult(
            query=None,
            stop_reason=f"invalid_typed_primary: {condition_error}",
            raw_response={"test_intent": "primary_verification"},
        )
    deterministic_query = _typed_observation_query(
        hypothesis=hypothesis,
        spec_payload=spec_payload,
        query_index=query_index,
        db=db,
    )
    primary_query = deterministic_query
    test_intent = "corroboration" if query_index > 1 else "primary_verification"
    already_attempted = False
    if deterministic_query is not None and db is not None:
        try:
            deterministic_query.sql = validate_select_sql(deterministic_query.sql)
            deterministic_query.sql = validate_select_sql_with_dryrun(
                deterministic_query.sql, db
            )
            query_fp = query_fingerprint(deterministic_query.sql)
            spec_fp = verification_spec_fingerprint(hypothesis.verification_spec)
            scope_fp = _evidence_scope_fingerprint(db, deterministic_query.sql)
            repeat_gate = _repeat_gate_decision(
                db,
                hypothesis,
                query_fp=query_fp,
                verification_fp=spec_fp,
                scope_fp=scope_fp,
            )
            already_attempted = repeat_gate["decision"] == "skip"
        except (ValueError, ValidationError) as exc:
            return HypothesisPlanResult(
                query=None,
                stop_reason=f"invalid_typed_primary: {str(exc).splitlines()[0][:300]}",
                raw_response={"test_intent": "primary_verification"},
            )
        if already_attempted:
            deterministic_query = None
            test_intent = "corroboration"
    _disclosure_tables, _primary_tables = disclosure_tables_for_spec(spec_payload)
    eligible_tables = _eligible_planner_tables(
        spec_payload,
        _disclosure_tables,
        include_corroboration=test_intent == "corroboration",
    )
    if eligible_tables == ():
        return HypothesisPlanResult(
            query=None,
            stop_reason="no_eligible_capability",
            raw_response={"test_intent": test_intent},
            disclosure={"schema_cards": [], "playbook_tables": [], "template_ids": []},
        )
    disclosure_record = {
        "schema_cards": (
            list(eligible_tables)
            if test_intent == "corroboration" and eligible_tables is not None
            else list(_primary_tables)
        )
        or ["evtx_events"],
        "playbook_tables": sorted(eligible_tables or _disclosure_tables) or None,
        "template_ids": [
            entry["template_id"]
            for entry in query_template_catalog_for_tables(
                eligible_tables or _disclosure_tables or ()
            )
        ],
    }
    if deterministic_query is not None:
        return HypothesisPlanResult(
            query=deterministic_query,
            stop_reason=None,
            raw_response={"test_intent": "primary_verification"},
            disclosure={
                "schema_cards": [],
                "playbook_tables": [],
                "template_ids": [],
            },
        )
    schema_tables = (
        list(eligible_tables)
        if test_intent == "corroboration" and eligible_tables is not None
        else list(_primary_tables)
    ) or ["evtx_events"]
    schema_card = _build_schema_guidance(
        schema_tables,
        db=db,
        session_id=state.session_id,
    )
    prior_check_feedback = _load_prior_check_feedback(db, hypothesis)
    working_state_block = _build_working_state_block(db, hypothesis.id)
    execution_error_block = _consume_execution_error_block(state)
    planner_error_block = _consume_planner_error_block(state, hypothesis.id)

    messages = build_query_intent_messages(
        hypothesis=hypothesis,
        recent_history=hypothesis_history,
        active_hypotheses=state.active_hypotheses,
        time_range=time_range or {},
        schema_context=schema_card,
        host_feedback=execution_error_block + planner_error_block,
        prior_check_feedback=prior_check_feedback,
        case_profile=case_profile,
        case_policy=case_policy,
        findings_snapshot=state.findings_snapshot,
        working_state_block=working_state_block,
        db=db,
        session_id=state.session_id,
        spec_payload=spec_payload,
        eligible_tables=eligible_tables,
        test_intent=test_intent,
    )

    intent_response = request_query_intent(
        messages,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        json_schema=(
            query_intent_schema_for_catalog(
                list(eligible_tables),
                [
                    entry["template_id"]
                    for entry in query_template_catalog_for_tables(eligible_tables)
                ],
            )
            if eligible_tables is not None
            else QUERY_INTENT_SCHEMA
        ),
        correction_budget=correction_budget,
    )
    action = intent_response.action
    error = intent_response.error
    planned_query = None
    if not error and isinstance(action, SQLQueryAction):
        try:
            planned_query = _materialize_planned_query(
                {
                    "query_id": f"{hypothesis.id}-q{query_index}",
                    "hypothesis_id": hypothesis.id,
                    "purpose": action.intent,
                    "target_table": action.target_table,
                    "template_id": action.template_id,
                    "params": action.params,
                    "sql": action.sql,
                    "test_intent": test_intent,
                },
                db,
                eligible_tables,
            )
            if (
                planned_query is not None
                and primary_query is not None
                and test_intent == "corroboration"
                and query_fingerprint(planned_query.sql)
                == query_fingerprint(primary_query.sql)
            ):
                planned_query = None
                error = (
                    "duplicate primary query; choose an eligible corroboration query"
                )
        except (ValueError, ValidationError) as exc:
            error = str(exc).splitlines()[0][:300]
            logger.debug("planned SQL rejected by host validation: %s", error)
    elif not error:
        error = "SQL action was not selected"
    return HypothesisPlanResult(
        query=planned_query,
        stop_reason=f"invalid_action: {error}" if error else None,
        raw_response=intent_response.raw_response,
        disclosure=disclosure_record,
        test_intent=test_intent,
    )
