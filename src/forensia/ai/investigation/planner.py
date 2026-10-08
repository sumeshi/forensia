"""Hypothesis query planning: one SQL decision plus deterministic host validation."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from forensia.ai.case_profile import CaseEvidenceProfile
from forensia.ai.hypotheses.hypothesis_store import _recent_reasoning_rows
from forensia.ai.llm import llm_gateway
from forensia.ai.llm.schemas import (
    QUERY_INTENT_SCHEMA,
    MemoryReadMoreAction,
    QueryIntentResponse,
    SQLQueryAction,
)
from forensia.ai.prompts.prompt_context import (
    _build_schema_guidance,
)
from forensia.ai.prompts.prompt_investigation import (
    build_query_intent_messages,
)
from forensia.ai.prompts.sql_templates import (
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.ai.retrieval_telemetry import ToolReceipt, evaluate_retrieval
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)


def eligible_query_actions(phase: str) -> tuple[str, ...]:
    """Return the bounded action menu for one query-intent phase."""

    if phase == "initial":
        return ("memory.read_more", "sql.query")
    if phase == "after_read_more":
        return ("sql.query",)
    raise ValueError(f"unknown query-intent phase: {phase}")


def normalize_query_intent_action(
    payload: dict[str, Any],
    *,
    phase: str = "initial",
) -> tuple[MemoryReadMoreAction | SQLQueryAction | None, str | None]:
    """Validate the single action envelope emitted by the current planner."""

    try:
        eligible = eligible_query_actions(phase)
    except ValueError as exc:
        return None, str(exc)
    if not isinstance(payload, dict):
        return None, "action payload is not an object"

    try:
        action = QueryIntentResponse.model_validate(payload).action
    except ValidationError:
        return None, "unknown or malformed action"

    if action.type not in eligible:
        return None, f"{action.type} is not eligible in {phase} phase"
    if isinstance(action, MemoryReadMoreAction):
        if any(not path.strip() for path in action.paths):
            return None, "memory.read_more paths must be non-empty"
    return action, None


def _materialize_planned_query(
    payload: dict[str, Any], db: CaseDB | None = None
) -> PlannedQuery:
    planned_query = PlannedQuery.model_validate(payload)
    tid = planned_query.template_id
    if tid:
        planned_query.sql = render_query_template(tid, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    if db is not None:
        planned_query.sql = validate_select_sql_with_dryrun(planned_query.sql, db)
    return planned_query


@dataclass(slots=True)
class _QueryIntentResult:
    """Keep host validation and selected context separate from raw model output."""

    action: MemoryReadMoreAction | SQLQueryAction | None
    raw_response: dict[str, Any]
    read_more: list[str]
    error: str | None = None


@dataclass(slots=True)
class HypothesisPlanResult:
    read_more: list[str]
    query: PlannedQuery | None
    stop_reason: str | None
    raw_response: dict[str, Any]


def persist_hypothesis_plan_result(
    *,
    db: CaseDB,
    session_id: str,
    iteration: int,
    hypothesis: Hypothesis,
    query_index: int,
    plan: HypothesisPlanResult,
    state: SessionState,
    emit: Callable[..., None] | None = None,
) -> str:
    """Persist query planning without changing the admitted hypothesis."""
    from forensia.ai.investigation.investigation_session import (
        _save_step,
        append_hypothesis_reasoning,
    )

    output = dict(plan.raw_response)
    output["_plan_status"] = {
        "query_materialized": plan.query is not None,
        "stop_reason": plan.stop_reason,
    }
    _save_step(
        db=db,
        session_id=session_id,
        iteration=iteration,
        phase="plan-hypothesis",
        hypothesis_id=hypothesis.id,
        input_json={"hypothesis": hypothesis.model_dump(), "query_index": query_index},
        output_json=output,
        suffix=f"{hypothesis.id}-{query_index:02d}",
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
    }
    if emit:
        emit(
            "investigate/plan",
            f"[plan] planner validation failed; retrying {hypothesis.id}: {reason}",
            iteration=iteration,
            hypothesis_id=hypothesis.id,
            planner_error=reason,
        )
    logger.warning("%s planner validation failed; retrying: %s", hypothesis.id, reason)
    return "continue"


def planner_retry_allowed(
    state: SessionState, hypothesis: Hypothesis, already_granted: bool
) -> bool:
    """Allow one bounded retry only for the hypothesis that failed planning."""
    return bool(
        state.last_planner_error
        and state.last_planner_error.get("hypothesis_id") == hypothesis.id
        and not already_granted
    )


def request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    initial_context: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    hypothesis_id: str | None = None,
    retrieval_callback: Callable[[dict[str, Any]], None] | None = None,
    json_schema: dict[str, Any] | None = None,
) -> _QueryIntentResult:
    """Request LLM with optional scoped memory expansion.

    First call uses default context. If the action requests memory paths,
    loads those paths and re-queries the LLM with the expanded context.
    """
    default_context = initial_context
    if default_context is None:
        default_context = memory.load_investigation_context(
            hypothesis_id,
            max_bytes=max(1024, memory.max_bytes // 3),
            include_overview=False,
        )
    parsed = llm_gateway.request_llm_json(
        messages=messages_builder(default_context),
        model=model,
        base_url=base_url,
        json_schema=json_schema,
        telemetry_phase="hypothesis-plan",
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    action, action_error = normalize_query_intent_action(parsed, phase="initial")
    if action_error:
        return _QueryIntentResult(None, parsed, [], action_error)
    assert action is not None
    if isinstance(action, SQLQueryAction):
        return _QueryIntentResult(action, parsed, [])

    requested_paths = list(action.paths)
    read_more, rejected_paths = memory.filter_paths_for_scope(
        requested_paths, hypothesis_id
    )
    if rejected_paths:
        read_more = []
    if not read_more:
        if retrieval_callback is not None and requested_paths:
            receipt = ToolReceipt(
                receipt_id=f"memory-{hypothesis_id or 'global'}-empty",
                call_id=f"memory-{hypothesis_id or 'global'}",
                hypothesis_id=hypothesis_id,
                phase="read_more",
                tool_id="memory.read_more",
                arguments={"paths": requested_paths},
                returned_count=0,
                sampled_count=0,
                truncated=False,
                status="partial" if rejected_paths else "empty",
                reason=("scope rejected" if rejected_paths else "no paths selected"),
            )
            evaluation = evaluate_retrieval(
                receipt,
                required_fields=["paths"],
                scope_status="rejected" if rejected_paths else "valid",
            )
            retrieval_callback(
                {
                    "requested_refs": requested_paths,
                    "selected_refs": [],
                    "rejected_refs": rejected_paths,
                    "selected_chars": 0,
                    "budget": memory.max_bytes,
                    "scope_status": "rejected" if rejected_paths else "valid",
                    "retrieval_evaluation": evaluation.model_dump(mode="json"),
                }
            )
        return _QueryIntentResult(
            None, parsed, [], "memory.read_more paths rejected by scope"
        )
    extra_context = memory.load_compact_context(read_more, max_bytes=memory.max_bytes)
    separator = "\n\n<READ_MORE_CONTEXT>\n"
    base_bytes = default_context.encode("utf-8")
    separator_bytes = separator.encode("utf-8")
    remaining = max(memory.max_bytes - len(base_bytes) - len(separator_bytes), 0)
    raw_extra_bytes = extra_context.encode("utf-8")
    extra_bytes = raw_extra_bytes[:remaining]
    selected_context = extra_bytes.decode("utf-8", errors="ignore")
    if retrieval_callback is not None:
        receipt = ToolReceipt(
            receipt_id=f"memory-{hypothesis_id or 'global'}-read-more",
            call_id=f"memory-{hypothesis_id or 'global'}",
            hypothesis_id=hypothesis_id,
            phase="read_more",
            tool_id="memory.read_more",
            arguments={"paths": requested_paths},
            returned_count=len(read_more),
            sampled_count=len(read_more),
            truncated=len(raw_extra_bytes) > len(extra_bytes),
            status=(
                "partial" if rejected_paths else ("ok" if selected_context else "empty")
            ),
            reason=(
                "some paths rejected by scope"
                if rejected_paths
                else (
                    None if selected_context else "selected paths contained no content"
                )
            ),
        )
        evaluation = evaluate_retrieval(
            receipt,
            required_fields=["paths"],
            scope_status="rejected" if rejected_paths else "valid",
        )
        retrieval_callback(
            {
                "requested_refs": requested_paths,
                "selected_refs": read_more,
                "rejected_refs": rejected_paths,
                "selected_chars": len(selected_context),
                "budget": memory.max_bytes,
                "scope_status": "rejected" if rejected_paths else "valid",
                "retrieval_evaluation": evaluation.model_dump(mode="json"),
            }
        )
    expanded_context = default_context
    if extra_bytes:
        expanded_context += separator + selected_context
    reparsed = llm_gateway.request_llm_json(
        messages=messages_builder(expanded_context),
        model=model,
        base_url=base_url,
        json_schema=json_schema,
        telemetry_phase="hypothesis-plan-read-more",
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    reparsed_action, reparsed_error = normalize_query_intent_action(
        reparsed, phase="after_read_more"
    )
    return _QueryIntentResult(reparsed_action, reparsed, read_more, reparsed_error)


def _compute_uncovered_keypoints(
    observed: list[str],
    active: list[Hypothesis],
    resolved: list[Hypothesis],
    proposed_counts: dict[str, int] | None = None,
) -> list[dict[str, str]]:
    """Compute uncovered keypoints using round-robin across families.

    A keypoint is considered covered (excluded from output) when:
    - Any active/resolved hypothesis has target_keypoint_id == keypoint name (exact match)
    - The keypoint has been proposed >=2 times (from proposed_counts)

    Remaining candidates are grouped by family (first underscore token) and
    selected round-robin across families up to 8 items.
    """
    if not observed:
        return []

    covered: set[str] = set()
    for hyp in list(active) + list(resolved):
        if hyp.target_keypoint_id:
            covered.add(hyp.target_keypoint_id.strip().lower())

    exhausted: set[str] = set()
    if proposed_counts:
        for kp_name, count in proposed_counts.items():
            if count >= 2:
                exhausted.add(kp_name.strip().lower())

    groups: dict[str, list[str]] = {}
    for item in observed:
        name = (
            item.split(" (")[0].strip().lower()
            if " (" in item
            else item.strip().lower()
        )
        if not name or name in covered or name in exhausted:
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


def _resolve_planner_context(
    memory: MemoryManager,
    hypothesis: Hypothesis,
    default_context_md: str | None,
) -> str:
    """Resolve investigation context for the planner when no default_context_md is provided."""
    if default_context_md is None:
        relevance = memory.build_relevance_terms_from_hypothesis(hypothesis)
        default_context_md = memory.load_investigation_context(
            hypothesis.id,
            relevance_terms=relevance or None,
            max_bytes=max(1024, memory.max_bytes // 3),
            include_overview=False,
        )
    return default_context_md


def _build_hypothesis_history(
    state: SessionState,
    hypothesis: Hypothesis,
    db: CaseDB | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Build hypothesis history list and seen query IDs from state history and DB reasoning rows."""
    hypothesis_history = [
        item.model_dump()
        for item in state.history
        if item.hypothesis_id == hypothesis.id
    ]
    seen_query_ids = {
        str(item.get("query_id")) for item in hypothesis_history if item.get("query_id")
    }
    if db is not None:
        for row in _recent_reasoning_rows(db, hypothesis.id, limit=limit):
            query_id = str(row.get("query_id") or "").strip()
            if query_id and query_id in seen_query_ids:
                continue
            hypothesis_history.append(row)
            if query_id:
                seen_query_ids.add(query_id)
    return hypothesis_history


def _load_prior_check_feedback(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Summarize recent checker and host-gate feedback for this hypothesis.

    Free text is a supplement only — the structured attempt history
    (<PRIOR_ATTEMPTS> in the intent prompt) carries the signal.
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
            FROM hypothesis_reasoning
            WHERE hypothesis_id = ?
              AND phase IN ('check', 'sufficiency', 'settlement')
        ) recent
        WHERE phase_rank <= CASE WHEN phase = 'check' THEN 2 ELSE 1 END
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
        "</PLANNER_VALIDATION_ERROR>\n"
    )
    state.last_planner_error = None
    return block


def _plan_query_intent(
    *,
    memory: MemoryManager,
    intent_messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    default_context_md: str,
    db: CaseDB | None,
    status_callback: Callable[[str], None] | None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None,
    hypothesis: Hypothesis,
    session_id: str | None,
) -> _QueryIntentResult:
    """Run the single query-intent LLM decision.

    The model response contains the complete bounded SQL action. All readiness
    validation (table/column/SELECT-only/allow-list/row-limit/dry-run) is
    performed deterministically by the host before execution.
    """

    def retrieval_callback(event: dict[str, Any]) -> None:
        if db is None:
            return
        from forensia.ai.retrieval_telemetry import record_retrieval_event

        record_retrieval_event(
            db,
            session_id=session_id,
            scope_kind="hypothesis",
            scope_id=hypothesis.id,
            phase="read_more",
            source_kind="memory",
            query_terms=[],
            candidate_count=len(event["requested_refs"]),
            selected_refs=event["selected_refs"],
            rejected_refs=event["rejected_refs"],
            selected_chars=event["selected_chars"],
            budget=event["budget"],
        )

    intent_response = request_with_optional_context(
        memory=memory,
        messages_builder=intent_messages_builder,
        base_url=base_url,
        model=model,
        initial_context=default_context_md,
        status_callback=status_callback,
        audit_callback=audit_callback,
        hypothesis_id=hypothesis.id,
        retrieval_callback=retrieval_callback,
        json_schema=QUERY_INTENT_SCHEMA,
    )
    return intent_response


def plan_hypothesis_query(
    state: SessionState,
    hypothesis: Hypothesis,
    memory: MemoryManager,
    base_url: str,
    model: str,
    db: CaseDB | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    query_index: int = 1,
    time_range: dict[str, str] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
) -> HypothesisPlanResult:
    """Plan the next query for a single hypothesis.

    Collapsed to a single SQL decision plus deterministic host validation (T-20):
    the query_intent_planner makes one model decision choosing a recipe
    (template_id+params) or a bounded fallback SELECT; the host then validates
    table/column/SELECT-only/allow-list/row-limit/dry-run before execution.

    The former second "schema-readiness" LLM self-check call was removed."""
    default_context_md = _resolve_planner_context(
        memory, hypothesis, default_context_md
    )
    hypothesis_history = _build_hypothesis_history(
        state, hypothesis, db, limit=10
    )
    schema_card = _build_schema_guidance("evtx_events", db=db)
    prior_check_feedback = _load_prior_check_feedback(db, hypothesis)
    execution_error_block = _consume_execution_error_block(state)
    planner_error_block = _consume_planner_error_block(state, hypothesis.id)

    def intent_messages_builder(extra_context: str) -> list[dict[str, str]]:
        return build_query_intent_messages(
            hypothesis=hypothesis,
            recent_history=hypothesis_history,
            active_hypotheses=state.active_hypotheses,
            time_range=time_range or {},
            schema_context=schema_card,
            extra_context_md=extra_context
            + execution_error_block
            + planner_error_block,
            prior_check_feedback=prior_check_feedback,
            case_profile=case_profile,
            findings_snapshot=state.findings_snapshot,
        )

    intent_response = _plan_query_intent(
        memory=memory,
        intent_messages_builder=intent_messages_builder,
        base_url=base_url,
        model=model,
        default_context_md=default_context_md,
        db=db,
        status_callback=status_callback,
        audit_callback=audit_callback,
        hypothesis=hypothesis,
        session_id=state.session_id,
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
                    "template_id": action.template_id,
                    "params": action.params,
                    "sql": action.sql,
                },
                db,
            )
        except (ValueError, ValidationError) as exc:
            error = str(exc).splitlines()[0][:300]
            logger.debug("planned SQL rejected by host validation: %s", error)
    elif not error:
        error = "SQL action was not selected"
    return HypothesisPlanResult(
        read_more=intent_response.read_more,
        query=planned_query,
        stop_reason=f"invalid_action: {error}" if error else None,
        raw_response=intent_response.raw_response,
    )
