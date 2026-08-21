"""Hypothesis query planning: query-intent phase, SQL composition with validation retry."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

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
    _trim_dynamic_content,
)
from forensia.ai.prompts.prompt_investigation import (
    build_query_intent_messages,
    build_sql_composer_messages,
)
from forensia.ai.prompts.sql_templates import (
    coerce_list,
    query_template_catalog,
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.ai.retrieval_telemetry import ToolReceipt, evaluate_retrieval
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)

_PLANNER_SQL_MAX_RETRIES = 3


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
    """Validate and normalize the small action contract at the planner boundary.

    Older local models omitted ``action``.  Their output is accepted only when
    it has one unambiguous meaning: a non-empty ``read_more`` list means memory
    expansion, otherwise a complete intent with a known table means SQL.
    """

    try:
        eligible = eligible_query_actions(phase)
    except ValueError as exc:
        return None, str(exc)
    if not isinstance(payload, dict):
        return None, "action payload is not an object"

    if "action" in payload:
        if coerce_list(payload.get("read_more")):
            return None, "explicit action conflicts with legacy read_more"
        try:
            # ``request_with_optional_context`` annotates the original response
            # with the normalized action while preserving legacy fields for
            # audit/debugging.  Validate only the action envelope here so those
            # retained fields do not turn a valid decision into an extra-field
            # error on the second normalization pass.
            action = QueryIntentResponse.model_validate(
                {"action": payload["action"]}
            ).action
        except ValidationError:
            return None, "unknown or malformed action"
    else:
        requested_paths = coerce_list(payload.get("read_more"))
        if requested_paths:
            if "memory.read_more" not in eligible:
                return (
                    None,
                    "memory.read_more is not eligible after read_more expansion",
                )
            paths = [str(path).strip() for path in requested_paths]
            if not paths or any(not path for path in paths):
                return None, "legacy read_more paths are invalid"
            action = MemoryReadMoreAction(type="memory.read_more", paths=paths)
        else:
            try:
                action = SQLQueryAction(
                    type="sql.query",
                    intent=str(payload.get("intent") or "").strip(),
                    target_table=str(payload.get("target_table") or "").strip(),
                    template_id=(
                        str(payload["template_id"]).strip()
                        if payload.get("template_id")
                        else None
                    ),
                    params=dict(payload.get("params") or {}),
                    sql=str(payload.get("sql") or "").strip(),
                    filters_required=[
                        str(item)
                        for item in coerce_list(payload.get("filters_required"))
                    ],
                    time_window=str(payload.get("time_window") or ""),
                    expected_row_shape=str(payload.get("expected_row_shape") or ""),
                )
            except ValidationError:
                return None, "missing action and incomplete query intent"

    if action.type not in eligible:
        return None, f"{action.type} is not eligible in {phase} phase"
    if isinstance(action, MemoryReadMoreAction):
        if any(not path.strip() for path in action.paths):
            return None, "memory.read_more paths must be non-empty"
    return action, None


def _materialize_planned_query(payload: dict[str, Any]) -> PlannedQuery:
    planned_query = PlannedQuery.model_validate(payload)
    tid = planned_query.template_id
    if isinstance(tid, str) and tid.strip().lower() in {"", "null", "none"}:
        planned_query.template_id = None
        tid = None
    if tid:
        planned_query.sql = render_query_template(tid, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    return planned_query


@dataclass(slots=True)
class _PlannerContext:
    """Container for pre-resolved planner dependencies to reduce verbosity."""

    hypothesis: Hypothesis
    seen_query_ids: set[str]
    hypothesis_history: list[dict[str, Any]]
    context_md: str


@dataclass(slots=True)
class HypothesisPlanResult:
    read_more: list[str]
    hypothesis: Hypothesis | None
    query: PlannedQuery | None
    needs_more: bool
    stop_reason: str | None
    raw_response: dict[str, Any]


def _retry_sql_composer(
    base_messages: list[dict[str, str]],
    hypothesis_id: str,
    query_index: int,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    db: CaseDB | None = None,
) -> dict[str, Any]:
    """Retry SQL composition up to _PLANNER_SQL_MAX_RETRIES times when SQL validation fails.

    Unlike _retry_query_once, this operates on the flattened composer response
    format (template_id/sql/params/purpose) without read_more or hypothesis wrapping.
    When a db handle is available, an EXPLAIN dry-run (R2-05) catches binder
    errors (unknown functions/columns) before execution so they feed the retry
    loop instead of failing at execute time.
    """
    messages = list(base_messages)
    for attempt in range(1, _PLANNER_SQL_MAX_RETRIES + 1):
        parsed = llm_gateway.request_llm_json(
            messages=messages,
            model=model,
            base_url=base_url,
            status_callback=status_callback,
            audit_callback=audit_callback,
        )
        query_dict = {
            "query_id": f"{hypothesis_id}-q{query_index}",
            "hypothesis_id": hypothesis_id,
            "purpose": parsed.get("purpose", ""),
            "template_id": parsed.get("template_id"),
            "params": parsed.get("params", {}),
            "sql": parsed.get("sql", ""),
        }
        try:
            planned = _materialize_planned_query(query_dict)
            if db is not None and planned.sql:
                validate_select_sql_with_dryrun(planned.sql, db)
            return parsed
        except ValueError as exc:
            err_msg = str(exc)
            # R2-03: check for placeholder literals in rejected SQL
            sql_text = str(parsed.get("sql", "") or "")
            placeholder_note = ""
            if re.search(
                r"\[\w*placeholder\w*\]|\[(start|end)_time\]|\{\w+\}", sql_text
            ):
                placeholder_note = " Your SQL contained an unresolved placeholder literal. Use real values from the hypothesis/case profile, or omit that filter."
                err_msg += placeholder_note
            if status_callback:
                status_callback(
                    f"SQL composer rejected (attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}): {err_msg}."
                )
            if attempt >= _PLANNER_SQL_MAX_RETRIES:
                return parsed
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}: the previous SQL was rejected. "
                        f"Error: {err_msg}. "
                        "MUST return corrected JSON with template_id (or null), sql (raw SELECT), params, purpose. "
                        "Do NOT leave both template_id and sql blank. "
                        "Use a valid SELECT statement against evtx_events / mft_entries / mft_timeline / prefetch_executions / findings. "
                        "Use simple SELECT cols FROM table WHERE event_id = N style if unsure."
                    ),
                }
            )
    return parsed


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
) -> dict[str, Any]:
    """Request LLM with optional read_more context expansion.

    First call uses default context. If the response includes read_more paths,
    loads those paths and re-queries the LLM with the expanded context.
    """
    default_context = initial_context
    if default_context is None:
        load_investigation_context = getattr(memory, "load_investigation_context", None)
        if callable(load_investigation_context):
            default_context = load_investigation_context(
                None,
                max_bytes=max(1024, memory.max_bytes // 3),
                include_overview=False,
            )
        else:
            default_context = memory.load_compact_context(
                ["facts.md", "tasks.md"],
                max_bytes=max(1024, memory.max_bytes // 3),
            )
    parsed = llm_gateway.request_llm_json(
        messages=messages_builder(default_context),
        model=model,
        base_url=base_url,
        json_schema=json_schema,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    action, action_error = normalize_query_intent_action(parsed, phase="initial")
    if action_error:
        parsed["_action_error"] = action_error
        parsed["read_more"] = []
        return parsed
    assert action is not None
    parsed["action"] = action.model_dump(mode="json")
    if isinstance(action, SQLQueryAction):
        parsed.update(action.model_dump(mode="json", exclude={"type"}))
        parsed["read_more"] = []
        return parsed

    requested_paths = list(action.paths)
    scope_filter = getattr(memory, "filter_paths_for_scope", None)
    if callable(scope_filter):
        read_more, rejected_paths = scope_filter(requested_paths, hypothesis_id)
    else:
        read_more, rejected_paths = requested_paths, []
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
        if rejected_paths:
            parsed["_action_error"] = "memory.read_more paths rejected by scope"
        parsed["read_more"] = []
        return parsed
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
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    reparsed_action, reparsed_error = normalize_query_intent_action(
        reparsed, phase="after_read_more"
    )
    if reparsed_error:
        reparsed["_action_error"] = reparsed_error
    elif reparsed_action is not None:
        reparsed["action"] = reparsed_action.model_dump(mode="json")
        if isinstance(reparsed_action, SQLQueryAction):
            reparsed.update(reparsed_action.model_dump(mode="json", exclude={"type"}))
    reparsed["read_more"] = read_more
    return reparsed


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
    initial_context: str | None = None,
) -> str:
    """Resolve investigation context for the planner when no default_context_md is provided."""
    if default_context_md is None:
        load_investigation_context = getattr(memory, "load_investigation_context", None)
        if callable(load_investigation_context):
            _relevance = memory.build_relevance_terms_from_hypothesis(hypothesis)
            default_context_md = load_investigation_context(
                hypothesis.id,
                relevance_terms=_relevance or None,
                max_bytes=max(1024, memory.max_bytes // 3),
                include_overview=False,
            )
        else:
            default_context_md = memory.load_compact_context(
                ["facts.md", "tasks.md"],
                max_bytes=max(1024, memory.max_bytes // 3),
            )
    return default_context_md


def _build_hypothesis_history(
    state: SessionState,
    hypothesis: Hypothesis,
    db: CaseDB | None = None,
    limit: int = 10,
) -> tuple[list[dict[str, Any]], set[str]]:
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
    return hypothesis_history, seen_query_ids


def _parse_planner_output(
    parsed: dict[str, Any],
) -> tuple[Hypothesis | None, PlannedQuery | None]:
    """Parse LLM planner output into optional Hypothesis and PlannedQuery."""
    parsed_hypothesis = None
    if isinstance(parsed.get("hypothesis"), dict):
        try:
            parsed_hypothesis = Hypothesis.model_validate(parsed["hypothesis"])
        except Exception as exc:
            logger.debug("hypothesis parse failed: %s", exc)
            parsed_hypothesis = None

    planned_query = None
    if isinstance(parsed.get("query"), dict):
        try:
            planned_query = _materialize_planned_query(parsed["query"])
        except Exception as exc:
            logger.debug("hypothesis/query parse failed: %s", exc)
            planned_query = None

    return parsed_hypothesis, planned_query


def _load_prior_check_feedback(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Summarize the last check-phase reasoning entries for this hypothesis.

    Free text is a supplement only — the structured attempt history
    (<PRIOR_ATTEMPTS> in the intent prompt) carries the signal.
    """
    if db is None or not hypothesis.id:
        return ""
    recent_checks = db.execute(
        """
        SELECT body FROM hypothesis_reasoning
        WHERE hypothesis_id = ? AND phase = 'check'
        ORDER BY created_at DESC LIMIT 2
    """,
        (hypothesis.id,),
    ).fetchall()
    if not recent_checks:
        return ""
    return "\n".join(f"- {row[0][:120]}" for row in recent_checks)


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
) -> tuple[dict[str, Any], str]:
    """Phase 1: plan the query intent (the single SQL decision follows in Phase 2).

    The model response contains the complete bounded SQL action. All readiness
    validation (table/column/SELECT-only/allow-list/row-limit/dry-run) is
    performed deterministically by the host before execution.

    Returns the normalized single-action response and its selected schema card.
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
    if intent_response.get("_action_error"):
        return intent_response, ""
    target_table = str(intent_response.get("target_table") or "evtx_events").strip()
    composer_schema_card = _build_schema_guidance(target_table, db=db)
    return intent_response, composer_schema_card


def _compose_sql(
    *,
    intent_response: dict[str, Any],
    composer_schema_card: str,
    time_range: dict[str, str] | None,
    prior_check_feedback: str,
    execution_error_block: str,
    hypothesis: Hypothesis,
    query_index: int,
    base_url: str,
    model: str,
    db: CaseDB | None,
    status_callback: Callable[[str], None] | None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None,
) -> dict[str, Any]:
    """Phase 2: compose the SELECT statement, with SQL validation retry."""
    composer_messages = build_sql_composer_messages(
        intent=intent_response,
        table_schema_card=composer_schema_card,
        template_catalog=query_template_catalog(),
        time_range=time_range or {},
        prior_check_feedback=prior_check_feedback,
    )
    if execution_error_block:
        composer_messages.append(
            {"role": "user", "content": execution_error_block.strip()}
        )
    composer_messages = _trim_dynamic_content(composer_messages)
    return _retry_sql_composer(
        base_messages=composer_messages,
        hypothesis_id=hypothesis.id,
        query_index=query_index,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        audit_callback=audit_callback,
        db=db,
    )


def _build_hypothesis_plan_result(
    hypothesis: Hypothesis,
    query_index: int,
    intent_response: dict[str, Any],
    composer_response: dict[str, Any],
) -> HypothesisPlanResult:
    """Build a PlannedQuery from the composer response and wrap it as a plan result."""
    wrapper = {
        "hypothesis": None,
        "query": {
            "query_id": f"{hypothesis.id}-q{query_index}",
            "hypothesis_id": hypothesis.id,
            "purpose": composer_response.get("purpose", ""),
            "template_id": composer_response.get("template_id"),
            "params": composer_response.get("params", {}),
            "sql": composer_response.get("sql", ""),
        }
        if composer_response.get("template_id") or composer_response.get("sql")
        else None,
    }
    _, planned_query = _parse_planner_output(wrapper)
    read_more = [str(item) for item in coerce_list(intent_response.get("read_more"))]
    return HypothesisPlanResult(
        read_more=read_more,
        hypothesis=None,
        query=planned_query,
        needs_more=planned_query is not None,
        stop_reason=None if planned_query else "SQL composition failed after retries",
        raw_response=composer_response,
    )


def plan_hypothesis_query(
    state: SessionState,
    hypothesis: Hypothesis,
    memory: MemoryManager,
    base_url: str,
    model: str,
    db: CaseDB | None = None,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
    query_index: int = 1,
    time_range: dict[str, str] | None = None,
    case_profile: str | None = None,
) -> HypothesisPlanResult:
    """Plan the next query for a single hypothesis.

    Collapsed to a single SQL decision plus deterministic host validation (T-20):
    1. query_intent_planner: decides WHAT data to fetch (read_more or sql.query)
    2. sql_composer: one model decision choosing a recipe (template_id+params)
       or a bounded fallback SELECT; the host then validates table/column/
       SELECT-only/allow-list/row-limit/dry-run before execution.

    The former second "schema-readiness" LLM self-check call was removed."""
    default_context_md = _resolve_planner_context(
        memory, hypothesis, default_context_md, initial_context=None
    )
    hypothesis_history, _seen_query_ids = _build_hypothesis_history(
        state, hypothesis, db, limit=10
    )
    schema_card = _build_schema_guidance("evtx_events", db=db)
    prior_check_feedback = _load_prior_check_feedback(db, hypothesis)
    execution_error_block = _consume_execution_error_block(state)

    def intent_messages_builder(extra_context: str) -> list[dict[str, str]]:
        return build_query_intent_messages(
            hypothesis=hypothesis,
            recent_history=hypothesis_history,
            active_hypotheses=[hypothesis],
            time_range=time_range or {},
            schema_context=schema_card,
            extra_context_md=extra_context + execution_error_block,
            prior_check_feedback=prior_check_feedback,
            case_profile=case_profile,
            findings_snapshot=state.findings_snapshot,
        )

    intent_response, composer_schema_card = _plan_query_intent(
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
    if intent_response.get("_action_error"):
        reason = str(intent_response["_action_error"])
        return HypothesisPlanResult(
            read_more=[
                str(item) for item in coerce_list(intent_response.get("read_more"))
            ],
            hypothesis=None,
            query=None,
            needs_more=False,
            stop_reason=f"invalid_action: {reason}",
            raw_response=intent_response,
        )
    # SQLQueryAction already contains a recipe or bounded SELECT. The host
    # materializes and validates it; a second LLM composer would recreate the
    # removed readiness/composition loop and double the prompt cost.
    action, action_error = normalize_query_intent_action(intent_response, phase="initial")
    if not isinstance(action, SQLQueryAction):
        return HypothesisPlanResult(
            read_more=[str(item) for item in coerce_list(intent_response.get("read_more"))],
            hypothesis=None,
            query=None,
            needs_more=False,
            stop_reason=action_error or "SQL action was not selected",
            raw_response=intent_response,
        )
    if not action.template_id and not action.sql.strip():
        return HypothesisPlanResult(
            read_more=[],
            hypothesis=None,
            query=None,
            needs_more=False,
            stop_reason="invalid_action: SQL action needs template_id or bounded SELECT",
            raw_response=intent_response,
        )
    return _build_hypothesis_plan_result(
        hypothesis, query_index, intent_response, intent_response
    )
