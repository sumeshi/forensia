from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai import llm_gateway
from forensia.ai.hypothesis_manager import _recent_reasoning_rows
from forensia.ai.prompt_context import (
    _build_schema_guidance,
    _trim_dynamic_content,
)
from forensia.ai.prompt_investigation import (
    build_query_intent_messages,
    build_sql_composer_messages,
    build_sql_self_check_messages,
)
from forensia.ai.sql_templates import (
    coerce_list,
    query_template_catalog,
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB

logger = logging.getLogger(__name__)

_PLANNER_SQL_MAX_RETRIES = 3


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


def _request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    initial_context: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
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
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    read_more = [str(item) for item in coerce_list(parsed.get("read_more"))]
    if not read_more:
        return parsed
    extra_context = memory.load_compact_context(read_more, max_bytes=memory.max_bytes)
    reparsed = llm_gateway.request_llm_json(
        messages=messages_builder(extra_context),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
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

    Two-phase split (PRM-010):
    1. query_intent_planner: decides WHAT data to fetch
    2. sql_composer: produces the SELECT statement

    Phase 1 uses read_more context expansion; phase 2 is idempotent with
    SQL validation retry."""

    overview_md = overview_md if overview_md is not None else memory.load_overview()
    default_context_md = _resolve_planner_context(
        memory, hypothesis, default_context_md, initial_context=None
    )
    extra_context_holder = {"value": ""}
    hypothesis_history, seen_query_ids = _build_hypothesis_history(
        state, hypothesis, db, limit=10
    )
    schema_card = _build_schema_guidance("evtx_events", db=db)

    prior_check_feedback = ""
    if db is not None and hypothesis.id:
        recent_checks = db.execute(
            """
            SELECT body FROM hypothesis_reasoning
            WHERE hypothesis_id = ? AND phase = 'check'
            ORDER BY created_at DESC LIMIT 2
        """,
            (hypothesis.id,),
        ).fetchall()
        if recent_checks:
            # Free text is a supplement only — the structured attempt history
            # (<PRIOR_ATTEMPTS> in the intent prompt) carries the signal.
            prior_check_feedback = "\n".join(
                f"- {row[0][:120]}" for row in recent_checks
            )

    execution_error_block = ""
    if state.last_execution_error:
        execution_error_block = (
            f"\n<EXECUTION_ERROR>\n"
            f"The previous SQL failed at execute time. Do NOT repeat the same SQL.\n"
            f"query_id: {state.last_execution_error['query_id']}\n"
            f"failing_sql: {state.last_execution_error['sql']}\n"
            f"error: {state.last_execution_error['error']}\n"
            f"</EXECUTION_ERROR>\n"
        )
        state.last_execution_error = None

    # Phase 1: Query Intent Planning (WHAT data to fetch)
    def intent_messages_builder(extra_context: str) -> list[dict[str, str]]:
        extra_context_holder["value"] = extra_context
        return build_query_intent_messages(
            hypothesis=hypothesis,
            recent_history=hypothesis_history,
            active_hypotheses=state.active_hypotheses,
            time_range=time_range or {},
            schema_context=schema_card,
            extra_context_md=extra_context + execution_error_block,
            prior_check_feedback=prior_check_feedback,
            case_profile=case_profile,
            findings_snapshot=state.findings_snapshot,
        )

    intent_response = _request_with_optional_context(
        memory=memory,
        messages_builder=intent_messages_builder,
        base_url=base_url,
        model=model,
        initial_context=default_context_md,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )

    target_table = str(intent_response.get("target_table") or "evtx_events").strip()
    composer_schema_card = _build_schema_guidance(target_table, db=db)

    self_check_messages, self_check_schema = build_sql_self_check_messages(
        intent_response, composer_schema_card
    )
    self_check = llm_gateway.request_llm_json(
        messages=self_check_messages,
        model=model,
        base_url=base_url,
        json_schema=self_check_schema,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    if not self_check.get("ready_to_compose", False):
        if status_callback:
            status_callback(
                f"SQL self-check blocked: {self_check.get('blockers', '')}. Retrying intent..."
            )
        intent_response = _request_with_optional_context(
            memory=memory,
            messages_builder=intent_messages_builder,
            base_url=base_url,
            model=model,
            initial_context=default_context_md
            + f"\n\n<SCHEMA_SELFCHECK_BLOCKERS>\n{self_check.get('blockers', '')}\n</SCHEMA_SELFCHECK_BLOCKERS>\n",
            status_callback=status_callback,
            audit_callback=audit_callback,
        )

    # Phase 2: SQL Composition (HOW to write the query)
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

    composer_response = _retry_sql_composer(
        base_messages=composer_messages,
        hypothesis_id=hypothesis.id,
        query_index=query_index,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        audit_callback=audit_callback,
        db=db,
    )

    # Build PlannedQuery from composer response via shared helper
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
