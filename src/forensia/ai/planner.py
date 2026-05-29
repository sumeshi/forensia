from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.hypothesis_manager import _recent_reasoning_rows
from forensia.ai.prompts import (
    _build_schema_guidance,
    _trim_dynamic_content,
    build_query_intent_messages,
    build_sql_composer_messages,
)
from forensia.ai.sql_templates import (
    coerce_list,
    query_template_catalog,
    render_query_template,
    validate_select_sql,
)
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB


logger = logging.getLogger(__name__)

_PLANNER_SQL_MAX_RETRIES = 3


def _materialize_planned_query(payload: dict[str, Any]) -> PlannedQuery:
    """Convert raw LLM query dict to PlannedQuery, rendering template or validating raw SQL."""
    planned_query = PlannedQuery.model_validate(payload)
    if planned_query.template_id:
        planned_query.sql = render_query_template(planned_query.template_id, planned_query.params)
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


_KEYPOINT_NAME_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")


def _compute_uncovered_keypoints(
    observed: list[str],
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
) -> list[dict[str, str]]:
    """Return keypoints not yet covered by existing active or resolved hypotheses."""
    haystack_parts: list[str] = []
    for h in active_hypotheses:
        haystack_parts.append(str(h.description).lower())
    for h in resolved_hypotheses:
        haystack_parts.append(str(h.id).lower())
        if h.description:
            haystack_parts.append(str(h.description).lower())
    haystack = " ".join(haystack_parts)
    uncovered: list[dict[str, str]] = []
    for item in observed:
        name = item.split(" (")[0].strip().lower() if " (" in item else item.strip().lower()
        if not name:
            continue
        tokens = _KEYPOINT_NAME_RE.findall(name)
        if name in haystack:
            continue
        if any(tok and len(tok) >= 4 and tok in haystack for tok in tokens):
            continue
        uncovered.append({"name": name})
        if len(uncovered) >= 5:
            break
    return uncovered


def _retry_sql_composer(
    base_messages: list[dict[str, str]],
    hypothesis_id: str,
    query_index: int,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Retry SQL composition up to _PLANNER_SQL_MAX_RETRIES times when SQL validation fails.
    
    Unlike _retry_query_once, this operates on the flattened composer response
    format (template_id/sql/params/purpose) without read_more or hypothesis wrapping.
    """
    messages = list(base_messages)
    for attempt in range(1, _PLANNER_SQL_MAX_RETRIES + 1):
        parsed = request_llm_json(
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
            _materialize_planned_query(query_dict)
            return parsed
        except ValueError as exc:
            if status_callback:
                status_callback(
                    f"SQL composer rejected (attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}): {exc}."
                )
            if attempt >= _PLANNER_SQL_MAX_RETRIES:
                return parsed
            messages.append({
                "role": "user",
                "content": (
                    f"Attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}: the previous SQL was rejected. "
                    f"Error: {exc}. "
                    "MUST return corrected JSON with template_id (or null), sql (raw SELECT), params, purpose. "
                    "Do NOT leave both template_id and sql blank. "
                    "Use a valid SELECT statement against evtx_events / mft_entries / mft_timeline / prefetch_executions / findings. "
                    "Use simple SELECT cols FROM table WHERE event_id = N style if unsure."
                ),
            })
    return parsed


def _request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    initial_context: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
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
    parsed = request_llm_json(
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
    reparsed = request_llm_json(
        messages=messages_builder(extra_context),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    reparsed["read_more"] = read_more
    return reparsed


_KEYPOINT_NAME_RE = re.compile(r"[a-zA-Z0-9_]+")


def _compute_uncovered_keypoints(
    observed: list[str],
    active: list[Hypothesis],
    resolved: list[Hypothesis],
) -> list[dict[str, str]]:
    """Heuristic: a keypoint is 'covered' if its name (or any token of it) appears
    in any active/resolved hypothesis's description or source_rule_ids.

    Returns up to 5 uncovered keypoint dicts that broad_plan must address.
    """
    if not observed:
        return []
    haystack_parts: list[str] = []
    for hyp in list(active) + list(resolved):
        haystack_parts.append((hyp.description or "").lower())
        for rid in getattr(hyp, "source_rule_ids", None) or []:
            haystack_parts.append(str(rid).lower())
    haystack = " ".join(haystack_parts)

    uncovered: list[dict[str, str]] = []
    for item in observed:
        name = item.split(" (")[0].strip().lower() if " (" in item else item.strip().lower()
        if not name:
            continue
        # cover if the keypoint name itself OR any of its underscore-separated tokens
        # appears in the active/resolved hypothesis context
        tokens = _KEYPOINT_NAME_RE.findall(name)
        if name in haystack:
            continue
        if any(tok and len(tok) >= 4 and tok in haystack for tok in tokens):
            continue
        uncovered.append({"name": name})
        if len(uncovered) >= 5:
            break
    return uncovered


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
            default_context_md = load_investigation_context(
                hypothesis.id,
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
        str(item.get("query_id"))
        for item in hypothesis_history
        if item.get("query_id")
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


def _parse_planner_output(parsed: dict[str, Any]) -> tuple[Hypothesis | None, PlannedQuery | None]:
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
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    query_index: int = 1,
) -> HypothesisPlanResult:
    """Plan the next query for a single hypothesis.

    Two-phase split (PRM-010):
    1. query_intent_planner: decides WHAT data to fetch
    2. sql_composer: produces the SELECT statement

    Phase 1 uses read_more context expansion; phase 2 is idempotent with
    SQL validation retry."""

    overview_md = overview_md if overview_md is not None else memory.load_overview()
    default_context_md = _resolve_planner_context(memory, hypothesis, default_context_md, initial_context=None)
    extra_context_holder = {"value": ""}
    hypothesis_history, seen_query_ids = _build_hypothesis_history(state, hypothesis, db, limit=10)
    schema_card = _build_schema_guidance("evtx_events")

    # Phase 1: Query Intent Planning (WHAT data to fetch)
    def intent_messages_builder(extra_context: str) -> list[dict[str, str]]:
        extra_context_holder["value"] = extra_context
        return build_query_intent_messages(
            hypothesis=hypothesis,
            recent_history=hypothesis_history,
            active_hypotheses=state.active_hypotheses,
            time_range={},
            schema_context=schema_card,
            extra_context_md=extra_context,
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

    # Phase 2: SQL Composition (HOW to write the query)
    composer_messages = build_sql_composer_messages(
        intent=intent_response,
        table_schema_card=schema_card,
        template_catalog=query_template_catalog(),
        time_range={},
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
        } if composer_response.get("template_id") or composer_response.get("sql") else None,
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
