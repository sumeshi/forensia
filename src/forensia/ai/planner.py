from __future__ import annotations

import json
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
    build_broad_plan_messages,
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


@dataclass(slots=True)
class BroadPlanResult:
    hypotheses: list[Hypothesis]
    stop: bool
    stop_reason: str | None
    raw_response: dict[str, Any]


@dataclass(slots=True)
class HypothesisPlanResult:
    read_more: list[str]
    hypothesis: Hypothesis | None
    query: PlannedQuery | None
    needs_more: bool
    stop_reason: str | None
    raw_response: dict[str, Any]


def _parse_hypotheses(items: Any) -> list[Hypothesis]:
    """Parse raw LLM JSON output into validated Hypothesis objects, normalizing source_rule_ids."""
    hypotheses: list[Hypothesis] = []
    for item in coerce_list(items):
        if not isinstance(item, dict):
            continue
        payload = dict(item)
        # Ensure source_rule_ids is a list
        if "source_rule_ids" not in payload or not isinstance(payload.get("source_rule_ids"), list):
            payload["source_rule_ids"] = []
        # Also normalize as list
        source_rules = payload.get("source_rule_ids") or []
        if isinstance(source_rules, str):
            source_rules = [source_rules]
        payload["source_rule_ids"] = [str(r) for r in source_rules if r]
        try:
            hypotheses.append(Hypothesis.model_validate(payload))
        except Exception as exc:
            logger.debug("hypothesis parse failed: %s", exc)
            continue
    return hypotheses


def _materialize_planned_query(payload: dict[str, Any]) -> PlannedQuery:
    """Convert raw LLM query dict to PlannedQuery, rendering template or validating raw SQL."""
    planned_query = PlannedQuery.model_validate(payload)
    if planned_query.template_id:
        planned_query.sql = render_query_template(planned_query.template_id, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    return planned_query


_PLANNER_SQL_MAX_RETRIES = 3


def _retry_query_once(
    parsed: dict[str, Any],
    messages_builder: Callable[[str], list[dict[str, str]]],
    extra_context: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Retry SQL generation up to _PLANNER_SQL_MAX_RETRIES times when the
    planner returns a query that fails validation. Weak local LLMs often need
    a couple of corrective turns before producing valid SELECT statements.
    """
    current = parsed
    query = current.get("query")
    if not isinstance(query, dict):
        return current

    base_fields = {field: query.get(field) for field in ("query_id", "hypothesis_id", "purpose")}

    for attempt in range(1, _PLANNER_SQL_MAX_RETRIES + 1):
        try:
            _materialize_planned_query(query)
            return current
        except ValueError as exc:
            if status_callback:
                status_callback(
                    f"Planner SQL rejected (attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}): {exc}."
                )
            retry_messages = messages_builder(extra_context)
            retry_messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Attempt {attempt}/{_PLANNER_SQL_MAX_RETRIES}: the previous query was rejected. "
                        f"Error: {exc}. "
                        "MUST return corrected JSON with query.sql set to a raw SELECT statement against "
                        "evtx_events / mft_entries / mft_timeline / prefetch_executions / findings. "
                        "Do NOT leave query.sql blank or null when no template_id fits — the investigation aborts otherwise. "
                        "Refer to <SCHEMA_CARDS> for valid column names and <SQL_COOKBOOK> for ready-made patterns. "
                        "Use simple `SELECT cols FROM table WHERE event_id = N` style if unsure."
                    ),
                }
            )
            retried = request_llm_json(
                messages=retry_messages,
                model=model,
                base_url=base_url,
                status_callback=status_callback,
                audit_callback=audit_callback,
            )
            retried["read_more"] = [str(item) for item in coerce_list(current.get("read_more"))]
            retried_query = retried.get("query")
            if isinstance(retried_query, dict):
                for field, value in base_fields.items():
                    if field not in retried_query and value is not None:
                        retried_query[field] = value
                current = retried
                query = retried_query
                continue
            # If retry didn't even return a query dict, give up early.
            return retried
    if status_callback:
        status_callback(f"Planner SQL still invalid after {_PLANNER_SQL_MAX_RETRIES} retries; will fall back.")
    return current


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


def broad_plan_investigation(
    state: SessionState,
    memory: MemoryManager,
    base_url: str,
    model: str,
    max_findings: int = 10,
    observed_keypoints: list[str] | None = None,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> BroadPlanResult:
    """Run the broad plan phase: generate new hypotheses from findings and keypoints.

    Computes uncovered keypoints, calls the LLM once (read_more is ignored;
    the stop field controls termination), and returns parsed hypotheses."""

    overview_md = overview_md if overview_md is not None else memory.load_overview()

    uncovered_keypoints = _compute_uncovered_keypoints(
        observed_keypoints or [],
        state.active_hypotheses,
        state.resolved_hypotheses,
    )

    def messages_builder(extra_context: str) -> list[dict[str, str]]:
        return build_broad_plan_messages(
            overview_md=overview_md,
            extra_context_md=extra_context,
            iteration=state.iteration,
            findings_snapshot=state.findings_snapshot,
            observed_keypoints=observed_keypoints,
            uncovered_keypoints=uncovered_keypoints,
            active_hypotheses=state.active_hypotheses,
            resolved_hypotheses=state.resolved_hypotheses,
            history=[item.model_dump() for item in state.history],
            max_findings=max_findings,
            max_resolved=20,
        )

    # QA3-7: Use direct single call. read_more from the LLM is intentionally ignored;
    # the stop field is used for termination.
    parsed = request_llm_json(
        messages=messages_builder(default_context_md or ""),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    return BroadPlanResult(
        hypotheses=_parse_hypotheses(parsed.get("hypotheses")),
        stop=bool(parsed.get("stop", False)),
        stop_reason=str(parsed.get("stop_reason") or "") or None,
        raw_response=parsed,
    )


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
    finding_candidates: list[dict[str, Any]],
    memory: MemoryManager,
    base_url: str,
    model: str,
    db: CaseDB | None = None,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    query_index: int = 1,
    max_queries: int = 5,
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
            finding_candidates=finding_candidates,
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
