from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import build_broad_plan_messages, build_hypothesis_plan_messages
from forensia.ai.sql_templates import (
    coerce_list,
    query_template_catalog,
    render_query_template,
    validate_select_sql,
)
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class BroadPlanResult:
    read_more: list[str]
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
    hypotheses: list[Hypothesis] = []
    for item in coerce_list(items):
        if not isinstance(item, dict):
            continue
        try:
            hypotheses.append(Hypothesis.model_validate(item))
        except Exception as exc:
            logger.debug("hypothesis parse failed: %s", exc)
            continue
    return hypotheses


def _materialize_planned_query(payload: dict[str, Any]) -> PlannedQuery:
    planned_query = PlannedQuery.model_validate(payload)
    if planned_query.template_id:
        planned_query.sql = render_query_template(planned_query.template_id, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    return planned_query


def _retry_query_once(
    parsed: dict[str, Any],
    messages_builder: Callable[[str], list[dict[str, str]]],
    extra_context: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    query = parsed.get("query")
    if not isinstance(query, dict):
        return parsed
    try:
        _materialize_planned_query(query)
        return parsed
    except ValueError as exc:
        if status_callback:
            status_callback(f"Planner SQL rejected: {exc}. Requesting one retry.")
        retry_messages = messages_builder(extra_context)
        retry_messages.append(
            {
                "role": "user",
                "content": (
                    "The previous SQL was rejected by validate_select_sql(). "
                    f"Error: {exc}. Return corrected JSON. "
                    "If you cannot produce a valid SELECT query, set query to null."
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
        retried["read_more"] = [str(item) for item in coerce_list(parsed.get("read_more"))]
        return retried


def _request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    initial_context: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    default_context = initial_context
    if default_context is None:
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


def broad_plan_investigation(
    state: SessionState,
    memory: MemoryManager,
    base_url: str,
    model: str,
    max_findings: int = 10,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> BroadPlanResult:
    overview_md = overview_md if overview_md is not None else memory.load_overview()

    def messages_builder(extra_context: str) -> list[dict[str, str]]:
        return build_broad_plan_messages(
            overview_md=overview_md,
            extra_context_md=extra_context,
            iteration=state.iteration,
            findings_snapshot=state.findings_snapshot,
            active_hypotheses=state.active_hypotheses,
            resolved_hypotheses=state.resolved_hypotheses,
            history=[item.model_dump() for item in state.history],
            max_findings=max_findings,
            max_resolved=20,
        )

    parsed = _request_with_optional_context(
        memory=memory,
        messages_builder=messages_builder,
        base_url=base_url,
        model=model,
        initial_context=default_context_md,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    return BroadPlanResult(
        read_more=[str(item) for item in coerce_list(parsed.get("read_more"))],
        hypotheses=_parse_hypotheses(parsed.get("hypotheses")),
        stop=bool(parsed.get("stop", False)),
        stop_reason=str(parsed.get("stop_reason") or "") or None,
        raw_response=parsed,
    )


def plan_hypothesis_query(
    state: SessionState,
    hypothesis: Hypothesis,
    finding_candidates: list[dict[str, Any]],
    memory: MemoryManager,
    base_url: str,
    model: str,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> HypothesisPlanResult:
    overview_md = overview_md if overview_md is not None else memory.load_overview()
    extra_context_holder = {"value": ""}
    hypothesis_history = [
        item.model_dump()
        for item in state.history
        if item.hypothesis_id == hypothesis.id
    ]

    def messages_builder(extra_context: str) -> list[dict[str, str]]:
        extra_context_holder["value"] = extra_context
        return build_hypothesis_plan_messages(
            overview_md=overview_md,
            extra_context_md=extra_context,
            iteration=state.iteration,
            hypothesis=hypothesis,
            finding_candidates=finding_candidates,
            hypothesis_history=hypothesis_history,
            query_templates=query_template_catalog(),
        )

    parsed = _request_with_optional_context(
        memory=memory,
        messages_builder=messages_builder,
        base_url=base_url,
        model=model,
        initial_context=default_context_md,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    parsed = _retry_query_once(
        parsed=parsed,
        messages_builder=messages_builder,
        extra_context=extra_context_holder["value"],
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )

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

    return HypothesisPlanResult(
        read_more=[str(item) for item in coerce_list(parsed.get("read_more"))],
        hypothesis=parsed_hypothesis,
        query=planned_query,
        needs_more=bool(parsed.get("needs_more", True)),
        stop_reason=str(parsed.get("stop_reason") or "") or None,
        raw_response=parsed,
    )
