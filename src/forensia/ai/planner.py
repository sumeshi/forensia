from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.hypothesis_manager import _recent_reasoning_rows
from forensia.ai.prompts import build_broad_plan_messages, build_hypothesis_plan_messages
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
        retried_query = retried.get("query")
        if isinstance(retried_query, dict):
            for field in ("query_id", "hypothesis_id", "purpose"):
                if field not in retried_query and field in query:
                    retried_query[field] = query[field]
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
    overview_md = overview_md if overview_md is not None else memory.load_overview()

    def messages_builder(extra_context: str) -> list[dict[str, str]]:
        return build_broad_plan_messages(
            overview_md=overview_md,
            extra_context_md=extra_context,
            iteration=state.iteration,
            findings_snapshot=state.findings_snapshot,
            observed_keypoints=observed_keypoints,
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
    db: CaseDB | None = None,
    overview_md: str | None = None,
    default_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
    query_index: int = 1,
    max_queries: int = 5,
) -> HypothesisPlanResult:
    overview_md = overview_md if overview_md is not None else memory.load_overview()
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
    extra_context_holder = {"value": ""}
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
        for row in _recent_reasoning_rows(db, hypothesis.id, limit=10):
            query_id = str(row.get("query_id") or "").strip()
            if query_id and query_id in seen_query_ids:
                continue
            hypothesis_history.append(row)
            if query_id:
                seen_query_ids.add(query_id)

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
            query_index=query_index,
            max_queries=max_queries,
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
