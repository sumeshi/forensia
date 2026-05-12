from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.json_response import request_llm_json
from forensia.ai.prompts import build_broad_plan_messages, build_hypothesis_plan_messages
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState

ALLOWED_TABLES = {
    "evtx_events",
    "mft_entries",
    "mft_timeline",
    "findings",
    "ai_reviews",
    "investigation_sessions",
    "investigation_steps",
}
ALLOWED_IDENTIFIER_REFERENCES = ALLOWED_TABLES | {
    "evidence_id",
    "source_file",
    "channel",
    "event_id",
    "record_id",
    "timestamp",
    "computer",
    "user_name",
    "target_user",
    "subject_user",
    "src_ip",
    "logon_type",
    "process_name",
    "command_line",
    "service_name",
    "message",
    "raw_json",
    "tags",
    "severity",
    "record_number",
    "file_path",
    "file_name",
    "extension",
    "is_directory",
    "is_deleted",
    "size",
    "si_created",
    "si_modified",
    "si_accessed",
    "si_mft_modified",
    "fn_created",
    "fn_modified",
    "fn_accessed",
    "fn_mft_modified",
    "timeline_id",
    "timestamp_type",
    "description",
    "finding_id",
    "rule_id",
    "title",
    "summary",
    "confidence",
    "status",
    "attack",
    "evidence",
    "ai_summary",
    "missing_checks",
    "created_at",
    "review_id",
    "verdict",
    "report_text",
    "confidence_adjustment",
    "notes",
    "session_id",
    "started_at",
    "finished_at",
    "iterations",
    "step_id",
    "iteration",
    "phase",
    "input_json",
    "output_json",
}
FORBIDDEN_SQL = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|copy|pragma|truncate|merge|replace)\b",
    re.IGNORECASE,
)
TABLE_NAME_PATTERN = re.compile(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)
CTE_NAME_PATTERN = re.compile(r"(?:with|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(", re.IGNORECASE)


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


def _coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _parse_hypotheses(items: Any) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []
    for item in _coerce_list(items):
        if not isinstance(item, dict):
            continue
        try:
            hypotheses.append(Hypothesis.model_validate(item))
        except Exception:
            continue
    return hypotheses


def validate_select_sql(sql: str) -> str:
    normalized = sql.strip().rstrip(";").strip()
    lowered = normalized.lower()
    if not normalized:
        raise ValueError("SQL is empty")
    if ";" in normalized:
        raise ValueError("Multiple SQL statements are not allowed")
    if not (lowered.startswith("select") or lowered.startswith("with")):
        raise ValueError("Only SELECT queries are allowed")
    if FORBIDDEN_SQL.search(normalized):
        raise ValueError("Forbidden SQL keyword detected")

    cte_names = {match.group(1) for match in CTE_NAME_PATTERN.finditer(normalized)}
    table_names = {match.group(1) for match in TABLE_NAME_PATTERN.finditer(normalized)}
    unknown_tables = sorted(
        name for name in table_names if name not in ALLOWED_IDENTIFIER_REFERENCES and name not in cte_names
    )
    if unknown_tables:
        raise ValueError(f"Unknown table(s) referenced: {', '.join(unknown_tables)}")
    return normalized


def _retry_query_once(
    parsed: dict[str, Any],
    messages_builder: Callable[[str], list[dict[str, str]]],
    extra_context: str,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    query = parsed.get("query")
    if not isinstance(query, dict):
        return parsed
    sql = query.get("sql")
    if not isinstance(sql, str):
        return parsed
    try:
        validate_select_sql(sql)
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
        )
        retried["read_more"] = [str(item) for item in _coerce_list(parsed.get("read_more"))]
        return retried


def _request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    parsed = request_llm_json(
        messages=messages_builder(""),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
    )
    read_more = [str(item) for item in _coerce_list(parsed.get("read_more"))]
    if not read_more:
        return parsed
    extra_context = memory.load_context(read_more)
    reparsed = request_llm_json(
        messages=messages_builder(extra_context),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
    )
    reparsed["read_more"] = read_more
    return reparsed


def broad_plan_investigation(
    state: SessionState,
    memory: MemoryManager,
    base_url: str,
    model: str,
    max_findings: int = 10,
    status_callback: Callable[[str], None] | None = None,
) -> BroadPlanResult:
    overview_md = memory.load_overview()

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
        )

    parsed = _request_with_optional_context(
        memory=memory,
        messages_builder=messages_builder,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
    )
    return BroadPlanResult(
        read_more=[str(item) for item in _coerce_list(parsed.get("read_more"))],
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
    status_callback: Callable[[str], None] | None = None,
) -> HypothesisPlanResult:
    overview_md = memory.load_overview()
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
        )

    parsed = _request_with_optional_context(
        memory=memory,
        messages_builder=messages_builder,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
    )
    parsed = _retry_query_once(
        parsed=parsed,
        messages_builder=messages_builder,
        extra_context=extra_context_holder["value"],
        base_url=base_url,
        model=model,
        status_callback=status_callback,
    )

    parsed_hypothesis = None
    if isinstance(parsed.get("hypothesis"), dict):
        try:
            parsed_hypothesis = Hypothesis.model_validate(parsed["hypothesis"])
        except Exception:
            parsed_hypothesis = None

    planned_query = None
    if isinstance(parsed.get("query"), dict):
        try:
            planned_query = PlannedQuery.model_validate(parsed["query"])
            planned_query.sql = validate_select_sql(planned_query.sql)
        except Exception:
            planned_query = None

    return HypothesisPlanResult(
        read_more=[str(item) for item in _coerce_list(parsed.get("read_more"))],
        hypothesis=parsed_hypothesis,
        query=planned_query,
        needs_more=bool(parsed.get("needs_more", True)),
        stop_reason=str(parsed.get("stop_reason") or "") or None,
        raw_response=parsed,
    )
