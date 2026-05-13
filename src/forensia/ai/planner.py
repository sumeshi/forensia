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
    "hypotheses",
    "report_sections",
    "claims",
    "ai_reviews",
    "investigation_sessions",
    "investigation_steps",
    "hypothesis_reasoning",
    "progress_events",
    "ingested_files",
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
    "hypothesis_id",
    "origin",
    "created_session",
    "resolved_session",
    "section_key",
    "body",
    "update_count",
    "gaps",
    "last_filled_session",
    "last_filled_at",
    "claim_id",
    "claim_text",
    "finding_ids",
    "hypothesis_ids",
    "evidence_ids",
    "support_status",
    "entry_id",
    "query_id",
    "path",
    "source_kind",
    "size",
    "ingested_at",
    "event_index",
    "current_query",
    "payload",
}
FORBIDDEN_SQL = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|copy|pragma|truncate|merge|replace)\b",
    re.IGNORECASE,
)
TABLE_NAME_PATTERN = re.compile(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)
CTE_NAME_PATTERN = re.compile(r"(?:with|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class QueryTemplateSpec:
    template_id: str
    description: str
    required_params: tuple[str, ...]
    sql_builder: Callable[[dict[str, Any]], str]


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


def _sql_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sql_text(value: Any, default: str = "") -> str:
    text = str(value or default)
    return text.replace("'", "''")


def _template_failed_logon_by_ip_window(params: dict[str, Any]) -> str:
    event_id = _sql_int(params.get("event_id"), 4625)
    hours = max(1, _sql_int(params.get("hours"), 24))
    threshold = max(1, _sql_int(params.get("threshold"), 5))
    return f"""
SELECT src_ip, COUNT(*) AS failed_count
FROM evtx_events
WHERE event_id = {event_id}
  AND timestamp >= now() - INTERVAL '{hours} hours'
  AND coalesce(src_ip, '') != ''
GROUP BY src_ip
HAVING COUNT(*) >= {threshold}
ORDER BY failed_count DESC
LIMIT 50
""".strip()


def _template_logon_by_user_window(params: dict[str, Any]) -> str:
    event_id = _sql_int(params.get("event_id"), 4624)
    hours = max(1, _sql_int(params.get("hours"), 24))
    user = _sql_text(params.get("user"))
    if not user:
        raise ValueError("q_logon_by_user_window requires user")
    return f"""
SELECT timestamp, computer, src_ip, logon_type, target_user
FROM evtx_events
WHERE event_id = {event_id}
  AND timestamp >= now() - INTERVAL '{hours} hours'
  AND lower(coalesce(target_user, '')) = lower('{user}')
ORDER BY timestamp DESC
LIMIT 100
""".strip()


def _template_powershell_after_logon(params: dict[str, Any]) -> str:
    user = _sql_text(params.get("user"))
    hours = max(1, _sql_int(params.get("hours"), 24))
    if not user:
        raise ValueError("q_powershell_after_logon requires user")
    return f"""
WITH logons AS (
    SELECT timestamp, computer, target_user
    FROM evtx_events
    WHERE event_id = 4624
      AND timestamp >= now() - INTERVAL '{hours} hours'
      AND lower(coalesce(target_user, '')) = lower('{user}')
),
ps AS (
    SELECT timestamp, computer, process_name, command_line, evidence_id
    FROM evtx_events
    WHERE event_id IN (4688, 4104)
)
SELECT ps.timestamp, ps.computer, ps.process_name, ps.command_line, ps.evidence_id
FROM ps
JOIN logons
  ON ps.computer = logons.computer
 AND ps.timestamp BETWEEN logons.timestamp AND logons.timestamp + INTERVAL '15 minutes'
ORDER BY ps.timestamp DESC
LIMIT 100
""".strip()


def _template_service_or_task_after_host_logon(params: dict[str, Any]) -> str:
    computer = _sql_text(params.get("computer"))
    hours = max(1, _sql_int(params.get("hours"), 24))
    if not computer:
        raise ValueError("q_service_or_task_after_host_logon requires computer")
    return f"""
SELECT timestamp, event_id, service_name, process_name, command_line, evidence_id
FROM evtx_events
WHERE event_id IN (4697, 7045, 4698)
  AND timestamp >= now() - INTERVAL '{hours} hours'
  AND lower(coalesce(computer, '')) = lower('{computer}')
ORDER BY timestamp DESC
LIMIT 100
""".strip()


QUERY_TEMPLATES: dict[str, QueryTemplateSpec] = {
    "q_failed_logon_by_ip_window": QueryTemplateSpec(
        template_id="q_failed_logon_by_ip_window",
        description="Failed logons grouped by src_ip within a recent time window.",
        required_params=("hours", "threshold"),
        sql_builder=_template_failed_logon_by_ip_window,
    ),
    "q_logon_by_user_window": QueryTemplateSpec(
        template_id="q_logon_by_user_window",
        description="Recent successful logons for one user.",
        required_params=("user", "hours"),
        sql_builder=_template_logon_by_user_window,
    ),
    "q_powershell_after_logon": QueryTemplateSpec(
        template_id="q_powershell_after_logon",
        description="Process or PowerShell execution within 15 minutes after a user's logon.",
        required_params=("user", "hours"),
        sql_builder=_template_powershell_after_logon,
    ),
    "q_service_or_task_after_host_logon": QueryTemplateSpec(
        template_id="q_service_or_task_after_host_logon",
        description="Service install or scheduled task creation on one host.",
        required_params=("computer", "hours"),
        sql_builder=_template_service_or_task_after_host_logon,
    ),
}


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


def query_template_catalog() -> list[dict[str, Any]]:
    return [
        {
            "template_id": spec.template_id,
            "description": spec.description,
            "required_params": list(spec.required_params),
        }
        for spec in QUERY_TEMPLATES.values()
    ]


def render_query_template(template_id: str, params: dict[str, Any]) -> str:
    spec = QUERY_TEMPLATES.get(template_id)
    if spec is None:
        raise ValueError(f"Unknown query template: {template_id}")
    missing = [key for key in spec.required_params if params.get(key) in (None, "")]
    if missing:
        raise ValueError(f"Missing template params for {template_id}: {', '.join(missing)}")
    return validate_select_sql(spec.sql_builder(params))


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
        retried["read_more"] = [str(item) for item in _coerce_list(parsed.get("read_more"))]
        return retried


def _request_with_optional_context(
    memory: MemoryManager,
    messages_builder: Callable[[str], list[dict[str, str]]],
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    parsed = request_llm_json(
        messages=messages_builder(""),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
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
    status_callback: Callable[[str], None] | None = None,
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
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
        audit_callback=audit_callback,
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
    audit_callback: Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None = None,
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
            query_templates=query_template_catalog(),
        )

    parsed = _request_with_optional_context(
        memory=memory,
        messages_builder=messages_builder,
        base_url=base_url,
        model=model,
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
        except Exception:
            parsed_hypothesis = None

    planned_query = None
    if isinstance(parsed.get("query"), dict):
        try:
            planned_query = _materialize_planned_query(parsed["query"])
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
