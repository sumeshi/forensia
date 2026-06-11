from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import duckdb

from forensia.ai.sql_schema import _LEGACY_ALLOWED_TABLES

ALLOWED_IDENTIFIER_REFERENCES = _LEGACY_ALLOWED_TABLES | {
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
    "fact_id",
    "fact_type",
    "fact_key",
    "fact_value",
    "source_query",
    "source_section",
    "block_heading",
    "sql_hash",
    "sql_text",
    "result_json",
    "executed_at",
    "run_id",
}
_SQL_FENCE_RE = re.compile(r"```(?:sql)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
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


def _sql_int(value: Any, default: int) -> int:
    """Safely cast value to int, returning default on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sql_text(value: Any, default: str = "") -> str:
    """Safely cast value to str, escaping single quotes for SQL injection safety."""
    text = str(value or default)
    return text.replace("'", "''")


def _template_failed_logon_by_ip_window(params: dict[str, Any]) -> str:
    """Build SQL for failed logons grouped by src_ip within a recent time window."""
    event_id = _sql_int(params.get("event_id"), 4625)
    hours = max(1, _sql_int(params.get("hours"), 24))
    threshold = max(1, _sql_int(params.get("threshold"), 5))
    return f"""
SELECT src_ip, COUNT(*) AS failed_count
FROM evtx_events
WHERE event_id = {event_id}
  AND timestamp >= (SELECT MAX(timestamp) FROM evtx_events) - INTERVAL '{hours} hours'
  AND coalesce(src_ip, '') != ''
GROUP BY src_ip
HAVING COUNT(*) >= {threshold}
ORDER BY failed_count DESC
LIMIT 50
""".strip()


def _template_logon_by_user_window(params: dict[str, Any]) -> str:
    """Build SQL for recent successful logons for one user."""
    event_id = _sql_int(params.get("event_id"), 4624)
    hours = max(1, _sql_int(params.get("hours"), 24))
    user = _sql_text(params.get("user"))
    if not user:
        raise ValueError("q_logon_by_user_window requires user")
    return f"""
SELECT timestamp, computer, src_ip, logon_type, target_user
FROM evtx_events
WHERE event_id = {event_id}
  AND timestamp >= (SELECT MAX(timestamp) FROM evtx_events) - INTERVAL '{hours} hours'
  AND lower(coalesce(target_user, '')) = lower('{user}')
ORDER BY timestamp DESC
LIMIT 100
""".strip()


def _template_powershell_after_logon(params: dict[str, Any]) -> str:
    """Build SQL for process/PowerShell execution within 15 minutes after a user logon."""
    user = _sql_text(params.get("user"))
    hours = max(1, _sql_int(params.get("hours"), 24))
    if not user:
        raise ValueError("q_powershell_after_logon requires user")
    return f"""
WITH logons AS (
    SELECT timestamp, computer, target_user
    FROM evtx_events
    WHERE event_id = 4624
      AND timestamp >= (SELECT MAX(timestamp) FROM evtx_events) - INTERVAL '{hours} hours'
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
    """Build SQL for service install or scheduled task creation on one host within a recent window."""
    computer = _sql_text(params.get("computer"))
    hours = max(1, _sql_int(params.get("hours"), 24))
    if not computer:
        raise ValueError("q_service_or_task_after_host_logon requires computer")
    return f"""
SELECT timestamp, event_id, service_name, process_name, command_line, evidence_id
FROM evtx_events
WHERE event_id IN (4697, 7045, 4698)
  AND timestamp >= (SELECT MAX(timestamp) FROM evtx_events) - INTERVAL '{hours} hours'
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


def coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str) and value:
        return [value]
    return []


def validate_select_sql(sql: str) -> str:
    """Validate and normalize a read-only SQL statement.

    Strips Markdown fences, enforces read-only (SELECT/WITH), checks for
    forbidden keywords, and verifies all referenced table names are known.
    """
    fence_match = _SQL_FENCE_RE.search(sql.strip())
    normalized = fence_match.group(1).strip() if fence_match else sql.strip().rstrip(";").strip()
    normalized = normalized.rstrip(";").strip()
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
    try:
        import sqlglot
        tree = sqlglot.parse_one(normalized)
        for coalesce_node in tree.find_all(sqlglot.exp.Coalesce):
            arg_types = set()
            has_cast = False
            has_column = False
            all_args = []
            if coalesce_node.this is not None:
                all_args.append(coalesce_node.this)
            all_args.extend(coalesce_node.expressions or [])
            for arg in all_args:
                if isinstance(arg, sqlglot.exp.Column):
                    has_column = True
                elif isinstance(arg, sqlglot.exp.Cast):
                    has_cast = True
                elif isinstance(arg, sqlglot.exp.Literal):
                    arg_types.add("string_literal" if arg.is_string else "number_literal")
                else:
                    arg_types.add(type(arg).__name__)
            if len(arg_types) > 1 and not has_column and not has_cast:
                raise ValueError(
                    f"COALESCE has mixed literal types: {arg_types}. "
                    "All COALESCE arguments must be the same type. Use explicit CAST if needed."
                )
    except ImportError:
        pass
    except ValueError:
        # Intentional validation failures (e.g. mixed COALESCE types) must propagate.
        raise
    except Exception:
        # sqlglot internal parse errors are not validation verdicts; ignore them
        # so they never surface as reasoning/rationale text (R2-05).
        pass
    # R2-03: Reject SQL with unresolved placeholder literals
    _PLACEHOLDER_RE = re.compile(r"\[\w*placeholder\w*\]|\[(start|end)_time\]|\{\w+\}")
    if _PLACEHOLDER_RE.search(normalized):
        raise ValueError("SQL contains unresolved placeholder literal; use real values from the hypothesis/case profile, or omit that filter")
    return normalized


def validate_select_sql_with_dryrun(sql: str, db: Any) -> str:
    """Validate a SELECT statement by running EXPLAIN against a live DuckDB connection.

    Catches statically valid SQL that references nonexistent functions or tables.
    `db` is anything with a DuckDB-backed ``.execute`` (raw connection or CaseDB).
    This is a binder-level check only; run `validate_select_sql` first for the
    read-only/allowlist/placeholder guarantees. Returns the normalized SQL on
    success, raises ValueError with the first line of the DuckDB error message
    on failure.
    """
    normalized = sql.strip().rstrip(";").strip()
    if not normalized:
        raise ValueError("SQL is empty")
    try:
        db.execute(f"EXPLAIN {normalized}")
    except duckdb.Error as exc:
        msg = str(exc).split("\n")[0].strip()
        raise ValueError(msg) from exc
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
    """Render a named query template with validated params, returning validated SQL."""
    spec = QUERY_TEMPLATES.get(template_id)
    if spec is None:
        raise ValueError(f"Unknown query template: {template_id}")
    missing = [key for key in spec.required_params if params.get(key) in (None, "")]
    if missing:
        raise ValueError(f"Missing template params for {template_id}: {', '.join(missing)}")
    return validate_select_sql(spec.sql_builder(params))
