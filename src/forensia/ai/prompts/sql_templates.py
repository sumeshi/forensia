"""Query template catalog and SELECT validation/rendering (sqlglot-based)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from string import Formatter
from typing import Any

import duckdb

from forensia.ai.prompts.sql_schema import _LEGACY_ALLOWED_TABLES
from forensia.knowledge.resources import schema_dir

ALLOWED_IDENTIFIER_REFERENCES = _LEGACY_ALLOWED_TABLES | {
    "evidence_id",
    "artifact_id",
    "dataset_id",
    "source_ids",
    "plugin",
    "hive",
    "key_path",
    "value_name",
    "timestamp_kind",
    "raw_timestamp",
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
TABLE_NAME_PATTERN = re.compile(
    r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE
)
CTE_NAME_PATTERN = re.compile(
    r"(?:with|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s*\(", re.IGNORECASE
)
LIMIT_PATTERN = re.compile(r"\blimit\s+(\d+)", re.IGNORECASE)

# Host-enforced upper bound on returned rows. Any explicit LIMIT above this is
# rejected so the host always produces a bounded observation (T-20).
MAX_SQL_ROWS = 1000


def _enforce_row_limit(sql: str) -> None:
    """Reject SQL whose explicit LIMIT exceeds the host-bound maximum."""

    match = LIMIT_PATTERN.search(sql)
    if not match:
        return
    limit = int(match.group(1))
    if limit <= 0:
        raise ValueError("SQL LIMIT must be a positive integer")
    if limit > MAX_SQL_ROWS:
        raise ValueError(
            f"SQL LIMIT {limit} exceeds the host maximum of {MAX_SQL_ROWS} rows"
        )


@dataclass(frozen=True, slots=True)
class QueryTemplateSpec:
    template_id: str
    description: str
    required_params: tuple[str, ...]
    parameters: dict[str, dict[str, Any]]
    sql: str


def _sql_int(value: Any, default: int) -> int:
    """Safely cast value to int, returning default on failure."""
    try:
        return int(value)
    except TypeError, ValueError:
        return default


def _sql_text(value: Any, default: str = "") -> str:
    """Safely cast value to str, escaping single quotes for SQL injection safety."""
    text = str(value or default)
    return text.replace("'", "''")


def _query_template_path() -> Path:
    return schema_dir() / "query_templates.yaml"


@lru_cache(maxsize=1)
def _load_query_templates() -> dict[str, QueryTemplateSpec]:
    """Load and validate declarative investigation query templates."""
    import yaml

    path = _query_template_path()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_templates = data.get("templates") if isinstance(data, dict) else None
    if data.get("version") != 1 or not isinstance(raw_templates, dict):
        raise ValueError(f"{path}: expected version 1 and a templates mapping")
    loaded: dict[str, QueryTemplateSpec] = {}
    for template_id, raw in raw_templates.items():
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: {template_id} must be a mapping")
        description = str(raw.get("description") or "").strip()
        sql = str(raw.get("sql") or "").strip()
        parameters = raw.get("parameters") or {}
        if not description or not sql or not isinstance(parameters, dict):
            raise ValueError(f"{path}: {template_id} has invalid metadata")
        placeholders = {
            name for _, name, _, _ in Formatter().parse(sql) if name is not None
        }
        if placeholders != set(parameters):
            raise ValueError(
                f"{path}: {template_id} placeholders must match parameters"
            )
        required = tuple(
            str(name)
            for name, declaration in parameters.items()
            if isinstance(declaration, dict) and declaration.get("required") is True
        )
        loaded[str(template_id)] = QueryTemplateSpec(
            template_id=str(template_id),
            description=description,
            required_params=required,
            parameters={str(name): dict(value) for name, value in parameters.items()},
            sql=sql,
        )
    return loaded


def _render_template_params(
    spec: QueryTemplateSpec, params: dict[str, Any]
) -> dict[str, int | str]:
    """Normalize declared parameters for safe SQL interpolation."""
    rendered: dict[str, int | str] = {}
    for name, declaration in spec.parameters.items():
        if declaration.get("required") is True and params.get(name) in (None, ""):
            raise ValueError(f"Missing template params for {spec.template_id}: {name}")
        raw = params.get(name, declaration.get("default"))
        if declaration.get("type") == "integer":
            value = _sql_int(raw, _sql_int(declaration.get("default"), 0))
            rendered[name] = max(_sql_int(declaration.get("minimum"), value), value)
        elif declaration.get("type") == "text":
            rendered[name] = _sql_text(raw, str(declaration.get("default") or ""))
        else:
            raise ValueError(f"{spec.template_id}.{name} has unsupported type")
    return rendered


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

    Host validation contract (T-20): strips Markdown fences, enforces read-only
    (SELECT/WITH), checks for forbidden keywords, enforces the host row-limit,
    and verifies all referenced table names are in the allow-list. Column and
    function validity is confirmed by the dry-run binder check in
    ``validate_select_sql_with_dryrun``.
    """
    fence_match = _SQL_FENCE_RE.search(sql.strip())
    normalized = (
        fence_match.group(1).strip() if fence_match else sql.strip().rstrip(";").strip()
    )
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
    _enforce_row_limit(normalized)

    cte_names = {match.group(1) for match in CTE_NAME_PATTERN.finditer(normalized)}
    table_names = {match.group(1) for match in TABLE_NAME_PATTERN.finditer(normalized)}
    unknown_tables = sorted(
        name
        for name in table_names
        if name not in ALLOWED_IDENTIFIER_REFERENCES and name not in cte_names
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
                    arg_types.add(
                        "string_literal" if arg.is_string else "number_literal"
                    )
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
        raise ValueError(
            "SQL contains unresolved placeholder literal; use real values from the hypothesis/case profile, or omit that filter"
        )
    return normalized


def validate_select_sql_with_dryrun(sql: str, db: Any) -> str:
    """Validate a SELECT statement by running EXPLAIN against a live DuckDB connection.

    Catches statically valid SQL that references nonexistent functions, columns,
    or tables (the host's deterministic column validation). `db` is anything with
    a DuckDB-backed ``.execute`` (raw connection or CaseDB). This is a binder-level
    check only; run `validate_select_sql` first for the read-only/allowlist/
    placeholder/row-limit guarantees. Returns the normalized SQL on success,
    raises ValueError with the first line of the DuckDB error message on failure.
    """
    normalized = sql.strip().rstrip(";").strip()
    if not normalized:
        raise ValueError("SQL is empty")
    _enforce_row_limit(normalized)
    try:
        db.execute(f"EXPLAIN {normalized}")
    except duckdb.Error as exc:
        msg = str(exc).split("\n")[0].strip()
        raise ValueError(msg) from exc
    return normalized


def query_template_catalog() -> list[dict[str, Any]]:
    """Return the bounded recipe menu (3-7 templates) the model may choose from.

    Each entry exposes only the template_id, a human description, and its
    required params so the single SQL decision can select a recipe plus typed
    params without writing SQL by hand.
    """
    return [
        {
            "template_id": spec.template_id,
            "description": spec.description,
            "required_params": list(spec.required_params),
        }
        for spec in _load_query_templates().values()
    ]


def render_query_template(template_id: str, params: dict[str, Any]) -> str:
    """Render a named query template with validated params, returning validated SQL."""
    spec = _load_query_templates().get(template_id)
    if spec is None:
        raise ValueError(f"Unknown query template: {template_id}")
    return validate_select_sql(spec.sql.format(**_render_template_params(spec, params)))
