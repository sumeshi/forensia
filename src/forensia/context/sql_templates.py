"""Query template catalog and SELECT validation/rendering (sqlglot-based)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from string import Formatter
from typing import Any

import duckdb
import sqlglot
from sqlglot.optimizer.scope import Scope, traverse_scope

from forensia.context.sql_schema import QUERY_TABLES
from forensia.knowledge.catalog import expand_catalog_sql_placeholders
from forensia.knowledge.resources import schema_dir

_SQL_FENCE_RE = re.compile(r"```(?:sql)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)
FORBIDDEN_SQL = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|copy|pragma|truncate|merge|replace)\b",
    re.IGNORECASE,
)

# Host-enforced upper bound on returned rows. Any explicit LIMIT above this is
# rejected so the host always produces a bounded observation (T-20).
MAX_SQL_ROWS = 1000


def _enforce_row_limit(sql: str) -> None:
    """Reject invalid or oversized LIMITs in every SELECT scope."""
    try:
        tree = sqlglot.parse_one(sql, read="duckdb")
    except sqlglot.errors.ParseError as exc:
        raise ValueError("SQL could not be parsed") from exc
    for limit_node in tree.find_all(sqlglot.exp.Limit):
        value = limit_node.expression
        if not isinstance(value, sqlglot.exp.Literal) or value.is_string:
            continue  # The DuckDB binder reports non-literal LIMIT expressions.
        limit = int(value.this)
        if limit <= 0:
            raise ValueError("SQL LIMIT must be a positive integer")
        if limit > MAX_SQL_ROWS:
            raise ValueError(
                f"SQL LIMIT {limit} exceeds the host maximum of {MAX_SQL_ROWS} rows"
            )


def bounded_select_sql(sql: str, *, max_rows: int = MAX_SQL_ROWS) -> str:
    """Bound the final result, including CTE and UNION output."""
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    normalized = sql.rstrip().rstrip(";")
    tree = sqlglot.parse_one(normalized, read="duckdb")
    limit = tree.args.get("limit")
    if limit is not None and not limit.args.get("limit_options"):
        value = limit.expression
        if isinstance(value, sqlglot.exp.Literal) and not value.is_string:
            try:
                if int(value.this) <= max_rows:
                    return normalized
            except ValueError:
                pass
    return f"SELECT * FROM ({normalized}) AS _forensia_bounded LIMIT {max_rows + 1}"


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
        sql = expand_catalog_sql_placeholders(str(raw.get("sql") or "").strip())
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


def query_referenced_tables(sql: str) -> set[str]:
    """Return physical tables only, excluding CTE aliases and subquery scopes."""
    try:
        tree = sqlglot.parse_one(sql, read="duckdb")
    except sqlglot.errors.ParseError as exc:
        raise ValueError("SQL could not be parsed") from exc
    tables: set[str] = set()
    for scope in traverse_scope(tree):
        for _, (node, source) in scope.selected_sources.items():
            if isinstance(source, Scope):
                continue
            if not isinstance(source, sqlglot.exp.Table):
                raise ValueError("Unsupported table reference")
            table = node if isinstance(node, sqlglot.exp.Table) else source
            tables.add(table.name.casefold())
    return tables


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

    try:
        tree = sqlglot.parse_one(normalized)
    except sqlglot.errors.ParseError as exc:
        raise ValueError("SQL could not be parsed") from exc
    unknown_tables: set[str] = set()
    allowed_tables = {name.casefold() for name in QUERY_TABLES}
    for scope in traverse_scope(tree):
        for _, (node, source) in scope.selected_sources.items():
            if isinstance(source, Scope):
                continue
            if not isinstance(source, sqlglot.exp.Table):
                raise ValueError("Unsupported table reference")
            table = node if isinstance(node, sqlglot.exp.Table) else source
            if table.catalog or table.db:
                raise ValueError("Schema-qualified table references are not allowed")
            if not isinstance(table.this, sqlglot.exp.Identifier):
                raise ValueError("Table functions are not allowed")
            name = table.name.casefold()
            if name not in allowed_tables:
                unknown_tables.add(name)
    if unknown_tables:
        raise ValueError(
            f"Unknown table(s) referenced: {', '.join(sorted(unknown_tables))}"
        )
    try:
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
            "parameters": spec.parameters,
            "tables": sorted(_query_template_tables()[spec.template_id]),
        }
        for spec in _load_query_templates().values()
    ]


@lru_cache(maxsize=1)
def _query_template_tables() -> dict[str, frozenset[str]]:
    """Map each declared template to the allowed tables its SQL references.

    Host validation already restricts rendered SQL to the allowed tables; this
    mapping only makes the same allow-list readable for prompt disclosure.
    A table name is counted only on a word boundary (``FROM``/``JOIN`` style
    references, never a column-name substring).
    """
    mapping: dict[str, frozenset[str]] = {}
    for template_id, spec in _load_query_templates().items():
        lowered = spec.sql.lower()
        referenced = frozenset(
            table
            for table in QUERY_TABLES
            if re.search(rf"(?<![a-z0-9]){re.escape(table)}(?![a-z0-9])", lowered)
        )
        mapping[template_id] = referenced
    return mapping


def query_template_catalog_for_tables(
    tables: tuple[str, ...] | None,
) -> list[dict[str, Any]]:
    """Bounded executable-template disclosure for one work's artifact tables (V2-08).

    Same projection entries as :func:`query_template_catalog`, narrowed to the
    templates whose referenced tables are all inside *tables* — the
    spec/coverage ↔ recipe correspondence from ``coverage.disclosure_tables_for_spec``.
    ``None`` (no spec-derived tables, e.g. before admission) discloses nothing
    beyond the cookbook index; an empty tuple means "no matching artifact
    family" and likewise discloses nothing (explicitly, not by widening).
    Deterministic: catalog declaration order, no ranking.
    """
    if tables is None:
        return []
    wanted = {str(table) for table in tables}
    if not wanted:
        return []
    return [
        entry
        for entry in query_template_catalog()
        if _query_template_tables().get(entry["template_id"], frozenset())
        and _query_template_tables()[entry["template_id"]] <= frozenset(wanted)
    ]


def render_query_template(template_id: str, params: dict[str, Any]) -> str:
    """Render a named query template with validated params, returning validated SQL."""
    spec = _load_query_templates().get(template_id)
    if spec is None:
        raise ValueError(f"Unknown query template: {template_id}")
    return validate_select_sql(spec.sql.format(**_render_template_params(spec, params)))
