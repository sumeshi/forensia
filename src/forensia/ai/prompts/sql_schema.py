"""Live DB schema guidance for SQL prompts: allowed tables, per-table schema cards."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

import duckdb
import yaml

from forensia.db.schema import CORE_SCHEMA_SQL
from forensia.knowledge.resources import schema_dir

if TYPE_CHECKING:
    from forensia.db.database import CaseDB

QUERY_TABLES = {
    "evtx_events",
    "mft_entries",
    "mft_timeline",
    "prefetch_executions",
    "prefetch_timeline",
    "registry_artifacts",
    "registry_timeline",
    "findings",
    "hypotheses",
    "report_sections",
    "claims",
}


def get_allowed_tables(db: CaseDB | None = None) -> set[str]:
    if db is None:
        return set(QUERY_TABLES)
    return {
        table
        for table in load_live_schema(db)
        if table.startswith(
            (
                "evtx_",
                "mft_",
                "prefetch_",
                "registry_",
                "findings",
                "hypotheses",
                "report_",
                "claims",
                "section_",
            )
        )
    }


@lru_cache(maxsize=1)
def _declared_schema() -> dict[str, tuple[str, ...]]:
    """Derive no-case prompt guidance from the current schema, never a second column list."""
    with duckdb.connect() as conn:
        conn.execute(CORE_SCHEMA_SQL)
        return load_live_schema(conn)


def load_live_schema(db: CaseDB) -> dict[str, tuple[str, ...]]:
    rows = db.execute("""
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'main'
        ORDER BY table_name, ordinal_position
    """).fetchall()
    result: dict[str, list[str]] = {}
    for tbl, col in rows:
        result.setdefault(str(tbl), []).append(str(col))
    return {k: tuple(v) for k, v in result.items()}


def schema_column_guidance(db: CaseDB | None = None) -> str:
    schema = load_live_schema(db) if db is not None else _declared_schema()
    allowed = get_allowed_tables(db)
    return "tables:\n" + "\n".join(
        f"  {table} columns: {', '.join(schema[table])}" for table in sorted(allowed)
    )


# PROMPT-4: Load domain knowledge from YAML schema files
@lru_cache(maxsize=1)
def load_logon_type_schema() -> dict:
    """Load logon type definitions from schema file."""
    schema_root = schema_dir()
    path = schema_root / "logon_types.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


@lru_cache(maxsize=1)
def load_app_catalog() -> dict:
    """Load application catalog from schema file."""
    schema_root = schema_dir()
    path = schema_root / "app_catalog.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


@lru_cache(maxsize=8)
def _load_table_notes(table_name: str) -> dict:
    """Load notes dict from _schema/{table_name}.yaml."""
    schema_root = schema_dir()
    path = schema_root / f"{table_name}.yaml"
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data.get("notes", {})
    return {}


def _fmt_table_notes(table_name: str) -> str:
    """Format table notes from YAML schema into a guidance paragraph for LLM prompts."""
    notes = _load_table_notes(table_name)
    if not notes:
        return ""
    lines = [f"{table_name} table guidance:"]
    for note in notes.values():
        lines.append(f"  {note}")
    return "\n".join(lines)


def build_investigation_framework(
    db: CaseDB | None = None,
    *,
    event_ids: set[int] | None = None,
    include_event_guidance: bool = True,
) -> str:
    """Build investigation framework from schema declarations.

    PROMPT-4: Framework is built from YAML schema, not Python literals.
    """
    logon_schema = load_logon_type_schema()
    app_catalog = load_app_catalog()

    # Logon type reference. Neutral section-plan blocks opt out so they do not
    # receive the case-wide event catalog while choosing a writing action.
    logontype_lines = []
    if include_event_guidance:
        for lt in sorted(
            logon_schema.get("types", {}).items(), key=lambda x: int(x[0])
        ):
            lt_id, lt_def = lt
            logontype_lines.append(
                f"  {lt_id}  = {lt_def.get('name', '?')} ({lt_def.get('description', '')})"
            )

    # Priority events
    priority_lines = [
        "Priority SQL guidance — investigate in this order when no prior history exists:"
    ]
    priority_entries = logon_schema.get("priority_events", [])
    if event_ids is not None:
        priority_entries = [
            pe
            for pe in priority_entries
            if isinstance(pe, dict)
            and any(
                int(eid) in event_ids
                for eid in pe.get("event_ids", [])
                if str(eid).isdigit()
            )
        ]
    for i, pe in enumerate(priority_entries if include_event_guidance else [], 1):
        eids = pe.get("event_ids", [])
        lts = pe.get("logon_types", [])
        suffix = f" with logon_type IN ({lts})" if lts else ""
        priority_lines.append(
            f"  {i}. event_id IN ({', '.join(str(e) for e in eids)}){suffix} — {pe.get('reason', '')}"
        )

    # App categorizations
    app_lines = ["Application categorization guidance:"]
    for exe, cat in app_catalog.get("mappings", {}).items():
        app_lines.append(f"  {exe}={cat.get('category', '?')}.")

    table_section = schema_column_guidance(db) + "\n"

    return (
        "Investigation framework — apply every iteration:\n"
        "  Who:  which user/account is involved (target_user, subject_user)\n"
        "  When: exact time; is it outside business hours? is it repeated in rapid succession?\n"
        "  From: source IP (src_ip) — internal IP, external IP, or known RDP gateway?\n"
        "  To:   destination host (computer)\n"
        "  What: event_id, process_name, command_line, service_name\n"
        "  How:  logon method (interpret logon_type carefully)\n\n"
        + (
            "LogonType reference:\n"
            + "\n".join(logontype_lines)
            + "\n\n"
            + "\n".join(priority_lines)
            + "\n\n"
            if include_event_guidance
            else ""
        )
        + _fmt_table_notes("evtx_events")
        + "\n"
        + "\n".join(app_lines)
        + "\n\n"
        + _fmt_table_notes("prefetch_executions")
        + "\n"
        + _fmt_table_notes("registry_artifacts")
        + "\n"
        + _fmt_table_notes("registry_timeline")
        + "\n"
        "Section-agent state tables:\n"
        "  section_facts stores reusable evidence-backed facts extracted during prior report-generation runs.\n"
        "  section_evidence links report sections/blocks to evidence_id values already judged relevant.\n"
        "  query_cache stores prior read-only query results by SQL hash.\n"
        "  section_runs stores the plan/query/check/write history for each report block.\n"
        "  section_questions stores the semantic QuestionSpec resolved for each report block.\n"
        "  Prefer reusing section_facts before issuing new SQL when the fact already answers the block question.\n\n"
        + table_section
        + "Only propose SELECT or WITH-prefixed read-only SQL compatible with DuckDB.\n"
    )
