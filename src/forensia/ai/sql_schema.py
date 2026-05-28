from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

ALLOWED_TABLES = {
    "evtx_events",
    "mft_entries",
    "mft_timeline",
    "prefetch_executions",
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
    "section_facts",
    "section_evidence",
    "query_cache",
    "section_runs",
    "section_run_coverage",
}

TABLE_COLUMN_REFERENCE: dict[str, tuple[str, ...]] = {
    "evtx_events": (
        "evidence_id", "source_file", "channel", "event_id", "record_id", "timestamp", "computer",
        "user_name", "target_user", "subject_user", "src_ip", "logon_type", "process_name",
        "command_line", "service_name", "message", "raw_json", "tags", "severity",
    ),
    "mft_entries": (
        "evidence_id", "source_file", "record_number", "file_path", "file_name", "extension",
        "is_directory", "is_deleted", "size", "si_created", "si_modified", "si_accessed",
        "si_mft_modified", "fn_created", "fn_modified", "fn_accessed", "fn_mft_modified",
        "raw_json", "tags", "severity",
    ),
    "mft_timeline": (
        "timeline_id", "evidence_id", "record_number", "file_path", "timestamp", "timestamp_type",
        "description", "tags",
    ),
    "findings": (
        "finding_id", "rule_id", "title", "summary", "severity", "confidence", "status", "tags",
        "attack", "evidence", "ai_summary", "missing_checks", "created_at",
    ),
    "hypotheses": (
        "hypothesis_id", "description", "status", "verdict", "summary", "origin",
        "created_session", "resolved_session", "created_at", "updated_at",
    ),
    "report_sections": (
        "section_key", "title", "body", "confidence", "status", "update_count", "gaps",
        "last_filled_session", "last_filled_at",
    ),
    "claims": (
        "claim_id", "section_key", "claim_text", "finding_ids", "hypothesis_ids", "evidence_ids",
        "support_status", "created_at", "updated_at",
    ),
    "ai_reviews": (
        "review_id", "finding_id", "verdict", "report_text", "missing_checks",
        "confidence_adjustment", "notes", "raw_response", "created_at",
    ),
    "investigation_sessions": ("session_id", "started_at", "finished_at", "iterations", "status"),
    "investigation_steps": (
        "step_id", "session_id", "hypothesis_id", "iteration", "phase", "input_json", "output_json", "created_at",
    ),
    "hypothesis_reasoning": (
        "entry_id", "hypothesis_id", "session_id", "iteration", "phase", "verdict", "query_id", "body", "created_at",
    ),
    "progress_events": ("event_index", "stage", "status", "iteration", "current_query", "summary", "payload", "created_at"),
    "prefetch_executions": (
        "evidence_id", "source_file", "executable_name", "exec_count",
        "last_exec_time", "exec_times", "prefetch_hash", "filenames", "volumes",
        "raw_json", "tags", "severity",
    ),
    "ingested_files": ("sha256", "path", "source_kind", "size", "ingested_at"),
    "section_facts": (
        "fact_id", "fact_type", "fact_key", "fact_value", "evidence_ids",
        "source_query", "source_section", "confidence", "created_at", "updated_at",
    ),
    "section_evidence": (
        "section_key", "block_heading", "evidence_id", "role", "source_query", "created_at",
    ),
    "query_cache": ("sql_hash", "sql_text", "result_json", "executed_at"),
    "section_runs": (
        "run_id", "section_key", "block_heading", "iteration", "phase", "payload", "verdict", "created_at",
    ),
    "section_run_coverage": (
        "section_key", "block_heading", "source_query", "evidence_table", "row_count", "used_in_answer", "queried", "created_at",
    ),
}


# PROMPT-4: Load domain knowledge from YAML schema files
@lru_cache(maxsize=1)
def _load_logon_type_schema() -> dict:
    """Load logon type definitions from schema file."""
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / "logon_types.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


@lru_cache(maxsize=1)
def _load_app_catalog() -> dict:
    """Load application catalog from schema file."""
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / "app_catalog.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {}


@lru_cache(maxsize=8)
def _load_table_notes(table_name: str) -> dict:
    """Load notes dict from _schema/{table_name}.yaml."""
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / f"{table_name}.yaml"
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data.get("notes", {})
    return {}


@lru_cache(maxsize=1)
def _load_fp_reduction_guidance() -> str:
    """Load false-positive reduction guidance from YAML schema file."""
    schema_dir = Path(__file__).parent.parent / "rulepacks" / "_schema"
    path = schema_dir / "false_positive_rules.yaml"
    if not path.exists():
        return ""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    g = data.get("reduction_guidance", {})
    lines = ["False-positive reduction — apply before raising confidence:"]
    normals = g.get("normal_patterns", [])
    if normals:
        lines.append("  The following are generally NORMAL and should not be flagged as suspicious on their own:")
        for item in normals:
            lines.append(f"    - {item}")
    amplifiers = g.get("risk_amplifiers", [])
    if amplifiers:
        lines.append("  Raise confidence only when ONE OR MORE of these risk amplifiers are present:")
        for item in amplifiers:
            lines.append(f"    + {item}")
    lower = g.get("lower_confidence_when", [])
    if lower:
        lines.append("  Lower confidence when:")
        for item in lower:
            lines.append(f"    - {item}")
    return "\n".join(lines) + "\n"


def _fmt_table_notes(table_name: str) -> str:
    """Format table notes from YAML into guidance paragraph."""
    notes = _load_table_notes(table_name)
    if not notes:
        return ""
    lines = [f"{table_name} table guidance:"]
    for note in notes.values():
        lines.append(f"  {note}")
    return "\n".join(lines)


def build_investigation_framework() -> str:
    """Build investigation framework from schema declarations.
    
    PROMPT-4: Framework is built from YAML schema, not Python literals.
    """
    logon_schema = _load_logon_type_schema()
    app_catalog = _load_app_catalog()

    # Logon type reference
    logontype_lines = []
    for lt in sorted(logon_schema.get("types", {}).items(), key=lambda x: int(x[0])):
        lt_id, lt_def = lt
        logontype_lines.append(f"  {lt_id}  = {lt_def.get('name', '?')} ({lt_def.get('description', '')})")

    # Priority events
    priority_lines = ["Priority SQL guidance — investigate in this order when no prior history exists:"]
    for i, pe in enumerate(logon_schema.get("priority_events", []), 1):
        eids = pe.get("event_ids", [])
        lts = pe.get("logon_types", [])
        suffix = f" with logon_type IN ({lts})" if lts else ""
        priority_lines.append(f"  {i}. event_id IN ({', '.join(str(e) for e in eids)}){suffix} — {pe.get('reason', '')}")

    # App categorizations
    app_lines = ["Application categorization guidance:"]
    for exe, cat in app_catalog.get("mappings", {}).items():
        app_lines.append(f"  {exe}={cat.get('category', '?')}.")

    table_lines = [
        f"{table_name} columns: {', '.join(TABLE_COLUMN_REFERENCE[table_name])}."
        for table_name in sorted(ALLOWED_TABLES)
    ]

    return (
        "Investigation framework — apply every iteration:\n"
        "  Who:  which user/account is involved (target_user, subject_user)\n"
        "  When: exact time; is it outside business hours? is it repeated in rapid succession?\n"
        "  From: source IP (src_ip) — internal IP, external IP, or known RDP gateway?\n"
        "  To:   destination host (computer)\n"
        "  What: event_id, process_name, command_line, service_name\n"
        "  How:  logon method (interpret logon_type carefully)\n\n"
        "LogonType reference:\n"
        + "\n".join(logontype_lines) + "\n\n"
        + "\n".join(priority_lines) + "\n\n"
        + _fmt_table_notes("evtx_events") + "\n"
        + "\n".join(app_lines) + "\n\n"
        + _fmt_table_notes("prefetch_executions") + "\n"
        "Section-agent state tables:\n"
        "  section_facts stores reusable evidence-backed facts extracted during prior report-generation runs.\n"
        "  section_evidence links report sections/blocks to evidence_id values already judged relevant.\n"
        "  query_cache stores prior read-only query results by SQL hash.\n"
        "  section_runs stores the plan/query/check/write history for each report block.\n"
        "  Prefer reusing section_facts before issuing new SQL when the fact already answers the block question.\n\n"
        f"Available tables: {', '.join(sorted(ALLOWED_TABLES))}.\n"
        + "\n".join(table_lines)
        + "\nOnly propose SELECT or WITH-prefixed read-only SQL compatible with DuckDB.\n"
    )
