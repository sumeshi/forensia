from __future__ import annotations

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
    "investigation_steps": ("step_id", "session_id", "iteration", "phase", "input_json", "output_json", "created_at"),
    "hypothesis_reasoning": (
        "entry_id", "hypothesis_id", "session_id", "iteration", "phase", "verdict", "query_id", "body", "created_at",
    ),
    "progress_events": ("event_index", "stage", "status", "iteration", "current_query", "summary", "payload", "created_at"),
    "ingested_files": ("path", "source_kind", "size", "ingested_at"),
}


def build_investigation_framework() -> str:
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
        "  2  = Interactive (console). Physical access or RunAs.\n"
        "  3  = Network auth. net use / PsExec / WinRM / remote MMC. Credentials do NOT remain on target.\n"
        "  5  = Service logon. Service account credentials remain in LSA.\n"
        "  9  = NewCredentials (RUNAS /NETWORK). Local identity unchanged; only outbound connections use the new credential.\n"
        "  10 = RemoteInteractive (RDP). Credentials remain in LSA on the TARGET — dangerous if host is compromised.\n"
        "  11 = CachedInteractive. DC not contacted; domain credentials cached locally.\n\n"
        "Priority SQL guidance — investigate in this order when no prior history exists:\n"
        "  1. Check event_id IN (1102, 104) first — log clearing indicates tampering and affects overall reliability.\n"
        "  2. event_id=4624 with logon_type IN ('3','10') — enumerate lateral movement sources (src_ip) and targets (computer).\n"
        "  3. event_id=4625 grouped by src_ip — identify brute-force attempts.\n"
        "  4. event_id IN (4688, 4104) — detect PowerShell and LOLBas execution.\n"
        "  5. event_id IN (4697, 7045, 4698) — find persistence (services, tasks).\n"
        "  6. event_id IN (4720, 4732, 4728) — find suspicious account operations.\n\n"
        f"Available tables: {', '.join(sorted(ALLOWED_TABLES))}.\n"
        + "\n".join(table_lines)
        + "\nOnly propose SELECT or WITH-prefixed read-only SQL compatible with DuckDB.\n"
    )
