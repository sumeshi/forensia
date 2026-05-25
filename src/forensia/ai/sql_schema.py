from __future__ import annotations

from functools import lru_cache

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
}


@lru_cache(maxsize=1)
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
        "Interactive logon guidance:\n"
        "  To identify the last logged-on user, query event_id = 4624 AND logon_type IN ('2','10').\n"
        "  Treat 4728/4732 and similar group-management events as account administration, NOT logon evidence.\n\n"
        "prefetch_executions table guidance:\n"
        "  executable_name holds the .exe filename (e.g. 'POWERSHELL.EXE').\n"
        "  exec_count is the total run count; last_exec_time is the most recent execution timestamp.\n"
        "  exec_times is a JSON array of up to 8 last run timestamps.\n"
        "  filenames is a JSON array of files loaded by the process (useful for DLL side-loading detection).\n"
        "  IMPORTANT: prefetch_executions has NO computer/hostname column — source_file is the .pf file path.\n"
        "  To filter by host, JOIN with evtx_events ON abs(epoch_ms(prefetch_executions.last_exec_time) - epoch_ms(evtx_events.timestamp)) < 5000 AND evtx_events.computer = ?.\n"
        "  Or query prefetch_executions without a host filter and correlate timestamps manually.\n\n"
        f"Available tables: {', '.join(sorted(ALLOWED_TABLES))}.\n"
        + "\n".join(table_lines)
        + "\nOnly propose SELECT or WITH-prefixed read-only SQL compatible with DuckDB.\n"
    )
