"""Keypoints for host identity, accounts, logon and session activity."""

from __future__ import annotations

from forensia.report.answers.event_semantics import (
    EXECUTION_EVENT_SQL,
    FAILED_LOGON_EVENT_SQL,
    LOG_CLEAR_EVENT_SQL,
    LOGOFF_EVENT_SQL,
    LOGON_EVENT_SQL,
    SECURITY_BOOT_EVENT_SQL,
    SECURITY_SERVICE_TASK_EVENT_SQL,
    SERVICE_TASK_EVENT_SQL,
    SESSION_EVENT_SQL,
    SUCCESS_LOGON_EVENT_SQL,
    SYSTEM_SHUTDOWN_EVENT_SQL,
    SYSTEM_STARTUP_EVENT_SQL,
)
from forensia.report.evidence_refs import (
    EvidenceResolver,
    _report_keypoint_rows,
)

HOST_ACCOUNT_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
    "host_compromise_candidates": (
        "Hosts with logon, execution, persistence, or log-clear activity (case/whitespace canonicalized).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            WITH raw AS (
              SELECT computer, COUNT(*) AS cnt, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
              FROM evtx_events
              WHERE ({LOGON_EVENT_SQL})
                 OR ({EXECUTION_EVENT_SQL})
                 OR ({SECURITY_SERVICE_TASK_EVENT_SQL})
                 OR {LOG_CLEAR_EVENT_SQL}
                 OR event_id = 5140
              GROUP BY computer
            )
            SELECT
              ARG_MAX(computer, cnt) AS computer,
              SUM(cnt) AS events,
              MIN(first_seen) AS first_seen,
              MAX(last_seen) AS last_seen
            FROM raw
            GROUP BY UPPER(TRIM(computer))
            ORDER BY events DESC
            LIMIT 20
            """,
        ),
    ),
    "host_suspicious_logons": (
        "Suspicious remote or explicit logons by host.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT computer, src_ip, target_user, logon_type, timestamp, evidence_id
            FROM evtx_events
            WHERE ({SUCCESS_LOGON_EVENT_SQL}) AND logon_type IN ('3','10','9')
            ORDER BY timestamp
            LIMIT 40
            """,
        ),
    ),
    "host_execution_activity": (
        "Observed process execution activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT computer, process_name, command_line, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE {EXECUTION_EVENT_SQL}
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "host_persistence_activity": (
        "Observed service and task persistence activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT computer, service_name, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE {SERVICE_TASK_EVENT_SQL}
            ORDER BY timestamp
            """,
        ),
    ),
    "account_logon_patterns": (
        "Observed account logon patterns for suspicious remote access.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT target_user, src_ip, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last, MIN(evidence_id) AS evidence_id
            FROM evtx_events
            WHERE ({SUCCESS_LOGON_EVENT_SQL}) AND logon_type IN ('3','9','10') AND target_user NOT LIKE '%$'
            GROUP BY target_user, src_ip, computer, logon_type
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "account_bruteforce_clusters": (
        "4625 failure clusters that may indicate brute force or password spray.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT src_ip, target_user, computer, COUNT(*) AS fail_count
            FROM evtx_events
            WHERE {FAILED_LOGON_EVENT_SQL}
            GROUP BY src_ip, target_user, computer
            HAVING COUNT(*) >= 5
            ORDER BY fail_count DESC
            LIMIT 20
            """,
        ),
    ),
    "account_management_changes": (
        "Observed account creation, deletion, reset, or group membership changes.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, subject_user, evidence_id
            FROM evtx_events
            WHERE event_id IN (4720,4726,4732,4728,4724)
            ORDER BY timestamp
            """,
        ),
    ),
    "account_explicit_credentials": (
        "Explicit credential usage events.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, computer, target_user, subject_user, evidence_id
            FROM evtx_events
            WHERE {LOGON_EVENT_SQL} AND event_id = 4648
            ORDER BY timestamp
            LIMIT 20
            """,
        ),
    ),
    "session_activity_events": (
        "Chronological logon, logoff, and system startup/shutdown events.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, computer, target_user, event_id, evidence_id
            FROM evtx_events
            WHERE ({SESSION_EVENT_SQL}) OR ({SECURITY_BOOT_EVENT_SQL})
               OR (event_id IN (6005,6006,6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "host_user_profile_paths": (
        "MFT entries under user profile directories.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE LOWER(file_path) LIKE '%/users/%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "account_all_logon_summary": (
        "All logon event counts grouped by user, computer, and logon type.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT target_user, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last, MIN(evidence_id) AS evidence_id
            FROM evtx_events
            WHERE ({SUCCESS_LOGON_EVENT_SQL}) AND target_user NOT LIKE '%$'
            GROUP BY target_user, computer, logon_type
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "account_logon_events": (
        "Raw logon, logoff, and session-disconnect events with evidence IDs.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, computer, target_user, logon_type, evidence_id
            FROM evtx_events
            WHERE {SESSION_EVENT_SQL}
            ORDER BY timestamp
            LIMIT 200
            """,
        ),
    ),
    "account_observed_users": (
        "Distinct user identities observed across all event records.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT target_user, subject_user, computer, evidence_id
            FROM evtx_events
            WHERE target_user IS NOT NULL OR subject_user IS NOT NULL
            LIMIT 40
            """,
        ),
    ),
    "system_shutdown_events": (
        "System shutdown events (event 1074/6006/6008).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, event_id, computer, message, evidence_id
            FROM evtx_events
            WHERE {SYSTEM_SHUTDOWN_EVENT_SQL}
            ORDER BY timestamp DESC
            LIMIT 50
        """,
        ),
    ),
    "system_startup_events": (
        "System startup events (event 6005).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, event_id, computer, evidence_id
            FROM evtx_events
            WHERE {SYSTEM_STARTUP_EVENT_SQL}
            ORDER BY timestamp
            LIMIT 50
        """,
        ),
    ),
    "interactive_logon_events": (
        "Interactive and remote-interactive logon events (4624 logon_type=2/10).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, computer, target_user, logon_type, src_ip, evidence_id
            FROM evtx_events
            WHERE ({SUCCESS_LOGON_EVENT_SQL}) AND logon_type IN ('2', '10')
            ORDER BY timestamp
            LIMIT 80
        """,
        ),
    ),
    "logoff_events": (
        "Logoff and session-disconnect events (4634/4647).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT timestamp, computer, target_user, evidence_id
            FROM evtx_events
            WHERE {LOGOFF_EVENT_SQL}
            ORDER BY timestamp
            LIMIT 80
        """,
        ),
    ),
}
