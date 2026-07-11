"""Keypoints for report overview, IOCs, and structured-answer sections."""

from __future__ import annotations

from forensia.report.answers.keypoint_sql import (
    _BROWSER_EXE_SQL,
    _CLOUD_FILE_SQL,
    _CLOUD_PATH_SQL,
    _EMAIL_DATA_FILE_SQL,
    _EMAIL_EXTENSION_SQL,
    _EMAIL_PATH_SQL,
)
from forensia.report.evidence_refs import (
    EvidenceResolver,
    _path_like_any,
    _report_keypoint_rows,
)

OVERVIEW_IOC_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
    "top_keypoints": (
        "Top finding-backed keypoints ranked by confidence.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, severity, confidence, summary
            FROM findings
            WHERE COALESCE(status, 'accepted') != 'suppressed'
            ORDER BY confidence DESC, created_at DESC
            LIMIT 12
            """,
        ),
    ),
    "overview_event_range": (
        "Earliest and latest observed event timestamps.",
        lambda db: _report_keypoint_rows(
            db,
            "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events",
        ),
    ),
    "overview_hosts": (
        "Observed hosts ranked by event volume (case/whitespace canonicalized).",
        lambda db: _report_keypoint_rows(
            db,
            """
            WITH raw AS (
              SELECT computer, COUNT(*) AS cnt
              FROM evtx_events
              WHERE computer IS NOT NULL
              GROUP BY computer
            )
            SELECT
              ARG_MAX(computer, cnt) AS computer,
              SUM(cnt) AS event_count
            FROM raw
            GROUP BY UPPER(TRIM(computer))
            ORDER BY event_count DESC
            LIMIT 20
            """,
        ),
    ),
    "overview_top_findings": (
        "Highest-severity accepted findings for the overview.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, summary, severity, confidence, evidence
            FROM findings
            WHERE severity IN ('critical','high')
              AND COALESCE(status, 'new') != 'suppressed'
              AND COALESCE(title, '') != ''
              AND title NOT LIKE '%:  @%'
            ORDER BY
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
              confidence DESC,
              created_at DESC
            LIMIT 10
            """,
        ),
    ),
    "ioc_source_ips": (
        "Distinct observed source IPs ranked by frequency.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT src_ip, COUNT(*) AS count
            FROM evtx_events
            WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','127.0.0.1','::1','-')
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "ioc_processes": (
        "Distinct suspicious processes or command lines.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT process_name, command_line, computer, evidence_id
            FROM evtx_events
            WHERE event_id IN (4688,4104) AND process_name IS NOT NULL
            ORDER BY evidence_id
            LIMIT 30
            """,
        ),
    ),
    "ioc_services": (
        "Distinct suspicious services observed.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT service_name, computer, evidence_id
            FROM evtx_events
            WHERE event_id IN (4697,7045) AND service_name IS NOT NULL
            """,
        ),
    ),
    "ioc_suspicious_files": (
        "Suspicious file paths from MFT entries.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE (
                LOWER(file_path) LIKE '%temp%' OR
                LOWER(file_path) LIKE '%appdata%' OR
                LOWER(file_path) LIKE '%public%'
            ) AND si_created IS NOT NULL
            ORDER BY si_created DESC
            LIMIT 30
            """,
        ),
    ),
    "ioc_suspicious_accounts": (
        "Suspicious account administration activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT target_user, subject_user, computer, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4720,4726,4732,4728,4724)
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "ioc_user_data_files": (
        "Notable user-data file paths from MFT (desktop, office, mail, cloud storage).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE
                LOWER(file_path) LIKE '%/desktop/%' OR
                LOWER(file_path) LIKE '%/office/%' OR
                {_EMAIL_PATH_SQL} OR
                {_CLOUD_PATH_SQL}
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "ioc_email_ost_files": (
        "Email OST/PST mailbox cache file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE {_EMAIL_EXTENSION_SQL}
            LIMIT 10
            """,
        ),
    ),
    "structured_last_shutdown": (
        "Last shutdown/startup event from System event log (event 1074/6006/6008/6013).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, event_id, computer, message
            FROM evtx_events
            WHERE (event_id = 1074)
               OR (event_id IN (6006, 6008, 6013) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            ORDER BY timestamp DESC LIMIT 1
        """,
        ),
    ),
    "structured_daily_session_activity": (
        "Daily user activity: logon/logoff/shutdown counts per date.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DATE(timestamp) AS date, event_id, COUNT(*) AS n
            FROM evtx_events
            WHERE (event_id IN (4624, 4634, 4647))
               OR (event_id IN (6005, 6006) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            GROUP BY 1, 2 ORDER BY 1
        """,
        ),
    ),
    "structured_browser_artifacts": (
        "Browser executable names from prefetch/mft.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT DISTINCT executable_name FROM prefetch_executions
            WHERE {_BROWSER_EXE_SQL}
        """,
        ),
    ),
    "structured_email_artifacts": (
        "OST/PST file paths from MFT entries (email client artifacts).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_modified FROM mft_entries
            WHERE {_EMAIL_DATA_FILE_SQL} OR {_EMAIL_PATH_SQL}
            """,
        ),
    ),
    "structured_desktop_rename_candidates": (
        "Files on Desktop with si_modified < fn_modified (rename indicator).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_modified, fn_modified
            FROM mft_entries
            WHERE {_path_like_any("file_path", "desktop")} AND si_modified < fn_modified
            """,
        ),
    ),
    "structured_cloud_artifacts": (
        "Cloud sync artifacts from MFT (Google Drive, OneDrive, Dropbox, iCloud).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, is_deleted FROM mft_entries
            WHERE (
                {_CLOUD_PATH_SQL}
                OR {_CLOUD_FILE_SQL}
            )
            """,
        ),
    ),
    "structured_antiforensics": (
        "Anti-forensic activity on the last day: log clearing, tool execution, prefetch deletion.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, event_id, computer, target_user, message
            FROM evtx_events
            WHERE (event_id = 1102 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
               OR (event_id = 1100 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
               OR (event_id = 104 AND LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) = 'microsoft-windows-eventlog')
            ORDER BY timestamp DESC LIMIT 50
        """,
        ),
    ),
}
