"""Keypoints for timeline, file-system, persistence, and network activity."""

from __future__ import annotations

from forensia.report.answers.keypoint_sql import (
    _CLOUD_FILE_SQL,
    _CLOUD_PATH_SQL,
    _EMAIL_EXTENSION_SQL,
    _EMAIL_PATH_SQL,
)
from forensia.report.evidence_refs import (
    EvidenceResolver,
    _path_like_any,
    _report_keypoint_rows,
)

ACTIVITY_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
    "timeline_high_signal_events": (
        "Chronological high-signal event records with evidence IDs.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE severity IN ('critical','high')
            ORDER BY timestamp
            LIMIT 50
            """,
        ),
    ),
    "timeline_mft_activity": (
        "Recent MFT timeline entries relevant to chronology.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, timestamp_type, file_path, description, evidence_id
            FROM mft_timeline
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "timeline_top_findings": (
        "Top findings that may anchor attack phases.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, severity, confidence, status
            FROM findings
            ORDER BY confidence DESC
            LIMIT 20
            """,
        ),
    ),
    "timeline_log_clearing": (
        "Observed log clearing or integrity-impacting events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, channel, target_user, src_ip, evidence_id
            FROM evtx_events
            WHERE (event_id IN (1100, 1102) AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
               OR (
                  event_id = 104
                  AND LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) = 'microsoft-windows-eventlog'
               )
            ORDER BY timestamp
            """,
        ),
    ),
    "persistence_service_installs": (
        "Service installation or creation events with classification (benign-known / unknown).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, service_name, subject_user, evidence_id,
              CASE
                WHEN regexp_matches(LOWER(COALESCE(service_name,'')),
                  'gupdate|gupdatem|google.update|bonjour|mdnsresponder'
                  '|msiserver|trustedinstaller|officeclicktorun|osppsvc'
                  '|office.64.source.engine|office.software.protection'
                  '|[.]net.framework.ngen|ngen.v4|mscorsvw|clr_optimization'
                  '|intel.*pro.*1000|intel.*82[.]|intel.*ndis|intel.*network'
                  '|microsoft.streaming|microsoft.memory.module|microsoft.trusted.audio'
                  '|uaa.*function.driver|uaa.bus.driver'
                  '|net[.]tcp.listener|net[.]pipe.listener|net[.]msmq.listener'
                  '|asp[.]net.state|wuauserv|sppsvc|wmpnetworksvc')
                THEN 'benign-known'
                ELSE 'unknown'
              END AS classification
            FROM evtx_events
            WHERE event_id IN (4697,7045)
            ORDER BY timestamp
            """,
        ),
    ),
    "persistence_scheduled_tasks": (
        "Scheduled task creation or deletion activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, subject_user, message, evidence_id
            FROM evtx_events
            WHERE event_id IN (4698,4699)
            ORDER BY timestamp
            """,
        ),
    ),
    "persistence_lolbas_execution": (
        "PowerShell and LOLBas execution events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE event_id = 4688 AND (
                LOWER(process_name) LIKE '%powershell%' OR
                LOWER(process_name) LIKE '%pwsh%' OR
                LOWER(process_name) LIKE '%certutil%' OR
                LOWER(process_name) LIKE '%mshta%' OR
                LOWER(process_name) LIKE '%rundll32%' OR
                LOWER(process_name) LIKE '%wscript%' OR
                LOWER(process_name) LIKE '%cscript%'
            )
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "persistence_defender_activity": (
        "Observed defensive-control disablement or malware events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, evidence_id, message
            FROM evtx_events
            WHERE event_id IN (5001,7040,1116)
            ORDER BY timestamp
            """,
        ),
    ),
    "timeline_system_events": (
        "Core system events covering startup, shutdown, logon, and logoff.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE (event_id IN (1074,4608,4609,4624,4634,4647))
               OR (event_id IN (6005,6006,6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            ORDER BY timestamp
            LIMIT 200
            """,
        ),
    ),
    "timeline_prefetch_history": (
        "Prefetch execution history ordered chronologically.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 80
            """,
        ),
    ),
    "timeline_prefetch_full_history": (
        "All execution timestamps recorded across Prefetch files (up to 8 per file).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_time, exec_index, prefetch_hash, evidence_id
            FROM prefetch_timeline
            WHERE exec_time IS NOT NULL
            ORDER BY exec_time DESC
            LIMIT 200
            """,
        ),
    ),
    "mft_user_app_activity": (
        "MFT timeline entries under user-controlled paths (AppData, Downloads, Desktop, Documents).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, timestamp_type, file_path, description, evidence_id
            FROM mft_timeline
            WHERE (
                LOWER(file_path) LIKE '%/appdata/%' OR
                LOWER(file_path) LIKE '%/downloads/%' OR
                LOWER(file_path) LIKE '%/desktop/%' OR
                LOWER(file_path) LIKE '%/documents/%'
            )
            ORDER BY timestamp
            LIMIT 80
            """,
        ),
    ),
    "mft_prefetch_filenames": (
        "Application names inferred from .pf filenames present in MFT.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_name, file_path, si_modified, evidence_id
            FROM mft_entries
            WHERE extension = 'pf'
            ORDER BY si_modified DESC
            LIMIT 120
            """,
        ),
    ),
    "mft_recent_folder_lnk": (
        "Recent-folder LNK files indicating recently accessed documents.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_name, file_path, si_created, fn_created, evidence_id
            FROM mft_entries
            WHERE (
                LOWER(file_path) LIKE '%/recent/%' OR
                LOWER(file_path) LIKE '%/office/recent/%'
            )
            AND extension IN ('lnk', 'url')
            ORDER BY si_created DESC
            LIMIT 40
            """,
        ),
    ),
    "mft_user_desktop_artifacts": (
        "Files found under any user Desktop path in MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE {_path_like_any("file_path", "desktop")}
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "mft_office_recent_artifacts": (
        "Office recent file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE {_path_like_any("file_path", "office", "office/recent")}
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "mft_outlook_artifacts": (
        "Outlook OST/PST and directory paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE {_EMAIL_EXTENSION_SQL} OR {_EMAIL_PATH_SQL}
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "mft_cloud_sync_artifacts": (
        "Cloud sync client artifacts from MFT (Google Drive, OneDrive, Dropbox, iCloud).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, is_deleted, evidence_id
            FROM mft_entries
            WHERE (
                {_CLOUD_PATH_SQL}
                OR {_CLOUD_FILE_SQL}
            )
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "evtx_network_connections": (
        "Network-related EVTX events (firewall, filtering platform, DHCP).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, src_ip, process_name, message, evidence_id
            FROM evtx_events
            WHERE event_id IN (5152, 5154, 5156, 5157, 5158, 5031, 5140, 5145)
               OR channel LIKE '%dhcp%' OR channel LIKE '%dns%'
            ORDER BY timestamp
            LIMIT 80
        """,
        ),
    ),
    "evtx_firewall_events": (
        "Windows Firewall allowed/blocked connection events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, src_ip, process_name, event_id, evidence_id
            FROM evtx_events
            WHERE event_id IN (5156, 5157)
            ORDER BY timestamp
            LIMIT 80
        """,
        ),
    ),
    "timeline_case_assembled": (
        "Deterministic case timeline from findings, verdicts, and structured answers (6 rows/day).",
        lambda db: _report_keypoint_rows(
            db,
            """
            WITH ranked AS (
                SELECT
                    timestamp, source, ref_id, host, summary, evidence_id,
                    CAST(timestamp AS DATE) AS day,
                    ROW_NUMBER() OVER (
                        PARTITION BY CAST(timestamp AS DATE)
                        ORDER BY
                            CASE source
                                WHEN 'finding' THEN 0
                                WHEN 'verdict' THEN 1
                                WHEN 'structured' THEN 2
                                ELSE 3
                            END,
                            timestamp
                    ) AS rn
                FROM case_timeline
                WHERE timestamp IS NOT NULL
            )
            SELECT timestamp, source, host, summary, evidence_id
            FROM ranked
            WHERE rn <= 6
            ORDER BY timestamp
            """,
        ),
    ),
}
