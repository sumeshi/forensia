from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.knowledge import (
    catalog_data_file_extensions,
    catalog_exe_globs,
    catalog_file_patterns,
    catalog_path_terms,
    exe_glob_sql,
    expand_catalog_sql_placeholders,
)
from forensia.questions import load_question_specs, project_rows_for_question_spec
from forensia.report.benchmark_keypoints import BENCHMARK_KEYPOINT_ALIASES

# ── SQL helpers used by keypoint lambdas ──


def _sql_like_any(column: str, *patterns: str) -> str:
    lowered = f"LOWER(COALESCE({column}, ''))"
    return (
        "("
        + " OR ".join(f"{lowered} LIKE '{pattern.lower()}'" for pattern in patterns)
        + ")"
    )


def _path_like_any(column: str, *segments: str) -> str:
    patterns = []
    for segment in segments:
        normalized = str(segment or "").strip().strip("/\\").lower().replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        if not parts:
            continue
        slash_pattern = "%/" + "/".join(parts) + "/%"
        backslash_pattern = "%\\" + "\\".join(parts) + "\\%"
        patterns.extend((slash_pattern, backslash_pattern))
    return _sql_like_any(column, *patterns)


def _like_any_or_false(column: str, patterns: tuple[str, ...]) -> str:
    return _sql_like_any(column, *patterns) if patterns else "FALSE"


def _path_like_any_or_false(column: str, segments: tuple[str, ...]) -> str:
    return _path_like_any(column, *segments) if segments else "FALSE"


def _extension_in_sql(column: str, extensions: tuple[str, ...]) -> str:
    if not extensions:
        return "FALSE"
    values = ", ".join(f"'{extension}'" for extension in extensions)
    return f"LOWER(COALESCE({column}, '')) IN ({values})"


_BROWSER_EXE_SQL = exe_glob_sql(
    "executable_name", catalog_exe_globs("browser_artifacts")
)
_EMAIL_DATA_FILE_SQL = _like_any_or_false(
    "file_name", catalog_file_patterns("email_artifacts", "data_files")
)
_EMAIL_EXTENSION_SQL = _extension_in_sql(
    "extension", catalog_data_file_extensions("email_artifacts")
)
_EMAIL_PATH_SQL = _path_like_any_or_false(
    "file_path", catalog_path_terms("email_artifacts")
)
_CLOUD_PATH_SQL = _path_like_any_or_false(
    "file_path", catalog_path_terms("cloud_sync_artifacts")
)
_CLOUD_FILE_SQL = _like_any_or_false(
    "file_name",
    catalog_file_patterns(
        "cloud_sync_artifacts", "exe_patterns", "paths", "prefetch_names"
    ),
)


# ── Pattern ──

EVIDENCE_ID_PATTERN = re.compile(
    r"\b(?:evtx-[a-zA-Z][a-zA-Z0-9.-]*-\d{12}|mft-\d{12,15}-\d{2,4}|prefetch-[a-zA-Z][a-zA-Z0-9._-]+-[a-f0-9]{5,32})\b"
)

EvidenceResolver = Callable[[CaseDB], list[dict[str, Any]]]


# ── Evidence ID extraction helpers ──


def _extract_evidence_ids_from_value(value: Any) -> list[str]:
    """Extract evidence_id values from nested row/finding payloads."""
    ids: list[str] = []
    seen: set[str] = set()

    def add(raw: Any) -> None:
        text = str(raw or "").strip()
        if text and text not in seen:
            seen.add(text)
            ids.append(text)

    def walk(item: Any) -> None:
        if isinstance(item, str):
            stripped = item.strip()
            if not stripped:
                return
            if EVIDENCE_ID_PATTERN.fullmatch(stripped):
                add(stripped)
                return
            if stripped[:1] in {"[", "{"}:
                try:
                    walk(json.loads(stripped))
                except json.JSONDecodeError:
                    return
            return
        if isinstance(item, dict):
            add(item.get("evidence_id"))
            many = item.get("evidence_ids")
            if isinstance(many, list):
                for value in many:
                    add(value)
            for key in ("evidence", "rows", "answer"):
                if key in item:
                    walk(item.get(key))
            return
        if isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return ids


def _row_with_evidence_ids(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a row and expose nested finding evidence IDs for report prompts."""
    normalized = normalize_value(row)
    if not isinstance(normalized, dict):
        return {}
    evidence_ids = _extract_evidence_ids_from_value(normalized)
    if evidence_ids:
        normalized.setdefault("evidence_ids", evidence_ids)
        normalized.setdefault("evidence_id", evidence_ids[0])
    else:
        normalized["citable"] = False
    return normalized


# ── Summary builder ──


def _summarize_rows(
    *,
    source_type: str,
    source_id: str,
    description: str,
    rows: list[dict[str, Any]],
    max_rows: int = 20,
) -> dict[str, Any]:
    """Build a structured summary dict from a list of database rows, extracting evidence/finding/hypothesis IDs."""
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized_row = _row_with_evidence_ids(row)
        normalized_rows.append(normalized_row)
        for evidence_id in _extract_evidence_ids_from_value(normalized_row):
            value = str(evidence_id)
            if value not in seen_evidence_ids:
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        finding_id = row.get("finding_id")
        if finding_id:
            value = str(finding_id)
            if value not in seen_finding_ids:
                seen_finding_ids.add(value)
                finding_ids.append(value)
        hypothesis_id = row.get("hypothesis_id")
        if hypothesis_id:
            value = str(hypothesis_id)
            if value not in seen_hypothesis_ids:
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        source_type: source_id,
        "description": description,
        "kind": "rows" if source_type == "keypoint" else "trace",
        "source_kind": source_type,
        "source_ref": source_id,
        "row_count": len(rows),
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
        "sample_rows": normalized_rows[:max_rows],
    }


# ── Keypoint query helper ──


def _report_keypoint_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return fetch_records(db, query)


# ── Gap extraction helper ──


def _extract_needed_evidence(latest_reasoning: str | None) -> str:
    """Parse missing_questions from latest_reasoning JSON, return first 2 items joined."""
    if not latest_reasoning:
        return ""
    try:
        parsed = json.loads(latest_reasoning)
        missing = parsed.get("missing_questions", [])
        if isinstance(missing, list) and missing:
            items = [str(q).strip() for q in missing if q]
            return "; ".join(items[:2])
    except json.JSONDecodeError, TypeError:
        pass
    return ""


# ====================================================================
# KEYPOINTS — keypoint definitions, aliases, resolvers
# ====================================================================


REPORT_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
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
    "host_compromise_candidates": (
        "Hosts with logon, execution, persistence, or log-clear activity (case/whitespace canonicalized).",
        lambda db: _report_keypoint_rows(
            db,
            """
            WITH raw AS (
              SELECT computer, COUNT(*) AS cnt, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
              FROM evtx_events
              WHERE event_id IN (4624,4625,4648,4688,4697,4698,5140,1102)
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
            """
            SELECT computer, src_ip, target_user, logon_type, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('3','10','9')
            ORDER BY timestamp
            LIMIT 40
            """,
        ),
    ),
    "host_execution_activity": (
        "Observed process execution activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, process_name, command_line, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4688,4104)
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "host_persistence_activity": (
        "Observed service and task persistence activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, service_name, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4697,7045,4698)
            ORDER BY timestamp
            """,
        ),
    ),
    "account_logon_patterns": (
        "Observed account logon patterns for suspicious remote access.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT target_user, src_ip, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('3','9','10') AND target_user NOT LIKE '%$'
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
            """
            SELECT src_ip, target_user, computer, COUNT(*) AS fail_count
            FROM evtx_events
            WHERE event_id = 4625
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
            """
            SELECT timestamp, computer, target_user, subject_user, evidence_id
            FROM evtx_events
            WHERE event_id = 4648
            ORDER BY timestamp
            LIMIT 20
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
    "gaps_event_coverage": (
        "Overall event coverage and time span.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT COUNT(*) AS total_events, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            """,
        ),
    ),
    "gaps_channel_coverage": (
        "Observed event distribution by channel.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT channel, COUNT(*) AS count
            FROM evtx_events
            GROUP BY channel
            ORDER BY count DESC
            """,
        ),
    ),
    "gaps_log_integrity_events": (
        "Observed log clearing or audit-policy-impacting events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT event_id, COUNT(*) AS count
            FROM evtx_events
            WHERE (event_id IN (1100,1102,4719) AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
               OR (
                  event_id = 104
                  AND LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) = 'microsoft-windows-eventlog'
               )
            GROUP BY event_id
            """,
        ),
    ),
    "recommendations_findings": (
        "Top findings that should drive recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, summary, severity, confidence, status, ai_summary, evidence
            FROM findings
            WHERE COALESCE(status, 'new') != 'suppressed'
              AND severity IN ('critical','high','medium')
              AND COALESCE(title, '') != ''
              AND title NOT LIKE '%:  @%'
            ORDER BY
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              confidence DESC,
              created_at DESC
            LIMIT 20
            """,
        ),
    ),
    "recommendations_recent_reviews": (
        "Recent AI review verdicts and report notes.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT verdict, report_text
            FROM ai_reviews
            ORDER BY created_at DESC
            LIMIT 10
            """,
        ),
    ),
    "appendix_findings_catalog": (
        "Raw findings catalog for appendix use, ordered by severity and confidence.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, rule_id, title, severity, confidence, status, summary, ai_summary
            FROM findings
            WHERE COALESCE(status, 'accepted') != 'suppressed'
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                confidence DESC,
                created_at DESC
            LIMIT 80
            """,
        ),
    ),
    "appendix_claims_needing_review": (
        "Claims whose support status needs review.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT section_key, claim_text, support_status
            FROM claims
            WHERE support_status IN ('unsupported', 'orphaned_reference', 'needs_review')
            ORDER BY section_key, updated_at DESC
            LIMIT 40
            """,
        ),
    ),
    "session_activity_events": (
        "Chronological logon, logoff, and system startup/shutdown events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, event_id, evidence_id
            FROM evtx_events
            WHERE (event_id IN (4624,4634,4647,4608,4609))
               OR (event_id IN (6005,6006,6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            ORDER BY timestamp
            LIMIT 30
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
            """
            SELECT target_user, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            WHERE event_id = 4624 AND target_user NOT LIKE '%$'
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
            """
            SELECT timestamp, computer, target_user, logon_type, evidence_id
            FROM evtx_events
            WHERE event_id IN (4624,4634,4647)
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
    "system_shutdown_events": (
        "System shutdown events (event 1074/6006/6008).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, event_id, computer, message, evidence_id
            FROM evtx_events
            WHERE (event_id = 1074)
               OR (event_id IN (6006, 6008) AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            ORDER BY timestamp DESC
            LIMIT 50
        """,
        ),
    ),
    "system_startup_events": (
        "System startup events (event 6005).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, event_id, computer, evidence_id
            FROM evtx_events
            WHERE (channel IS NULL OR LOWER(channel) LIKE '%system%')
               AND event_id = 6005
            ORDER BY timestamp
            LIMIT 50
        """,
        ),
    ),
    "interactive_logon_events": (
        "Interactive and remote-interactive logon events (4624 logon_type=2/10).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, logon_type, src_ip, evidence_id
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('2', '10')
            ORDER BY timestamp
            LIMIT 80
        """,
        ),
    ),
    "logoff_events": (
        "Logoff and session-disconnect events (4634/4647).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, evidence_id
            FROM evtx_events
            WHERE event_id IN (4634, 4647)
            ORDER BY timestamp
            LIMIT 80
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
    "unresolved_hypotheses_summary": (
        "Open or unresolved hypotheses from the investigation.",
        lambda db: [
            {
                "hypothesis_id": row["hypothesis_id"],
                "description": row["description"],
                "status": row["status"],
                "verdict": row["verdict"],
                "summary": row["summary"],
                "updated_at": row["updated_at"],
                "needed_evidence": _extract_needed_evidence(
                    row.get("latest_reasoning")
                ),
            }
            for row in _report_keypoint_rows(
                db,
                """
                WITH latest AS (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY hypothesis_id ORDER BY created_at DESC, entry_id DESC
                    ) AS rn
                    FROM hypothesis_reasoning
                    WHERE phase != 'error'
                )
                SELECT h.hypothesis_id, h.description, h.status, h.verdict,
                       h.summary, h.updated_at, l.body AS latest_reasoning
                FROM hypotheses h
                LEFT JOIN latest l ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
                WHERE COALESCE(h.verdict, h.status) NOT IN ('confirmed', 'refuted', 'rejected', 'untestable')
                ORDER BY h.updated_at DESC NULLS LAST
                LIMIT 30
                """,
            )
        ],
    ),
    "resolved_hypotheses_with_evidence": (
        "Confirmed and refuted hypotheses with verdict, description, and evidence references.",
        lambda db: [
            {
                **row,
                "evidence_ids": list(
                    set(
                        EVIDENCE_ID_PATTERN.findall(
                            str(row.get("latest_reasoning") or "")
                        )
                    )
                ),
            }
            for row in _report_keypoint_rows(
                db,
                """
                WITH latest AS (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY hypothesis_id
                        ORDER BY created_at DESC, entry_id DESC
                    ) AS rn
                    FROM hypothesis_reasoning
                )
                SELECT h.hypothesis_id, h.verdict, h.description, h.summary,
                       l.body AS latest_reasoning,
                       l.verdict AS latest_verdict
                FROM hypotheses h
                LEFT JOIN latest l
                    ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
                WHERE h.status IN ('confirmed', 'refuted')
                ORDER BY h.updated_at DESC NULLS LAST
                LIMIT 30
                """,
            )
        ],
    ),
    "untestable_hypotheses_summary": (
        "Hypotheses that could not be tested due to missing telemetry.",
        lambda db: [
            {
                "hypothesis_id": row["hypothesis_id"],
                "description": row["description"],
                "status": row["status"],
                "verdict": row["verdict"],
                "summary": row["summary"],
                "updated_at": row["updated_at"],
                "needed_evidence": _extract_needed_evidence(
                    row.get("latest_reasoning")
                ),
            }
            for row in _report_keypoint_rows(
                db,
                """
                WITH latest AS (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY hypothesis_id ORDER BY created_at DESC, entry_id DESC
                    ) AS rn
                    FROM hypothesis_reasoning
                    WHERE phase != 'error'
                )
                SELECT h.hypothesis_id, h.description, h.status, h.verdict,
                       h.summary, h.updated_at, l.body AS latest_reasoning
                FROM hypotheses h
                LEFT JOIN latest l ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
                WHERE COALESCE(h.verdict, h.status) = 'untestable'
                ORDER BY h.updated_at DESC NULLS LAST
                LIMIT 20
                """,
            )
        ],
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
    "report_sections_with_gaps": (
        "Report sections that have outstanding gaps or low confidence.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT section_key, title, confidence, gaps, status
            FROM report_sections
            WHERE confidence < 0.7 OR gaps IS NOT NULL
            ORDER BY confidence
            LIMIT 20
        """,
        ),
    ),
}


REPORT_KEYPOINT_ALIASES = {
    "top_findings": "overview_top_findings",
    "network_connections": "ioc_source_ips",
    "evidence_gaps": "gaps_event_coverage",
    "overview_window": "overview_event_range",
    "overview_findings": "overview_top_findings",
    "timeline_events": "timeline_high_signal_events",
    "timeline_mft": "timeline_mft_activity",
    "timeline_findings": "timeline_top_findings",
    "timeline_log_clear": "timeline_log_clearing",
    "hosts_summary": "host_compromise_candidates",
    "hosts_logons": "host_suspicious_logons",
    "hosts_processes": "host_execution_activity",
    "hosts_services": "host_persistence_activity",
    "accounts_logon_summary": "account_logon_patterns",
    "accounts_failed_logons": "account_bruteforce_clusters",
    "accounts_changes": "account_management_changes",
    "accounts_explicit_credentials": "account_explicit_credentials",
    "persistence_services": "persistence_service_installs",
    "persistence_tasks": "persistence_scheduled_tasks",
    "persistence_lolbas": "persistence_lolbas_execution",
    "persistence_defender": "persistence_defender_activity",
    "ioc_ips": "ioc_source_ips",
    "ioc_mft_paths": "ioc_suspicious_files",
    "gaps_volume": "gaps_event_coverage",
    "gaps_channels": "gaps_channel_coverage",
    "gaps_log_clear": "gaps_log_integrity_events",
    "recommendations_reviews": "recommendations_recent_reviews",
    "untestable_hypotheses": "untestable_hypotheses_summary",
    "timeline_chronological_events": "timeline_case_assembled",
    "chronological_events": "timeline_case_assembled",
}

# Benchmark-question-oriented aliases live in a separate module so the generic
# alias map above stays free of benchmark-specific names (CLAUDE.md Rule 16).
# They resolve to the same generic keypoints and are only used by the optional
# external benchmark template.
REPORT_KEYPOINT_ALIASES.update(BENCHMARK_KEYPOINT_ALIASES)


# ── Default keypoints for section ──


def _default_keypoints_for_section(
    section_key: str,
    benchmark_mode: bool = False,
    block_heading: str = "",
) -> tuple[str, ...]:
    """Return default keypoint names to seed a section's evidence collection.

    All returned names MUST exist in REPORT_KEYPOINTS — otherwise the planner's
    keypoint_catalog ends up empty and the section silently writes "not_searched".
    Each family's set is intentionally heterogeneous so different sections do
    not all surface the same finding list.
    """
    if benchmark_mode:
        return ()

    # Block-heading-level overrides take precedence over family defaults.
    # Keys are lowercase partial matches against block_heading.
    _heading_overrides: dict[str, tuple[str, ...]] = {
        "log integrity": (
            "timeline_log_clearing",
            "gaps_log_integrity_events",
            "timeline_system_events",
        ),
        "network": (
            "evtx_network_connections",
            "ioc_source_ips",
            "evtx_firewall_events",
        ),
        "lateral": (
            "account_logon_patterns",
            "account_explicit_credentials",
            "ioc_source_ips",
        ),
        "evidence gap": (
            "unresolved_hypotheses_summary",
            "untestable_hypotheses_summary",
            "gaps_event_coverage",
            "gaps_channel_coverage",
        ),
        "gap": (
            "unresolved_hypotheses_summary",
            "untestable_hypotheses_summary",
            "gaps_event_coverage",
            "gaps_channel_coverage",
        ),
        "execution": (
            "host_execution_activity",
            "persistence_lolbas_execution",
            "persistence_service_installs",
        ),
        "persistence": (
            "host_persistence_activity",
            "persistence_service_installs",
            "persistence_scheduled_tasks",
        ),
        "authentication": (
            "account_logon_patterns",
            "account_bruteforce_clusters",
            "account_explicit_credentials",
        ),
        "overview": (
            "overview_top_findings",
            "resolved_hypotheses_with_evidence",
            "overview_hosts",
        ),
        "chronological": (
            "timeline_high_signal_events",
            "timeline_system_events",
            "timeline_log_clearing",
            "timeline_case_assembled",
        ),
    }
    if block_heading:
        heading_lower = block_heading.lower()
        for keyword, keypoints in _heading_overrides.items():
            if keyword in heading_lower:
                return keypoints

    family = section_key.split("_", 1)[0] if "_" in section_key else section_key
    mapping = {
        "1": (
            "overview_top_findings",
            "resolved_hypotheses_with_evidence",
            "overview_hosts",
            "overview_event_range",
        ),
        "2": (
            "timeline_high_signal_events",
            "timeline_system_events",
            "timeline_log_clearing",
            "timeline_case_assembled",
        ),
        "3": (
            "host_execution_activity",
            "host_persistence_activity",
            "account_logon_patterns",
            "ioc_source_ips",
        ),
        "4": (
            "unresolved_hypotheses_summary",
            "gaps_event_coverage",
            "gaps_channel_coverage",
        ),
        "5": ("recommendations_findings", "recommendations_recent_reviews"),
        "6": ("appendix_findings_catalog", "appendix_claims_needing_review"),
    }
    return mapping.get(family, ("overview_top_findings",))


# ── Keypoint cards ──


def _load_keypoint_cards(
    case: Case, max_cards: int = 8, max_chars: int = 1200
) -> list[dict[str, str]]:
    """Load keypoint card markdown files from the case memory directory."""
    cards: list[dict[str, str]] = []
    for path in sorted(case.memory_dir.glob("keypoints/KP-*.md"))[:max_cards]:
        text = path.read_text(encoding="utf-8").strip()
        if len(text) > max_chars:
            text = text[:max_chars].rstrip() + "\n..."
        cards.append({"card_id": path.stem, "content": text})
    return cards


# ── Evidence resolver ──


def _question_spec_keypoint_rows(
    db: CaseDB, keypoint: str
) -> tuple[str, list[dict[str, Any]]] | None:
    """Resolve a keypoint declared by question_routing.yaml evidence_chain."""
    normalized = str(keypoint or "").strip()
    if not normalized:
        return None
    for spec in load_question_specs():
        if normalized not in set(spec.keypoints):
            continue
        rows: list[dict[str, Any]] = []
        for index, entry in enumerate(spec.evidence_chain, start=1):
            query = str(entry.get("query") or "").strip()
            if not query:
                continue
            query = expand_catalog_sql_placeholders(query)
            source = str(entry.get("source") or f"query_{index}").strip()
            try:
                source_rows = _report_keypoint_rows(db, query)
            except Exception:
                continue
            rows.extend({**row, "_question_source": source} for row in source_rows)
        return (
            spec.intent or f"Evidence chain for question spec {spec.semantic_id}.",
            project_rows_for_question_spec(spec, rows),
        )
    return None


def _resolve_evidence_results(
    case: Case,
    db: CaseDB,
    *,
    keypoints: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Resolve named keypoints against the database and return structured evidence result dicts."""
    results: list[dict[str, Any]] = []
    seen_keypoints: set[str] = set()
    for keypoint in keypoints or []:
        normalized = str(keypoint or "").strip()
        if not normalized or normalized in seen_keypoints:
            continue
        seen_keypoints.add(normalized)
        if normalized in {"top_keypoints", "memory_keypoint_cards"}:
            cards = _load_keypoint_cards(case)
            results.append(
                {
                    "keypoint": normalized,
                    "description": "Current memory keypoint cards derived from findings.",
                    "kind": "rows",
                    "source_kind": "keypoint",
                    "source_ref": normalized,
                    "row_count": len(cards),
                    "evidence_ids": [],
                    "finding_ids": [],
                    "hypothesis_ids": [],
                    "sample_rows": cards,
                }
            )
            continue
        resolved_name = REPORT_KEYPOINT_ALIASES.get(normalized, normalized)
        resolver_entry = REPORT_KEYPOINTS.get(resolved_name)
        if resolver_entry is None:
            spec_result = _question_spec_keypoint_rows(db, resolved_name)
            if spec_result is None:
                raise ValueError(f"unknown report template keypoint: {normalized}")
            description, rows = spec_result
            results.append(
                _summarize_rows(
                    source_type="keypoint",
                    source_id=normalized,
                    description=description,
                    rows=rows,
                )
            )
            continue
        description, resolver = resolver_entry
        rows = resolver(db)
        results.append(
            _summarize_rows(
                source_type="keypoint",
                source_id=normalized,
                description=description,
                rows=rows,
            )
        )
    return results
