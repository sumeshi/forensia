from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from forensia.ai.lmstudio import chat_completion
from forensia.ai.prompts import build_report_section_messages
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.report.html import render_html_report

GAP_PATTERN = re.compile(
    r"【調査不足:\s*([^】]+)】|\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]",
    re.IGNORECASE,
)
PLACEHOLDER_ENTITY_PATTERN = re.compile(r"(?<![\w/.-])(none|n/?a|null)(?![\w/.-])", re.IGNORECASE)
EVIDENCE_ID_PATTERN = re.compile(r"\bev-[A-Za-z0-9._:-]+\b")
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
FINDING_ID_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9-]*-\d{4}\b")
HTML_FILL_PATTERN = re.compile(r"<!--\s*fill(?:[^>]*)-->", re.IGNORECASE)
EvidenceResolver = Callable[[CaseDB], list[dict[str, Any]]]


@lru_cache(maxsize=None)
def _parse_template(template_path: str) -> tuple[dict[str, Any], str]:
    text = Path(template_path).read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    _, frontmatter, body = text.split("---\n", 2)
    meta = yaml.safe_load(frontmatter) or {}
    return meta, body.strip()


def _section_confidence(body: str) -> float:
    paragraphs = [item.strip() for item in re.split(r"\n\s*\n", body) if item.strip()]
    paragraph_count = max(len(paragraphs), 1)
    gap_count = len(GAP_PATTERN.findall(body))
    return max(0.0, min(1.0, 1.0 - (gap_count / paragraph_count)))


def _timeline_rows_are_chronological(body: str) -> bool:
    timestamps: list[str] = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        stripped = line.strip()
        if stripped.startswith("|---") or "Timestamp" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if not first or "<!--" in first:
            continue
        timestamps.append(first)
    return timestamps == sorted(timestamps)


def _normalized_text_key(text: str) -> str:
    lowered = text.casefold()
    cleaned = re.sub(r"[^a-z0-9]+", " ", lowered)
    return " ".join(cleaned.split())


def _first_heading_text(body: str) -> str:
    for line in body.splitlines():
        match = HEADING_PATTERN.match(line.strip())
        if match and len(match.group(1)) == 1:
            return match.group(2).strip()
    return ""


def _title_matches_body_heading(title: str, body: str) -> bool:
    heading = _first_heading_text(body)
    if not heading:
        return True
    normalized_title = _normalized_text_key(title)
    normalized_heading = _normalized_text_key(heading)
    return (
        not normalized_title
        or not normalized_heading
        or normalized_title in normalized_heading
        or normalized_heading in normalized_title
    )


def _duplicate_finding_titles(db: CaseDB, body: str) -> list[str]:
    lowered_body = body.casefold()
    duplicates: list[str] = []
    rows = fetch_records(
        db,
        """
        SELECT DISTINCT title
        FROM findings
        WHERE COALESCE(title, '') != ''
        """,
    )
    for row in rows:
        title = str(row.get("title") or "").strip()
        if len(title) < 5:
            continue
        count = lowered_body.count(title.casefold())
        if count > 2:
            duplicates.append(title)
    return duplicates


def _correlation_finding_ids(finding_ids: list[str], db: CaseDB) -> list[str]:
    if not finding_ids:
        return []
    placeholders = ", ".join("?" for _ in finding_ids)
    rows = fetch_records(
        db,
        f"""
        SELECT finding_id
        FROM findings
        WHERE finding_id IN ({placeholders})
          AND rule_id LIKE '%corr-%'
        """,
        tuple(finding_ids),
    )
    return [str(row.get("finding_id") or "") for row in rows if str(row.get("finding_id") or "")]


def _quality_gate_section(
    section_key: str,
    title: str,
    body: str,
    gaps: list[str],
    confidence: float,
) -> tuple[list[str], float]:
    gated_gaps = list(gaps)
    gated_confidence = confidence
    if PLACEHOLDER_ENTITY_PATTERN.search(body):
        note = "Placeholder entity values detected; additional review is required."
        if note not in gated_gaps:
            gated_gaps.append(note)
        gated_confidence = min(gated_confidence, 0.5)
    if HTML_FILL_PATTERN.search(body):
        note = "Template placeholder markers remain in the section body."
        if note not in gated_gaps:
            gated_gaps.append(note)
        gated_confidence = min(gated_confidence, 0.3)
    if not _title_matches_body_heading(title, body):
        note = "Section heading does not match the expected section title; review for claim/title consistency."
        if note not in gated_gaps:
            gated_gaps.append(note)
        gated_confidence = min(gated_confidence, 0.65)
    if section_key == "2_timeline" and not _timeline_rows_are_chronological(body):
        note = "Timeline ordering requires review; events are not strictly chronological."
        if note not in gated_gaps:
            gated_gaps.append(note)
        gated_confidence = min(gated_confidence, 0.6)
    if section_key == "8_recommendations":
        lowered = body.lower()
        strength_markers = (
            "confirmed",
            "strongly suggests",
            "may indicate",
            "additional verification",
            "consider containment after verification",
        )
        if not any(marker in lowered for marker in strength_markers):
            note = "Recommendations should state evidence strength or verification-first wording."
            if note not in gated_gaps:
                gated_gaps.append(note)
            gated_confidence = min(gated_confidence, 0.65)
    return gated_gaps, gated_confidence


def _sort_markdown_table_by_first_column(body: str) -> str:
    lines = body.splitlines()
    sorted_lines: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("|") or index + 1 >= len(lines) or not lines[index + 1].startswith("|---"):
            sorted_lines.append(line)
            index += 1
            continue
        header = line
        separator = lines[index + 1]
        rows: list[str] = []
        index += 2
        while index < len(lines) and lines[index].startswith("|"):
            rows.append(lines[index])
            index += 1
        def sort_key(row: str) -> str:
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            return cells[0] if cells else ""
        sorted_lines.extend([header, separator, *sorted(rows, key=sort_key)])
    return "\n".join(sorted_lines)


def _validate_body_evidence_ids(db: CaseDB, body: str) -> list[str]:
    evidence_ids = sorted(set(EVIDENCE_ID_PATTERN.findall(body)))
    if not evidence_ids:
        return []
    placeholders = ", ".join("?" for _ in evidence_ids)
    found = {
        str(row[0])
        for row in db.execute(
            f"""
            SELECT evidence_id FROM evtx_events WHERE evidence_id IN ({placeholders})
            UNION
            SELECT evidence_id FROM mft_entries WHERE evidence_id IN ({placeholders})
            """,
            tuple(evidence_ids + evidence_ids),
        ).fetchall()
    }
    return [evidence_id for evidence_id in evidence_ids if evidence_id not in found]



def _summarize_rows(
    *,
    source_type: str,
    source_id: str,
    description: str,
    rows: list[dict[str, Any]],
    max_rows: int = 20,
) -> dict[str, Any]:
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    for row in rows:
        evidence_id = row.get("evidence_id")
        if evidence_id:
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
        "row_count": len(rows),
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
        "sample_rows": [normalize_value(row) for row in rows[:max_rows]],
    }


def _report_keypoint_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return fetch_records(db, query)


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
        "Observed hosts ranked by event volume.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, COUNT(*) AS event_count
            FROM evtx_events
            WHERE computer IS NOT NULL
            GROUP BY computer
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
            SELECT finding_id, title, severity, confidence
            FROM findings
            WHERE severity IN ('critical','high')
            ORDER BY confidence DESC
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
            SELECT timestamp, computer, target_user, src_ip, evidence_id
            FROM evtx_events
            WHERE event_id IN (1102, 104)
            ORDER BY timestamp
            """,
        ),
    ),
    "host_compromise_candidates": (
        "Hosts with logon, execution, persistence, or log-clear activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
            FROM evtx_events
            WHERE event_id IN (4624,4625,4648,4688,4697,4698,5140,1102)
            GROUP BY computer
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
            WHERE event_id IN (1102,104,4719)
            GROUP BY event_id
            """,
        ),
    ),
    "recommendations_findings": (
        "Top findings that should drive recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, severity, confidence, status, ai_summary
            FROM findings
            ORDER BY confidence DESC
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
            WHERE event_id IN (4624,4634,4647,4608,4609,6005,6006,6008)
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
            WHERE event_id IN (1074,4608,4609,4624,4634,4647,6005,6006,6008)
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
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE
                LOWER(file_path) LIKE '%/desktop/%' OR
                LOWER(file_path) LIKE '%/office/%' OR
                LOWER(file_path) LIKE '%/outlook/%' OR
                LOWER(file_path) LIKE '%googledrivesync%' OR
                LOWER(file_path) LIKE '%/icloud%' OR
                LOWER(file_path) LIKE '%/onedrive%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "ioc_email_ost_files": (
        "Email OST/PST mailbox cache file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE extension IN ('ost', 'pst')
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
}

REPORT_KEYPOINT_ALIASES = {
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
    "benchmark_window": "overview_event_range",
    "benchmark_hosts": "overview_hosts",
    "benchmark_logon_window": "session_activity_events",
    "benchmark_timeline_events": "timeline_system_events",
    "benchmark_timeline_files": "timeline_mft_activity",
    "benchmark_prefetch_recent": "timeline_prefetch_history",
    "benchmark_host_spans": "overview_hosts",
    "benchmark_host_logons": "session_activity_events",
    "benchmark_accounts_summary": "account_all_logon_summary",
    "benchmark_accounts_events": "account_logon_events",
    "benchmark_accounts_observed": "account_observed_users",
    "benchmark_exec_processes": "host_execution_activity",
    "benchmark_exec_related_mft": "mft_user_app_activity",
    "benchmark_artifact_processes": "mft_prefetch_filenames",
    "benchmark_artifact_paths": "ioc_user_data_files",
    "benchmark_ost_file": "ioc_email_ost_files",
    "benchmark_recent_lnk": "mft_recent_folder_lnk",
    "benchmark_reco_system_events": "timeline_system_events",
    "benchmark_reco_desktop_paths": "ioc_user_data_files",
}


def _resolve_evidence_results(
    case: Case,
    db: CaseDB,
    *,
    keypoints: list[str] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for keypoint in (keypoints or []):
        normalized = str(keypoint or "").strip()
        if not normalized:
            continue
        if normalized in {"top_keypoints", "memory_keypoint_cards"}:
            cards = _load_keypoint_cards(case)
            results.append(
                {
                    "keypoint": normalized,
                    "description": "Current memory keypoint cards derived from findings.",
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
            raise ValueError(f"unknown report template keypoint: {normalized}")
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


def _load_keypoint_cards(case: Case, max_cards: int = 8, max_chars: int = 1200) -> list[dict[str, str]]:
    cards: list[dict[str, str]] = []
    for path in sorted(case.memory_dir.glob("keypoints/KP-*.md"))[:max_cards]:
        text = path.read_text(encoding="utf-8").strip()
        if len(text) > max_chars:
            text = text[:max_chars].rstrip() + "\n..."
        cards.append({"card_id": path.stem, "content": text})
    return cards



def _extract_claim_texts(body: str) -> list[str]:
    claims: list[str] = []
    seen: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", body):
        text = paragraph.strip()
        if not text or text.startswith("#") or GAP_PATTERN.search(text):
            continue
        normalized = " ".join(line.strip("- ").strip() for line in text.splitlines() if line.strip())
        key = _claim_text_key(normalized)
        if normalized and normalized not in ("[]", "{}", "<!--", "-->") and key not in seen:
            seen.add(key)
            claims.append(normalized)
    return claims


def _claim_text_key(text: str) -> str:
    return " ".join(text.lower().split())


def _collect_claim_provenance(evidence_results: list[dict[str, Any]]) -> dict[str, list[str]]:
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    for result in evidence_results:
        for evidence_id in result.get("evidence_ids") or []:
            value = str(evidence_id)
            if value and value not in seen_evidence_ids:
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        for finding_id in result.get("finding_ids") or []:
            value = str(finding_id)
            if value and value not in seen_finding_ids:
                seen_finding_ids.add(value)
                finding_ids.append(value)
        for hypothesis_id in result.get("hypothesis_ids") or []:
            value = str(hypothesis_id)
            if value and value not in seen_hypothesis_ids:
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
    }


def _build_report_brief(db: CaseDB) -> dict[str, Any]:
    findings = fetch_records(
        db,
        """
        SELECT finding_id, title, severity, confidence, summary
        FROM findings
        WHERE COALESCE(status, 'accepted') != 'suppressed'
        ORDER BY confidence DESC, created_at DESC
        LIMIT 8
        """,
    )
    active_hypotheses = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary
        FROM hypotheses
        WHERE status = 'active'
        ORDER BY updated_at DESC, hypothesis_id
        LIMIT 8
        """,
    )
    prior_sections = fetch_records(
        db,
        """
        SELECT section_key, title, LEFT(body, 400) AS body_excerpt, confidence, status
        FROM report_sections
        WHERE COALESCE(body, '') != ''
        ORDER BY section_key
        """,
    )
    existing_claims = fetch_records(
        db,
        """
        SELECT section_key, claim_text, support_status
        FROM claims
        ORDER BY updated_at DESC, claim_id DESC
        LIMIT 20
        """,
    )
    deduped_claims: list[dict[str, Any]] = []
    seen_claim_keys: set[str] = set()
    for item in existing_claims:
        key = _claim_text_key(str(item.get("claim_text") or ""))
        if not key or key in seen_claim_keys:
            continue
        seen_claim_keys.add(key)
        deduped_claims.append(normalize_value(item))
    return {
        "top_findings": [normalize_value(item) for item in findings],
        "active_hypotheses": [normalize_value(item) for item in active_hypotheses],
        "prior_sections": [
            {
                "section_key": item["section_key"],
                "title": item["title"],
                "confidence": item["confidence"],
                "status": item["status"],
                "excerpt": str(item.get("body_excerpt") or "").strip(),
            }
            for item in prior_sections
        ],
        "existing_claims": deduped_claims,
    }


def write_report_brief(case: Case, db: CaseDB) -> dict[str, Any]:
    brief = _build_report_brief(db)
    overview_path = case.memory_dir / "overview.md"
    if overview_path.exists():
        overview_text = overview_path.read_text(encoding="utf-8")
        match = re.search(r"## Investigation Objective\s+-\s+(.+)", overview_text)
        if match:
            brief["investigation_objective"] = match.group(1).strip()
    path = case.reports_dir / "report_brief.json"
    path.write_text(json.dumps(brief, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return brief


def _claim_support_status(
    db: CaseDB,
    evidence_ids: list[str],
    finding_ids: list[str],
    hypothesis_ids: list[str],
) -> str:
    if not evidence_ids and not finding_ids and not hypothesis_ids:
        return "unsupported"
    if finding_ids:
        placeholders = ", ".join("?" for _ in finding_ids)
        found_finding_ids = {
            str(row[0])
            for row in db.execute(
                f"SELECT finding_id FROM findings WHERE finding_id IN ({placeholders})",
                tuple(finding_ids),
            ).fetchall()
        }
        if any(finding_id not in found_finding_ids for finding_id in finding_ids):
            return "orphaned_reference"
    if hypothesis_ids:
        placeholders = ", ".join("?" for _ in hypothesis_ids)
        found_hypothesis_ids = {
            str(row[0])
            for row in db.execute(
                f"SELECT hypothesis_id FROM hypotheses WHERE hypothesis_id IN ({placeholders})",
                tuple(hypothesis_ids),
            ).fetchall()
        }
        if any(hypothesis_id not in found_hypothesis_ids for hypothesis_id in hypothesis_ids):
            return "orphaned_reference"
    if evidence_ids:
        placeholders = ", ".join("?" for _ in evidence_ids)
        found_evidence_ids = {
            str(row[0])
            for row in db.execute(
                f"""
                SELECT evidence_id FROM evtx_events WHERE evidence_id IN ({placeholders})
                UNION
                SELECT evidence_id FROM mft_entries WHERE evidence_id IN ({placeholders})
                """,
                tuple(evidence_ids + evidence_ids),
            ).fetchall()
        }
        if any(evidence_id not in found_evidence_ids for evidence_id in evidence_ids):
            return "orphaned_reference"
    return "supported"


def _upsert_claims(
    db: CaseDB,
    section_key: str,
    body: str,
    evidence_results: list[dict[str, Any]],
) -> list[str]:
    now = datetime.now(UTC).replace(tzinfo=None)
    claims = _extract_claim_texts(body)
    provenance = _collect_claim_provenance(evidence_results)
    support_status = _claim_support_status(
        db,
        provenance["evidence_ids"],
        provenance["finding_ids"],
        provenance["hypothesis_ids"],
    )
    db.execute("DELETE FROM claims WHERE section_key = ?", (section_key,))
    rows: list[tuple[Any, ...]] = []
    for index, claim_text in enumerate(claims, start=1):
        claim_id = hashlib.sha1(f"{section_key}-{index}-{claim_text}".encode("utf-8")).hexdigest()[:16]
        rows.append(
            (
                claim_id,
                section_key,
                claim_text,
                json.dumps(provenance["finding_ids"], ensure_ascii=False),
                json.dumps(provenance["hypothesis_ids"], ensure_ascii=False),
                json.dumps(provenance["evidence_ids"], ensure_ascii=False),
                support_status,
                now,
                now,
            )
        )
    db.insert_many(
        """
        INSERT INTO claims (
            claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
            support_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if not claims:
        return []
    text_groups = fetch_records(
        db,
        """
        SELECT claim_id, claim_text, section_key, finding_ids, hypothesis_ids, evidence_ids, support_status
        FROM claims
        WHERE claim_text IN (
            SELECT claim_text FROM claims GROUP BY claim_text HAVING COUNT(*) > 1
        )
        ORDER BY claim_text, section_key, claim_id
        """,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in text_groups:
        grouped.setdefault(_claim_text_key(str(row.get("claim_text") or "")), []).append(row)
    for rows_for_text in grouped.values():
        provenance_keys = {
            json.dumps(
                {
                    "finding_ids": normalize_value(row.get("finding_ids")) or [],
                    "hypothesis_ids": normalize_value(row.get("hypothesis_ids")) or [],
                    "evidence_ids": normalize_value(row.get("evidence_ids")) or [],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            for row in rows_for_text
        }
        if len(provenance_keys) <= 1:
            continue
        for row in rows_for_text:
            db.execute(
                "UPDATE claims SET support_status = 'needs_review', updated_at = ? WHERE claim_id = ?",
                (now, str(row["claim_id"])),
            )
    statuses = fetch_records(
        db,
        "SELECT DISTINCT support_status FROM claims WHERE section_key = ?",
        (section_key,),
    )
    return [str(row.get("support_status") or "") for row in statuses if str(row.get("support_status") or "")]


def _update_section_quality_only(
    db: CaseDB,
    section_key: str,
    confidence: float,
    gaps: list[str],
) -> None:
    row = db.execute(
        "SELECT status FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(row[0] or "draft") if row else "draft"
    if gaps or confidence < 0.9:
        next_status = existing_status if existing_status in {"ai_exhausted", "human_reviewed"} else "draft"
    else:
        next_status = existing_status
    db.execute(
        """
        UPDATE report_sections
        SET confidence = ?, gaps = ?, status = ?
        WHERE section_key = ?
        """,
        (confidence, json.dumps(gaps, ensure_ascii=False), next_status, section_key),
    )


def _upsert_report_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    confidence: float,
    gaps: list[str],
    session_id: str | None = None,
) -> bool:
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        "SELECT status, update_count, body FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(existing[0] or "draft") if existing else "draft"
    if existing_status == "human_reviewed" and str(existing[2] or "").strip():
        return False
    update_count = int(existing[1] or 0) + 1 if existing else 1
    if gaps or confidence < 0.9:
        next_status = "draft"
    elif existing_status == "human_reviewed":
        next_status = "human_reviewed"
    elif existing_status == "ai_exhausted":
        next_status = "ai_exhausted"
    else:
        next_status = "stable"
    db.execute(
        """
        INSERT INTO report_sections (
            section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (section_key) DO UPDATE SET
            title = excluded.title,
            body = excluded.body,
            confidence = excluded.confidence,
            status = excluded.status,
            update_count = excluded.update_count,
            gaps = excluded.gaps,
            last_filled_session = excluded.last_filled_session,
            last_filled_at = excluded.last_filled_at
        """,
        (
            section_key,
            title,
            body,
            confidence,
            next_status,
            update_count,
            json.dumps(gaps, ensure_ascii=False),
            session_id,
            now,
        ),
    )
    return True


def mark_report_sections_ai_exhausted(db: CaseDB) -> None:
    db.execute(
        """
        UPDATE report_sections
        SET status = 'ai_exhausted'
        WHERE COALESCE(body, '') != ''
        """
    )


def set_report_section_status(db: CaseDB, section_key: str, status: str) -> None:
    if status not in {"draft", "stable", "ai_exhausted", "human_reviewed"}:
        raise ValueError(f"unsupported report section status: {status}")
    db.execute(
        """
        UPDATE report_sections
        SET status = ?
        WHERE section_key = ?
        """,
        (status, section_key),
    )


def fetch_report_sections(db: CaseDB) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )


def load_report_sections_map(db: CaseDB) -> dict[str, str]:
    return {
        str(row.get("section_key")): str(row.get("body") or "")
        for row in fetch_report_sections(db)
    }


def build_report_markdown_from_db(db: CaseDB) -> str:
    sections = fetch_report_sections(db)
    ordered = [str(row.get("body") or "").strip() for row in sections if str(row.get("body") or "").strip()]
    if not ordered:
        return ""
    return "\n\n".join(ordered).strip() + "\n"


def prepare_section_request(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read template + evidence and build the LLM messages.

    Pure I/O against DuckDB; safe to call from the main thread before
    dispatching parallel LLM workers.
    """
    section_meta, template_body = _parse_template(str(template_path))
    evidence_results = _resolve_evidence_results(
        case,
        db,
        keypoints=list(section_meta.get("keypoints") or []),
    )
    messages = build_report_section_messages(
        section_meta=section_meta,
        evidence_results=evidence_results,
        context_sections=context_sections,
        template_body=template_body,
        report_brief=report_brief,
    )
    section_key = str(section_meta.get("section") or Path(template_path).stem)
    title = str(section_meta.get("title") or section_key)
    return {
        "section_key": section_key,
        "title": title,
        "messages": messages,
        "template_path": str(template_path),
        "evidence_results": evidence_results,
    }


def finalize_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """UPSERT the section into DuckDB. Returns gap list and confidence."""
    if section_key == "2_timeline":
        body = _sort_markdown_table_by_first_column(body)
    candidate_gaps = collect_gaps({section_key: body})
    candidate_confidence = _section_confidence(body)
    missing_evidence_ids = _validate_body_evidence_ids(db, body)
    if missing_evidence_ids:
        candidate_gaps.append(
            f"Referenced evidence_id values not found in database: {', '.join(missing_evidence_ids[:5])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    candidate_gaps, candidate_confidence = _quality_gate_section(
        section_key,
        title,
        body,
        candidate_gaps,
        candidate_confidence,
    )
    duplicate_titles = _duplicate_finding_titles(db, body)
    if duplicate_titles:
        candidate_gaps.append(
            f"Finding titles are repeated too often in this section: {', '.join(duplicate_titles[:3])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    updated = _upsert_report_section(
        db=db,
        section_key=section_key,
        title=title,
        body=body,
        confidence=candidate_confidence,
        gaps=candidate_gaps,
        session_id=session_id,
    )
    if not updated:
        row = db.execute(
            "SELECT body, confidence, gaps FROM report_sections WHERE section_key = ?",
            (section_key,),
        ).fetchone()
        persisted_body = str(row[0] or "")
        persisted_confidence = float(row[1] or 0.0)
        persisted_gaps = normalize_value(row[2]) or []
        if not isinstance(persisted_gaps, list):
            persisted_gaps = []
        return {"gaps": persisted_gaps, "confidence": persisted_confidence}
    claim_statuses = _upsert_claims(db, section_key, body, evidence_results or [])
    referenced_finding_ids = sorted(set(FINDING_ID_PATTERN.findall(body)))
    correlation_finding_ids = _correlation_finding_ids(referenced_finding_ids, db)
    if correlation_finding_ids and "confirmed" in body.casefold() and not EVIDENCE_ID_PATTERN.search(body):
        candidate_gaps.append(
            "Correlation-rule findings are described as confirmed without direct evidence_id support; rewrite as hypothesis."
        )
        candidate_confidence = min(candidate_confidence, 0.55)
        _update_section_quality_only(
            db=db,
            section_key=section_key,
            confidence=candidate_confidence,
            gaps=candidate_gaps,
        )
    if any(status in {"unsupported", "orphaned_reference", "needs_review"} for status in claim_statuses):
        claim_gap = "One or more claims require support review due to unsupported, orphaned, or conflicting provenance."
        if claim_gap not in candidate_gaps:
            candidate_gaps.append(claim_gap)
        candidate_confidence = min(candidate_confidence, 0.65)
        _update_section_quality_only(
            db=db,
            section_key=section_key,
            confidence=candidate_confidence,
            gaps=candidate_gaps,
        )
    return {"gaps": candidate_gaps, "confidence": candidate_confidence}


def fill_section(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    session_id: str | None = None,
    audit_callback: Callable[[list[dict[str, str]], str], None] | None = None,
) -> str:
    request = prepare_section_request(case, db, template_path, context_sections, report_brief=report_brief)
    body = chat_completion(messages=request["messages"], model=model, base_url=base_url).strip()
    if audit_callback:
        audit_callback(request["messages"], body)
    finalize_section(
        db=db,
        section_key=request["section_key"],
        title=request["title"],
        body=body,
        evidence_results=request["evidence_results"],
        session_id=session_id,
    )
    return body


def collect_gaps(filled_sections: dict[str, str]) -> list[str]:
    gaps: list[str] = []
    seen: set[str] = set()
    for content in filled_sections.values():
        for match in GAP_PATTERN.finditer(content):
            gap = (match.group(1) or match.group(2) or "").strip()
            if gap and gap not in seen:
                seen.add(gap)
                gaps.append(gap)
    return gaps


def write_report(case: Case, filled_sections: dict[str, str]) -> Path:
    ordered = [filled_sections[key].strip() for key in sorted(filled_sections) if filled_sections[key].strip()]
    report_md = "\n\n".join(ordered).strip() + "\n"
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def write_report_from_db(case: Case, db: CaseDB) -> Path:
    report_md = build_report_markdown_from_db(db)
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def render_written_report(
    case: Case,
    db: CaseDB,
    filled_sections: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    report_md = write_report(case, filled_sections) if filled_sections is not None else write_report_from_db(case, db)
    report_html = render_html_report(case, db)
    return report_md, report_html
