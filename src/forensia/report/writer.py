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
        "Service installation or creation events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, service_name, subject_user, message, evidence_id
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
    "benchmark_overview_session_activity": (
        "Recent logon and shutdown events for benchmark scoping.",
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
    "benchmark_timeline_core_events": (
        "Benchmark timeline events across startup, shutdown, and logon activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE event_id IN (4608,4609,4624,4634,4647,6005,6006,6008)
            ORDER BY timestamp
            LIMIT 80
            """,
        ),
    ),
    "benchmark_timeline_prefetch": (
        "Benchmark Prefetch execution history for chronology.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 50
            """,
        ),
    ),
    "benchmark_host_prefetch": (
        "Benchmark Prefetch execution records by host context.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 40
            """,
        ),
    ),
    "benchmark_host_user_paths": (
        "Benchmark MFT entries under user profile paths.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE LOWER(file_path) LIKE '%\\users\\%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "benchmark_account_logons": (
        "Benchmark account logon patterns on the suspect PC.",
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
    "benchmark_account_events": (
        "Benchmark account events with evidence IDs.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, logon_type, evidence_id
            FROM evtx_events
            WHERE event_id IN (4624,4634,4647)
            ORDER BY timestamp
            LIMIT 80
            """,
        ),
    ),
    "benchmark_account_identities": (
        "Observed account identities from event records.",
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
    "benchmark_execution_prefetch": (
        "Benchmark Prefetch execution records.",
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
    "benchmark_execution_events": (
        "Benchmark process execution events from Evtx.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, process_name, command_line, target_user, evidence_id
            FROM evtx_events
            WHERE event_id = 4688
            ORDER BY timestamp
            LIMIT 50
            """,
        ),
    ),
    "benchmark_execution_file_activity": (
        "Benchmark file-activity rows related to browsers, mail, cloud, and cleanup tools.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, timestamp_type, file_path, description, evidence_id
            FROM mft_timeline
            WHERE
                LOWER(file_path) LIKE '%eraser%' OR
                LOWER(file_path) LIKE '%ccleaner%' OR
                LOWER(file_path) LIKE '%google%' OR
                LOWER(file_path) LIKE '%outlook%' OR
                LOWER(file_path) LIKE '%chrome%' OR
                LOWER(file_path) LIKE '%iexplore%'
            ORDER BY timestamp
            LIMIT 80
            """,
        ),
    ),
    "benchmark_ioc_prefetch": (
        "Benchmark executable paths from Prefetch.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 60
            """,
        ),
    ),
    "benchmark_ioc_processes": (
        "Benchmark executed processes from Evtx.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT process_name, command_line, computer, evidence_id
            FROM evtx_events
            WHERE event_id = 4688 AND process_name IS NOT NULL
            ORDER BY timestamp
            LIMIT 40
            """,
        ),
    ),
    "benchmark_ioc_files": (
        "Benchmark notable file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE
                LOWER(file_path) LIKE '%desktop%' OR
                LOWER(file_path) LIKE '%google\\drive%' OR
                LOWER(file_path) LIKE '%office%' OR
                LOWER(file_path) LIKE '%outlook%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "benchmark_recommendation_events": (
        "Benchmark events relevant to response recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, event_id, evidence_id
            FROM evtx_events
            WHERE event_id IN (4624,4647,6006,6008,1102,104)
            ORDER BY timestamp
            LIMIT 50
            """,
        ),
    ),
    "benchmark_recommendation_prefetch": (
        "Benchmark executed applications relevant to response recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 50
            """,
        ),
    ),
    "benchmark_recommendation_files": (
        "Benchmark desktop and cloud-related file paths for response recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE LOWER(file_path) LIKE '%desktop%' OR LOWER(file_path) LIKE '%google\\drive%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 50
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
    "benchmark_logon_window": "benchmark_overview_session_activity",
    "benchmark_timeline_events": "benchmark_timeline_core_events",
    "benchmark_timeline_files": "timeline_mft_activity",
    "benchmark_prefetch_recent": "benchmark_timeline_prefetch",
    "benchmark_host_spans": "overview_hosts",
    "benchmark_host_logons": "benchmark_overview_session_activity",
    "benchmark_accounts_summary": "benchmark_account_logons",
    "benchmark_accounts_events": "benchmark_account_events",
    "benchmark_accounts_observed": "benchmark_account_identities",
    "benchmark_exec_processes": "benchmark_execution_events",
    "benchmark_exec_related_mft": "benchmark_execution_file_activity",
    "benchmark_artifact_processes": "benchmark_ioc_processes",
    "benchmark_artifact_paths": "benchmark_ioc_files",
    "benchmark_reco_system_events": "benchmark_recommendation_events",
    "benchmark_reco_desktop_paths": "benchmark_recommendation_files",
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
    for paragraph in re.split(r"\n\s*\n", body):
        text = paragraph.strip()
        if not text or text.startswith("#") or GAP_PATTERN.search(text):
            continue
        normalized = " ".join(line.strip("- ").strip() for line in text.splitlines() if line.strip())
        if normalized:
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
        "existing_claims": [normalize_value(item) for item in existing_claims],
    }


def write_report_brief(case: Case, db: CaseDB) -> dict[str, Any]:
    brief = _build_report_brief(db)
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
) -> None:
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
        return
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
    candidate_gaps = collect_gaps({section_key: body})
    candidate_confidence = _section_confidence(body)
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
    _upsert_claims(db, section_key, body, evidence_results or [])
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
