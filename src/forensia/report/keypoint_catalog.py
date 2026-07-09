"""Report keypoint catalog: named SQL resolvers per report section."""

from __future__ import annotations

from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge import (
    expand_catalog_sql_placeholders,
)
from forensia.questions import load_question_specs, project_rows_for_question_spec
from forensia.report.benchmark_keypoints import BENCHMARK_KEYPOINT_ALIASES
from forensia.report.evidence_refs import (
    EvidenceResolver,
    _report_keypoint_rows,
    _summarize_rows,
)
from forensia.report.keypoints_activity import ACTIVITY_KEYPOINTS
from forensia.report.keypoints_host_account import HOST_ACCOUNT_KEYPOINTS
from forensia.report.keypoints_overview_ioc import OVERVIEW_IOC_KEYPOINTS
from forensia.report.keypoints_report_meta import REPORT_META_KEYPOINTS

REPORT_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
    **HOST_ACCOUNT_KEYPOINTS,
    **ACTIVITY_KEYPOINTS,
    **OVERVIEW_IOC_KEYPOINTS,
    **REPORT_META_KEYPOINTS,
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

