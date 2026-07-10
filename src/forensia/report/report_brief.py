"""Report brief assembly: top findings, hypotheses, and case context."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.textutil import sanitize_ingest_path
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.report.benign_auth import finding_is_auth_scoped, is_benign_local_auth
from forensia.report.evidence_refs import (
    _extract_evidence_ids_from_value,
)
from forensia.report.markdown import (
    _render_timestamp_with_timezone,
    _tz_offset_str,
)
from forensia.report.ranking import (
    load_top_findings_priority_keywords,
    priority_rank,
)
from forensia.report.section_quality import _collect_section_coverage
from forensia.report.section_store import _claim_text_key

# ====================================================================
# RENDER HELPERS — markdown table rendering, timestamp formatting
# Lines: ~2206-2910
# ====================================================================


def _query_top_findings(
    db: CaseDB,
    limit: int = 8,
    *,
    priority_keywords: list[list[str]] | None = None,
) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT
          finding_id, title, severity, confidence, summary, evidence,
          CASE
            -- Report-worthiness is decided generically: a finding mapped to an
            -- ATT&CK technique leads over an unmapped one at the same severity.
            -- There is intentionally no keyword bias toward any particular
            -- case's event IDs, applications, or tooling, so the leading thesis
            -- generalizes across cases. The single finding-id-specific entry
            -- below only demotes a known-noisy correlation rule.
            WHEN finding_id LIKE 'windows-corr-logon-then-service%' THEN 9
            WHEN attack IS NOT NULL
              AND TRIM(CAST(attack AS VARCHAR)) NOT IN ('', '[]', 'null', '{}') THEN 0
            ELSE 1
          END AS signal_rank
        FROM findings
        WHERE COALESCE(status, 'accepted') != 'suppressed'
          AND severity IN ('critical','high','medium')
          AND confidence >= 0.5
          AND COALESCE(title, '') != ''
          AND title NOT LIKE '%:  @%'
          AND NOT (finding_id LIKE 'windows-corr-logon-then-service%' AND confidence < 0.7)
        ORDER BY
          signal_rank,
          CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
          confidence DESC,
          created_at DESC
        LIMIT ?
        """,
        (max(limit * 6, limit),),
    )
    # Presentation policy supplied by the active template set (report/ranking.py):
    # when it declares a priority-keyword ordering, regroup the severity-ranked
    # rows into those narrative tiers. The stable sort keeps the generic
    # severity / confidence order within each tier, and with no policy the rows
    # keep the case-agnostic default order — so an external question sheet's narrative order
    # lives in its overview template's frontmatter, not in this core query.
    if priority_keywords:
        rows = sorted(
            rows,
            key=lambda r: priority_rank(
                f"{r.get('finding_id', '')} {r.get('title', '')} "
                f"{r.get('summary', '')}",
                priority_keywords,
            ),
        )
    # RPT-04: a self-referential machine account ("<COMPUTER>$") using explicit
    # credentials (4648) locally on its own host is normal Windows behavior
    # (e.g. winlogon.exe credential prompts), not a lateral-movement signal.
    # Demote such rows below genuinely cross-host candidates instead of
    # letting them dominate the top slots.
    local_machine_rows: list[dict[str, Any]] = []
    other_rows: list[dict[str, Any]] = []
    for row in rows:
        if _is_local_machine_account_4648(row):
            local_machine_rows.append(row)
        else:
            other_rows.append(row)
    rows = [*other_rows, *local_machine_rows]

    normalized: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    seen_titles: set[str] = set()
    for row in rows:
        item = normalize_value(row)
        if isinstance(item, dict):
            title_key = _claim_text_key(str(item.get("title") or ""))
            if title_key and title_key in seen_titles:
                continue
            finding_id = str(item.get("finding_id") or "")
            family = re.sub(r"-\d{3,}$", "", finding_id) or finding_id
            if family_counts.get(family, 0) >= 3:
                continue
            family_counts[family] = family_counts.get(family, 0) + 1
            if title_key:
                seen_titles.add(title_key)
            evidence_ids = _extract_evidence_ids_from_value(item.get("evidence"))
            if evidence_ids:
                item["evidence_ids"] = evidence_ids[:5]
            item["evidence"] = _sanitize_evidence_paths(item.get("evidence"))
            item.pop("signal_rank", None)
        normalized.append(item)
        if len(normalized) >= limit:
            break
    return normalized


_EVIDENCE_PATH_KEYS = ("source_file", "prefetch_file", "executable_path")


def _short_path_context(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    text = sanitize_ingest_path(text)
    parts = [part for part in re.split(r"[\\/]+", text) if part]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else text


def _sanitize_evidence_paths(evidence: Any) -> Any:
    """Reduce local ingest paths in finding evidence to basenames.

    Defense-in-depth for the report brief: findings persisted before the
    engine-side sanitize (or by a resumed case whose rules were not
    re-seeded) still carry raw ingest paths like ``sample/<case>/...pf`` in
    their evidence rows. Sanitizing at brief-build time guarantees the local
    filesystem layout never reaches report_brief.json regardless of when the
    finding was stored. Real Windows paths are left unchanged.
    """
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (json.JSONDecodeError, TypeError):
            return evidence
    if not isinstance(evidence, list):
        return evidence
    out: list[Any] = []
    for entry in evidence:
        if isinstance(entry, dict):
            entry = {
                key: (
                    sanitize_ingest_path(value)
                    if key in _EVIDENCE_PATH_KEYS and value
                    else value
                )
                for key, value in entry.items()
            }
        out.append(entry)
    return out


def _is_local_machine_account_4648(row: dict[str, Any]) -> bool:
    """True when a finding's evidence is all benign local auth.

    Delegates to :func:`is_benign_local_auth` for each evidence row.
    Returns True when every evidence entry in the row is benign local auth
    (loopback src_ip, machine-account subject, local auth processes, etc.)

    Auth rule queries often filter on an event ID without SELECTing it, so
    evidence rows may lack ``event_id``; when the finding is itself scoped to
    an auth event (rule_id / title), the predicate is applied on that basis.
    """
    evidence = row.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = []
    if not isinstance(evidence, list):
        return False
    if not evidence:
        return False
    assume_auth = finding_is_auth_scoped(
        row.get("rule_id") or row.get("finding_id"), row.get("title")
    )
    for entry in evidence:
        if not isinstance(entry, dict):
            return False
        if not is_benign_local_auth(entry, assume_auth_event=assume_auth):
            return False
    return True


def _query_hypotheses_by_status(
    db: CaseDB, status: str, limit: int = 8
) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids, required_entities
        FROM hypotheses
        WHERE status = ?
        ORDER BY updated_at DESC, hypothesis_id
        LIMIT ?
        """,
        (status, limit),
    )


def _query_prior_sections(db: CaseDB) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT section_key, title, LEFT(body, 400) AS body_excerpt, confidence, status
        FROM report_sections
        WHERE COALESCE(body, '') != ''
        ORDER BY section_key
        """,
    )


def _query_existing_claims(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT section_key, claim_text, support_status
        FROM claims
        ORDER BY updated_at DESC, claim_id DESC
        LIMIT ?
        """,
        (limit,),
    )


def _dedupe_claims(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        key = _claim_text_key(str(item.get("claim_text") or ""))
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(normalize_value(item))
    return deduped


def _query_evtx_time_range(db: CaseDB, case: Case | None = None) -> dict[str, str]:
    rows = fetch_records(
        db,
        "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events",
    )
    time_range: dict[str, str] = {}
    if rows:
        first = str(rows[0].get("first_event") or "")
        last = str(rows[0].get("last_event") or "")
        if first or last:
            time_range = {
                "first_event": _render_timestamp_with_timezone(first, case)
                if first
                else "unknown",
                "last_event": _render_timestamp_with_timezone(last, case)
                if last
                else "unknown",
            }
    return time_range


def _summarize_section_coverage(db: CaseDB) -> dict[str, Any]:
    coverage_map = _collect_section_coverage(db)
    return {
        "sections": coverage_map,
        "section_count": len(coverage_map),
        "total_sources": sum(len(items) for items in coverage_map.values()),
    }


def _hypothesis_source_rule_ids(item: dict[str, Any]) -> list[str]:
    raw = item.get("source_rule_ids")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = []
    if not isinstance(raw, list):
        return []
    return [str(rule_id).strip() for rule_id in raw if str(rule_id or "").strip()]


def _rule_ids_have_benign_context(db: CaseDB, rule_ids: list[str]) -> bool:
    """True when every finding produced by these rule_ids is benign-context tagged.

    A hypothesis whose only rule-seeded evidence is downgraded to a known-benign
    pattern should not be treated as strong narrative support (RPT-02).
    """
    if not rule_ids:
        return False
    placeholders = ", ".join("?" for _ in rule_ids)
    rows = fetch_records(
        db,
        f"SELECT tags FROM findings WHERE rule_id IN ({placeholders})",
        tuple(rule_ids),
    )
    if not rows:
        return False
    return all(_has_benign_context_tag(row) for row in rows)


def _annotate_confirmed_hypotheses(
    db: CaseDB, items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Annotate confirmed hypotheses with provenance flags for narrative weighting.

    - `rule_seeded`: the hypothesis was seeded from a detection rule
      (`source_rule_ids` non-empty) rather than derived from a generic gap.
    - `benign_context`: every rule-seeded finding behind this hypothesis was
      itself downgraded to a known-benign pattern.
    - `narrative_strength`: "strong" only when rule-seeded AND not
      benign-context; otherwise "weak". Narrative sections should not treat
      "weak" confirmed hypotheses as the backbone of the main storyline.
    """
    annotated: list[dict[str, Any]] = []
    for item in items:
        rule_ids = _hypothesis_source_rule_ids(item)
        rule_seeded = bool(rule_ids)
        benign_context = _rule_ids_have_benign_context(db, rule_ids)
        item = dict(item)
        item["rule_seeded"] = rule_seeded
        item["benign_context"] = benign_context
        item["narrative_strength"] = (
            "strong" if rule_seeded and not benign_context else "weak"
        )
        annotated.append(item)
    return annotated


def _build_report_brief(
    db: CaseDB,
    case: Case | None = None,
    *,
    template_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Assemble a structured brief of top findings, hypotheses, section excerpts, and coverage data for LLM context."""
    tz_name = getattr(case, "source_timezone", "UTC") if case else "UTC"
    tz_offset = _tz_offset_str(tz_name) if tz_name != "UTC" else ""
    # The leading-thesis ordering policy travels with the active template set,
    # not with this core builder (report/ranking.py). Fall back to the case's
    # bundled templates when an explicit dir is not threaded in.
    resolved_template_dir = template_dir or (
        getattr(case, "report_template_dir", None) if case else None
    )
    priority_keywords = load_top_findings_priority_keywords(resolved_template_dir)
    return {
        "top_findings": [
            normalize_value(item)
            for item in _query_top_findings(db, priority_keywords=priority_keywords)
        ],
        "active_hypotheses": [
            normalize_value(item) for item in _query_hypotheses_by_status(db, "active")
        ],
        "confirmed_hypotheses": [
            normalize_value(item)
            for item in _annotate_confirmed_hypotheses(
                db, _query_hypotheses_by_status(db, "confirmed")
            )
        ],
        "refuted_hypotheses": [
            normalize_value(item) for item in _query_hypotheses_by_status(db, "refuted")
        ],
        "untestable_hypotheses": [
            normalize_value(item)
            for item in _query_hypotheses_by_status(db, "untestable")
        ],
        "prior_sections": _query_prior_sections(db),
        "existing_claims": _dedupe_claims(_query_existing_claims(db)),
        "evidence_coverage": _summarize_section_coverage(db),
        "source_timezone": tz_name,
        "timezone_offset": tz_offset,
        "time_range": _query_evtx_time_range(db, case),
    }


def write_report_brief(
    case: Case, db: CaseDB, *, template_dir: Path | str | None = None
) -> dict[str, Any]:
    """Write the report brief to reports/report_brief.json and return the dict."""
    brief = _build_report_brief(db, case, template_dir=template_dir)
    overview_path = case.memory_dir / "overview.md"
    if overview_path.exists():
        overview_text = overview_path.read_text(encoding="utf-8")
        match = re.search(r"## Investigation Objective\s+-\s+(.+)", overview_text)
        if match:
            brief["investigation_objective"] = match.group(1).strip()
    path = case.reports_dir / "report_brief.json"
    path.write_text(
        json.dumps(brief, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    # Post-generation validation: warn (never block) on thesis/evidence
    # misalignment, refuted-content leakage, and contradictory verdicts.
    from forensia.report.report_validation import validate_report

    for issue in validate_report(brief):
        _log("VALIDATION", f"[{issue.severity}] {issue.check_name}: {issue.message}")
    return brief


def _has_benign_context_tag(row: dict[str, Any]) -> bool:
    tags = row.get("tags")
    if not tags:
        return False
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except json.JSONDecodeError, TypeError:
            return False
    if isinstance(tags, list):
        return any("benign-context:" in str(t).lower() for t in tags)
    return False


build_report_brief = _build_report_brief
query_top_findings = _query_top_findings
