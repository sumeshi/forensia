"""Keypoints for gaps, recommendations, hypotheses, and report appendix."""

from __future__ import annotations

from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.answers.event_semantics import LOG_CLEAR_EVENT_SQL
from forensia.report.evidence_refs import (
    EvidenceResolver,
    _extract_needed_evidence,
    _report_keypoint_rows,
)
from forensia.report.sections.report_input import active_report_section_keys


def _report_sections_with_gaps(db: CaseDB) -> list[dict[str, Any]]:
    active = active_report_section_keys(db)
    if active is not None and not active:
        return []
    clause = (
        "AND section_key IN (" + ", ".join("?" for _ in active) + ")"
        if active is not None
        else ""
    )
    return fetch_records(
        db,
        f"""
        SELECT section_key, title, confidence, gaps, status
        FROM report_sections
        WHERE (confidence < 0.7 OR gaps IS NOT NULL) {clause}
        ORDER BY confidence
        LIMIT 20
        """,
        tuple(active) if active is not None else (),
    )


def _appendix_claims_needing_review(db: CaseDB) -> list[dict[str, Any]]:
    active = active_report_section_keys(db)
    if active is not None and not active:
        return []
    clause = (
        "AND section_key IN (" + ", ".join("?" for _ in active) + ")"
        if active is not None
        else ""
    )
    return fetch_records(
        db,
        f"""
        SELECT section_key, claim_text, support_status
        FROM claims
        WHERE support_status IN ('unsupported', 'orphaned_reference', 'needs_review')
        {clause}
        ORDER BY section_key, updated_at DESC
        LIMIT 40
        """,
        tuple(active) if active is not None else (),
    )


def hypothesis_latest_reasoning_cte(exclude_error_phase: bool = True) -> str:
    """Single definition of the "latest reasoning row per hypothesis" CTE.

    All report consumers must resolve the same latest non-error reasoning row.
    """
    filter_sql = " WHERE phase != 'error'" if exclude_error_phase else ""
    return f"""
            WITH latest AS (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY hypothesis_id ORDER BY created_at DESC, entry_id DESC
                ) AS rn
                FROM trace.hypothesis_reasoning{filter_sql}
            )
"""


def _hypothesis_reasoning_rows(
    db: CaseDB,
    *,
    where: str,
    params: tuple[Any, ...] = (),
    limit: int,
) -> list[dict[str, Any]]:
    """Shared resolver for hypothesis rows joined with their latest reasoning."""
    placeholders = ", ".join("?" for _ in params)
    rendered_where = where.format(placeholders=placeholders) if params else where
    rows = fetch_records(
        db,
        f"""
        {hypothesis_latest_reasoning_cte()}
        SELECT h.hypothesis_id, h.description, h.status, h.verdict,
               h.summary, h.updated_at, l.body AS latest_reasoning,
               l.verdict AS latest_verdict
        FROM hypotheses h
        LEFT JOIN latest l ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
        {rendered_where}
        ORDER BY h.updated_at DESC NULLS LAST
        LIMIT {int(limit)}
        """,
        params,
    )

    from forensia.evidence.links import load_evidence_links

    for row in rows:
        roles = (
            {"supporting", "corroborating"}
            if row["status"] == "confirmed"
            else {"contradictory"}
            if row["status"] == "refuted"
            else {"supporting", "corroborating", "contextual", "contradictory"}
        )
        row["evidence_ids"] = sorted(
            {
                link.evidence_id
                for link in load_evidence_links(
                    db, row["hypothesis_id"], current_only=True
                )
                if link.assessment_id and link.role in roles
            }
        )
    return rows


def _needed_evidence_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "hypothesis_id": row["hypothesis_id"],
        "description": row["description"],
        "status": row["status"],
        "verdict": row["verdict"],
        "summary": row["summary"],
        "updated_at": row["updated_at"],
        "needed_evidence": _extract_needed_evidence(row.get("latest_reasoning")),
        "evidence_ids": row.get("evidence_ids") or [],
    }


REPORT_META_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
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
            ORDER BY count DESC, channel ASC NULLS LAST
            """,
        ),
    ),
    "gaps_log_integrity_events": (
        "Observed log clearing or audit-policy-impacting events.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT event_id, COUNT(*) AS count
            FROM evtx_events
            WHERE {LOG_CLEAR_EVENT_SQL}
               OR (event_id = 4719 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
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
        "Historical AI review output (non-authoritative); current hypothesis settlement is shown separately.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT r.finding_id,
                   r.verdict AS historical_ai_review_verdict,
                   r.report_text AS historical_ai_review_text,
                   h.status AS current_hypothesis_status,
                   h.verdict AS current_settled_verdict
            FROM trace.ai_reviews AS r
            LEFT JOIN hypotheses AS h
              ON h.hypothesis_id = REPLACE(r.finding_id, 'hypothesis:', '')
            ORDER BY r.created_at DESC
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
        _appendix_claims_needing_review,
    ),
    "unresolved_hypotheses_summary": (
        "Open or unresolved hypotheses from the investigation.",
        lambda db: [
            _needed_evidence_row(row)
            for row in _hypothesis_reasoning_rows(
                db,
                where="""
                WHERE COALESCE(h.verdict, h.status) NOT IN ('confirmed', 'refuted', 'rejected', 'untestable')
                """,
                limit=30,
            )
        ],
    ),
    "resolved_hypotheses_with_evidence": (
        "Confirmed and refuted hypotheses with verdict, description, and evidence references.",
        lambda db: _hypothesis_reasoning_rows(
            db,
            where="WHERE h.status IN ('confirmed', 'refuted')",
            limit=30,
        ),
    ),
    "untestable_hypotheses_summary": (
        "Hypotheses that could not be tested due to missing telemetry.",
        lambda db: [
            _needed_evidence_row(row)
            for row in _hypothesis_reasoning_rows(
                db,
                where="WHERE COALESCE(h.verdict, h.status) = 'untestable'",
                limit=20,
            )
        ],
    ),
    "report_sections_with_gaps": (
        "Report sections that have outstanding gaps or low confidence.",
        _report_sections_with_gaps,
    ),
}
