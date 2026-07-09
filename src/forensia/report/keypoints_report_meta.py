"""Keypoints for gaps, recommendations, hypotheses, and report appendix."""

from __future__ import annotations

from forensia.report.evidence_refs import (
    EVIDENCE_ID_PATTERN,
    EvidenceResolver,
    _extract_needed_evidence,
    _report_keypoint_rows,
)

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
