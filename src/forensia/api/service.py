from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from forensia.api.dto import (
    AIReviewDTO,
    CaseDTO,
    CaseStatsDTO,
    ClaimDTO,
    EventVolumePointDTO,
    FindingDTO,
    HypothesisDTO,
    HypothesisReasoningEntryDTO,
    HypothesesResponseDTO,
    InvestigationStepDTO,
    MftTimelineDTO,
    ReportSectionDTO,
    SessionDTO,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: normalize_value(value) for key, value in row.items()}


def get_case_dto(case: Case) -> CaseDTO:
    manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8")) or {}
    paths = {str(key): str(value) for key, value in (manifest.get("paths") or {}).items()}
    return CaseDTO(case_name=case.path.name, paths=paths, manifest=manifest)


def get_case_stats_dto(db: CaseDB) -> CaseStatsDTO:
    event_rows = db.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM evtx_events) AS evtx_rows,
            (SELECT COUNT(*) FROM mft_entries) AS mft_entries,
            (SELECT COUNT(DISTINCT channel) FROM evtx_events) AS channel_count
        """
    ).fetchone()
    finding_rows = db.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE COALESCE(status, 'accepted') != 'suppressed') AS findings_accepted,
            COUNT(*) FILTER (WHERE status = 'suppressed') AS findings_suppressed
        FROM findings
        """
    ).fetchone()
    hypothesis_rows = db.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE status = 'active') AS active_hypotheses,
            COUNT(*) FILTER (WHERE status IN ('confirmed', 'refuted')) AS resolved_hypotheses
        FROM hypotheses
        """
    ).fetchone()
    report_rows = db.execute(
        """
        SELECT
            COALESCE(SUM(CASE
                WHEN json_array_length(CAST(gaps AS JSON)) IS NULL THEN 0
                ELSE json_array_length(CAST(gaps AS JSON))
            END), 0) AS open_gaps,
            COUNT(*) FILTER (WHERE status = 'human_reviewed') AS report_human_reviewed,
            COUNT(*) FILTER (WHERE status = 'ai_exhausted') AS report_ai_exhausted
        FROM report_sections
        """
    ).fetchone()
    session_rows = db.execute(
        """
        SELECT
            COUNT(*) AS sessions,
            COALESCE(SUM(iterations) FILTER (WHERE COALESCE(status, '') != 'failed'), 0) AS total_iterations,
            COUNT(*) AS session_count
        FROM investigation_sessions
        """
    ).fetchone()
    return CaseStatsDTO(
        evtx_rows=int(event_rows[0] or 0),
        mft_entries=int(event_rows[1] or 0),
        channel_count=int(event_rows[2] or 0),
        findings_accepted=int(finding_rows[0] or 0),
        findings_suppressed=int(finding_rows[1] or 0),
        active_hypotheses=int(hypothesis_rows[0] or 0),
        resolved_hypotheses=int(hypothesis_rows[1] or 0),
        open_gaps=int(report_rows[0] or 0),
        sessions=int(session_rows[0] or 0),
        total_iterations=int(session_rows[1] or 0),
        session_count=int(session_rows[2] or 0),
        report_human_reviewed=int(report_rows[1] or 0),
        report_ai_exhausted=int(report_rows[2] or 0),
    )


def list_findings_dto(
    db: CaseDB,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[FindingDTO]:
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = fetch_records(
        db,
        f"""
        SELECT finding_id, rule_id, title, summary, severity, confidence, status,
               tags, attack, evidence, ai_summary, missing_checks, created_at
        FROM findings
        {where}
        ORDER BY created_at DESC, confidence DESC
        LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    )
    return [FindingDTO.model_validate(_normalize_row(row)) for row in rows]


def get_finding_dto(db: CaseDB, finding_id: str) -> FindingDTO | None:
    rows = fetch_records(
        db,
        """
        SELECT finding_id, rule_id, title, summary, severity, confidence, status,
               tags, attack, evidence, ai_summary, missing_checks, created_at
        FROM findings
        WHERE finding_id = ?
        """,
        (finding_id,),
    )
    if not rows:
        return None
    return FindingDTO.model_validate(_normalize_row(rows[0]))


def list_hypothesis_reasoning_dto(
    db: CaseDB,
    hypothesis_id: str,
    limit: int = 20,
) -> list[HypothesisReasoningEntryDTO]:
    rows = fetch_records(
        db,
        """
        SELECT entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        FROM hypothesis_reasoning
        WHERE hypothesis_id = ?
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (hypothesis_id, limit),
    )
    return [HypothesisReasoningEntryDTO.model_validate(_normalize_row(row)) for row in rows]


def list_hypothesis_reasoning_map_dto(
    db: CaseDB,
    limit_per_hypothesis: int = 20,
) -> dict[str, list[HypothesisReasoningEntryDTO]]:
    rows = fetch_records(
        db,
        """
        WITH ranked AS (
            SELECT
                entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY hypothesis_id
                    ORDER BY created_at DESC, entry_id DESC
                ) AS row_num
            FROM hypothesis_reasoning
        )
        SELECT entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        FROM ranked
        WHERE row_num <= ?
        ORDER BY hypothesis_id, created_at DESC, entry_id DESC
        """,
        (limit_per_hypothesis,),
    )
    items: dict[str, list[HypothesisReasoningEntryDTO]] = {}
    for row in rows:
        normalized = _normalize_row(row)
        hypothesis_id = str(normalized.get("hypothesis_id") or "")
        items.setdefault(hypothesis_id, []).append(HypothesisReasoningEntryDTO.model_validate(normalized))
    return items


def list_latest_hypothesis_reasoning_dto(
    db: CaseDB,
    since: str | None = None,
    limit: int = 100,
) -> list[HypothesisReasoningEntryDTO]:
    params: list[Any] = []
    where = ""
    if since:
        row = db.execute(
            "SELECT created_at, entry_id FROM hypothesis_reasoning WHERE entry_id = ?",
            (since,),
        ).fetchone()
        if row:
            where = "WHERE (created_at > ?) OR (created_at = ? AND entry_id > ?)"
            params.extend([row[0], row[0], since])
    rows = fetch_records(
        db,
        f"""
        SELECT entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        FROM hypothesis_reasoning
        {where}
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    return [HypothesisReasoningEntryDTO.model_validate(_normalize_row(row)) for row in rows]


def list_hypotheses_dto(db: CaseDB) -> HypothesesResponseDTO:
    latest_rows = fetch_records(
        db,
        """
        WITH ranked AS (
            SELECT
                entry_id,
                hypothesis_id,
                session_id,
                iteration,
                phase,
                verdict,
                query_id,
                body,
                created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY hypothesis_id
                    ORDER BY created_at DESC, entry_id DESC
                ) AS row_num,
                COUNT(*) OVER (PARTITION BY hypothesis_id) AS reasoning_count,
                MAX(iteration) OVER (PARTITION BY hypothesis_id) AS latest_iteration
            FROM hypothesis_reasoning
        )
        SELECT
            entry_id,
            hypothesis_id,
            session_id,
            iteration,
            phase,
            verdict,
            query_id,
            body,
            created_at,
            reasoning_count,
            latest_iteration
        FROM ranked
        WHERE row_num <= 3
        ORDER BY hypothesis_id, created_at DESC, entry_id DESC
        """
    )
    latest_by_hypothesis: dict[str, list[HypothesisReasoningEntryDTO]] = {}
    reasoning_count_by_hypothesis: dict[str, int] = {}
    latest_iteration_by_hypothesis: dict[str, int | None] = {}
    latest_reasoning_at_by_hypothesis: dict[str, str | None] = {}
    for row in latest_rows:
        normalized = _normalize_row(row)
        hypothesis_id = str(normalized.get("hypothesis_id") or "")
        latest_by_hypothesis.setdefault(hypothesis_id, []).append(
            HypothesisReasoningEntryDTO.model_validate(normalized)
        )
        reasoning_count_by_hypothesis[hypothesis_id] = int(normalized.get("reasoning_count") or 0)
        latest_iteration_by_hypothesis[hypothesis_id] = (
            int(normalized["latest_iteration"]) if normalized.get("latest_iteration") is not None else None
        )
        latest_reasoning_at_by_hypothesis.setdefault(
            hypothesis_id,
            str(normalized.get("created_at") or "") or None,
        )

    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, origin,
               created_session, resolved_session, created_at, updated_at
        FROM hypotheses
        ORDER BY created_at, hypothesis_id
        """,
    )
    active: list[HypothesisDTO] = []
    resolved: list[HypothesisDTO] = []
    for row in rows:
        normalized = _normalize_row(row)
        hypothesis_id = str(normalized.get("hypothesis_id") or "")
        normalized["latest_reasoning"] = [
            item.model_dump(mode="json") for item in latest_by_hypothesis.get(hypothesis_id, [])
        ]
        normalized["reasoning_count"] = reasoning_count_by_hypothesis.get(hypothesis_id, 0)
        normalized["latest_iteration"] = latest_iteration_by_hypothesis.get(hypothesis_id)
        normalized["latest_reasoning_at"] = latest_reasoning_at_by_hypothesis.get(hypothesis_id)
        dto = HypothesisDTO.model_validate(normalized)
        if dto.status == "active":
            active.append(dto)
        else:
            resolved.append(dto)
    return HypothesesResponseDTO(active=active, resolved=resolved)


def list_sessions_dto(db: CaseDB) -> list[SessionDTO]:
    rows = fetch_records(
        db,
        """
        SELECT session_id, started_at, finished_at, iterations, status
        FROM investigation_sessions
        ORDER BY started_at DESC, session_id DESC
        """,
    )
    return [SessionDTO.model_validate(_normalize_row(row)) for row in rows]


def list_steps_dto(db: CaseDB, session_id: str) -> list[InvestigationStepDTO]:
    rows = fetch_records(
        db,
        """
        SELECT step_id, session_id, iteration, phase, input_json, output_json, created_at
        FROM investigation_steps
        WHERE session_id = ?
        ORDER BY created_at, step_id
        """,
        (session_id,),
    )
    return [InvestigationStepDTO.model_validate(_normalize_row(row)) for row in rows]


def list_report_sections_dto(db: CaseDB) -> list[ReportSectionDTO]:
    rows = fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )
    items: list[ReportSectionDTO] = []
    for row in rows:
        normalized = _normalize_row(row)
        gaps = normalized.get("gaps") or []
        if not isinstance(gaps, list):
            gaps = []
        normalized["gaps"] = gaps
        normalized["status"] = str(normalized.get("status") or "draft")
        normalized["update_count"] = int(normalized.get("update_count") or 0)
        normalized["gap_hypothesis_ids"] = [
            f"gap-{hashlib.sha1(str(gap).encode('utf-8')).hexdigest()[:10]}"
            for gap in gaps
        ]
        normalized["gap_count"] = len(gaps)
        items.append(ReportSectionDTO.model_validate(normalized))
    return items


def list_claims_dto(db: CaseDB, section_key: str | None = None) -> list[ClaimDTO]:
    params: tuple[Any, ...] | None = None
    where = ""
    if section_key:
        where = "WHERE section_key = ?"
        params = (section_key,)
    rows = fetch_records(
        db,
        f"""
        SELECT claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
               support_status, created_at, updated_at
        FROM claims
        {where}
        ORDER BY section_key, created_at, claim_id
        """,
        params,
    )
    return [ClaimDTO.model_validate(_normalize_row(row)) for row in rows]


def list_mft_timeline_dto(
    db: CaseDB,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    limit: int = 200,
) -> list[MftTimelineDTO]:
    clauses: list[str] = []
    params: list[Any] = []
    if from_timestamp:
        clauses.append("timestamp >= ?")
        params.append(from_timestamp)
    if to_timestamp:
        clauses.append("timestamp <= ?")
        params.append(to_timestamp)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = fetch_records(
        db,
        f"""
        SELECT t.timeline_id, t.evidence_id, t.record_number, t.file_path, t.timestamp, t.timestamp_type,
               t.description, t.tags, e.is_deleted
        FROM mft_timeline AS t
        LEFT JOIN mft_entries AS e
          ON t.evidence_id = e.evidence_id
         AND t.record_number = e.record_number
        {where}
        ORDER BY t.timestamp DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    return [MftTimelineDTO.model_validate(_normalize_row(row)) for row in rows]


def list_ai_reviews_dto(
    db: CaseDB,
    finding_id: str | None = None,
    hypothesis_id: str | None = None,
) -> list[AIReviewDTO]:
    clauses: list[str] = []
    params: list[Any] = []
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    if hypothesis_id:
        clauses.append("finding_id = ?")
        params.append(f"hypothesis:{hypothesis_id}")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = fetch_records(
        db,
        f"""
        SELECT review_id, finding_id, verdict, report_text, missing_checks,
               confidence_adjustment, notes, raw_response, created_at
        FROM ai_reviews
        {where}
        ORDER BY created_at DESC
        LIMIT 200
        """,
        tuple(params) if params else None,
    )
    return [AIReviewDTO.model_validate(_normalize_row(row)) for row in rows]


def list_event_volume_dto(db: CaseDB, bucket: str = "hour", source: str = "all") -> list[EventVolumePointDTO]:
    bucket_expr = "day" if bucket == "day" else "hour"
    if source == "detected":
        rows = fetch_records(
            db,
            """
            SELECT evidence, created_at
            FROM findings
            WHERE COALESCE(status, 'accepted') != 'suppressed'
            ORDER BY created_at
            """,
        )
        bucket_counts: dict[str, int] = {}
        for row in rows:
            evidence_items = normalize_value(row.get("evidence")) or []
            if not isinstance(evidence_items, list):
                evidence_items = []
            timestamps: list[str] = []
            for item in evidence_items:
                if isinstance(item, dict):
                    timestamp = item.get("timestamp")
                    if isinstance(timestamp, str) and timestamp:
                        timestamps.append(timestamp)
            if not timestamps:
                created_at = normalize_value(row.get("created_at"))
                if isinstance(created_at, str) and created_at:
                    timestamps.append(created_at)
            for timestamp in timestamps:
                normalized = timestamp.replace(" ", "T")
                key = normalized[:13] + ":00:00" if bucket_expr == "hour" else normalized[:10] + "T00:00:00"
                bucket_counts[key] = bucket_counts.get(key, 0) + 1
        return [
            EventVolumePointDTO(bucket=bucket_key, series="detected", count=count)
            for bucket_key, count in sorted(bucket_counts.items())
        ]

    rows: list[dict[str, Any]] = []
    if source in {"evtx", "all"}:
        rows.extend(
            fetch_records(
                db,
                f"""
                SELECT date_trunc('{bucket_expr}', timestamp) AS bucket, channel AS series, COUNT(*) AS count
                FROM evtx_events
                WHERE timestamp IS NOT NULL
                GROUP BY 1, 2
                ORDER BY 1, 2
                """
            )
        )
    if source in {"mft", "all"}:
        rows.extend(
            fetch_records(
                db,
                f"""
                SELECT date_trunc('{bucket_expr}', timestamp) AS bucket,
                       CASE WHEN ? = 'all' THEN 'mft:' || timestamp_type ELSE timestamp_type END AS series,
                       COUNT(*) AS count
                FROM mft_timeline
                WHERE timestamp IS NOT NULL
                GROUP BY 1, 2
                ORDER BY 1, 2
                """,
                (source,),
            )
        )
    normalized = []
    for row in rows:
        item = _normalize_row(row)
        bucket_value = str(item.get("bucket") or "")
        if bucket_value.endswith("+00:00"):
            bucket_value = bucket_value[:-6]
        item["bucket"] = bucket_value
        normalized.append(EventVolumePointDTO.model_validate(item))
    normalized.sort(key=lambda item: (item.bucket, item.series))
    return normalized
