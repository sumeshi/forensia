from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from forensia.api.dto import (
    AIReviewDTO,
    CaseDTO,
    CaseStatsDTO,
    EventVolumePointDTO,
    FindingDTO,
    HypothesisDTO,
    HypothesesResponseDTO,
    InvestigationStepDTO,
    MftTimelineDTO,
    ReportSectionDTO,
    SessionDTO,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB


def _fetch_records(db: CaseDB, query: str, params: tuple[Any, ...] | None = None) -> list[dict[str, Any]]:
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _normalize_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                return _normalize_value(json.loads(stripped))
            except json.JSONDecodeError:
                return value
    return value


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: _normalize_value(value) for key, value in row.items()}


def get_case_dto(case: Case) -> CaseDTO:
    manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8")) or {}
    paths = {str(key): str(value) for key, value in (manifest.get("paths") or {}).items()}
    return CaseDTO(case_name=case.path.name, paths=paths, manifest=manifest)


def get_case_stats_dto(db: CaseDB) -> CaseStatsDTO:
    open_gaps = db.execute(
        """
        SELECT COALESCE(SUM(CASE
            WHEN json_array_length(CAST(gaps AS JSON)) IS NULL THEN 0
            ELSE json_array_length(CAST(gaps AS JSON))
        END), 0)
        FROM report_sections
        """
    ).fetchone()[0]
    return CaseStatsDTO(
        evtx_rows=int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]),
        mft_entries=int(db.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0]),
        channel_count=int(db.execute("SELECT COUNT(DISTINCT channel) FROM evtx_events").fetchone()[0]),
        findings_accepted=int(
            db.execute("SELECT COUNT(*) FROM findings WHERE COALESCE(status, 'accepted') != 'suppressed'").fetchone()[0]
        ),
        findings_suppressed=int(db.execute("SELECT COUNT(*) FROM findings WHERE status = 'suppressed'").fetchone()[0]),
        active_hypotheses=int(db.execute("SELECT COUNT(*) FROM hypotheses WHERE status = 'active'").fetchone()[0]),
        resolved_hypotheses=int(
            db.execute("SELECT COUNT(*) FROM hypotheses WHERE status IN ('confirmed', 'refuted')").fetchone()[0]
        ),
        open_gaps=int(open_gaps or 0),
        sessions=int(db.execute("SELECT COUNT(*) FROM investigation_sessions").fetchone()[0]),
        total_iterations=int(
            db.execute(
                "SELECT COALESCE(SUM(iterations), 0) FROM investigation_sessions WHERE COALESCE(status, '') != 'failed'"
            ).fetchone()[0]
        ),
        session_count=int(db.execute("SELECT COUNT(*) FROM investigation_sessions").fetchone()[0]),
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
    rows = _fetch_records(
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
    rows = _fetch_records(
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


def list_hypotheses_dto(db: CaseDB) -> HypothesesResponseDTO:
    rows = _fetch_records(
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
        dto = HypothesisDTO.model_validate(_normalize_row(row))
        if dto.status == "active":
            active.append(dto)
        else:
            resolved.append(dto)
    return HypothesesResponseDTO(active=active, resolved=resolved)


def list_sessions_dto(db: CaseDB) -> list[SessionDTO]:
    rows = _fetch_records(
        db,
        """
        SELECT session_id, started_at, finished_at, iterations, status
        FROM investigation_sessions
        ORDER BY started_at DESC, session_id DESC
        """,
    )
    return [SessionDTO.model_validate(_normalize_row(row)) for row in rows]


def list_steps_dto(db: CaseDB, session_id: str) -> list[InvestigationStepDTO]:
    rows = _fetch_records(
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
    rows = _fetch_records(
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
    rows = _fetch_records(
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
    rows = _fetch_records(
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
        rows = _fetch_records(
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
            evidence_items = _normalize_value(row.get("evidence")) or []
            if not isinstance(evidence_items, list):
                evidence_items = []
            timestamps: list[str] = []
            for item in evidence_items:
                if isinstance(item, dict):
                    timestamp = item.get("timestamp")
                    if isinstance(timestamp, str) and timestamp:
                        timestamps.append(timestamp)
            if not timestamps:
                created_at = _normalize_value(row.get("created_at"))
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
            _fetch_records(
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
            _fetch_records(
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
