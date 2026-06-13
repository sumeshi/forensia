from __future__ import annotations

import hashlib
from datetime import date as _date
from pathlib import Path
from typing import Any

import yaml

from forensia.api.dto import (
    AIReviewDTO,
    AttackCoverageRowDTO,
    CaseDTO,
    CaseStatsDTO,
    ClaimDTO,
    EntityCardDTO,
    EventVolumePointDTO,
    EvidenceRecordDTO,
    FindingDTO,
    HypothesesResponseDTO,
    HypothesisDTO,
    HypothesisReasoningEntryDTO,
    InvestigationStepDTO,
    MftTimelineDTO,
    ReportSectionDTO,
    SectionQuestionDTO,
    SessionDTO,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record
from forensia.db.query import fetch_records, normalize_value
from forensia.report.evidence_map import build_evidence_map
from forensia.report.html import (
    _inject_evidence_interactivity,
    render_markdown_fragment,
)


def _evidence_ids_from_payload(value: Any) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()

    def add(raw: Any) -> None:
        text = str(raw or "").strip()
        if text and text not in seen:
            seen.add(text)
            ids.append(text)

    def walk(item: Any) -> None:
        item = normalize_value(item)
        if isinstance(item, dict):
            add(item.get("evidence_id"))
            many = item.get("evidence_ids")
            if isinstance(many, list):
                for value in many:
                    add(value)
            for key in ("evidence", "rows", "answer"):
                if key in item:
                    walk(item.get(key))
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return ids


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: normalize_value(value) for key, value in row.items()}


def get_case_dto(case: Case) -> CaseDTO:
    """Build a CaseDTO from the case manifest YAML."""
    manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8")) or {}
    paths = {
        str(key): str(value) for key, value in (manifest.get("paths") or {}).items()
    }
    return CaseDTO(case_name=case.path.name, paths=paths, manifest=manifest)


def get_case_stats_dto(db: CaseDB) -> CaseStatsDTO:
    """Aggregate case-wide statistics from multiple tables into a single DTO."""
    event_rows = db.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM evtx_events) AS evtx_rows,
            (SELECT COUNT(*) FROM mft_entries) AS mft_entries,
            (SELECT COUNT(DISTINCT channel) FROM evtx_events) AS channel_count,
            (SELECT COUNT(DISTINCT UPPER(TRIM(computer))) FROM evtx_events WHERE COALESCE(computer, '') != '') AS host_count
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
            COALESCE(SUM(iterations) FILTER (WHERE COALESCE(status, '') != 'failed'), 0) AS total_iterations
        FROM investigation_sessions
        """
    ).fetchone()
    return CaseStatsDTO(
        evtx_rows=int(event_rows[0] or 0),
        mft_entries=int(event_rows[1] or 0),
        channel_count=int(event_rows[2] or 0),
        host_count=int(event_rows[3] or 0),
        findings_accepted=int(finding_rows[0] or 0),
        findings_suppressed=int(finding_rows[1] or 0),
        active_hypotheses=int(hypothesis_rows[0] or 0),
        resolved_hypotheses=int(hypothesis_rows[1] or 0),
        open_gaps=int(report_rows[0] or 0),
        sessions=int(session_rows[0] or 0),
        total_iterations=int(session_rows[1] or 0),
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
    """Query findings with optional status/severity filters, ordered by recency and confidence."""
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
    items: list[FindingDTO] = []
    for row in rows:
        normalized = _normalize_row(row)
        evidence_ids = _evidence_ids_from_payload(normalized.get("evidence"))
        normalized["evidence_ids"] = evidence_ids
        normalized["evidence_count"] = len(evidence_ids)
        items.append(FindingDTO.model_validate(normalized))
    return items


def get_finding_dto(db: CaseDB, finding_id: str) -> FindingDTO | None:
    """Return a single finding by ID, or None if not found."""
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
    normalized = _normalize_row(rows[0])
    evidence_ids = _evidence_ids_from_payload(normalized.get("evidence"))
    normalized["evidence_ids"] = evidence_ids
    normalized["evidence_count"] = len(evidence_ids)
    return FindingDTO.model_validate(normalized)


def list_hypothesis_reasoning_dto(
    db: CaseDB,
    hypothesis_id: str,
    limit: int = 20,
) -> list[HypothesisReasoningEntryDTO]:
    """Return reasoning entries for a single hypothesis, most recent first."""
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
    return [
        HypothesisReasoningEntryDTO.model_validate(_normalize_row(row)) for row in rows
    ]


def list_hypothesis_reasoning_map_dto(
    db: CaseDB,
    limit_per_hypothesis: int = 20,
) -> dict[str, list[HypothesisReasoningEntryDTO]]:
    """Return a dict mapping hypothesis_id to its most recent reasoning entries."""
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
        items.setdefault(hypothesis_id, []).append(
            HypothesisReasoningEntryDTO.model_validate(normalized)
        )
    return items


def list_latest_hypothesis_reasoning_dto(
    db: CaseDB,
    since: str | None = None,
    limit: int = 100,
) -> list[HypothesisReasoningEntryDTO]:
    """Return the most recent reasoning entries across all hypotheses, with optional cursor-based pagination."""
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
    return [
        HypothesisReasoningEntryDTO.model_validate(_normalize_row(row)) for row in rows
    ]


def list_hypotheses_dto(db: CaseDB) -> HypothesesResponseDTO:
    """Query all hypotheses, partition into active/resolved, and attach latest reasoning for each."""
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
        """,
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
        reasoning_count_by_hypothesis[hypothesis_id] = int(
            normalized.get("reasoning_count") or 0
        )
        latest_iteration_by_hypothesis[hypothesis_id] = (
            int(normalized["latest_iteration"])
            if normalized.get("latest_iteration") is not None
            else None
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
            item.model_dump(mode="json")
            for item in latest_by_hypothesis.get(hypothesis_id, [])
        ]
        normalized["reasoning_count"] = reasoning_count_by_hypothesis.get(
            hypothesis_id, 0
        )
        normalized["latest_iteration"] = latest_iteration_by_hypothesis.get(
            hypothesis_id
        )
        normalized["latest_reasoning_at"] = latest_reasoning_at_by_hypothesis.get(
            hypothesis_id
        )
        dto = HypothesisDTO.model_validate(normalized)
        if dto.status == "active":
            active.append(dto)
        else:
            resolved.append(dto)
    return HypothesesResponseDTO(active=active, resolved=resolved)


def list_sessions_dto(db: CaseDB) -> list[SessionDTO]:
    """Return all investigation sessions ordered by recency."""
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
    """Return investigation steps for a given session."""
    rows = fetch_records(
        db,
        """
        SELECT step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at
        FROM investigation_steps
        WHERE session_id = ?
        ORDER BY created_at, step_id
        """,
        (session_id,),
    )
    return [InvestigationStepDTO.model_validate(_normalize_row(row)) for row in rows]


def list_report_sections_dto(db: CaseDB) -> list[ReportSectionDTO]:
    """Return all report sections with synthetic gap hypothesis IDs."""
    rows = fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )
    evidence_by_section: dict[str, list[str]] = {}
    for row in fetch_records(
        db,
        """
        SELECT section_key, evidence_id
        FROM section_evidence
        WHERE COALESCE(evidence_id, '') != ''
        ORDER BY section_key, created_at, evidence_id
        """,
    ):
        section_key = str(row.get("section_key") or "")
        evidence_id = str(row.get("evidence_id") or "").strip()
        if not section_key or not evidence_id:
            continue
        bucket = evidence_by_section.setdefault(section_key, [])
        if evidence_id not in bucket:
            bucket.append(evidence_id)
    items: list[ReportSectionDTO] = []
    for row in rows:
        normalized = _normalize_row(row)
        section_key = str(normalized.get("section_key") or "")
        evidence_ids = evidence_by_section.get(section_key, [])
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
        normalized["evidence_ids"] = evidence_ids
        normalized["evidence_count"] = len(evidence_ids)
        items.append(ReportSectionDTO.model_validate(normalized))

    # Populate body_html (server-rendered HTML from markdown body)
    non_empty_bodies = [item.body for item in items if item.body]
    if non_empty_bodies:
        all_bodies = "\n\n".join(non_empty_bodies)
        evidence_map = build_evidence_map(db, all_bodies)
        for item in items:
            if item.body:
                html = str(render_markdown_fragment(item.body))
                item.body_html = _inject_evidence_interactivity(html, evidence_map)

    return items


def list_section_questions_dto(
    db: CaseDB, section_key: str | None = None
) -> list[SectionQuestionDTO]:
    """Return resolved QuestionSpec rows for report sections and case-wide probes."""
    params: tuple[Any, ...] | None = None
    where = ""
    if section_key:
        where = "WHERE section_key = ?"
        params = (section_key,)
    rows = fetch_records(
        db,
        f"""
        SELECT question_id, section_key, block_heading, question_text, question_type,
               answer_spec, intent, confidence, matched_rule, required_evidence,
               status, created_at, updated_at
        FROM section_questions
        {where}
        ORDER BY section_key, block_heading, question_id
        """,
        params,
    )
    return [SectionQuestionDTO.model_validate(_normalize_row(row)) for row in rows]


def list_claims_dto(db: CaseDB, section_key: str | None = None) -> list[ClaimDTO]:
    """Return claims with optional section_key filter."""
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
    result = []
    for row in rows:
        normalized = _normalize_row(row)
        ct = normalized.get("claim_text")
        if not isinstance(ct, str):
            normalized["claim_text"] = "" if not ct else str(ct)
        result.append(ClaimDTO.model_validate(normalized))
    return result


def list_mft_timeline_dto(
    db: CaseDB,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    limit: int = 200,
) -> list[MftTimelineDTO]:
    """Return MFT timeline entries with optional timestamp range filtering."""
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
    """Return AI reviews filtered by finding_id or hypothesis_id."""
    clauses: list[str] = []
    params: list[Any] = []
    if finding_id:
        clauses.append("finding_id = ?")
        params.append(finding_id)
    if hypothesis_id:
        clauses.append("finding_id = ?")
        params.append(f"hypothesis:{hypothesis_id}")
    where = f"WHERE {' OR '.join(clauses)}" if clauses else ""
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


_VALID_BUCKETS = {"year", "month", "day", "hour"}
# Drop pre-1980 (Windows epoch 1601 garbage) and far-future overflow
# (NTFS int64-MAX → 3220 / 30828 etc when raw FILETIME is misinterpreted).
_VOLUME_MIN_YEAR = 1980
_VOLUME_MAX_YEAR = _date.today().year + 5
_BUCKET_RANK = {"year": 0, "month": 1, "day": 2, "hour": 3}


def _trunc_key(timestamp_iso: str, bucket: str) -> str:
    t = timestamp_iso.replace(" ", "T")
    if bucket == "year":
        return t[:4] + "-01-01T00:00:00"
    if bucket == "month":
        return t[:7] + "-01T00:00:00"
    if bucket == "day":
        return t[:10] + "T00:00:00"
    return t[:13] + ":00:00"


def aggregate_event_volume(
    items: list[EventVolumePointDTO],
    target_bucket: str,
    start: str | None = None,
    end: str | None = None,
) -> list[EventVolumePointDTO]:
    """Rebucket finer-grained event volume data into a coarser time bucket."""
    if target_bucket not in _VALID_BUCKETS:
        return list(items)
    grouped: dict[tuple[str, str], int] = {}
    for item in items:
        ts = item.bucket
        if ts[:4].isdigit():
            year = int(ts[:4])
            if year < _VOLUME_MIN_YEAR or year > _VOLUME_MAX_YEAR:
                continue
        if start and ts < start:
            continue
        if end and ts >= end:
            continue
        key = (_trunc_key(ts, target_bucket), item.series)
        grouped[key] = grouped.get(key, 0) + item.count
    result = [
        EventVolumePointDTO(bucket=k[0], series=k[1], count=v)
        for k, v in grouped.items()
    ]
    result.sort(key=lambda item: (item.bucket, item.series))
    return result


def _build_range_filter(start: str | None, end: str | None) -> tuple[str, list[Any]]:
    """Build SQL range filter clause and parameters for volume queries."""
    range_clauses: list[str] = [
        f"EXTRACT(year FROM timestamp) BETWEEN {_VOLUME_MIN_YEAR} AND {_VOLUME_MAX_YEAR}",
    ]
    range_params: list[Any] = []
    if start:
        range_clauses.append("timestamp >= ?")
        range_params.append(start)
    if end:
        range_clauses.append("timestamp < ?")
        range_params.append(end)
    return " AND ".join(range_clauses), range_params


def _detected_volume_points(
    db: CaseDB, bucket: str, start: str | None, end: str | None
) -> list[EventVolumePointDTO]:
    """Compute event volume from findings JSON evidence timestamps."""
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
            if not timestamp[:4].isdigit():
                continue
            year = int(timestamp[:4])
            if year < _VOLUME_MIN_YEAR or year > _VOLUME_MAX_YEAR:
                continue
            if start and timestamp < start:
                continue
            if end and timestamp >= end:
                continue
            key = _trunc_key(timestamp, bucket)
            bucket_counts[key] = bucket_counts.get(key, 0) + 1
    return [
        EventVolumePointDTO(bucket=bucket_key, series="detected", count=count)
        for bucket_key, count in sorted(bucket_counts.items())
    ]


def _evtx_volume_points(
    db: CaseDB, bucket: str, range_sql: str, range_params: list[Any]
) -> list[dict[str, Any]]:
    """Query evtx_events volume grouped by bucket and channel."""
    return fetch_records(
        db,
        f"""
        SELECT date_trunc('{bucket}', timestamp) AS bucket, channel AS series, COUNT(*) AS count
        FROM evtx_events
        WHERE timestamp IS NOT NULL AND {range_sql}
        GROUP BY 1, 2
        ORDER BY 1, 2
        """,
        tuple(range_params) if range_params else None,
    )


def _mft_volume_points(
    db: CaseDB, bucket: str, range_sql: str, range_params: list[Any], source: str
) -> list[dict[str, Any]]:
    """Query mft_timeline volume grouped by bucket and timestamp_type."""
    return fetch_records(
        db,
        f"""
        SELECT date_trunc('{bucket}', timestamp) AS bucket,
               CASE WHEN ? = 'all' THEN 'mft:' || timestamp_type ELSE timestamp_type END AS series,
               COUNT(*) AS count
        FROM mft_timeline
        WHERE timestamp IS NOT NULL AND {range_sql}
        GROUP BY 1, 2
        ORDER BY 1, 2
        """,
        tuple([source, *range_params]),
    )


def _normalize_volume_rows(rows: list[dict[str, Any]]) -> list[EventVolumePointDTO]:
    """Normalize raw DB rows into EventVolumePointDTO list."""
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


def list_event_volume_dto(
    db: CaseDB,
    bucket: str = "day",
    source: str = "all",
    start: str | None = None,
    end: str | None = None,
) -> list[EventVolumePointDTO]:
    """Return event volume time-series data from evtx_events and/or mft_timeline, bucketed by time grain."""
    bucket_expr = bucket if bucket in _VALID_BUCKETS else "day"
    if source == "detected":
        return _detected_volume_points(db, bucket_expr, start, end)
    range_sql, range_params = _build_range_filter(start, end)
    rows: list[dict[str, Any]] = []
    if source in {"evtx", "all"}:
        rows.extend(_evtx_volume_points(db, bucket_expr, range_sql, range_params))
    if source in {"mft", "all"}:
        rows.extend(
            _mft_volume_points(db, bucket_expr, range_sql, range_params, source)
        )
    return _normalize_volume_rows(rows)


def get_evidence_record_dto(db: CaseDB, evidence_id: str) -> EvidenceRecordDTO | None:
    """Return a single evidence record as a DTO, or None if not found."""
    record = lookup_evidence_record(db, evidence_id)
    if record is None:
        return None
    # The lookup tags the owning table itself (correct for prefetch IDs that
    # may live in prefetch_timeline); don't re-derive it from the prefix.
    source = str(record.pop("_source", "unknown"))
    return EvidenceRecordDTO(evidence_id=evidence_id, source=source, record=record)


def list_entity_cards_dto(case: Case) -> list[EntityCardDTO]:
    """Read entity card markdown files from the case memory directory."""
    result: list[EntityCardDTO] = []
    entities_dir = case.memory_dir / "entities"
    if not entities_dir.exists():
        return result
    for kind_dir in sorted(entities_dir.iterdir()):
        if not kind_dir.is_dir():
            continue
        kind = kind_dir.name
        for path in sorted(kind_dir.glob("*.md")):
            result.append(
                EntityCardDTO(
                    kind=kind,
                    name=path.stem,
                    mention_count=None,
                    summary=_entity_card_summary(path),
                )
            )
    return result


def _entity_card_summary(
    path: Path, max_lines: int = 3, max_chars: int = 240
) -> str | None:
    """Extract a short human-readable preview from an entity card markdown file.

    The investigator writes cards as a `- role: ...` / `- notes: ...` bullet list under an H1.
    We prefer `role` + `notes` when present; otherwise fall back to the first non-empty body lines.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    role: str | None = None
    notes: str | None = None
    fallback: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lstrip("- ").lower()
        if role is None and lower.startswith("role:"):
            role = line.lstrip("- ").split(":", 1)[1].strip()
            continue
        if notes is None and lower.startswith("notes:"):
            notes = line.lstrip("- ").split(":", 1)[1].strip()
            continue
        if lower.startswith(("type:", "name:")):
            continue
        fallback.append(line.lstrip("- ").strip())
    parts: list[str] = []
    if role:
        parts.append(f"role: {role}")
    if notes:
        parts.append(notes)
    if not parts:
        parts = fallback[:max_lines]
    if not parts:
        return None
    summary = " · ".join(parts[:max_lines])
    if len(summary) > max_chars:
        summary = summary[: max_chars - 1].rstrip() + "…"
    return summary


def list_attack_coverage_dto(db: CaseDB) -> list[AttackCoverageRowDTO]:
    """Aggregate MITRE ATT&CK coverage from all findings, grouped by tactic and technique."""
    rows = fetch_records(
        db,
        """
        SELECT attack, status
        FROM findings
        WHERE attack IS NOT NULL
          AND json_array_length(CAST(attack AS JSON)) > 0
        """,
    )
    tactic_order = [
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]
    coverage: dict[str, dict[str, dict[str, int]]] = {}
    for row in rows:
        attack_val = normalize_value(row.get("attack"))
        if not isinstance(attack_val, list):
            continue
        status = str(row.get("status") or "accepted")
        for entry in attack_val:
            if not isinstance(entry, dict):
                continue
            tactic = str(entry.get("tactic") or "").lower().strip()
            technique_id = str(entry.get("technique_id") or "").strip().upper()
            technique_name = str(entry.get("technique_name") or entry.get("name") or "")
            if not tactic or not technique_id:
                continue
            if tactic not in tactic_order:
                tactic_order.append(tactic)
            tech_map = coverage.setdefault(tactic, {})
            tech_entry = tech_map.setdefault(
                technique_id,
                {
                    "count": 0,
                    "accepted": 0,
                    "suppressed": 0,
                    "technique_name": technique_name,
                },
            )
            tech_entry["count"] += 1
            if status == "suppressed":
                tech_entry["suppressed"] += 1
            else:
                tech_entry["accepted"] += 1
            if technique_name and not tech_entry.get("technique_name"):
                tech_entry["technique_name"] = technique_name

    result: list[AttackCoverageRowDTO] = []
    for tactic in tactic_order:
        tech_map = coverage.get(tactic)
        if not tech_map:
            continue
        for technique_id, stats in sorted(tech_map.items()):
            result.append(
                AttackCoverageRowDTO(
                    tactic=tactic,
                    technique_id=technique_id,
                    technique_name=stats.get("technique_name"),
                    count=stats["count"],
                    accepted=stats["accepted"],
                    suppressed=stats["suppressed"],
                )
            )
    return result
