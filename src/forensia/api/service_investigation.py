"""Investigation state service functions for the M1+ investigation harness.

Separated from service.py to keep file sizes under the 1000-line import contract.
"""

from __future__ import annotations

import json
from typing import Any

from forensia.api.dto import (
    EvidenceCoverageDTO,
    EvidenceSourceDTO,
    HypothesisEvidenceLinkDTO,
    HypothesisRelationDTO,
    InvestigationStateDTO,
    InvestigationTaskDTO,
    ReportGapDTO,
)
from forensia.db.database import CaseDB


def list_evidence_sources_dto(db: CaseDB) -> list[EvidenceSourceDTO]:
    """Return all evidence sources."""
    rows = db.execute(
        "SELECT source_id, artifact_family, display_path, ingest_status, "
        "parser_name, row_count, channel, hosts, min_time, max_time, "
        "error_code, error_summary FROM evidence_sources ORDER BY artifact_family, display_path"
    ).fetchall()
    return [
        EvidenceSourceDTO(
            source_id=r[0],
            artifact_family=r[1],
            display_path=r[2],
            ingest_status=r[3],
            parser_name=r[4] or "",
            row_count=r[5] or 0,
            channel=r[6] or "",
            hosts=r[7] if isinstance(r[7], list) else [],
            min_time=r[8].isoformat() if r[8] else None,
            max_time=r[9].isoformat() if r[9] else None,
            error_code=r[10] or "",
            error_summary=r[11] or "",
        )
        for r in rows
    ]


def list_evidence_coverage_dto(db: CaseDB) -> list[EvidenceCoverageDTO]:
    """Return all evidence coverage entries."""
    rows = db.execute(
        "SELECT capability, host, channel, source_family, state, reason_code, "
        "source_ids, start_time, end_time, confidence FROM evidence_coverage "
        "ORDER BY source_family, capability"
    ).fetchall()
    return [
        EvidenceCoverageDTO(
            capability=r[0],
            host=r[1] or "",
            channel=r[2] or "",
            source_family=r[3],
            state=r[4],
            reason_code=r[5] or "",
            source_ids=r[6] if isinstance(r[6], list) else [],
            start_time=r[7].isoformat() if r[7] else None,
            end_time=r[8].isoformat() if r[8] else None,
            confidence=r[9] or 0.0,
        )
        for r in rows
    ]


def get_investigation_state_dto(db: CaseDB) -> InvestigationStateDTO | None:
    """Return the investigation state singleton."""
    row = db.execute(
        "SELECT state_id, objective, status, termination_policy, "
        "stop_reason_code, stop_reason, updated_at FROM investigation_state "
        "WHERE state_id = 'case'"
    ).fetchone()
    if not row:
        return None
    return InvestigationStateDTO(
        state_id=row[0],
        objective=row[1] or "",
        status=row[2] or "active",
        termination_policy=(
            row[3]
            if isinstance(row[3], dict)
            else json.loads(row[3])
            if isinstance(row[3], str)
            else None
        ),
        stop_reason_code=row[4] or "",
        stop_reason=row[5] or "",
        updated_at=row[6].isoformat() if row[6] else None,
    )


def list_report_gaps_dto(db: CaseDB, status: str | None = None) -> list[ReportGapDTO]:
    """Return report gaps, optionally filtered by status."""
    query = (
        "SELECT gap_id, section_key, block_heading, description, kind, status, "
        "source_claim_id, hypothesis_id, task_id, coverage_reason, "
        "created_at, updated_at FROM report_gaps"
    )
    params: list[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC"
    rows = db.execute(query, params).fetchall()
    return [
        ReportGapDTO(
            gap_id=r[0],
            section_key=r[1] or "",
            block_heading=r[2] or "",
            description=r[3] or "",
            kind=r[4] or "",
            status=r[5] or "open",
            source_claim_id=r[6] or "",
            hypothesis_id=r[7] or "",
            task_id=r[8] or "",
            coverage_reason=r[9] or "",
            created_at=r[10].isoformat() if r[10] else None,
            updated_at=r[11].isoformat() if r[11] else None,
        )
        for r in rows
    ]


def list_investigation_tasks_dto(
    db: CaseDB, status: str | None = None
) -> list[InvestigationTaskDTO]:
    """Return investigation tasks, optionally filtered by status."""
    query = (
        "SELECT task_id, kind, description, status, gap_id, hypothesis_id, "
        "required_capability, reason, created_at, updated_at FROM investigation_tasks"
    )
    params: list[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC"
    rows = db.execute(query, params).fetchall()
    return [
        InvestigationTaskDTO(
            task_id=r[0],
            kind=r[1] or "",
            description=r[2] or "",
            status=r[3] or "open",
            gap_id=r[4] or "",
            hypothesis_id=r[5] or "",
            required_capability=r[6] or "",
            reason=r[7] or "",
            created_at=r[8].isoformat() if r[8] else None,
            updated_at=r[9].isoformat() if r[9] else None,
        )
        for r in rows
    ]


def list_hypothesis_relations_dto(db: CaseDB) -> list[HypothesisRelationDTO]:
    rows = db.execute(
        "SELECT from_hypothesis_id, to_hypothesis_id, relation_type, origin, "
        "confidence, rationale FROM hypothesis_relations "
        "ORDER BY from_hypothesis_id, to_hypothesis_id, relation_type"
    ).fetchall()
    return [
        HypothesisRelationDTO(
            from_hypothesis_id=row[0],
            to_hypothesis_id=row[1],
            relation_type=row[2],
            origin=row[3] or "",
            confidence=row[4] or 0.0,
            rationale=row[5] or "",
        )
        for row in rows
    ]


def list_hypothesis_evidence_dto(db: CaseDB) -> list[HypothesisEvidenceLinkDTO]:
    rows = db.execute(
        "SELECT link_id, hypothesis_id, evidence_id, finding_id, query_id, "
        "assessment_id, role, source_family, derivation_group, strength "
        "FROM hypothesis_evidence ORDER BY hypothesis_id, created_at"
    ).fetchall()
    return [
        HypothesisEvidenceLinkDTO(
            link_id=row[0],
            hypothesis_id=row[1],
            evidence_id=row[2],
            finding_id=row[3] or "",
            query_id=row[4] or "",
            assessment_id=row[5] or "",
            role=row[6] or "supporting",
            source_family=row[7] or "",
            derivation_group=row[8] or "",
            strength=row[9] or "moderate",
        )
        for row in rows
    ]
