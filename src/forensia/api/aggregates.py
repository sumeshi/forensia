"""Authoritative bounded finding projections for the API."""

from __future__ import annotations

from typing import Any

from forensia.api.dto import FindingAggregatesDTO, FindingPageDTO
from forensia.api.service import list_attack_coverage_dto, list_findings_dto
from forensia.db.database import CaseDB


def get_finding_aggregates_dto(db: CaseDB) -> FindingAggregatesDTO:
    total_row = db.execute(
        "SELECT COUNT(*), "
        "COUNT(*) FILTER (WHERE COALESCE(status, 'accepted') != 'suppressed'), "
        "COUNT(*) FILTER (WHERE status = 'suppressed') FROM findings"
    ).fetchone()
    total = int(total_row[0] or 0)
    accepted = int(total_row[1] or 0)
    suppressed = int(total_row[2] or 0)
    severity_rows = db.execute(
        "SELECT COALESCE(severity, 'unknown'), COUNT(*) FROM findings "
        "WHERE COALESCE(status, 'accepted') != 'suppressed' "
        "GROUP BY severity ORDER BY COUNT(*) DESC"
    ).fetchall()
    severity_counts = {str(row[0]): int(row[1] or 0) for row in severity_rows}
    status_rows = db.execute(
        "SELECT COALESCE(status, 'accepted'), COUNT(*) FROM findings GROUP BY 1"
    ).fetchall()
    status_counts = {str(row[0]): int(row[1] or 0) for row in status_rows}
    rule_rows = db.execute(
        "SELECT rule_id, MAX(title), COUNT(*) FROM findings "
        "WHERE COALESCE(status, 'accepted') != 'suppressed' "
        "GROUP BY rule_id ORDER BY COUNT(*) DESC, rule_id LIMIT 10"
    ).fetchall()
    top_rules = [
        {"rule_id": str(row[0] or "unknown"), "title": str(row[1] or ""), "count": int(row[2] or 0)}
        for row in rule_rows
    ]
    coverage = list_attack_coverage_dto(db)
    top_families = [
        {
            "tactic": item.tactic,
            "technique_id": item.technique_id,
            "technique_name": item.technique_name,
            "count": item.count,
        }
        for item in sorted(coverage, key=lambda item: item.count, reverse=True)[:10]
    ]
    return FindingAggregatesDTO(
        total=total,
        accepted=accepted,
        suppressed=suppressed,
        severity_counts=severity_counts,
        status_counts=status_counts,
        top_rules=top_rules,
        top_families=top_families,
    )


def list_findings_page_dto(
    db: CaseDB,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> FindingPageDTO:
    items = list_findings_dto(db, status=status, severity=severity, limit=limit, offset=offset)
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    row = db.execute(f"SELECT COUNT(*) FROM findings{where}", params).fetchone()
    total = int(row[0] or 0) if row else 0
    return FindingPageDTO(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        is_sample=total > offset + len(items),
        aggregates=get_finding_aggregates_dto(db),
    )
