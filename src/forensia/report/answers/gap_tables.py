"""Gap and hypothesis summary tables for the report."""

from __future__ import annotations

from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import catalog_exe_globs, exe_glob_sql
from forensia.report.answers.keypoints_report_meta import (
    hypothesis_latest_reasoning_cte,
)
from forensia.report.answers.summary_rows import (
    _as_int,
    _network_summary_rows,
)
from forensia.report.evidence_refs import (
    _extract_needed_evidence,
)
from forensia.report.render.formats import load_report_formats
from forensia.report.report_brief import (
    _annotate_confirmed_hypotheses,
    _hypothesis_source_rule_ids,
    _query_hypotheses_by_status,
)


def _forensic_gap_rows(db: CaseDB) -> list[dict[str, Any]]:
    """Evidence-gap rows derived from what the case actually contains.

    Each row is emitted only when the corresponding artifact family or signal
    is present in the evidence — no fixed scenario assumptions (Rule 16).
    """
    from forensia.knowledge.rules.loader import detect_artifact_families

    network = _network_summary_rows(db)
    try:
        families = detect_artifact_families(db)
    except Exception:
        families = set()

    gap_specs = load_report_formats(db.case.report_template_dir)["gaps"]
    gaps: list[dict[str, Any]] = []
    if "cloud_sync" in families:
        gaps.append(dict(gap_specs["cloud_sync"]))
    if "mailbox" in families:
        gaps.append(dict(gap_specs["mailbox"]))
    antiforensic_findings = _count_findings_with_tag(
        db, "benign-context:", negate=True, tag_like="%antiforensic%"
    )
    if antiforensic_findings or _has_antiforensic_executions(db):
        gaps.append(dict(gap_specs["antiforensic"]))
    if network and not (
        _as_int(network[0].get("outbound_rows"))
        or _as_int(network[0].get("inbound_rows"))
    ):
        gaps.append(dict(gap_specs["network"]))
    return gaps


def _count_findings_with_tag(
    db: CaseDB, exclude_prefix: str, *, negate: bool, tag_like: str
) -> int:
    """Count non-suppressed findings whose tags match tag_like, excluding benign-context ones."""
    try:
        row = db.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE COALESCE(status, 'new') != 'suppressed'
              AND LOWER(COALESCE(tags, '')) LIKE ?
              AND LOWER(COALESCE(tags, '')) NOT LIKE ?
            """,
            (tag_like.lower(), f"%{exclude_prefix.lower()}%"),
        ).fetchone()
        return int(row[0] or 0)
    except Exception:
        return 0


def _has_antiforensic_executions(db: CaseDB) -> bool:
    """True when prefetch shows execution of a catalog-listed cleanup tool."""
    tool_sql = exe_glob_sql("executable_name", catalog_exe_globs("antiforensic_tools"))
    try:
        row = db.execute(
            f"SELECT COUNT(*) FROM prefetch_executions WHERE {tool_sql}"
        ).fetchone()
        return bool(row and row[0])
    except Exception:
        return False


def _hypothesis_rows(
    db: CaseDB, status: str | tuple[str, ...] | None = None, limit: int = 12
) -> list[dict[str, Any]]:
    statuses = (status,) if isinstance(status, str) else status or ()
    placeholders = ", ".join("?" for _ in statuses)
    where = f"WHERE h.status IN ({placeholders})" if statuses else ""
    params: tuple[Any, ...] = (*statuses, limit)
    return fetch_records(
        db,
        f"""
        {hypothesis_latest_reasoning_cte()}
        SELECT h.hypothesis_id, h.status, h.verdict, h.description, h.summary,
               COUNT(r.entry_id) AS reasoning_count,
               MAX(r.iteration) AS latest_iteration,
               l.verdict AS latest_verdict,
               l.body AS latest_reasoning
        FROM hypotheses h
        LEFT JOIN hypothesis_reasoning r ON r.hypothesis_id = h.hypothesis_id
        LEFT JOIN latest l ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
        {where}
        GROUP BY h.hypothesis_id, h.status, h.verdict, h.description, h.summary, l.verdict, l.body
        ORDER BY
          CASE WHEN COUNT(r.entry_id) = 0 THEN 0 ELSE 1 END,
          MAX(r.iteration) DESC NULLS LAST,
          h.hypothesis_id
        LIMIT ?
        """,
        params,
    )


def _build_gaps_unresolved_table(db: CaseDB) -> list[dict[str, Any]]:
    all_rows = _hypothesis_rows(
        db, ("active", "deferred", "blocked", "needs_review"), 20
    )

    work_by_hypothesis = {
        str(row[0]): {
            "kind": str(row[1] or ""),
            "task_id": str(row[2] or ""),
            "gap_id": str(row[3] or ""),
            "reason": str(row[4] or ""),
        }
        for row in db.execute(
            "SELECT hypothesis_id, kind, task_id, gap_id, reason "
            "FROM investigation_tasks WHERE status IN ('open', 'in_progress') "
            "AND hypothesis_id IS NOT NULL"
        ).fetchall()
    }

    result: list[dict[str, Any]] = []
    for row in all_rows:
        hyp_id = str(row.get("hypothesis_id") or "")
        description = str(row.get("description") or hyp_id or "")[:120]
        latest = str(row.get("latest_reasoning") or "").strip()
        needed = _extract_needed_evidence(row.get("latest_reasoning"))
        if latest and latest[:80] == description[:80]:
            latest = ""
        work = work_by_hypothesis.get(hyp_id, {})
        status = str(work.get("kind") or row.get("status") or "") or str(
            row.get("latest_verdict") or row.get("verdict") or "inconclusive"
        )
        result.append(
            {
                "hypothesis_id": hyp_id,
                "hypothesis": description,
                "status": status,
                "evidence_rows": row.get("reasoning_count"),
                "missing_rationale": latest,
                "next_step": needed if needed else str(work.get("reason") or ""),
                "task_id": str(work.get("task_id") or ""),
                "gap_id": str(work.get("gap_id") or ""),
            }
        )

    return result


def _build_gaps_untestable_table(db: CaseDB) -> list[dict[str, Any]]:
    """Untestable hypotheses: transform raw rows into schema-matched columns."""
    rows = _hypothesis_rows(db, "untestable", 8)
    work_by_hypothesis = {
        str(item[0]): (str(item[1] or ""), str(item[2] or ""))
        for item in db.execute(
            "SELECT hypothesis_id, task_id, gap_id FROM investigation_tasks "
            "WHERE status IN ('open', 'in_progress') "
            "AND hypothesis_id IS NOT NULL"
        ).fetchall()
    }
    result: list[dict[str, Any]] = []
    for row in rows:
        hypothesis_id = str(row.get("hypothesis_id") or "")
        task_id, gap_id = work_by_hypothesis.get(hypothesis_id, ("", ""))
        needed = _extract_needed_evidence(row.get("latest_reasoning"))
        result.append(
            {
                "hypothesis_id": hypothesis_id,
                "hypothesis": str(row.get("description") or hypothesis_id)[:120],
                "missing_telemetry": needed if needed else "",
                "rationale": str(row.get("latest_reasoning") or "")[:200],
                "next_step": "acquire missing telemetry"
                if needed
                else "re-evaluate with available data",
                "task_id": task_id,
                "gap_id": gap_id,
            }
        )
    return result


def _build_gaps_confirmed_table(db: CaseDB) -> list[dict[str, Any]]:
    """RPT-05: surface confirmed hypotheses for audit, including their basis.

    Each row shows whether the confirmation was seeded by a detection rule or
    derived from a generic gap (`source_rule_ids` empty), and whether the
    rule-seeded findings were themselves downgraded to a benign-context
    pattern. This makes mis-confirmations visible to the reader instead of
    silently driving the narrative.
    """
    rows: list[dict[str, Any]] = []
    for item in _annotate_confirmed_hypotheses(
        db, _query_hypotheses_by_status(db, "confirmed", 20)
    ):
        rule_ids = _hypothesis_source_rule_ids(item)
        if rule_ids:
            evidence_basis = "rule-seeded: " + ", ".join(rule_ids[:2])
        else:
            evidence_basis = "gap-derived"
        rows.append(
            {
                "hypothesis": str(
                    item.get("description") or item.get("hypothesis_id") or ""
                )[:120],
                "verdict": str(item.get("verdict") or item.get("status") or ""),
                "evidence_basis": evidence_basis,
                "related_context": "yes" if item.get("benign_context") else "no",
                "summary": str(item.get("summary") or "")[:160],
            }
        )
    return rows


def _build_evidence_gaps_table(db: CaseDB) -> list[dict[str, Any]]:
    return _forensic_gap_rows(db)


build_evidence_gaps_table = _build_evidence_gaps_table
hypothesis_rows = _hypothesis_rows
