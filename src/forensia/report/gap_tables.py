"""Gap and hypothesis summary tables for the report."""

from __future__ import annotations

from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.report.keypoints import (
    _extract_needed_evidence,
)
from forensia.report.report_brief import (
    _annotate_confirmed_hypotheses,
    _hypothesis_source_rule_ids,
    _query_hypotheses_by_status,
)
from forensia.report.summary_rows import (
    _as_int,
    _catalog_exe_globs,
    _exe_glob_sql,
    _network_summary_rows,
)


def _forensic_gap_rows(db: CaseDB) -> list[dict[str, Any]]:
    """Evidence-gap rows derived from what the case actually contains.

    Each row is emitted only when the corresponding artifact family or signal
    is present in the evidence — no fixed scenario assumptions (Rule 16).
    """
    from forensia.rules.loader import detect_artifact_families

    network = _network_summary_rows(db)
    try:
        families = detect_artifact_families(db)
    except Exception:
        families = set()

    gaps: list[dict[str, Any]] = []
    if "cloud_sync" in families:
        gaps.append(
            {
                "gap": "Direct evidence of cloud sync destinations and targets",
                "why_it_matters": "Cloud sync client traces show the environment exists but do not directly show sync targets, destinations, or completion status.",
                "next_step": "Correlate sync client logs, local DB, and network logs.",
            }
        )
    if "mailbox" in families:
        gaps.append(
            {
                "gap": "Email content and send/receive verification",
                "why_it_matters": "Email data file existence shows client usage but content and attachment movement need other evidence.",
                "next_step": "Correlate email data file analysis results and server-side logs if available.",
            }
        )
    antiforensic_findings = _count_findings_with_tag(
        db, "benign-context:", negate=True, tag_like="%antiforensic%"
    )
    if antiforensic_findings or _has_antiforensic_executions(db):
        gaps.append(
            {
                "gap": "Scope of wiping tool execution",
                "why_it_matters": "Cleaning tool execution traces are a strong candidate but do not reveal deletion targets or execution details alone.",
                "next_step": "Correlate tool settings, task files, deleted MFT entries, and log stop times.",
            }
        )
    if network and not (
        _as_int(network[0].get("external_src_rows"))
        or _as_int(network[0].get("external_dst_rows"))
    ):
        gaps.append(
            {
                "gap": "Insufficient normalized network evidence",
                "why_it_matters": "EVTX alone is insufficient to determine external communication.",
                "next_step": "Ingest firewall/proxy/DNS/cloud client logs if available.",
            }
        )
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
    tool_sql = _exe_glob_sql(
        "executable_name", _catalog_exe_globs("antiforensic_tools")
    )
    try:
        row = db.execute(
            f"SELECT COUNT(*) FROM prefetch_executions WHERE {tool_sql}"
        ).fetchone()
        return bool(row and row[0])
    except Exception:
        return False


def _hypothesis_rows(
    db: CaseDB, status: str | None = None, limit: int = 12
) -> list[dict[str, Any]]:
    where = "WHERE h.status = ?" if status else ""
    params: tuple[Any, ...] = (status, limit) if status else (limit,)
    return fetch_records(
        db,
        f"""
        WITH latest AS (
          SELECT *, ROW_NUMBER() OVER (
            PARTITION BY hypothesis_id ORDER BY created_at DESC, entry_id DESC
          ) AS rn
          FROM hypothesis_reasoning
        )
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


def _hypothesis_count(db: CaseDB, status: str) -> int:
    row = db.execute(
        "SELECT COUNT(*) FROM hypotheses WHERE status = ?", (status,)
    ).fetchone()
    return int(row[0] or 0) if row else 0


def _section_gap_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in fetch_records(
        db, "SELECT section_key, gaps FROM report_sections ORDER BY section_key"
    ):
        gaps = normalize_value(row.get("gaps")) or []
        if not isinstance(gaps, list):
            continue
        for gap in gaps:
            text = str(gap or "").strip()
            if text:
                rows.append(
                    {
                        "section": row.get("section_key"),
                        "gap": text,
                        "next_step": "Regenerate or verify this section with supporting evidence.",
                    }
                )
    return rows[:limit]


def _build_gaps_unresolved_table(db: CaseDB) -> list[dict[str, Any]]:
    all_rows = _hypothesis_rows(db, "active", 20)
    investigated = [r for r in all_rows if int(r.get("reasoning_count") or 0) > 0]
    untouched = [r for r in all_rows if int(r.get("reasoning_count") or 0) == 0]

    result: list[dict[str, Any]] = []
    for row in investigated:
        description = str(row.get("description") or row.get("hypothesis_id") or "")[
            :120
        ]
        latest = str(row.get("latest_reasoning") or "").strip()
        needed = _extract_needed_evidence(row.get("latest_reasoning"))
        if latest and latest[:80] == description[:80]:
            latest = ""
        result.append(
            {
                "hypothesis": description,
                "state": str(
                    row.get("latest_verdict") or row.get("verdict") or "inconclusive"
                ),
                "reasoning": row.get("reasoning_count"),
                "latest": latest,
                "needed": needed if needed else "",
            }
        )

    if untouched:
        result.append(
            {
                "hypothesis": f"{len(untouched)} drafted hypotheses not yet investigated",
                "state": "not started",
                "reasoning": 0,
                "latest": "",
                "needed": "",
            }
        )

    return result


def _build_gaps_untestable_table(db: CaseDB) -> list[dict[str, Any]]:
    return _hypothesis_rows(db, "untestable", 8)


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
            basis = "rule-seeded: " + ", ".join(rule_ids[:2])
        else:
            basis = "gap-derived"
        rows.append(
            {
                "hypothesis": str(
                    item.get("description") or item.get("hypothesis_id") or ""
                )[:120],
                "verdict": str(item.get("verdict") or item.get("status") or ""),
                "basis": basis,
                "benign_context": "yes" if item.get("benign_context") else "no",
                "summary": str(item.get("summary") or "")[:160],
            }
        )
    return rows


def _build_evidence_gaps_table(db: CaseDB) -> list[dict[str, Any]]:
    return _forensic_gap_rows(db)

