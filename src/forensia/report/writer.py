from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from forensia.ai.lmstudio import chat_completion
from forensia.ai.prompts import build_report_section_messages
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.html import render_html_report

GAP_PATTERN = re.compile(r"【調査不足:\s*([^】]+)】")


def _fetch_records(db: CaseDB, query: str) -> list[dict[str, Any]]:
    result = db.execute(query)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _normalize_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return value


def _parse_template(template_path: str | Path) -> tuple[dict[str, Any], str]:
    text = Path(template_path).read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    _, frontmatter, body = text.split("---\n", 2)
    meta = yaml.safe_load(frontmatter) or {}
    return meta, body.strip()


def _section_confidence(body: str) -> float:
    paragraphs = [item.strip() for item in re.split(r"\n\s*\n", body) if item.strip()]
    paragraph_count = max(len(paragraphs), 1)
    gap_count = len(GAP_PATTERN.findall(body))
    return max(0.0, min(1.0, 1.0 - (gap_count / paragraph_count)))


def _summarize_query_results(db: CaseDB, queries: list[str], max_rows: int = 20) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for query in queries:
        rows = _fetch_records(db, query)
        evidence_ids: list[str] = []
        finding_ids: list[str] = []
        hypothesis_ids: list[str] = []
        for row in rows:
            evidence_id = row.get("evidence_id")
            if evidence_id and str(evidence_id) not in evidence_ids:
                evidence_ids.append(str(evidence_id))
            finding_id = row.get("finding_id")
            if finding_id and str(finding_id) not in finding_ids:
                finding_ids.append(str(finding_id))
            hypothesis_id = row.get("hypothesis_id")
            if hypothesis_id and str(hypothesis_id) not in hypothesis_ids:
                hypothesis_ids.append(str(hypothesis_id))
        summaries.append(
            {
                "query": query,
                "row_count": len(rows),
                "evidence_ids": evidence_ids,
                "finding_ids": finding_ids,
                "hypothesis_ids": hypothesis_ids,
                "sample_rows": [_normalize_value(row) for row in rows[:max_rows]],
            }
        )
    return summaries


def _extract_claim_texts(body: str) -> list[str]:
    claims: list[str] = []
    for paragraph in re.split(r"\n\s*\n", body):
        text = paragraph.strip()
        if not text or text.startswith("#") or GAP_PATTERN.search(text):
            continue
        normalized = " ".join(line.strip("- ").strip() for line in text.splitlines() if line.strip())
        if normalized:
            claims.append(normalized)
    return claims


def _claim_text_key(text: str) -> str:
    return " ".join(text.lower().split())


def _collect_claim_provenance(evidence_results: list[dict[str, Any]]) -> dict[str, list[str]]:
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    for result in evidence_results:
        for evidence_id in result.get("evidence_ids") or []:
            value = str(evidence_id)
            if value and value not in evidence_ids:
                evidence_ids.append(value)
        for finding_id in result.get("finding_ids") or []:
            value = str(finding_id)
            if value and value not in finding_ids:
                finding_ids.append(value)
        for hypothesis_id in result.get("hypothesis_ids") or []:
            value = str(hypothesis_id)
            if value and value not in hypothesis_ids:
                hypothesis_ids.append(value)
    return {
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
    }


def _build_report_brief(db: CaseDB) -> dict[str, Any]:
    findings = _fetch_records(
        db,
        """
        SELECT finding_id, title, severity, confidence, summary
        FROM findings
        WHERE COALESCE(status, 'accepted') != 'suppressed'
        ORDER BY confidence DESC, created_at DESC
        LIMIT 8
        """,
    )
    active_hypotheses = _fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary
        FROM hypotheses
        WHERE status = 'active'
        ORDER BY updated_at DESC, hypothesis_id
        LIMIT 8
        """,
    )
    prior_sections = _fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status
        FROM report_sections
        WHERE COALESCE(body, '') != ''
        ORDER BY section_key
        """,
    )
    existing_claims = _fetch_records(
        db,
        """
        SELECT section_key, claim_text, support_status
        FROM claims
        ORDER BY updated_at DESC, claim_id DESC
        LIMIT 20
        """,
    )
    return {
        "top_findings": [_normalize_value(item) for item in findings],
        "active_hypotheses": [_normalize_value(item) for item in active_hypotheses],
        "prior_sections": [
            {
                "section_key": item["section_key"],
                "title": item["title"],
                "confidence": item["confidence"],
                "status": item["status"],
                "excerpt": str(item.get("body") or "").strip()[:400],
            }
            for item in prior_sections
        ],
        "existing_claims": [_normalize_value(item) for item in existing_claims],
    }


def write_report_brief(case: Case, db: CaseDB) -> dict[str, Any]:
    brief = _build_report_brief(db)
    path = case.reports_dir / "report_brief.json"
    path.write_text(json.dumps(brief, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return brief


def _claim_support_status(
    db: CaseDB,
    evidence_ids: list[str],
    finding_ids: list[str],
    hypothesis_ids: list[str],
) -> str:
    if not evidence_ids and not finding_ids and not hypothesis_ids:
        return "unsupported"
    for finding_id in finding_ids:
        if not db.execute("SELECT 1 FROM findings WHERE finding_id = ? LIMIT 1", (finding_id,)).fetchone():
            return "orphaned_reference"
    for hypothesis_id in hypothesis_ids:
        if not db.execute("SELECT 1 FROM hypotheses WHERE hypothesis_id = ? LIMIT 1", (hypothesis_id,)).fetchone():
            return "orphaned_reference"
    for evidence_id in evidence_ids:
        evtx_row = db.execute("SELECT 1 FROM evtx_events WHERE evidence_id = ? LIMIT 1", (evidence_id,)).fetchone()
        mft_row = db.execute("SELECT 1 FROM mft_entries WHERE evidence_id = ? LIMIT 1", (evidence_id,)).fetchone()
        if not evtx_row and not mft_row:
            return "orphaned_reference"
    return "supported"


def _upsert_claims(
    db: CaseDB,
    section_key: str,
    body: str,
    evidence_results: list[dict[str, Any]],
) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    claims = _extract_claim_texts(body)
    provenance = _collect_claim_provenance(evidence_results)
    support_status = _claim_support_status(
        db,
        provenance["evidence_ids"],
        provenance["finding_ids"],
        provenance["hypothesis_ids"],
    )
    db.execute("DELETE FROM claims WHERE section_key = ?", (section_key,))
    rows: list[tuple[Any, ...]] = []
    for index, claim_text in enumerate(claims, start=1):
        claim_id = hashlib.sha1(f"{section_key}-{index}-{claim_text}".encode("utf-8")).hexdigest()[:16]
        rows.append(
            (
                claim_id,
                section_key,
                claim_text,
                json.dumps(provenance["finding_ids"], ensure_ascii=False),
                json.dumps(provenance["hypothesis_ids"], ensure_ascii=False),
                json.dumps(provenance["evidence_ids"], ensure_ascii=False),
                support_status,
                now,
                now,
            )
        )
    db.insert_many(
        """
        INSERT INTO claims (
            claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
            support_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if not claims:
        return
    text_groups = _fetch_records(
        db,
        """
        SELECT claim_id, claim_text, section_key, finding_ids, hypothesis_ids, evidence_ids, support_status
        FROM claims
        WHERE claim_text IN (
            SELECT claim_text FROM claims GROUP BY claim_text HAVING COUNT(*) > 1
        )
        ORDER BY claim_text, section_key, claim_id
        """,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in text_groups:
        grouped.setdefault(_claim_text_key(str(row.get("claim_text") or "")), []).append(row)
    for rows_for_text in grouped.values():
        provenance_keys = {
            json.dumps(
                {
                    "finding_ids": _normalize_value(row.get("finding_ids")) or [],
                    "hypothesis_ids": _normalize_value(row.get("hypothesis_ids")) or [],
                    "evidence_ids": _normalize_value(row.get("evidence_ids")) or [],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            for row in rows_for_text
        }
        if len(provenance_keys) <= 1:
            continue
        for row in rows_for_text:
            db.execute(
                "UPDATE claims SET support_status = 'needs_review', updated_at = ? WHERE claim_id = ?",
                (now, str(row["claim_id"])),
            )


def _upsert_report_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    confidence: float,
    gaps: list[str],
    session_id: str | None = None,
) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        "SELECT status, update_count FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(existing[0] or "draft") if existing else "draft"
    update_count = int(existing[1] or 0) + 1 if existing else 1
    if gaps or confidence < 0.9:
        next_status = "draft"
    elif existing_status == "human_reviewed":
        next_status = "human_reviewed"
    elif existing_status == "ai_exhausted":
        next_status = "ai_exhausted"
    else:
        next_status = "stable"
    db.execute(
        """
        INSERT INTO report_sections (
            section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (section_key) DO UPDATE SET
            title = excluded.title,
            body = excluded.body,
            confidence = excluded.confidence,
            status = excluded.status,
            update_count = excluded.update_count,
            gaps = excluded.gaps,
            last_filled_session = excluded.last_filled_session,
            last_filled_at = excluded.last_filled_at
        """,
        (
            section_key,
            title,
            body,
            confidence,
            next_status,
            update_count,
            json.dumps(gaps, ensure_ascii=False),
            session_id,
            now,
        ),
    )


def mark_report_sections_ai_exhausted(db: CaseDB) -> None:
    db.execute(
        """
        UPDATE report_sections
        SET status = 'ai_exhausted'
        WHERE COALESCE(body, '') != ''
        """
    )


def set_report_section_status(db: CaseDB, section_key: str, status: str) -> None:
    if status not in {"draft", "stable", "ai_exhausted", "human_reviewed"}:
        raise ValueError(f"unsupported report section status: {status}")
    db.execute(
        """
        UPDATE report_sections
        SET status = ?
        WHERE section_key = ?
        """,
        (status, section_key),
    )


def fetch_report_sections(db: CaseDB) -> list[dict[str, Any]]:
    return _fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )


def load_report_sections_map(db: CaseDB) -> dict[str, str]:
    return {
        str(row.get("section_key")): str(row.get("body") or "")
        for row in fetch_report_sections(db)
    }


def build_report_markdown_from_db(db: CaseDB) -> str:
    sections = fetch_report_sections(db)
    ordered = [str(row.get("body") or "").strip() for row in sections if str(row.get("body") or "").strip()]
    if not ordered:
        return ""
    return "\n\n".join(ordered).strip() + "\n"


def prepare_section_request(
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read template + evidence and build the LLM messages.

    Pure I/O against DuckDB; safe to call from the main thread before
    dispatching parallel LLM workers.
    """
    section_meta, template_body = _parse_template(template_path)
    evidence_results = _summarize_query_results(db, list(section_meta.get("evidence_queries") or []))
    messages = build_report_section_messages(
        section_meta=section_meta,
        evidence_results=evidence_results,
        context_sections=context_sections,
        template_body=template_body,
        report_brief=report_brief,
    )
    section_key = str(section_meta.get("section") or Path(template_path).stem)
    title = str(section_meta.get("title") or section_key)
    return {
        "section_key": section_key,
        "title": title,
        "messages": messages,
        "template_path": str(template_path),
        "evidence_results": evidence_results,
    }


def finalize_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """UPSERT the section into DuckDB. Returns gap list and confidence."""
    gaps = collect_gaps({section_key: body})
    confidence = _section_confidence(body)
    _upsert_report_section(
        db=db,
        section_key=section_key,
        title=title,
        body=body,
        confidence=confidence,
        gaps=gaps,
        session_id=session_id,
    )
    _upsert_claims(db, section_key, body, evidence_results or [])
    return {"gaps": gaps, "confidence": confidence}


def fill_section(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    session_id: str | None = None,
    audit_callback: Callable[[list[dict[str, str]], str], None] | None = None,
) -> str:
    request = prepare_section_request(db, template_path, context_sections, report_brief=report_brief)
    body = chat_completion(messages=request["messages"], model=model, base_url=base_url).strip()
    if audit_callback:
        audit_callback(request["messages"], body)
    finalize_section(
        db=db,
        section_key=request["section_key"],
        title=request["title"],
        body=body,
        evidence_results=request["evidence_results"],
        session_id=session_id,
    )
    return body


def collect_gaps(filled_sections: dict[str, str]) -> list[str]:
    gaps: list[str] = []
    for content in filled_sections.values():
        for match in GAP_PATTERN.finditer(content):
            gap = match.group(1).strip()
            if gap and gap not in gaps:
                gaps.append(gap)
    return gaps


def write_report(case: Case, filled_sections: dict[str, str]) -> Path:
    ordered = [filled_sections[key].strip() for key in sorted(filled_sections) if filled_sections[key].strip()]
    report_md = "\n\n".join(ordered).strip() + "\n"
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def write_report_from_db(case: Case, db: CaseDB) -> Path:
    report_md = build_report_markdown_from_db(db)
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def render_written_report(
    case: Case,
    db: CaseDB,
    filled_sections: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    report_md = write_report(case, filled_sections) if filled_sections is not None else write_report_from_db(case, db)
    report_html = render_html_report(case, db)
    return report_md, report_html
