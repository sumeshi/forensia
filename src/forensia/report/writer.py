from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
        summaries.append(
            {
                "query": query,
                "row_count": len(rows),
                "sample_rows": [_normalize_value(row) for row in rows[:max_rows]],
            }
        )
    return summaries


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
    elif existing_status == "approved":
        next_status = "approved"
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


def mark_report_sections_approved(db: CaseDB) -> None:
    db.execute(
        """
        UPDATE report_sections
        SET status = 'approved'
        WHERE COALESCE(body, '') != ''
        """
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
    )
    section_key = str(section_meta.get("section") or Path(template_path).stem)
    title = str(section_meta.get("title") or section_key)
    return {
        "section_key": section_key,
        "title": title,
        "messages": messages,
        "template_path": str(template_path),
    }


def finalize_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
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
    return {"gaps": gaps, "confidence": confidence}


def fill_section(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    base_url: str,
    model: str,
    session_id: str | None = None,
) -> str:
    request = prepare_section_request(db, template_path, context_sections)
    body = chat_completion(messages=request["messages"], model=model, base_url=base_url).strip()
    finalize_section(
        db=db,
        section_key=request["section_key"],
        title=request["title"],
        body=body,
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
