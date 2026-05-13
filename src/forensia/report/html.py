from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from forensia.core.case import Case
from forensia.db.database import CaseDB


def _fetch_records(db: CaseDB, query: str, params: tuple[Any, ...] | None = None) -> list[dict[str, Any]]:
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _normalize_value(value: Any) -> Any:
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


def _normalize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: _normalize_value(value) for key, value in row.items()} for row in rows]


def _load_report_sections(db: CaseDB) -> tuple[list[dict[str, Any]], str]:
    sections = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT section_key, title, body, confidence, status, gaps, last_filled_session, last_filled_at
            FROM report_sections
            ORDER BY section_key
            """,
        )
    )
    ordered = [str(section.get("body") or "").strip() for section in sections if str(section.get("body") or "").strip()]
    report_markdown = "\n\n".join(ordered).strip()
    if report_markdown:
        report_markdown += "\n"
    for section in sections:
        gaps = section.get("gaps") or []
        if not isinstance(gaps, list):
            gaps = []
        section["gaps"] = gaps
        section["gap_count"] = len(gaps)
    return sections, report_markdown


def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=True)


def render_html_report(case: Case, db: CaseDB, output_path: str | Path | None = None) -> Path:
    manifest = case.manifest_path.read_text(encoding="utf-8")
    findings = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT finding_id, rule_id, title, summary, severity, confidence, status,
                   tags, attack, ai_summary, evidence, missing_checks, created_at
            FROM findings
            ORDER BY confidence DESC, created_at DESC
            """,
        )
    )
    timeline = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT timeline_id, evidence_id, record_number, file_path, timestamp, timestamp_type, description, tags
            FROM mft_timeline
            ORDER BY timestamp
            LIMIT 500
            """,
        )
    )
    reviews = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT review_id, finding_id, verdict, report_text, confidence_adjustment, created_at
            FROM ai_reviews
            ORDER BY created_at DESC
            LIMIT 200
            """,
        )
    )
    claims = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids, support_status
            FROM claims
            ORDER BY section_key, created_at, claim_id
            """,
        )
    )
    report_sections, report_markdown = _load_report_sections(db)
    payload = {
        "case_name": case.path.name,
        "manifest": manifest,
        "findings": findings,
        "timeline": timeline,
        "reviews": reviews,
        "claims": claims,
        "evtx_count": int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]),
        "mft_count": int(db.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0]),
        "report_sections": report_sections,
        "report_markdown": report_markdown,
    }
    output = Path(output_path) if output_path else case.reports_dir / "report.html"
    template = _env().get_template("report.html.j2")
    output.write_text(template.render(**payload), encoding="utf-8")
    return output
