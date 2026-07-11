"""Write the final report: concatenate persisted section bodies to report.md and render HTML."""

from __future__ import annotations

from pathlib import Path

from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.db.database import CaseDB
from forensia.report.render.html import render_html_report
from forensia.report.sections.section_quality import _final_report_section_body
from forensia.report.sections.section_store import fetch_report_sections

__all__ = [
    "build_report_markdown_from_db",
    "render_written_report",
]


def build_report_markdown_from_db(db: CaseDB, case: Case | None = None) -> str:
    sections = fetch_report_sections(db)
    ordered: list[str] = []
    for row in sections:
        section_key = str(row.get("section_key") or "")
        body = str(row.get("body") or "").strip()
        if not body:
            continue
        ordered.append(_final_report_section_body(section_key, body, db=db, case=case))
    if not ordered:
        return ""
    return "\n\n".join(ordered).strip() + "\n"


def render_written_report(
    case: Case,
    db: CaseDB,
    filled_sections: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    """Write report Markdown (from sections or DB) and generate the corresponding HTML report."""
    if filled_sections is not None:
        ordered = [
            filled_sections[key].strip()
            for key in sorted(filled_sections)
            if filled_sections[key].strip()
        ]
        report_body = "\n\n".join(ordered).strip() + "\n"
    else:
        report_body = build_report_markdown_from_db(db, case=case)
    from forensia.report.render.evidence_map import write_evidence_map

    write_evidence_map(db, report_body, case.reports_dir)
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_body, encoding="utf-8")
    from forensia.config import get_llm_settings
    from forensia.report.report_validation import (
        check_fallback_stub,
        check_language_consistency,
        check_local_path_leak,
    )

    expected_language = str(get_llm_settings().get("output_language", ""))
    for issue in [
        *check_local_path_leak(report_body),
        *check_fallback_stub(report_body),
        *check_language_consistency(report_body, expected_language),
    ]:
        _log("VALIDATION", f"[{issue.severity}] {issue.check_name}: {issue.message}")
    report_html = render_html_report(case, db)
    return report_path, report_html
