"""Write the final report: concatenate persisted section bodies to report.md and render HTML."""

from __future__ import annotations

import json
from pathlib import Path

from forensia.config import get_settings
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.db.database import CaseDB
from forensia.report.render.formats import load_report_formats
from forensia.report.render.html import render_html_report
from forensia.report.sections.section_quality import _final_report_section_body
from forensia.report.sections.section_store import fetch_report_sections

__all__ = [
    "build_report_markdown_from_db",
    "render_written_report",
]


def _publication_notice(state: dict[str, object]) -> str:
    """Render the durable publication gate as reader-visible report metadata."""
    wording = load_report_formats()["publication"][get_settings().llm_output_language]
    reasons = ", ".join(str(item) for item in state.get("reasons", []) if item)
    confirmed = state.get("confirmed_hypothesis_count", 0)
    steps = state.get("hypothesis_execution_step_count", 0)
    drafts = state.get("draft_sections") or []
    draft_text = (
        ", ".join(str(item) for item in drafts) if drafts else wording["no_drafts"]
    )
    return wording["notice"].format(
        confirmed=confirmed,
        steps=steps,
        drafts=draft_text,
        reasons=reasons or wording["incomplete_reason"],
    )


def _section_publication_constraint(section_key: str, state: dict[str, object]) -> str:
    """Constrain narrative sections when publication requirements are incomplete."""
    if state.get("publication_status") != "needs_review":
        return ""
    from forensia.report.sections.section_taxonomy import report_slug_family

    family = report_slug_family(section_key)
    confirmed = int(state.get("confirmed_hypothesis_count") or 0)
    wording = load_report_formats()["publication"][get_settings().llm_output_language]
    if family == "overview":
        key = "overview_confirmed" if confirmed else "overview_unconfirmed"
        return wording[key].format(confirmed=confirmed)
    if family == "recommendations":
        return wording["recommendations"]
    return ""


def build_report_markdown_from_db(db: CaseDB, case: Case | None = None) -> str:
    from forensia.report.report_validation import (
        derive_publication_state,
        has_failure_marker,
    )

    sections = fetch_report_sections(db)
    publication_state = derive_publication_state(db)
    ordered: list[str] = []
    for row in sections:
        section_key = str(row.get("section_key") or "")
        body = str(row.get("body") or "").strip()
        if not body or has_failure_marker(body):
            continue
        rendered = _final_report_section_body(section_key, body, db=db, case=case)
        constraint = _section_publication_constraint(section_key, publication_state)
        if constraint:
            rendered = f"{constraint}\n\n{rendered}"
        ordered.append(rendered)
    if not ordered:
        if publication_state.get("publication_status") == "needs_review":
            return _publication_notice(publication_state) + "\n"
        return ""
    report_body = "\n\n".join(ordered).strip()
    if publication_state.get("publication_status") == "needs_review":
        report_body = f"{_publication_notice(publication_state)}\n\n{report_body}"
    return report_body + "\n"


def render_written_report(
    case: Case,
    db: CaseDB,
    filled_sections: dict[str, str] | None = None,
    *,
    html_output: str | Path | None = None,
) -> tuple[Path, Path]:
    """Write report Markdown (from sections or DB) and generate the corresponding HTML report."""
    from forensia.report.report_validation import derive_publication_state
    from forensia.report.sections.report_input import ensure_report_output_paths

    # Same-file guard: never overwrite a case REPORT.md input with report
    # output (resolved paths, case-insensitive compare). Raises before
    # anything is written when an output target would collide with the input.
    ensure_report_output_paths(
        case,
        (
            case.reports_dir / "report.md",
            html_output
            if html_output is not None
            else case.reports_dir / "report.html",
        ),
    )
    publication_state = derive_publication_state(db)
    if filled_sections is not None:
        ordered = []
        for key in sorted(filled_sections):
            body = filled_sections[key].strip()
            if not body:
                continue
            constraint = _section_publication_constraint(key, publication_state)
            ordered.append(f"{constraint}\n\n{body}" if constraint else body)
        report_body = "\n\n".join(ordered).strip()
        if publication_state.get("publication_status") == "needs_review":
            report_body = f"{_publication_notice(publication_state)}\n\n{report_body}"
        report_body += "\n"
    else:
        report_body = build_report_markdown_from_db(db, case=case)
    from forensia.report.render.evidence_map import write_evidence_map

    write_evidence_map(db, report_body, case.reports_dir)
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_body, encoding="utf-8")
    from forensia.config import get_llm_settings
    from forensia.report.report_brief import build_report_brief
    from forensia.report.report_validation import (
        validate_report,
        validation_check_names,
    )

    expected_language = str(get_llm_settings().get("output_language", ""))
    brief = build_report_brief(db, case)
    findings = validate_report(
        brief,
        report_body=report_body,
        expected_language=expected_language,
        db=db,
    )
    fatal = [issue for issue in findings if issue.severity == "error"]
    validation = {
        "publishable": not fatal,
        "publication_status": publication_state["publication_status"],
        "evidence_confidence": publication_state["evidence_confidence"],
        "claim_scope": publication_state["claim_scope"],
        "publication_state": publication_state,
        "checks_run": validation_check_names(
            brief,
            report_body=report_body,
            expected_language=expected_language,
            db=db,
        ),
        "fatal_errors": [issue.as_dict() for issue in fatal],
        "warnings": [
            issue.as_dict() for issue in findings if issue.severity == "warning"
        ],
    }
    (case.reports_dir / "report_validation.json").write_text(
        json.dumps(validation, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    _log(
        "VALIDATION",
        f"publishable={validation['publishable']} errors={len(fatal)} "
        f"warnings={len(validation['warnings'])}",
        level="success" if validation["publishable"] else "error",
    )
    for issue in findings:
        _log(
            "VALIDATION",
            f"{issue.check_name}: {issue.message}",
            level="error" if issue.severity == "error" else "warning",
        )
    report_html = render_html_report(case, db, output_path=html_output)
    return report_path, report_html
