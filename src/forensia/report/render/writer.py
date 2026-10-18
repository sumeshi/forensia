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
from forensia.report.sections.section_quality import _strip_narrative_status_lines
from forensia.report.sections.section_store import fetch_report_sections

__all__ = [
    "build_report_markdown_from_db",
    "render_written_report",
]


def _publication_notice(state: dict[str, object]) -> str:
    """Explain which adopted report sections prevent a complete report."""
    wording = load_report_formats()["publication"][get_settings().llm_output_language]
    reasons = ", ".join(str(item) for item in state.get("reasons", []) if item)
    missing = state.get("missing_section_keys") or []
    stale = state.get("stale_section_keys") or []
    unresolved = state.get("invalid_reference_sections") or []
    return wording["notice"].format(
        missing=", ".join(str(item) for item in missing) or wording["none"],
        stale=", ".join(str(item) for item in stale) or wording["none"],
        unresolved=", ".join(str(item) for item in unresolved) or wording["none"],
        reasons=reasons or wording["incomplete_reason"],
    )


def _audit_notice(state: dict[str, object], fatal: list[object]) -> str:
    """Make final audit failures visible in every rendered report format."""
    wording = load_report_formats()["publication"][get_settings().llm_output_language]
    checks = sorted(
        {str(getattr(issue, "check_name", "validation")) for issue in fatal}
    )
    confirmed = state.get("confirmed_hypothesis_count")
    return wording["audit_notice"].format(
        case_status=(
            wording["case_complete"]
            if state.get("report_complete")
            else wording["case_incomplete"]
        ),
        investigation_status=state.get("investigation_status") or "unknown",
        stop_reason_code=state.get("stop_reason_code") or wording["stop_reason_none"],
        stop_reason=state.get("stop_reason") or wording["stop_reason_none"],
        evidence_confidence=state.get("evidence_confidence") or "not_established",
        confirmed=str(confirmed) if confirmed is not None else wording["unknown"],
        investigation_reasons=(
            ", ".join(
                str(reason)
                for reason in state.get("investigation_reasons", [])
                if reason
            )
            or wording["investigation_reason_none"]
        ),
        checks=", ".join(checks) or wording["audit_clear"],
    )


def _investigation_notice(state: dict[str, object]) -> str:
    wording = load_report_formats()["publication"][get_settings().llm_output_language]
    count = state.get("confirmed_hypothesis_count")
    report_reasons = state.get("reasons") or []
    investigation_reasons = state.get("investigation_reasons") or []
    report_unknown = any(
        reason in {"database_unavailable", "report_status_unavailable"}
        for reason in report_reasons
    )
    investigation_unknown = any(
        reason in {"database_unavailable", "investigation_state_unavailable"}
        for reason in investigation_reasons
    )
    return wording["state_notice"].format(
        investigation_status=state.get("investigation_status") or "unknown",
        stop_reason_code=(
            wording["unknown"]
            if investigation_unknown
            else state.get("stop_reason_code") or wording["stop_reason_none"]
        ),
        stop_reason=(
            wording["unknown"]
            if investigation_unknown
            else state.get("stop_reason") or wording["stop_reason_none"]
        ),
        confirmed=(str(count) if count is not None else wording["unknown"]),
        claim_scope=state.get("claim_scope") or wording["unknown"],
        report_status=wording[
            "unknown"
            if report_unknown
            else "report_complete"
            if state.get("report_complete")
            else "report_incomplete"
        ],
    )


def _rule_attribution(db: CaseDB) -> str:
    """Keep supplied authors visible even when finding summaries are abbreviated."""
    rows = db.execute("""
        SELECT DISTINCT rule_id, title,
            json_extract_string(evidence, '$[0].sigma_author') AS author,
            json_extract_string(evidence, '$[0].sigma_source') AS source
        FROM findings
        WHERE json_extract_string(evidence, '$[0].sigma_author') IS NOT NULL
        ORDER BY rule_id, author, source
    """).fetchall()
    if not rows:
        return ""
    japanese = get_settings().llm_output_language == "ja"
    heading = "検出ルールの著者・出典" if japanese else "Detection Rule Attribution"
    columns = "ルール | 著者 | 出典" if japanese else "Rule | Author | Source"

    def cell(value: object) -> str:
        return (
            str(value or "—").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
        )

    lines = [f"## {heading}", "", f"| {columns} |", "| --- | --- | --- |"]
    lines.extend(
        f"| {cell(title)} ({cell(rule_id)}) | {cell(author)} | {cell(source)} |"
        for rule_id, title, author, source in rows
    )
    return "\n".join(lines)


def build_report_markdown_from_db(db: CaseDB, case: Case | None = None) -> str:
    from forensia.report.report_validation import (
        derive_publication_state,
        has_failure_marker,
    )

    sections = fetch_report_sections(db)
    publication_state = derive_publication_state(db)
    ordered: list[str] = []
    for row in sections:
        if row.get("stale"):
            continue
        body = str(row.get("body") or "").strip()
        if not body or has_failure_marker(body):
            continue
        rendered = _strip_narrative_status_lines(body)
        ordered.append(rendered)
    notice = _investigation_notice(publication_state)
    if attribution := _rule_attribution(db):
        ordered.append(attribution)
    if not ordered:
        if publication_state.get("publication_status") == "needs_review":
            return notice + "\n\n" + _publication_notice(publication_state) + "\n"
        return notice + "\n"
    report_body = f"{notice}\n\n" + "\n\n".join(ordered).strip()
    if publication_state.get("publication_status") == "needs_review":
        report_body = f"{_publication_notice(publication_state)}\n\n{report_body}"
    return report_body + "\n"


def render_written_report(
    case: Case,
    db: CaseDB,
    *,
    html_output: str | Path | None = None,
) -> tuple[Path, Path]:
    """Write report Markdown (from sections or DB) and generate the corresponding HTML report."""
    from forensia.report.report_validation import derive_publication_state
    from forensia.report.sections.report_input import ensure_report_output_paths
    from forensia.report.sections.status import build_report_status

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
    # This projection has no repository consumer and can lag the final section state.
    (case.reports_dir / "report_brief.json").unlink(missing_ok=True)
    publication_state = derive_publication_state(db)
    report_status = build_report_status(db)
    report_body = build_report_markdown_from_db(db, case=case)
    report_path = case.reports_dir / "report.md"
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
    if fatal:
        report_body = f"{_audit_notice(publication_state, fatal)}\n\n{report_body}"
        findings = validate_report(
            brief,
            report_body=report_body,
            expected_language=expected_language,
            db=db,
        )
        fatal = [issue for issue in findings if issue.severity == "error"]
    from forensia.report.render.evidence_map import write_evidence_map

    write_evidence_map(db, report_body, case.reports_dir)
    report_path.write_text(report_body, encoding="utf-8")
    publication_state["audit_status"] = "nonpublishable" if fatal else "publishable"
    validation = {
        "publishable": not fatal,
        "audit_status": publication_state["audit_status"],
        "report_complete": bool(report_status.get("complete")),
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
