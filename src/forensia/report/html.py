from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape
import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import normalize_value


def _fetch_records(db: CaseDB, query: str, params: tuple[Any, ...] | None = None) -> list[dict[str, Any]]:
    """Execute a query and return the result as a list of dicts keyed by column name."""
    result = db.execute(query, params)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]

def _normalize_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: normalize_value(value) for key, value in row.items()} for row in rows]


def _load_report_sections(db: CaseDB) -> tuple[list[dict[str, Any]], str]:
    """Load report sections from the database into an ordered list, returning both list and concatenated markdown."""
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


def _render_inline_markdown(text: str) -> str:
    """Render basic inline Markdown (code, bold, italic) to HTML, escaping the rest."""
    escaped = escape(text)
    rendered = re.sub(r"`([^`]+)`", r"<code>\1</code>", str(escaped))
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    rendered = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", rendered)
    return rendered


def _split_table_row(line: str) -> list[str]:
    """Split a Markdown table row line into individual cell values."""
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def _is_table_separator(line: str) -> bool:
    cells = _split_table_row(line)
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def _is_table_row(line: str) -> bool:
    return "|" in line and len(_split_table_row(line)) >= 2


def _render_table(table_lines: list[str]) -> str:
    """Render a list of Markdown table lines as an HTML <table> element."""
    headers = _split_table_row(table_lines[0])
    body_lines = table_lines[2:] if len(table_lines) >= 2 and _is_table_separator(table_lines[1]) else table_lines[1:]
    thead = "".join(f"<th>{_render_inline_markdown(cell)}</th>" for cell in headers)
    rows = []
    for line in body_lines:
        cells = _split_table_row(line)
        rows.append("".join(f"<td>{_render_inline_markdown(cell)}</td>" for cell in cells))
    tbody = "".join(f"<tr>{row}</tr>" for row in rows)
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>"


@dataclass
class _MdState:
    blocks: list[str] = field(default_factory=list)
    paragraph_lines: list[str] = field(default_factory=list)
    list_items: list[str] = field(default_factory=list)
    list_kind: str | None = None
    in_code: bool = False
    code_lines: list[str] = field(default_factory=list)
    table_lines: list[str] = field(default_factory=list)


def _flush_paragraph(state: _MdState) -> None:
    if not state.paragraph_lines:
        return
    content = "<br>".join(_render_inline_markdown(line.strip()) for line in state.paragraph_lines if line.strip())
    if content:
        state.blocks.append(f"<p>{content}</p>")
    state.paragraph_lines = []


def _flush_list(state: _MdState) -> None:
    if not state.list_items or state.list_kind is None:
        state.list_items = []
        state.list_kind = None
        return
    tag = "ol" if state.list_kind == "ol" else "ul"
    items = "".join(f"<li>{_render_inline_markdown(item)}</li>" for item in state.list_items)
    state.blocks.append(f"<{tag}>{items}</{tag}>")
    state.list_items = []
    state.list_kind = None


def _flush_code(state: _MdState) -> None:
    state.blocks.append(f"<pre><code>{escape(chr(10).join(state.code_lines))}</code></pre>")
    state.code_lines = []


def _flush_table(state: _MdState) -> None:
    if not state.table_lines:
        return
    state.blocks.append(_render_table(state.table_lines))
    state.table_lines = []


def _flush_all(state: _MdState) -> None:
    _flush_paragraph(state)
    _flush_list(state)
    _flush_table(state)


def _handle_code_fence(state: _MdState, stripped: str) -> bool:
    if not stripped.startswith("```"):
        return False
    _flush_paragraph(state)
    _flush_list(state)
    _flush_table(state)
    if state.in_code:
        _flush_code(state)
        state.in_code = False
    else:
        state.in_code = True
    return True


def _handle_horizontal_rule(state: _MdState, stripped: str) -> bool:
    if not re.fullmatch(r"(-{3,}|\*{3,}|_{3,})", stripped):
        return False
    _flush_paragraph(state)
    _flush_list(state)
    _flush_table(state)
    state.blocks.append("<hr>")
    return True


def _handle_table_row(state: _MdState, stripped: str) -> bool:
    if _is_table_row(stripped):
        _flush_paragraph(state)
        _flush_list(state)
        state.table_lines.append(stripped)
        return True
    _flush_table(state)
    return False


def _handle_heading(state: _MdState, stripped: str) -> bool:
    heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
    if not heading:
        return False
    _flush_paragraph(state)
    _flush_list(state)
    level = min(len(heading.group(1)) + 1, 6)
    state.blocks.append(f"<h{level}>{_render_inline_markdown(heading.group(2).strip())}</h{level}>")
    return True


def _handle_ordered_list_item(state: _MdState, stripped: str) -> bool:
    ordered_item = re.match(r"^\d+\.\s+(.*)$", stripped)
    if not ordered_item:
        return False
    _flush_paragraph(state)
    if state.list_kind not in (None, "ol"):
        _flush_list(state)
    state.list_kind = "ol"
    state.list_items.append(ordered_item.group(1).strip())
    return True


def _handle_unordered_list_item(state: _MdState, stripped: str) -> bool:
    unordered_item = re.match(r"^[-*]\s+(.*)$", stripped)
    if not unordered_item:
        return False
    _flush_paragraph(state)
    if state.list_kind not in (None, "ul"):
        _flush_list(state)
    state.list_kind = "ul"
    state.list_items.append(unordered_item.group(1).strip())
    return True


def render_markdown_fragment(markdown: str) -> Markup:
    """Convert a Markdown string (headings, tables, lists, code, paragraphs, HR) to safe HTML via Markup."""
    if not markdown.strip():
        return Markup('<p class="empty-report">No report content yet.</p>')

    state = _MdState()
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if state.in_code and not stripped.startswith("```"):
            state.code_lines.append(line)
            continue
        if _handle_code_fence(state, stripped):
            continue
        if not stripped:
            _flush_all(state)
            continue

        for handler in (_handle_horizontal_rule, _handle_table_row, _handle_heading, _handle_ordered_list_item, _handle_unordered_list_item):
            if handler(state, stripped):
                break
        else:
            if state.list_kind is not None:
                _flush_list(state)
            state.paragraph_lines.append(stripped)

    if state.in_code:
        _flush_code(state)
    _flush_all(state)
    return Markup("\n".join(state.blocks))


def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=True)


def render_html_report(case: Case, db: CaseDB, output_path: str | Path | None = None) -> Path:
    """Render the full HTML report from case data and DB content using a Jinja2 template."""
    manifest = case.manifest_path.read_text(encoding="utf-8")
    try:
        manifest_data = yaml.safe_load(manifest) or {}
    except Exception:
        manifest_data = {}
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
    report_body_html = render_markdown_fragment(report_markdown)
    host_rows = _normalize_rows(
        _fetch_records(
            db,
            """
            SELECT DISTINCT computer
            FROM evtx_events
            WHERE COALESCE(computer, '') != ''
            ORDER BY computer
            LIMIT 8
            """,
        )
    )
    hostnames = [str(row.get("computer") or "").strip() for row in host_rows if str(row.get("computer") or "").strip()]
    generated_at = datetime.now().isoformat(timespec="seconds")
    payload = {
        "case_name": case.path.name,
        "manifest": manifest,
        "manifest_data": manifest_data,
        "findings": findings,
        "timeline": timeline,
        "reviews": reviews,
        "claims": claims,
        "evtx_count": int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]),
        "mft_count": int(db.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0]),
        "report_sections": report_sections,
        "report_markdown": report_markdown,
        "report_body_html": report_body_html,
        "hostnames": hostnames,
        "generated_at": generated_at,
    }
    output = Path(output_path) if output_path else case.reports_dir / "report.html"
    template = _env().get_template("report.html.j2")
    output.write_text(template.render(**payload), encoding="utf-8")
    return output
