from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup, escape
import yaml

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


def _render_inline_markdown(text: str) -> str:
    escaped = escape(text)
    rendered = re.sub(r"`([^`]+)`", r"<code>\1</code>", str(escaped))
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    rendered = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", rendered)
    return rendered


def _split_table_row(line: str) -> list[str]:
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
    headers = _split_table_row(table_lines[0])
    body_lines = table_lines[2:] if len(table_lines) >= 2 and _is_table_separator(table_lines[1]) else table_lines[1:]
    thead = "".join(f"<th>{_render_inline_markdown(cell)}</th>" for cell in headers)
    rows = []
    for line in body_lines:
        cells = _split_table_row(line)
        rows.append("".join(f"<td>{_render_inline_markdown(cell)}</td>" for cell in cells))
    tbody = "".join(f"<tr>{row}</tr>" for row in rows)
    return f"<table><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>"


def render_markdown_fragment(markdown: str) -> Markup:
    if not markdown.strip():
        return Markup('<p class="empty-report">No report content yet.</p>')

    blocks: list[str] = []
    paragraph_lines: list[str] = []
    list_items: list[str] = []
    list_kind: str | None = None
    in_code = False
    code_lines: list[str] = []
    table_lines: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph_lines
        if not paragraph_lines:
            return
        content = "<br>".join(_render_inline_markdown(line.strip()) for line in paragraph_lines if line.strip())
        if content:
            blocks.append(f"<p>{content}</p>")
        paragraph_lines = []

    def flush_list() -> None:
        nonlocal list_items, list_kind
        if not list_items or list_kind is None:
            list_items = []
            list_kind = None
            return
        tag = "ol" if list_kind == "ol" else "ul"
        items = "".join(f"<li>{_render_inline_markdown(item)}</li>" for item in list_items)
        blocks.append(f"<{tag}>{items}</{tag}>")
        list_items = []
        list_kind = None

    def flush_code() -> None:
        nonlocal code_lines
        blocks.append(f"<pre><code>{escape(chr(10).join(code_lines))}</code></pre>")
        code_lines = []

    def flush_table() -> None:
        nonlocal table_lines
        if not table_lines:
            return
        blocks.append(_render_table(table_lines))
        table_lines = []

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if stripped.startswith("```"):
            flush_paragraph()
            flush_list()
            flush_table()
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not stripped:
            flush_paragraph()
            flush_list()
            flush_table()
            continue

        if re.fullmatch(r"(-{3,}|\*{3,}|_{3,})", stripped):
            flush_paragraph()
            flush_list()
            flush_table()
            blocks.append("<hr>")
            continue

        if _is_table_row(stripped):
            flush_paragraph()
            flush_list()
            table_lines.append(stripped)
            continue
        flush_table()

        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            flush_paragraph()
            flush_list()
            level = min(len(heading.group(1)) + 1, 6)
            blocks.append(f"<h{level}>{_render_inline_markdown(heading.group(2).strip())}</h{level}>")
            continue

        ordered_item = re.match(r"^\d+\.\s+(.*)$", stripped)
        if ordered_item:
            flush_paragraph()
            if list_kind not in (None, "ol"):
                flush_list()
            list_kind = "ol"
            list_items.append(ordered_item.group(1).strip())
            continue

        unordered_item = re.match(r"^[-*]\s+(.*)$", stripped)
        if unordered_item:
            flush_paragraph()
            if list_kind not in (None, "ul"):
                flush_list()
            list_kind = "ul"
            list_items.append(unordered_item.group(1).strip())
            continue

        if list_kind is not None:
            flush_list()
        paragraph_lines.append(stripped)

    if in_code:
        flush_code()
    flush_paragraph()
    flush_list()
    flush_table()
    return Markup("\n".join(blocks))


def _env() -> Environment:
    return Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=True)


def render_html_report(case: Case, db: CaseDB, output_path: str | Path | None = None) -> Path:
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
