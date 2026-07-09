"""Section body verification, coverage tracking, and gap detection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.answer_registry import (
    build_structured_answer,
)
from forensia.report.answer_store import (
    _render_structured_answer_markdown,
    _structured_answer_interpretation,
    _structured_block_id,
)
from forensia.report.evidence_refs import (
    EVIDENCE_ID_PATTERN,
)
from forensia.report.markdown import (
    _strip_hidden_report_columns_from_markdown_tables,
)
from forensia.report.quality_gates import (
    HTML_FILL_PATTERN,
    _first_heading_text,
)


@dataclass(frozen=True)
class TemplateMeta:
    behaviors: tuple[str, ...] = ()


GAP_PATTERN = re.compile(
    r"\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]",
    re.IGNORECASE,
)
BLOCK_HINT_PATTERN = re.compile(
    r"<!--\s*(?P<name>evidence_keypoints|mode|question_id|benchmark_id|answer_id|answer_spec|builder)\s*:\s*(?P<value>.*?)\s*-->",
    re.IGNORECASE,
)
QUESTION_HINT_PATTERN = re.compile(
    r"<!--\s*question(?:\s*:\s*(?P<value>.*?))?\s*-->", re.IGNORECASE
)
RAW_EVIDENCE_HEADING_PATTERN = re.compile(r"^#{2,6}\s*Raw Evidence\s*$", re.IGNORECASE)


def _section_confidence(body: str) -> float:
    """Estimate confidence from the ratio of gap markers to total paragraphs."""
    paragraphs = [item.strip() for item in re.split(r"\n\s*\n", body) if item.strip()]
    paragraph_count = max(len(paragraphs), 1)
    gap_count = len(GAP_PATTERN.findall(body))
    return max(0.0, min(1.0, 1.0 - (gap_count / paragraph_count)))


def _title_from_template_body(template_body: str, fallback: str) -> str:
    title = _first_heading_text(template_body)
    return title or fallback


def _duplicate_finding_titles(db: CaseDB, body: str) -> list[str]:
    """Detect finding titles that appear more than twice in a section body."""
    lowered_body = body.casefold()
    duplicates: list[str] = []
    rows = fetch_records(
        db,
        """
        SELECT DISTINCT title
        FROM findings
        WHERE COALESCE(title, '') != ''
        """,
    )
    for row in rows:
        title = str(row.get("title") or "").strip()
        if len(title) < 5:
            continue
        count = lowered_body.count(title.casefold())
        if count > 2:
            duplicates.append(title)
    return duplicates


def _correlation_finding_ids(finding_ids: list[str], db: CaseDB) -> list[str]:
    """Filter a list of finding IDs to those belonging to correlation rules."""
    if not finding_ids:
        return []
    placeholders = ", ".join("?" for _ in finding_ids)
    rows = fetch_records(
        db,
        f"""
        SELECT finding_id
        FROM findings
        WHERE finding_id IN ({placeholders})
          AND rule_id LIKE '%corr-%'
        """,
        tuple(finding_ids),
    )
    return [
        str(row.get("finding_id") or "")
        for row in rows
        if str(row.get("finding_id") or "")
    ]


@lru_cache(maxsize=1)
def _load_event_id_hints() -> dict[int, dict[str, Any]]:
    """Load the event_id to hints mapping from _schema/event_ids.yaml."""
    import yaml

    path = Path(__file__).parent.parent / "rulepacks" / "_schema" / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    raw_events = data.get("events") if isinstance(data, dict) else {}
    if not isinstance(raw_events, dict):
        return {}
    hints: dict[int, dict[str, Any]] = {}
    for key, value in raw_events.items():
        try:
            event_id = int(key)
        except TypeError, ValueError:
            continue
        if isinstance(value, dict):
            hints[event_id] = value
    return hints


def _collect_event_ids_from_results(
    evidence_results: list[dict[str, Any]] | None,
) -> set[int]:
    """Collect distinct event_id values from evidence result rows."""
    event_ids: set[int] = set()
    for result in evidence_results or []:
        for row in (
            (result.get("sample_rows") or [])
            + (result.get("head_rows") or [])
            + (result.get("tail_rows") or [])
        ):
            if not isinstance(row, dict):
                continue
            try:
                event_id = int(row.get("event_id"))
            except TypeError, ValueError:
                continue
            event_ids.add(event_id)
    return event_ids


def _event_claim_gaps(
    body: str, evidence_results: list[dict[str, Any]] | None
) -> list[str]:
    """Check if the body uses disallowed wording for event IDs that require extra support."""
    hints = _load_event_id_hints()
    event_ids = _collect_event_ids_from_results(evidence_results)
    if not hints or not event_ids:
        return []
    lowered = body.casefold()
    gaps: list[str] = []
    for event_id in sorted(event_ids):
        hint = hints.get(event_id)
        if not hint:
            continue
        disallowed = [
            str(item).casefold()
            for item in hint.get("disallowed_without_extra") or []
            if str(item).strip()
        ]
        if any(term and term in lowered for term in disallowed):
            label = f"Event ID {event_id} claim uses disallowed wording without extra support."
            if label not in gaps:
                gaps.append(label)
    return gaps


def _parse_section_run_payload(payload: Any) -> dict[str, Any]:
    """Parse a section run payload from JSON string or dict."""
    if isinstance(payload, dict):
        return payload
    if not isinstance(payload, str) or not payload.strip():
        return {}
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coverage_source_label(result: dict[str, Any], payload: dict[str, Any]) -> str:
    """Derive a human-readable source label from a coverage result and its payload."""
    candidates = [
        str(result.get("keypoint") or "").strip(),
        str(result.get("query_id") or "").strip(),
        str(result.get("purpose") or "").strip(),
        str(result.get("source_ref") or "").strip(),
        str(payload.get("source_ref") or "").strip(),
        str(payload.get("source_kind") or "").strip(),
    ]
    for candidate in candidates:
        if candidate:
            return candidate
    return "unknown_source"


def _collect_section_coverage(db: CaseDB) -> dict[str, list[dict[str, Any]]]:
    """Aggregate evidence coverage information per section from the database."""
    try:
        rows = fetch_records(
            db,
            """
            SELECT section_key, source_query, evidence_table, row_count, used_in_answer, queried
            FROM section_run_coverage
            ORDER BY section_key, source_query
            """,
        )
    except Exception:
        rows = fetch_records(
            db,
            """
            SELECT section_key, block_heading, phase, payload, created_at
            FROM section_runs
            WHERE phase = 'query'
            ORDER BY created_at, iteration
            """,
        )
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        section_key = str(row.get("section_key") or "").strip()
        if not section_key:
            continue
        payload = _parse_section_run_payload(row.get("payload"))
        result = (
            payload.get("result") if isinstance(payload.get("result"), dict) else {}
        )
        source_label = str(row.get("source_query") or "").strip()
        if not source_label:
            source_label = _coverage_source_label(result, payload)
        section_map = grouped.setdefault(section_key, {})
        entry = section_map.setdefault(
            source_label,
            {
                "source": source_label,
                "queried": str(row.get("queried") or "Yes"),
                "rows": 0,
                "used_in_answer": str(row.get("used_in_answer") or "Yes"),
                "source_kind": str(
                    row.get("evidence_table")
                    or payload.get("source_kind")
                    or result.get("source_kind")
                    or ""
                ).strip(),
            },
        )
        try:
            row_count = int(row.get("row_count") or result.get("row_count") or 0)
        except TypeError, ValueError:
            row_count = 0
        entry["rows"] = max(int(entry.get("rows") or 0), row_count)
        if str(row.get("used_in_answer") or result.get("kind") or "rows") != "Yes":
            entry["used_in_answer"] = "No"
    return {
        section_key: list(section_map.values())
        for section_key, section_map in grouped.items()
    }


def _coverage_table_markdown(rows: list[dict[str, Any]]) -> str:
    """Render a list of coverage rows as a Markdown table."""
    if not rows:
        return ""
    header = "| Source | Queried | Rows | Used in answer |"
    separator = "|---|---|---|---|"
    lines = []
    for row in rows:
        rows_value = row.get("rows")
        rows_text = "-" if rows_value in {None, ""} else str(rows_value)
        lines.append(
            f"| {str(row.get('source') or '').replace('|', '\\|')} | "
            f"{str(row.get('queried') or 'No')} | "
            f"{rows_text} | "
            f"{str(row.get('used_in_answer') or 'No')} |"
        )
    return "\n".join([header, separator, *lines])


def _validate_body_evidence_ids(db: CaseDB, body: str) -> list[str]:
    """Check that every evidence_id referenced in the body exists in evidence tables."""
    evidence_ids = sorted(set(EVIDENCE_ID_PATTERN.findall(body)))
    if not evidence_ids:
        return []
    placeholders = ", ".join("?" for _ in evidence_ids)
    found = {
        str(row[0])
        for row in db.execute(
            f"""
            SELECT evidence_id FROM evtx_events WHERE evidence_id IN ({placeholders})
            UNION
            SELECT evidence_id FROM mft_entries WHERE evidence_id IN ({placeholders})
            UNION
            SELECT evidence_id FROM prefetch_executions WHERE evidence_id IN ({placeholders})
            UNION
            SELECT evidence_id FROM prefetch_timeline WHERE evidence_id IN ({placeholders})
            """,
            tuple(evidence_ids * 4),
        ).fetchall()
    }
    return [evidence_id for evidence_id in evidence_ids if evidence_id not in found]


def _verify_block_output(db: CaseDB, body: str) -> tuple[list[str], float]:
    """Verify a single block's output for gaps, confidence, missing evidence IDs, and template placeholders."""
    gaps = collect_gaps({"block": body})
    confidence = _section_confidence(body)
    missing_evidence_ids = _validate_body_evidence_ids(db, body)
    if missing_evidence_ids:
        gaps.append(
            f"Referenced evidence_id values not found in database: {', '.join(missing_evidence_ids[:5])}"
        )
        confidence = min(confidence, 0.6)
    if HTML_FILL_PATTERN.search(body):
        note = "Template placeholder markers remain in the section body."
        if note not in gaps:
            gaps.append(note)
        confidence = min(confidence, 0.3)
    return gaps, confidence


@cache
def _load_template_meta(section_key: str) -> TemplateMeta:
    """Load template frontmatter metadata for a section key from the packaged template."""
    from importlib import resources

    from forensia.report.writer import _parse_frontmatter

    try:
        text = (
            resources.files("forensia")
            .joinpath(f"report_template/{section_key}.md")
            .read_text(encoding="utf-8")
        )
    except Exception:
        return TemplateMeta()
    meta = _parse_frontmatter(text)
    behaviors = tuple(meta.get("behaviors") or [])
    return TemplateMeta(behaviors=behaviors)


def _strip_narrative_status_lines(body: str) -> str:
    """Remove internal block status badges from human-facing narrative sections.

    The raw_sql → evidence query replacement is a legacy safeguard for section bodies
    persisted before `_result_source_label` was renamed; new runs emit `evidence_query`
    via the source label itself and never hit the replace branch.
    """
    lines = []
    for line in str(body or "").splitlines():
        stripped = line.strip()
        if re.match(
            r"^\*\*Status:\*\*\s*(answered|partial|not_found|not_searched|wrong_query|insufficient_evidence|error)\b",
            stripped,
            flags=re.IGNORECASE,
        ):
            continue
        lines.append(line)
    text = "\n".join(lines)
    text = text.replace("raw_sql", "evidence query")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _parse_markdown_answer_rows(block: str) -> list[dict[str, Any]]:
    answer_part = re.split(
        r"(?m)^### (?:Missing Reason|Queries Run|Structured Data)\s*$",
        block,
        maxsplit=1,
    )[0]
    if "### Answer" in answer_part:
        answer_part = answer_part.split("### Answer", 1)[1]
    table_lines = [
        line.strip()
        for line in answer_part.splitlines()
        if line.strip().startswith("|") and line.strip().endswith("|")
    ]
    if len(table_lines) < 2:
        return []
    headers = [
        cell.strip().replace("\\|", "|")
        for cell in table_lines[0].strip("|").split("|")
    ]
    rows: list[dict[str, Any]] = []
    for line in table_lines[1:]:
        cells = [
            cell.strip().replace("\\|", "|") for cell in line.strip("|").split("|")
        ]
        if all(re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells):
            continue
        if len(cells) != len(headers):
            continue
        rows.append(dict(zip(headers, cells, strict=False)))
    return rows


def _ensure_appendix_interpretations(body: str, tz_name: str | None = None) -> str:
    """Insert short reader-facing interpretations into existing appendix question blocks."""
    chunks = re.split(r"(?m)(?=^## .+$)", str(body or "").strip())
    rendered: list[str] = []
    for chunk in chunks:
        if not chunk.strip() or not chunk.lstrip().startswith("## "):
            rendered.append(chunk)
            continue
        if "### Interpretation" in chunk or "### Answer" not in chunk:
            rendered.append(chunk)
            continue
        heading = chunk.splitlines()[0].lstrip("#").strip()
        id_match = re.search(r"(?m)^\*\*ID:\*\*\s*(.+)$", chunk)
        status_match = re.search(r"(?m)^\*\*Status:\*\*\s*(.+)$", chunk)
        spec_match = re.search(r"(?m)^- structured:(?P<spec>[^:]+):", chunk)
        answer = {
            "answer_spec": spec_match.group("spec").strip() if spec_match else "",
            "id": id_match.group(1).strip()
            if id_match
            else _structured_block_id(heading),
            "status": status_match.group(1).strip() if status_match else "",
            "answer": _parse_markdown_answer_rows(chunk),
        }
        interpretation = _structured_answer_interpretation(
            answer, heading, tz_name=tz_name
        )
        chunk = chunk.replace(
            "\n### Answer", f"\n### Interpretation\n{interpretation}\n\n### Answer", 1
        )
        rendered.append(chunk)
    text = "".join(rendered)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _refresh_appendix_structured_blocks(
    db: CaseDB | None, body: str, tz_name: str | None = None
) -> str:
    """Refresh stale high-risk appendix blocks whose old Markdown can retain noisy rows."""
    if db is None:
        return body
    chunks = re.split(r"(?m)(?=^## .+$)", str(body or "").strip())
    rendered: list[str] = []
    for chunk in chunks:
        if not chunk.strip() or not chunk.lstrip().startswith("## "):
            rendered.append(chunk)
            continue
        heading = chunk.splitlines()[0].lstrip("#").strip()
        lower_heading = heading.casefold()
        answer_spec = ""
        if "antiforensic" in lower_heading or "anti-forensic" in lower_heading:
            answer_spec = "antiforensic_activity"
        if not answer_spec:
            rendered.append(chunk)
            continue
        id_match = re.search(r"(?m)^\*\*ID:\*\*\s*(.+)$", chunk)
        answer_id = (
            id_match.group(1).strip() if id_match else _structured_block_id(heading)
        )
        try:
            answer = build_structured_answer(
                db.case,
                db,
                answer_spec=answer_spec,
                answer_id=answer_id,
                section_key="6_appendix",
                block_heading=heading,
            )
        except Exception:
            answer = None
        rendered.append(
            _render_structured_answer_markdown(answer, heading, tz_name=tz_name)
            if answer
            else chunk
        )
    return "".join(rendered).strip()


def _final_report_section_body(
    section_key: str, body: str, db: CaseDB | None = None, case: Case | None = None
) -> str:
    """Return the Markdown body intended for report.md, leaving debug metadata out."""
    text = str(body or "").strip()
    if section_key != "6_appendix":
        text = _strip_narrative_status_lines(text)
    else:
        tz_name = getattr(case, "source_timezone", "UTC") if case else "UTC"
        text = _refresh_appendix_structured_blocks(db, text, tz_name=tz_name)
        text = _ensure_appendix_interpretations(text, tz_name=tz_name)
        text = _strip_hidden_report_columns_from_markdown_tables(text)
    return text


def _sanitize_raw_evidence_body(section_key: str, body: str) -> tuple[str, bool]:
    """Replace raw evidence tables under Raw Evidence headings with a redirection notice."""
    text = str(body or "").rstrip()
    if not text:
        return text, False
    lines = text.splitlines()
    out: list[str] = []
    removed = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if RAW_EVIDENCE_HEADING_PATTERN.match(line.strip()):
            removed = True
            out.append(line)
            out.append("")
            out.append(
                f"Raw evidence moved to reports/evidence/{section_key}.json; this section keeps only normalized summaries."
            )
            index += 1
            while index < len(lines):
                next_line = lines[index]
                if next_line.strip().startswith(
                    "## "
                ) and not next_line.strip().startswith("### "):
                    break
                if next_line.strip().startswith(
                    "### "
                ) and not next_line.strip().startswith("#### "):
                    break
                index += 1
            continue
        out.append(line)
        index += 1
    sanitized = "\n".join(out).strip()
    if removed and (
        "| None |" in text
        or "| NULL |" in text
        or "| - |" in text
        or "None" in text
        or "NULL" in text
    ):
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized, removed


# ====================================================================
# ORCHESTRATION (cont.) — write_report, render_written_report
# Lines: ~6000-6078
# ====================================================================


def collect_gaps(filled_sections: dict[str, str]) -> list[str]:
    """Collect unique gap markers from filled section texts by matching GAP_PATTERN."""
    gaps: list[str] = []
    seen: set[str] = set()
    for content in filled_sections.values():
        for match in GAP_PATTERN.finditer(content):
            gap = (match.group(1) or match.group(2) or "").strip()
            if gap and gap not in seen:
                seen.add(gap)
                gaps.append(gap)
    return gaps

