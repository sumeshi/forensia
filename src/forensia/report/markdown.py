"""Pure markdown/text rendering utilities extracted from probes.py.

This module provides deterministic rendering helpers for building Markdown
tables, formatting timestamps, and processing report body strings.  It is a
pure rendering layer with no database or case imports beyond typing.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from forensia.core.case import Case
from forensia.db.query import normalize_value


# ====================================================================
# Markdown table sorting
# ====================================================================


def _sort_markdown_table_by_first_column(body: str) -> str:
    """Sort the rows of every Markdown table in the body by the first column's value."""
    lines = body.splitlines()
    sorted_lines: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.startswith("|") or index + 1 >= len(lines) or not lines[index + 1].startswith("|---"):
            sorted_lines.append(line)
            index += 1
            continue
        header = line
        separator = lines[index + 1]
        rows: list[str] = []
        index += 2
        while index < len(lines) and lines[index].startswith("|"):
            rows.append(lines[index])
            index += 1

        def sort_key(row: str) -> str:
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            return cells[0] if cells else ""

        sorted_lines.extend([header, separator, *sorted(rows, key=sort_key)])
    return "\n".join(sorted_lines)


# ====================================================================
# Timezone / timestamp helpers
# ====================================================================


def _tz_offset_str(tz_name: str, at_time_str: str | None = None) -> str:
    """Return the UTC offset string (e.g. 'UTC-4', 'UTC+9') for a given IANA timezone."""
    if not tz_name or tz_name == "UTC":
        return "UTC"
    try:
        tz = ZoneInfo(tz_name)
        if at_time_str:
            try:
                dt = datetime.fromisoformat(str(at_time_str).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=ZoneInfo("UTC"))
                offset = dt.astimezone(tz).utcoffset()
            except (ValueError, TypeError, OSError):
                offset = tz.utcoffset(datetime.now(UTC))
        else:
            offset = tz.utcoffset(datetime.now(UTC))
        if offset is None:
            return f"{tz_name}"
        total_minutes = int(offset.total_seconds() // 60)
        sign = "+" if total_minutes >= 0 else "-"
        abs_min = abs(total_minutes)
        hours = abs_min // 60
        minutes = abs_min % 60
        if minutes:
            return f"UTC{sign}{hours}:{minutes:02d}"
        return f"UTC{sign}{hours}"
    except (OSError, KeyError):
        return tz_name


def _local_time_from_utc(utc_str: str, tz_name: str) -> str | None:
    if not utc_str or not tz_name or tz_name == "UTC":
        return None
    try:
        utc_dt = datetime.fromisoformat(str(utc_str).replace("Z", "+00:00"))
        if utc_dt.tzinfo is None:
            utc_dt = utc_dt.replace(tzinfo=ZoneInfo("UTC"))
        tz = ZoneInfo(tz_name)
        local_dt = utc_dt.astimezone(tz)
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError, KeyError):
        return None


def _render_timestamp_with_timezone(timestamp_str: str, case: Case) -> str:
    """Render timestamp with timezone qualifier.

    When the case has a known non-UTC timezone, shows dual-time format:
      2015-03-25 15:31:00 UTC (11:31:00 local, UTC-4, basis: …)
    Otherwise shows UTC-only.
    """
    if not timestamp_str:
        return "unknown"
    tz = getattr(case, 'source_timezone', 'UTC')
    if tz == "UTC":
        return f"{timestamp_str} UTC"
    local_time = _local_time_from_utc(timestamp_str, tz)
    if local_time:
        offset = _tz_offset_str(tz, timestamp_str)
        return f"{timestamp_str} UTC ({local_time} local, {offset})"
    return f"{timestamp_str} {tz}"


# ====================================================================
# Markdown table cell helpers
# ====================================================================


def _split_markdown_table_cells(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def _join_markdown_table_cells(cells: list[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _strip_hidden_markdown_table_columns(table_lines: list[str]) -> list[str]:
    if not table_lines:
        return table_lines
    headers = _split_markdown_table_cells(table_lines[0])
    if not headers:
        return table_lines
    keep_indexes = [index for index, header in enumerate(headers) if not _is_human_report_hidden_column(header)]
    if len(keep_indexes) == len(headers):
        return table_lines
    if not keep_indexes:
        return ["_No report-visible columns._"]
    stripped_lines: list[str] = []
    for line_index, line in enumerate(table_lines):
        cells = _split_markdown_table_cells(line)
        if len(cells) != len(headers):
            stripped_lines.append(line)
            continue
        if line_index == 1 and all(re.fullmatch(r":?-{3,}:?", cell or "") for cell in cells):
            stripped_lines.append(_join_markdown_table_cells(["---"] * len(keep_indexes)))
        else:
            stripped_lines.append(_join_markdown_table_cells([cells[index] for index in keep_indexes]))
    return stripped_lines


def _strip_hidden_report_columns_from_markdown_tables(body: str) -> str:
    lines = str(body or "").splitlines()
    output: list[str] = []
    table: list[str] = []

    def flush_table() -> None:
        nonlocal table
        if table:
            output.extend(_strip_hidden_markdown_table_columns(table))
            table = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            table.append(line)
            continue
        flush_table()
        output.append(line)
    flush_table()
    return "\n".join(output).strip()


# ====================================================================
# Hidden column filtering (pure rendering)
# ====================================================================


_HUMAN_REPORT_HIDDEN_COLUMNS = frozenset({"evidence_id", "evidence_ids", "reference", "references", "source_file"})


def _is_human_report_hidden_column(column: Any) -> bool:
    normalized = str(column or "").strip().lower()
    return normalized in _HUMAN_REPORT_HIDDEN_COLUMNS


# ====================================================================
# Table rendering for deterministic sections
# ====================================================================


def _compact_cell(value: Any, max_chars: int = 110) -> str:
    """Render a value safely inside a Markdown table cell."""
    value = normalize_value(value)
    if isinstance(value, list):
        text = "; ".join(str(item) for item in value if str(item).strip())
    elif isinstance(value, dict):
        text = ", ".join(f"{key}={val}" for key, val in value.items() if val not in (None, "", []))
    else:
        text = str(value if value is not None else "")
    text = " ".join(text.replace("\n", " ").split())
    text = text.replace("|", "\\|")
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text or "-"


def _markdown_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]], *, max_rows: int = 12) -> str:
    """Build a compact Markdown table for deterministic report sections."""
    if not rows:
        return "_No rows available._"
    header = "| " + " | ".join(label for _, label in columns) + " |"
    sep = "| " + " | ".join("---" for _ in columns) + " |"
    body = [
        "| " + " | ".join(_compact_cell(row.get(key)) for key, _ in columns) + " |"
        for row in rows[:max_rows]
    ]
    table = "\n".join([header, sep, *body])
    if len(rows) > max_rows:
        table += f"\n\n_Showing {max_rows} of {len(rows)} rows._"
    return table


def render_rows_template(template: str, rows: list[dict[str, Any]]) -> str:
    """Fill a declarative text template from result rows.

    Supports the same placeholder grammar as the question-routing
    interpretation templates: ``{row_count}``, ``{first.col}``, ``{last.col}``
    and ``{sample(col, n)}`` (up to n distinct values of a column).
    """
    result = template.replace("{row_count}", str(len(rows)))

    def replace_first(match: re.Match[str]) -> str:
        col = match.group(1)
        if rows:
            val = rows[0].get(col, "")
            return str(val) if val is not None else ""
        return ""

    result = re.sub(r"\{first\.(\w+)\}", replace_first, result)

    def replace_last(match: re.Match[str]) -> str:
        col = match.group(1)
        if rows:
            val = rows[-1].get(col, "")
            return str(val) if val is not None else ""
        return ""

    result = re.sub(r"\{last\.(\w+)\}", replace_last, result)

    def replace_sample(match: re.Match[str]) -> str:
        col = match.group(1)
        n = int(match.group(2)) if match.group(2) else 5
        seen: list[str] = []
        for row in rows:
            val = row.get(col)
            if val is not None and str(val) not in seen:
                seen.append(str(val))
            if len(seen) >= n:
                break
        return "、".join(seen) if seen else ""

    return re.sub(r"\{sample\((\w+),\s*(\d+)\)\}", replace_sample, result)


def _build_host_note(clusters: list[dict[str, Any]]) -> str:
    """Build a human-readable note for a host's epoch clusters."""
    pre_deploy = [c for c in clusters if c["label"] == "pre-deployment"]
    active = [c for c in clusters if c["label"] == "active"]
    if not pre_deploy:
        return "active"
    parts: list[str] = []
    if pre_deploy:
        bulk = max(pre_deploy, key=lambda c: c["event_count"])
        year = bulk["first_seen"][:4]
        parts.append(f"pre-deployment bulk ({year}, {bulk['event_count']} events)")
    if active:
        total_active = sum(c["event_count"] for c in active)
        last_active = max(c["last_seen"] for c in active)
        parts.append(f"minor activity ({last_active[:10]}, {total_active} events)")
    return " + ".join(parts)
