from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, date as _date, datetime
from pathlib import Path
from typing import Any

from forensia.core.case import Case
from forensia.core.memory import MemoryManager, memory_for_section
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.ai.question_registry import (
    evaluate_question_spec_status,
    project_rows_for_question_spec,
    question_spec_for_answer_spec,
)
from forensia.report.html import render_html_report


def _sql_like_any(column: str, *patterns: str) -> str:
    lowered = f"LOWER(COALESCE({column}, ''))"
    return "(" + " OR ".join(f"{lowered} LIKE '{pattern.lower()}'" for pattern in patterns) + ")"


def _path_like_any(column: str, *segments: str) -> str:
    patterns = []
    for segment in segments:
        normalized = str(segment or "").strip().strip("/\\").lower().replace("\\", "/")
        parts = [part for part in normalized.split("/") if part]
        if not parts:
            continue
        slash_pattern = "%/" + "/".join(parts) + "/%"
        backslash_pattern = "%\\" + "\\".join(parts) + "\\%"
        patterns.extend((slash_pattern, backslash_pattern))
    return _sql_like_any(column, *patterns)


@dataclass(frozen=True)
class TemplateMeta:
    behaviors: tuple[str, ...] = ()


GAP_PATTERN = re.compile(
    r"\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]|【調査不足:\s*([^】]+)】",
    re.IGNORECASE,
)
PLACEHOLDER_ENTITY_PATTERN = re.compile(r"(?<![\w/.-])(none|n/?a|null)(?![\w/.-])", re.IGNORECASE)
EVIDENCE_ID_PATTERN = re.compile(r"\b(?:evtx-[a-zA-Z][a-zA-Z0-9.-]*-\d{12}|mft-\d{12,15}-\d{2,4}|prefetch-[a-zA-Z][a-zA-Z0-9._-]+-[a-f0-9]{5,32})\b")
HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.*)$")
FINDING_ID_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9-]*-\d{4}\b")
HTML_FILL_PATTERN = re.compile(r"<!--\s*fill(?:[^>]*)-->", re.IGNORECASE)
BLOCK_HINT_PATTERN = re.compile(
    r"<!--\s*(?P<name>evidence_keypoints|mode|benchmark_id|answer_id|answer_spec)\s*:\s*(?P<value>.*?)\s*-->",
    re.IGNORECASE,
)
QUESTION_HINT_PATTERN = re.compile(r"<!--\s*question(?:\s*:\s*(?P<value>.*?))?\s*-->", re.IGNORECASE)
RAW_EVIDENCE_HEADING_PATTERN = re.compile(r"^#{2,6}\s*Raw Evidence\s*$", re.IGNORECASE)
EvidenceResolver = Callable[[CaseDB], list[dict[str, Any]]]


def _parse_frontmatter(text: str) -> dict:
    """Extract YAML frontmatter dict from text starting with ---."""
    if not text.startswith("---\n"):
        return {}
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return {}
    import yaml
    try:
        meta = yaml.safe_load(parts[1])
    except Exception:
        meta = {}
    return meta if isinstance(meta, dict) else {}


@lru_cache(maxsize=None)
def _parse_template(template_path: str) -> tuple[str, TemplateMeta]:
    """Parse YAML front matter from a template file, returning (body, meta)."""
    text = Path(template_path).read_text(encoding="utf-8")
    meta = _parse_frontmatter(text)
    if text.startswith("---\n"):
        parts = text.split("---\n", 2)
        body = parts[2].strip() if len(parts) == 3 else text.strip()
    else:
        body = text.strip()
    behaviors = tuple(meta.get("behaviors") or [])
    return body, TemplateMeta(behaviors=behaviors)


def _parse_block_hints(block_body: str) -> dict[str, Any]:
    """Extract hint annotations (evidence_keypoints, mode) from a block's HTML comment markers."""
    hints: dict[str, Any] = {
        "evidence_keypoints": [],
        "mode": "",
        "benchmark_id": "",
        "answer_id": "",
        "answer_spec": "",
        "question": "",
    }
    seen_keypoints: set[str] = set()
    for match in BLOCK_HINT_PATTERN.finditer(block_body):
        name = str(match.group("name") or "").strip().lower()
        value = str(match.group("value") or "").strip()
        if not name or not value:
            continue
        if name == "evidence_keypoints":
            keypoints = [item.strip() for item in re.split(r"[,，\s]+", value) if item.strip()]
            for keypoint in keypoints:
                if keypoint in seen_keypoints:
                    continue
                seen_keypoints.add(keypoint)
                hints["evidence_keypoints"].append(keypoint)
        elif name == "mode":
            hints["mode"] = value.casefold()
        elif name == "benchmark_id":
            hints["benchmark_id"] = value.strip()
            hints["answer_id"] = value.strip()
        elif name == "answer_id":
            hints["answer_id"] = value.strip()
        elif name == "answer_spec":
            hints["answer_spec"] = value.strip()
    question_match = QUESTION_HINT_PATTERN.search(block_body)
    if question_match:
        hints["question"] = str(question_match.group("value") or "").strip()
        if not hints["mode"]:
            hints["mode"] = "structured"
    return hints


def _split_template_body(template_body: str) -> tuple[str, list[dict[str, Any]]]:
    """Split a template body into preamble and annotated Markdown blocks delimited by ## headings."""
    lines = template_body.splitlines()
    preamble: list[str] = []
    blocks: list[dict[str, Any]] = []
    current_heading: str | None = None
    current_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            if current_heading is not None:
                current_text = "\n".join(current_lines).strip()
                blocks.append(
                    {
                        "heading": current_heading,
                        "template_body": current_text,
                        **_parse_block_hints(current_text),
                    }
                )
            current_heading = stripped[3:].strip()
            current_lines = [line]
            continue
        if current_heading is None:
            preamble.append(line)
        else:
            current_lines.append(line)
    if current_heading is not None:
        current_text = "\n".join(current_lines).strip()
        blocks.append(
            {
                "heading": current_heading,
                "template_body": current_text,
                **_parse_block_hints(current_text),
            }
        )
    preamble_text = "\n".join(preamble).strip()
    return preamble_text, blocks


SECTION_KEYPOINT_PREFIXES: dict[str, tuple[str, ...]] = {
    "overview": ("overview_",),
    "timeline": ("timeline_",),
    "technical": ("host_", "account_", "persistence_", "ioc_", "execution_"),
    "gaps": ("gaps_",),
    "recommendations": ("recommendations_",),
    "appendix": ("appendix_",),
}

SECTION_EXTRA_KEYPOINTS: dict[str, tuple[str, ...]] = {
    "overview": ("top_keypoints", "session_activity_events"),
    "timeline": ("top_keypoints", "gaps_log_integrity_events", "timeline_prefetch_full_history"),
    "technical": ("top_keypoints", "overview_hosts", "session_activity_events", "host_user_profile_paths", "timeline_prefetch_history", "timeline_prefetch_full_history", "host_execution_activity", "mft_prefetch_filenames", "mft_user_app_activity", "mft_recent_folder_lnk", "ioc_user_data_files"),
    "gaps": ("top_keypoints",),
    "recommendations": ("top_keypoints", "timeline_system_events", "timeline_prefetch_history", "ioc_user_data_files"),
    "appendix": ("top_keypoints",),
}


def _section_family(section_key: str) -> str:
    parts = str(section_key or "").split("_", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def _default_keypoints_for_section(
    section_key: str,
    benchmark_mode: bool = False,
    block_heading: str = "",
) -> tuple[str, ...]:
    """Return default keypoint names to seed a section's evidence collection.

    All returned names MUST exist in REPORT_KEYPOINTS — otherwise the planner's
    keypoint_catalog ends up empty and the section silently writes "not_searched".
    Each family's set is intentionally heterogeneous so different sections do
    not all surface the same finding list.
    """
    if benchmark_mode:
        return ()

    # Block-heading-level overrides take precedence over family defaults.
    # Keys are lowercase partial matches against block_heading.
    _heading_overrides: dict[str, tuple[str, ...]] = {
        "log integrity": ("timeline_log_clearing", "gaps_log_integrity_events", "timeline_system_events"),
        "network": ("evtx_network_connections", "ioc_source_ips", "evtx_firewall_events"),
        "lateral": ("account_logon_patterns", "account_explicit_credentials", "ioc_source_ips"),
        "evidence gap": ("unresolved_hypotheses_summary", "gaps_event_coverage", "gaps_channel_coverage"),
        "gap": ("unresolved_hypotheses_summary", "gaps_event_coverage", "gaps_channel_coverage"),
        "execution": ("host_execution_activity", "persistence_lolbas_execution", "persistence_service_installs"),
        "persistence": ("host_persistence_activity", "persistence_service_installs", "persistence_scheduled_tasks"),
        "authentication": ("account_logon_patterns", "account_bruteforce_clusters", "account_explicit_credentials"),
    }
    if block_heading:
        heading_lower = block_heading.lower()
        for keyword, keypoints in _heading_overrides.items():
            if keyword in heading_lower:
                return keypoints

    family = section_key.split("_", 1)[0] if "_" in section_key else section_key
    mapping = {
        "1": ("overview_top_findings", "overview_hosts", "overview_event_range"),
        "2": ("timeline_high_signal_events", "timeline_system_events", "timeline_log_clearing"),
        "3": ("host_execution_activity", "host_persistence_activity", "account_logon_patterns", "ioc_source_ips"),
        "4": ("unresolved_hypotheses_summary", "gaps_event_coverage", "gaps_channel_coverage"),
        "5": ("recommendations_findings", "recommendations_recent_reviews"),
        "6": ("appendix_findings_catalog", "appendix_claims_needing_review"),
    }
    return mapping.get(family, ("overview_top_findings",))


def _section_confidence(body: str) -> float:
    """Estimate confidence from the ratio of gap markers to total paragraphs."""
    paragraphs = [item.strip() for item in re.split(r"\n\s*\n", body) if item.strip()]
    paragraph_count = max(len(paragraphs), 1)
    gap_count = len(GAP_PATTERN.findall(body))
    return max(0.0, min(1.0, 1.0 - (gap_count / paragraph_count)))


def _timeline_rows_are_chronological(body: str) -> bool:
    """Verify that timeline Markdown table rows are sorted by first-column timestamp."""
    timestamps: list[str] = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        stripped = line.strip()
        if stripped.startswith("|---") or "Timestamp" in stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if not first or "<!--" in first:
            continue
        timestamps.append(first)
    return timestamps == sorted(timestamps)


def _normalized_text_key(text: str) -> str:
    lowered = text.casefold()
    cleaned = re.sub(r"[^a-z0-9]+", " ", lowered)
    return " ".join(cleaned.split())


def _first_heading_text(body: str) -> str:
    """Extract the first H1 heading text from a Markdown body."""
    for line in body.splitlines():
        match = HEADING_PATTERN.match(line.strip())
        if match and len(match.group(1)) == 1:
            return match.group(2).strip()
    return ""


def _title_from_template_body(template_body: str, fallback: str) -> str:
    title = _first_heading_text(template_body)
    return title or fallback


def _title_matches_body_heading(title: str, body: str) -> bool:
    """Check whether a section title is compatible with the first H1 heading in the body."""
    heading = _first_heading_text(body)
    if not heading:
        return True
    normalized_title = _normalized_text_key(title)
    normalized_heading = _normalized_text_key(heading)
    return (
        not normalized_title
        or not normalized_heading
        or normalized_title in normalized_heading
        or normalized_heading in normalized_title
    )


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
    return [str(row.get("finding_id") or "") for row in rows if str(row.get("finding_id") or "")]


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
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            hints[event_id] = value
    return hints


def _collect_event_ids_from_results(evidence_results: list[dict[str, Any]] | None) -> set[int]:
    """Collect distinct event_id values from evidence result rows."""
    event_ids: set[int] = set()
    for result in evidence_results or []:
        for row in (result.get("sample_rows") or []) + (result.get("head_rows") or []) + (result.get("tail_rows") or []):
            if not isinstance(row, dict):
                continue
            try:
                event_id = int(row.get("event_id"))
            except (TypeError, ValueError):
                continue
            event_ids.add(event_id)
    return event_ids


def _event_claim_gaps(body: str, evidence_results: list[dict[str, Any]] | None) -> list[str]:
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
        disallowed = [str(item).casefold() for item in hint.get("disallowed_without_extra") or [] if str(item).strip()]
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


def _extract_evidence_ids_from_value(value: Any) -> list[str]:
    """Extract evidence_id values from nested row/finding payloads."""
    ids: list[str] = []
    seen: set[str] = set()

    def add(raw: Any) -> None:
        text = str(raw or "").strip()
        if text and text not in seen:
            seen.add(text)
            ids.append(text)

    def walk(item: Any) -> None:
        if isinstance(item, str):
            stripped = item.strip()
            if not stripped:
                return
            if EVIDENCE_ID_PATTERN.fullmatch(stripped):
                add(stripped)
                return
            if stripped[:1] in {"[", "{"}:
                try:
                    walk(json.loads(stripped))
                except json.JSONDecodeError:
                    return
            return
        if isinstance(item, dict):
            add(item.get("evidence_id"))
            many = item.get("evidence_ids")
            if isinstance(many, list):
                for value in many:
                    add(value)
            for key in ("evidence", "rows", "answer"):
                if key in item:
                    walk(item.get(key))
            return
        if isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return ids


def _row_with_evidence_ids(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a row and expose nested finding evidence IDs for report prompts."""
    normalized = normalize_value(row)
    if not isinstance(normalized, dict):
        return {}
    evidence_ids = _extract_evidence_ids_from_value(normalized)
    if evidence_ids:
        normalized.setdefault("evidence_ids", evidence_ids)
        normalized.setdefault("evidence_id", evidence_ids[0])
    return normalized


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
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
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
                "source_kind": str(row.get("evidence_table") or payload.get("source_kind") or result.get("source_kind") or "").strip(),
            },
        )
        try:
            row_count = int(row.get("row_count") or result.get("row_count") or 0)
        except (TypeError, ValueError):
            row_count = 0
        entry["rows"] = max(int(entry.get("rows") or 0), row_count)
        if str(row.get("used_in_answer") or result.get("kind") or "rows") != "Yes":
            entry["used_in_answer"] = "No"
    return {section_key: list(section_map.values()) for section_key, section_map in grouped.items()}


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





_OPEN_QUESTION_RE = re.compile(r"(?:^|[\s\(])(\?|？|TBD|TODO|FIXME|要確認|要調査|未確認|未調査|未特定|不明瞭|未解明|XXX|N\/A\?)")
_CITATION_TOKENS_RE = re.compile(r"(?:証拠|証拠ID|finding[_\s]?id|evidence|根拠は|に基づく|according to|based on the)", re.IGNORECASE)
_FINDING_ID_RE = re.compile(r"\b[a-z]+-[a-z0-9]+-[0-9]+-[a-z0-9-]+\b")
_PURE_HEDGE_RE = re.compile(r"(?:may|might|could|possibly|perhaps|seem(?:s|ed)?|appears? to|思われる|可能性が|かもしれない)", re.IGNORECASE)
_TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}([T\s]\d{2}:\d{2})?")
_ENGLISH_PARAGRAPH_RE = re.compile(r"^[\x20-\x7e]{120,}$", re.MULTILINE)
_JAPANESE_CHAR_RE = re.compile(r"[぀-ヿ一-鿿]")


def _detect_body_language(text: str) -> str:
    """Crude heuristic: count Japanese chars vs ASCII letters; return 'ja', 'en', or 'mixed'."""
    ja_chars = len(_JAPANESE_CHAR_RE.findall(text))
    en_chars = sum(1 for ch in text if "a" <= ch.lower() <= "z")
    if ja_chars == 0 and en_chars > 50:
        return "en"
    if en_chars == 0 and ja_chars > 0:
        return "ja"
    if ja_chars > 0 and en_chars > 0:
        # Compare structural balance — pure JA reports usually have ja_chars >> en_chars
        return "ja" if ja_chars * 2 > en_chars else "en" if en_chars > ja_chars * 4 else "mixed"
    return "unknown"


@dataclass
class _GateCtx:
    section_key: str
    title: str
    evidence_results: list[dict[str, Any]] | None
    db: CaseDB | None
    behaviors: tuple[str, ...] = ()


QualityCheck = Callable[[str, _GateCtx], tuple[str | None, float | None]]


def _check_placeholder_entity(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if PLACEHOLDER_ENTITY_PATTERN.search(body):
        return "Placeholder entity values detected; additional review is required.", 0.5
    return None, None


def _check_template_marker(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if HTML_FILL_PATTERN.search(body):
        return "Template placeholder markers remain in the section body.", 0.3
    return None, None


def _check_heading_mismatch(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if not _title_matches_body_heading(ctx.title, body):
        return "Section heading does not match the expected section title; review for claim/title consistency.", 0.65
    return None, None


def _check_timeline_ordering(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if "require_chronological_table" in ctx.behaviors and not _timeline_rows_are_chronological(body):
        return "Timeline ordering requires review; events are not strictly chronological.", 0.6
    return None, None


def _check_recommendations_strength(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if "require_recommendations_strength" in ctx.behaviors:
        lowered = body.lower()
        strength_markers = (
            "confirmed",
            "strongly suggests",
            "may indicate",
            "additional verification",
            "consider containment after verification",
            "追加の相関確認",
            "追加確認",
            "検証後",
            "証拠不足",
            "根拠",
            "中程度",
            "高信頼",
        )
        if not any(marker in lowered for marker in strength_markers):
            return "Recommendations should state evidence strength or verification-first wording.", 0.65
    return None, None


def _check_verdict_inflation(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    source_verdicts = {str(result.get("source_verdict") or "").strip().lower() for result in ctx.evidence_results or [] if str(result.get("source_verdict") or "").strip()}
    if source_verdicts and "confirmed" not in source_verdicts:
        lowered = body.casefold()
        strong_markers = (
            "confirmed",
            "executed",
            "compromised",
            "attack succeeded",
            "侵害",
            "実行された",
            "確認された",
        )
        if any(marker in lowered for marker in strong_markers):
            return "Section language is stronger than the evidence verdicts support; rewrite with cautious wording.", 0.6
    return None, None


def _check_raw_evidence_dump(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    raw_evidence_patterns = (
        "#### raw evidence",
        "### raw evidence",
        "raw_evidence_rows",
        "raw evidence moved to reports/evidence/",
    )
    lowered_body = body.casefold()
    if any(pattern in lowered_body for pattern in raw_evidence_patterns):
        raw_row_dump = any(
            token in lowered_body for token in ("| none |", "| null |", "| - |", ": none", ": null", ": -")
        )
        if raw_row_dump:
            return "Raw evidence rows should be moved to the appendix evidence export or reports/evidence JSON, not copied into the narrative body.", 0.55
    return None, None


def _check_output_language(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    from forensia.config import get_llm_settings

    expected_lang = str(get_llm_settings().get("output_language", "ja")).lower()
    body_for_lang = re.sub(r"`[^`]+`|```.*?```|\[[^\]]+\]\([^)]+\)|\|[^\n]+\|", " ", body, flags=re.DOTALL)
    detected_lang = _detect_body_language(body_for_lang)
    if expected_lang in {"ja", "japanese"} and detected_lang == "en":
        return f"Section body appears to be in English but LLM_OUTPUT_LANGUAGE='{expected_lang}'. LLM ignored language constraint.", 0.4
    elif expected_lang in {"en", "english"} and detected_lang == "ja":
        return f"Section body appears to be in Japanese but LLM_OUTPUT_LANGUAGE='{expected_lang}'.", 0.4
    return None, None


def _check_open_questions(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    question_hits = _OPEN_QUESTION_RE.findall(body)
    if question_hits:
        return f"Unresolved-question markers remain in body ({sorted(set(question_hits))[:3]}); investigate or remove before finalizing.", 0.55
    return None, None


def _check_empty_body(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    stripped_body = re.sub(r"```.*?```|\|[^\n]+\||^[#\->\s]+$", "", body, flags=re.DOTALL | re.MULTILINE)
    if len(stripped_body.strip()) < 80:
        return "Section body has no substantive narrative (< 80 chars after stripping tables / headings).", 0.3
    return None, None


def _check_bullet_only(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    non_bullet_lines = [ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith(("-", "*", "#", "|", ">"))]
    if not non_bullet_lines and len([ln for ln in body.splitlines() if ln.strip().startswith(("-", "*"))]) >= 3:
        return "Section has only bullet list, no narrative paragraph. Add a short prose summary.", 0.6
    return None, None


def _check_kp_citation(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if re.search(r"KP-\d{4}", body):
        return "Body contains KP-NNNN identifiers that should not appear as evidence citations.", 0.65
    return None, None


def _check_hedge_no_citation(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if (
        _PURE_HEDGE_RE.search(body)
        and not EVIDENCE_ID_PATTERN.search(body)
        and not _FINDING_ID_RE.search(body)
        and not _TIMESTAMP_RE.search(body)
    ):
        return "Section uses hedge language (may/could/possibly) without any timestamp, evidence_id, or finding_id citation.", 0.5
    return None, None


def _check_citation_token_no_finding_id(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if EVIDENCE_ID_PATTERN.search(body) or FINDING_ID_PATTERN.search(body):
        return None, None
    if not _CITATION_TOKENS_RE.search(body):
        return None, None
    return "Body references evidence/finding language without evidence_id or finding_id citation.", 0.75


def _check_duplicate_paragraph(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if len(p.strip()) > 40]
    if len(paragraphs) != len(set(paragraphs)):
        return "Section contains duplicate paragraphs (LLM likely looped).", 0.5
    return None, None


def _check_out_of_range_timestamp(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    for match in _TIMESTAMP_RE.finditer(body):
        ts = match.group(0)
        try:
            year = int(ts[:4])
        except ValueError:
            continue
        if year > _date.today().year + 1 or year < 1990:
            return f"Body contains out-of-range timestamp '{ts}' — likely fabricated or NTFS overflow.", 0.4
    return None, None


def _check_overused_evidence_id(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if ctx.db is None:
        return None, None
    used_ids = set(EVIDENCE_ID_PATTERN.findall(body))
    if not used_ids:
        return None, None
    overused: list[str] = []
    for eid in used_ids:
        count = ctx.db.execute(
            "SELECT COUNT(DISTINCT section_key) FROM section_evidence WHERE evidence_id = ?",
            (eid,),
        ).fetchone()[0]
        if count > 2:
            overused.append(eid)
    if overused:
        return f"Evidence id reused across > 2 sections: {overused[:3]}", 0.7
    return None, None


def _check_json_object_leak(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if re.search(r'^\s*\{.*"body"\s*:', body, re.DOTALL):
        return "Section body contains JSON object leak (raw LLM response not parsed correctly).", 0.3
    return None, None


_SEVERE_GATE_SUBSTRINGS = [
    "JSON object leak",
    "Section block failed",
    "answered_empty_answer",
    "unknown report template keypoint",
]


def _check_failure_spam(body: str, ctx: _GateCtx) -> tuple[str | None, float | None]:
    if "Section block failed" in body or "Block skipped" in body:
        return "Section contains failure markers.", 0.15
    return None, None


_QUALITY_CHECKS: tuple[QualityCheck, ...] = (
    _check_placeholder_entity,
    _check_template_marker,
    _check_heading_mismatch,
    _check_timeline_ordering,
    _check_recommendations_strength,
    _check_verdict_inflation,
    _check_raw_evidence_dump,
    _check_output_language,
    _check_open_questions,
    _check_empty_body,
    _check_bullet_only,
    _check_hedge_no_citation,
    _check_citation_token_no_finding_id,
    _check_duplicate_paragraph,
    _check_out_of_range_timestamp,
    _check_overused_evidence_id,
    _check_kp_citation,
    _check_json_object_leak,
    _check_failure_spam,
)


def _quality_gate_section(
    section_key: str,
    title: str,
    body: str,
    gaps: list[str],
    confidence: float,
    evidence_results: list[dict[str, Any]] | None = None,
    db: CaseDB | None = None,
    behaviors: tuple[str, ...] = (),
) -> tuple[list[str], float]:
    """Apply quality-gating checks to a section body, returning augmented gaps and adjusted confidence."""
    ctx = _GateCtx(section_key=section_key, title=title, evidence_results=evidence_results, db=db, behaviors=behaviors)
    gated_gaps = list(gaps)
    gated_confidence = confidence
    for check in _QUALITY_CHECKS:
        note, cap = check(body, ctx)
        if note and note not in gated_gaps:
            gated_gaps.append(note)
        if cap is not None:
            gated_confidence = min(gated_confidence, cap)
    for gap in gated_gaps:
        if any(severe in gap for severe in _SEVERE_GATE_SUBSTRINGS):
            gated_confidence = min(gated_confidence, 0.2)
    return gated_gaps, gated_confidence


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



def _summarize_rows(
    *,
    source_type: str,
    source_id: str,
    description: str,
    rows: list[dict[str, Any]],
    max_rows: int = 20,
) -> dict[str, Any]:
    """Build a structured summary dict from a list of database rows, extracting evidence/finding/hypothesis IDs."""
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        normalized_row = _row_with_evidence_ids(row)
        normalized_rows.append(normalized_row)
        for evidence_id in _extract_evidence_ids_from_value(normalized_row):
            value = str(evidence_id)
            if value not in seen_evidence_ids:
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        finding_id = row.get("finding_id")
        if finding_id:
            value = str(finding_id)
            if value not in seen_finding_ids:
                seen_finding_ids.add(value)
                finding_ids.append(value)
        hypothesis_id = row.get("hypothesis_id")
        if hypothesis_id:
            value = str(hypothesis_id)
            if value not in seen_hypothesis_ids:
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        source_type: source_id,
        "description": description,
        "kind": "rows" if source_type == "keypoint" else "trace",
        "source_kind": source_type,
        "source_ref": source_id,
        "row_count": len(rows),
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
        "sample_rows": normalized_rows[:max_rows],
    }


def _report_keypoint_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return fetch_records(db, query)


REPORT_KEYPOINTS: dict[str, tuple[str, EvidenceResolver]] = {
    "top_keypoints": (
        "Top finding-backed keypoints ranked by confidence.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, severity, confidence, summary
            FROM findings
            WHERE COALESCE(status, 'accepted') != 'suppressed'
            ORDER BY confidence DESC, created_at DESC
            LIMIT 12
            """,
        ),
    ),
    "overview_event_range": (
        "Earliest and latest observed event timestamps.",
        lambda db: _report_keypoint_rows(
            db,
            "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events",
        ),
    ),
    "overview_hosts": (
        "Observed hosts ranked by event volume.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, COUNT(*) AS event_count
            FROM evtx_events
            WHERE computer IS NOT NULL
            GROUP BY computer
            ORDER BY event_count DESC
            LIMIT 20
            """,
        ),
    ),
    "overview_top_findings": (
        "Highest-severity accepted findings for the overview.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, summary, severity, confidence, evidence
            FROM findings
            WHERE severity IN ('critical','high')
              AND COALESCE(status, 'new') != 'suppressed'
              AND COALESCE(title, '') != ''
              AND title NOT LIKE '%:  @%'
            ORDER BY
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
              confidence DESC,
              created_at DESC
            LIMIT 10
            """,
        ),
    ),
    "timeline_high_signal_events": (
        "Chronological high-signal event records with evidence IDs.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE severity IN ('critical','high')
            ORDER BY timestamp
            LIMIT 50
            """,
        ),
    ),
    "timeline_mft_activity": (
        "Recent MFT timeline entries relevant to chronology.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, timestamp_type, file_path, description, evidence_id
            FROM mft_timeline
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "timeline_top_findings": (
        "Top findings that may anchor attack phases.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, severity, confidence, status
            FROM findings
            ORDER BY confidence DESC
            LIMIT 20
            """,
        ),
    ),
    "timeline_log_clearing": (
        "Observed log clearing or integrity-impacting events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, channel, target_user, src_ip, evidence_id
            FROM evtx_events
            WHERE event_id = 1102
               OR (
                  event_id = 104
                  AND LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) = 'microsoft-windows-eventlog'
               )
            ORDER BY timestamp
            """,
        ),
    ),
    "host_compromise_candidates": (
        "Hosts with logon, execution, persistence, or log-clear activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, COUNT(*) AS events, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
            FROM evtx_events
            WHERE event_id IN (4624,4625,4648,4688,4697,4698,5140,1102)
            GROUP BY computer
            ORDER BY events DESC
            LIMIT 20
            """,
        ),
    ),
    "host_suspicious_logons": (
        "Suspicious remote or explicit logons by host.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, src_ip, target_user, logon_type, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('3','10','9')
            ORDER BY timestamp
            LIMIT 40
            """,
        ),
    ),
    "host_execution_activity": (
        "Observed process execution activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, process_name, command_line, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4688,4104)
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "host_persistence_activity": (
        "Observed service and task persistence activity per host.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT computer, service_name, target_user, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4697,7045,4698)
            ORDER BY timestamp
            """,
        ),
    ),
    "account_logon_patterns": (
        "Observed account logon patterns for suspicious remote access.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT target_user, src_ip, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('3','9','10') AND target_user NOT LIKE '%$'
            GROUP BY target_user, src_ip, computer, logon_type
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "account_bruteforce_clusters": (
        "4625 failure clusters that may indicate brute force or password spray.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT src_ip, target_user, computer, COUNT(*) AS fail_count
            FROM evtx_events
            WHERE event_id = 4625
            GROUP BY src_ip, target_user, computer
            HAVING COUNT(*) >= 5
            ORDER BY fail_count DESC
            LIMIT 20
            """,
        ),
    ),
    "account_management_changes": (
        "Observed account creation, deletion, reset, or group membership changes.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, subject_user, evidence_id
            FROM evtx_events
            WHERE event_id IN (4720,4726,4732,4728,4724)
            ORDER BY timestamp
            """,
        ),
    ),
    "account_explicit_credentials": (
        "Explicit credential usage events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, subject_user, evidence_id
            FROM evtx_events
            WHERE event_id = 4648
            ORDER BY timestamp
            LIMIT 20
            """,
        ),
    ),
    "persistence_service_installs": (
        "Service installation or creation events with classification (benign-known / unknown).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, service_name, subject_user, evidence_id,
              CASE
                WHEN regexp_matches(LOWER(COALESCE(service_name,'')),
                  'gupdate|gupdatem|google.update|bonjour|mdnsresponder'
                  '|msiserver|trustedinstaller|officeclicktorun|osppsvc'
                  '|office.64.source.engine|office.software.protection'
                  '|[.]net.framework.ngen|ngen.v4|mscorsvw|clr_optimization'
                  '|intel.*pro.*1000|intel.*82[.]|intel.*ndis|intel.*network'
                  '|microsoft.streaming|microsoft.memory.module|microsoft.trusted.audio'
                  '|uaa.*function.driver|uaa.bus.driver'
                  '|net[.]tcp.listener|net[.]pipe.listener|net[.]msmq.listener'
                  '|asp[.]net.state|wuauserv|sppsvc|wmpnetworksvc')
                THEN 'benign-known'
                ELSE 'unknown'
              END AS classification
            FROM evtx_events
            WHERE event_id IN (4697,7045)
            ORDER BY timestamp
            """,
        ),
    ),
    "persistence_scheduled_tasks": (
        "Scheduled task creation or deletion activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, subject_user, message, evidence_id
            FROM evtx_events
            WHERE event_id IN (4698,4699)
            ORDER BY timestamp
            """,
        ),
    ),
    "persistence_lolbas_execution": (
        "PowerShell and LOLBas execution events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE event_id = 4688 AND (
                LOWER(process_name) LIKE '%powershell%' OR
                LOWER(process_name) LIKE '%pwsh%' OR
                LOWER(process_name) LIKE '%certutil%' OR
                LOWER(process_name) LIKE '%mshta%' OR
                LOWER(process_name) LIKE '%rundll32%' OR
                LOWER(process_name) LIKE '%wscript%' OR
                LOWER(process_name) LIKE '%cscript%'
            )
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "persistence_defender_activity": (
        "Observed defensive-control disablement or malware events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, evidence_id, message
            FROM evtx_events
            WHERE event_id IN (5001,7040,1116)
            ORDER BY timestamp
            """,
        ),
    ),
    "ioc_source_ips": (
        "Distinct observed source IPs ranked by frequency.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT src_ip, COUNT(*) AS count
            FROM evtx_events
            WHERE src_ip IS NOT NULL AND src_ip NOT IN ('','127.0.0.1','::1','-')
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "ioc_processes": (
        "Distinct suspicious processes or command lines.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT process_name, command_line, computer, evidence_id
            FROM evtx_events
            WHERE event_id IN (4688,4104) AND process_name IS NOT NULL
            ORDER BY evidence_id
            LIMIT 30
            """,
        ),
    ),
    "ioc_services": (
        "Distinct suspicious services observed.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT service_name, computer, evidence_id
            FROM evtx_events
            WHERE event_id IN (4697,7045) AND service_name IS NOT NULL
            """,
        ),
    ),
    "ioc_suspicious_files": (
        "Suspicious file paths from MFT entries.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE (
                LOWER(file_path) LIKE '%temp%' OR
                LOWER(file_path) LIKE '%appdata%' OR
                LOWER(file_path) LIKE '%public%'
            ) AND si_created IS NOT NULL
            ORDER BY si_created DESC
            LIMIT 30
            """,
        ),
    ),
    "ioc_suspicious_accounts": (
        "Suspicious account administration activity.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT target_user, subject_user, computer, timestamp, evidence_id
            FROM evtx_events
            WHERE event_id IN (4720,4726,4732,4728,4724)
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "gaps_event_coverage": (
        "Overall event coverage and time span.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT COUNT(*) AS total_events, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            """,
        ),
    ),
    "gaps_channel_coverage": (
        "Observed event distribution by channel.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT channel, COUNT(*) AS count
            FROM evtx_events
            GROUP BY channel
            ORDER BY count DESC
            """,
        ),
    ),
    "gaps_log_integrity_events": (
        "Observed log clearing or audit-policy-impacting events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT event_id, COUNT(*) AS count
            FROM evtx_events
            WHERE event_id IN (1102,4719)
               OR (
                  event_id = 104
                  AND LOWER(COALESCE(json_extract_string(raw_json, '$.winlog.provider.name'), '')) = 'microsoft-windows-eventlog'
               )
            GROUP BY event_id
            """,
        ),
    ),
    "recommendations_findings": (
        "Top findings that should drive recommendations.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, title, summary, severity, confidence, status, ai_summary, evidence
            FROM findings
            WHERE COALESCE(status, 'new') != 'suppressed'
              AND severity IN ('critical','high','medium')
              AND COALESCE(title, '') != ''
              AND title NOT LIKE '%:  @%'
            ORDER BY
              CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
              confidence DESC,
              created_at DESC
            LIMIT 20
            """,
        ),
    ),
    "recommendations_recent_reviews": (
        "Recent AI review verdicts and report notes.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT verdict, report_text
            FROM ai_reviews
            ORDER BY created_at DESC
            LIMIT 10
            """,
        ),
    ),
    "appendix_findings_catalog": (
        "Raw findings catalog for appendix use, ordered by severity and confidence.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT finding_id, rule_id, title, severity, confidence, status, summary, ai_summary
            FROM findings
            WHERE COALESCE(status, 'accepted') != 'suppressed'
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                confidence DESC,
                created_at DESC
            LIMIT 80
            """,
        ),
    ),
    "appendix_claims_needing_review": (
        "Claims whose support status needs review.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT section_key, claim_text, support_status
            FROM claims
            WHERE support_status IN ('unsupported', 'orphaned_reference', 'needs_review')
            ORDER BY section_key, updated_at DESC
            LIMIT 40
            """,
        ),
    ),
    "session_activity_events": (
        "Chronological logon, logoff, and system startup/shutdown events.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, event_id, evidence_id
            FROM evtx_events
            WHERE event_id IN (4624,4634,4647,4608,4609,6005,6006,6008)
            ORDER BY timestamp
            LIMIT 30
            """,
        ),
    ),
    "timeline_system_events": (
        "Core system events covering startup, shutdown, logon, and logoff.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, event_id, target_user, src_ip, process_name, command_line, evidence_id
            FROM evtx_events
            WHERE event_id IN (1074,4608,4609,4624,4634,4647,6005,6006,6008)
            ORDER BY timestamp
            LIMIT 200
            """,
        ),
    ),
    "timeline_prefetch_history": (
        "Prefetch execution history ordered chronologically.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_count, last_exec_time, source_file
            FROM prefetch_executions
            ORDER BY last_exec_time
            LIMIT 80
            """,
        ),
    ),
    "timeline_prefetch_full_history": (
        "All execution timestamps recorded across Prefetch files (up to 8 per file).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT executable_name, exec_time, exec_index, prefetch_hash, evidence_id
            FROM prefetch_timeline
            WHERE exec_time IS NOT NULL
            ORDER BY exec_time DESC
            LIMIT 200
            """,
        ),
    ),
    "host_user_profile_paths": (
        "MFT entries under user profile directories.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE LOWER(file_path) LIKE '%/users/%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "account_all_logon_summary": (
        "All logon event counts grouped by user, computer, and logon type.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT target_user, computer, logon_type, COUNT(*) AS count, MIN(timestamp) AS first, MAX(timestamp) AS last
            FROM evtx_events
            WHERE event_id = 4624 AND target_user NOT LIKE '%$'
            GROUP BY target_user, computer, logon_type
            ORDER BY count DESC
            LIMIT 30
            """,
        ),
    ),
    "account_logon_events": (
        "Raw logon, logoff, and session-disconnect events with evidence IDs.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, computer, target_user, logon_type, evidence_id
            FROM evtx_events
            WHERE event_id IN (4624,4634,4647)
            ORDER BY timestamp
            LIMIT 200
            """,
        ),
    ),
    "account_observed_users": (
        "Distinct user identities observed across all event records.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT DISTINCT target_user, subject_user, computer, evidence_id
            FROM evtx_events
            WHERE target_user IS NOT NULL OR subject_user IS NOT NULL
            LIMIT 40
            """,
        ),
    ),
    "mft_user_app_activity": (
        "MFT timeline entries under user-controlled paths (AppData, Downloads, Desktop, Documents).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT timestamp, timestamp_type, file_path, description, evidence_id
            FROM mft_timeline
            WHERE (
                LOWER(file_path) LIKE '%/appdata/%' OR
                LOWER(file_path) LIKE '%/downloads/%' OR
                LOWER(file_path) LIKE '%/desktop/%' OR
                LOWER(file_path) LIKE '%/documents/%'
            )
            ORDER BY timestamp
            LIMIT 80
            """,
        ),
    ),
    "mft_prefetch_filenames": (
        "Application names inferred from .pf filenames present in MFT.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_name, file_path, si_modified, evidence_id
            FROM mft_entries
            WHERE extension = 'pf'
            ORDER BY si_modified DESC
            LIMIT 120
            """,
        ),
    ),
    "ioc_user_data_files": (
        "Notable user-data file paths from MFT (desktop, office, mail, cloud storage).",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE
                LOWER(file_path) LIKE '%/desktop/%' OR
                LOWER(file_path) LIKE '%/office/%' OR
                LOWER(file_path) LIKE '%/outlook/%' OR
                LOWER(file_path) LIKE '%googledrivesync%' OR
                LOWER(file_path) LIKE '%/icloud%' OR
                LOWER(file_path) LIKE '%/onedrive%'
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "ioc_email_ost_files": (
        "Email OST/PST mailbox cache file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE extension IN ('ost', 'pst')
            LIMIT 10
            """,
        ),
    ),
    "mft_recent_folder_lnk": (
        "Recent-folder LNK files indicating recently accessed documents.",
        lambda db: _report_keypoint_rows(
            db,
            """
            SELECT file_name, file_path, si_created, fn_created, evidence_id
            FROM mft_entries
            WHERE (
                LOWER(file_path) LIKE '%/recent/%' OR
                LOWER(file_path) LIKE '%/office/recent/%'
            )
            AND extension IN ('lnk', 'url')
            ORDER BY si_created DESC
            LIMIT 40
            """,
        ),
    ),
    "structured_last_shutdown": (
        "Last shutdown/startup event from System event log (event 1074/6006/6008/6013).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, event_id, computer, message
            FROM evtx_events
            WHERE event_id IN (1074, 6006, 6008, 6013)
            ORDER BY timestamp DESC LIMIT 1
        """),
    ),
    "structured_daily_session_activity": (
        "Daily user activity: logon/logoff/shutdown counts per date.",
        lambda db: _report_keypoint_rows(db, """
            SELECT DATE(timestamp) AS date, event_id, COUNT(*) AS n
            FROM evtx_events
            WHERE event_id IN (4624, 4634, 4647, 6005, 6006)
            GROUP BY 1, 2 ORDER BY 1
        """),
    ),
    "structured_browser_artifacts": (
        "Browser executable names from prefetch/mft.",
        lambda db: _report_keypoint_rows(db, """
            SELECT DISTINCT executable_name FROM prefetch_executions
            WHERE LOWER(executable_name) IN ('chrome.exe','firefox.exe','msedge.exe','iexplore.exe','brave.exe','opera.exe')
        """),
    ),
    "structured_email_artifacts": (
        "OST/PST file paths from MFT entries (email client artifacts).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_modified FROM mft_entries
            WHERE file_name ILIKE '%.ost' OR file_name ILIKE '%.pst' OR {_path_like_any("file_path", "outlook")}
            """,
        ),
    ),
    "structured_desktop_rename_candidates": (
        "Files on Desktop with si_modified < fn_modified (rename indicator).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_modified, fn_modified
            FROM mft_entries
            WHERE {_path_like_any("file_path", "desktop")} AND si_modified < fn_modified
            """,
        ),
    ),
    "structured_resignation_files": (
        "Files matching resignation keywords.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_modified FROM mft_entries
            WHERE (
                {_sql_like_any("file_name", "%resign%", "%resignation%", "%retire%")}
                OR {_path_like_any("file_path", "resign", "resignation", "retire")}
            )
            """,
        ),
    ),
    "structured_cloud_artifacts": (
        "Cloud sync artifacts from MFT (Google Drive, OneDrive, Dropbox, iCloud).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, is_deleted FROM mft_entries
            WHERE (
                {_path_like_any("file_path", "google/drive", "apple computer", "onedrive", "dropbox", "icloud")}
                OR {_sql_like_any("file_name", "%googledrivesync.exe%", "%icloudsetup.exe%", "%onedrive.exe%", "%dropbox.exe%", "%sync_config.db%", "%snapshot.db%", "%config.dbx%")}
            )
            """,
        ),
    ),
    "structured_antiforensics": (
        "Anti-forensic activity on the last day: log clearing, tool execution, prefetch deletion.",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, event_id, computer, target_user, message
            FROM evtx_events
            WHERE event_id IN (1102, 104, 1100)
            ORDER BY timestamp DESC LIMIT 50
        """),
    ),
    "system_shutdown_events": (
        "System shutdown events (event 1074/6006/6008).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, event_id, computer, message, evidence_id
            FROM evtx_events
            WHERE event_id IN (1074, 6006, 6008)
            ORDER BY timestamp DESC
            LIMIT 50
        """),
    ),
    "system_startup_events": (
        "System startup events (event 6005).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, event_id, computer, evidence_id
            FROM evtx_events
            WHERE event_id = 6005
            ORDER BY timestamp
            LIMIT 50
        """),
    ),
    "interactive_logon_events": (
        "Interactive and remote-interactive logon events (4624 logon_type=2/10).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, computer, target_user, logon_type, src_ip, evidence_id
            FROM evtx_events
            WHERE event_id = 4624 AND logon_type IN ('2', '10')
            ORDER BY timestamp
            LIMIT 80
        """),
    ),
    "logoff_events": (
        "Logoff and session-disconnect events (4634/4647).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, computer, target_user, evidence_id
            FROM evtx_events
            WHERE event_id IN (4634, 4647)
            ORDER BY timestamp
            LIMIT 80
        """),
    ),
    "mft_user_desktop_artifacts": (
        "Files found under any user Desktop path in MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, fn_modified, is_deleted, evidence_id
            FROM mft_entries
            WHERE {_path_like_any("file_path", "desktop")}
            ORDER BY COALESCE(si_modified, fn_modified, si_created) DESC
            LIMIT 80
            """,
        ),
    ),
    "mft_office_recent_artifacts": (
        "Office recent file paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE {_path_like_any("file_path", "office", "office/recent")}
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "mft_outlook_artifacts": (
        "Outlook OST/PST and directory paths from MFT.",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, si_created, si_modified, evidence_id
            FROM mft_entries
            WHERE extension IN ('ost', 'pst') OR {_path_like_any("file_path", "outlook")}
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "mft_cloud_sync_artifacts": (
        "Cloud sync client artifacts from MFT (Google Drive, OneDrive, Dropbox, iCloud).",
        lambda db: _report_keypoint_rows(
            db,
            f"""
            SELECT file_name, file_path, is_deleted, evidence_id
            FROM mft_entries
            WHERE (
                {_path_like_any("file_path", "google/drive", "apple computer", "onedrive", "dropbox", "icloud")}
                OR {_sql_like_any("file_name", "%googledrivesync.exe%", "%icloudsetup.exe%", "%onedrive.exe%", "%dropbox.exe%", "%sync_config.db%", "%snapshot.db%", "%config.dbx%")}
            )
            ORDER BY COALESCE(si_modified, si_created) DESC
            LIMIT 40
            """,
        ),
    ),
    "evtx_network_connections": (
        "Network-related EVTX events (firewall, filtering platform, DHCP).",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, computer, event_id, src_ip, process_name, message, evidence_id
            FROM evtx_events
            WHERE event_id IN (5152, 5154, 5156, 5157, 5158, 5031, 5140, 5145)
               OR channel LIKE '%dhcp%' OR channel LIKE '%dns%'
            ORDER BY timestamp
            LIMIT 80
        """),
    ),
    "evtx_firewall_events": (
        "Windows Firewall allowed/blocked connection events.",
        lambda db: _report_keypoint_rows(db, """
            SELECT timestamp, computer, src_ip, process_name, event_id, evidence_id
            FROM evtx_events
            WHERE event_id IN (5156, 5157)
            ORDER BY timestamp
            LIMIT 80
        """),
    ),
    "unresolved_hypotheses_summary": (
        "Open or unresolved hypotheses from the investigation.",
        lambda db: _report_keypoint_rows(db, """
            SELECT hypothesis_id, description, status, verdict, summary, updated_at
            FROM hypotheses
            WHERE COALESCE(verdict, status) NOT IN ('confirmed', 'refuted', 'rejected')
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 30
        """),
    ),
    "report_sections_with_gaps": (
        "Report sections that have outstanding gaps or low confidence.",
        lambda db: _report_keypoint_rows(db, """
            SELECT section_key, title, confidence, gaps, status
            FROM report_sections
            WHERE confidence < 0.7 OR gaps IS NOT NULL
            ORDER BY confidence
            LIMIT 20
        """),
    ),
}

REPORT_KEYPOINT_ALIASES = {
    "top_findings": "overview_top_findings",
    "network_connections": "ioc_source_ips",
    "evidence_gaps": "gaps_event_coverage",
    "overview_window": "overview_event_range",
    "overview_findings": "overview_top_findings",
    "timeline_events": "timeline_high_signal_events",
    "timeline_mft": "timeline_mft_activity",
    "timeline_findings": "timeline_top_findings",
    "timeline_log_clear": "timeline_log_clearing",
    "hosts_summary": "host_compromise_candidates",
    "hosts_logons": "host_suspicious_logons",
    "hosts_processes": "host_execution_activity",
    "hosts_services": "host_persistence_activity",
    "accounts_logon_summary": "account_logon_patterns",
    "accounts_failed_logons": "account_bruteforce_clusters",
    "accounts_changes": "account_management_changes",
    "accounts_explicit_credentials": "account_explicit_credentials",
    "persistence_services": "persistence_service_installs",
    "persistence_tasks": "persistence_scheduled_tasks",
    "persistence_lolbas": "persistence_lolbas_execution",
    "persistence_defender": "persistence_defender_activity",
    "ioc_ips": "ioc_source_ips",
    "ioc_mft_paths": "ioc_suspicious_files",
    "gaps_volume": "gaps_event_coverage",
    "gaps_channels": "gaps_channel_coverage",
    "gaps_log_clear": "gaps_log_integrity_events",
    "recommendations_reviews": "recommendations_recent_reviews",
    "benchmark_window": "overview_event_range",
    "benchmark_hosts": "overview_hosts",
    "benchmark_logon_window": "session_activity_events",
    "benchmark_timeline_events": "timeline_system_events",
    "benchmark_timeline_files": "timeline_mft_activity",
    "benchmark_prefetch_recent": "timeline_prefetch_history",
    "benchmark_host_spans": "overview_hosts",
    "benchmark_host_logons": "session_activity_events",
    "benchmark_accounts_summary": "account_all_logon_summary",
    "benchmark_accounts_events": "account_logon_events",
    "benchmark_accounts_observed": "account_observed_users",
    "benchmark_exec_processes": "host_execution_activity",
    "benchmark_exec_related_mft": "mft_user_app_activity",
    "benchmark_artifact_processes": "mft_prefetch_filenames",
    "benchmark_artifact_paths": "ioc_user_data_files",
    "benchmark_ost_file": "ioc_email_ost_files",
    "benchmark_recent_lnk": "mft_recent_folder_lnk",
    "benchmark_reco_system_events": "timeline_system_events",
    "benchmark_reco_desktop_paths": "ioc_user_data_files",
    "benchmark_last_shutdown": "structured_last_shutdown",
    "benchmark_daily_logon_shutdown": "structured_daily_session_activity",
    "benchmark_browser_artifacts": "structured_browser_artifacts",
    "benchmark_email_ost_paths": "structured_email_artifacts",
    "benchmark_desktop_rename_candidates": "structured_desktop_rename_candidates",
    "benchmark_resignation_file": "structured_resignation_files",
    "benchmark_cloud_artifacts": "structured_cloud_artifacts",
    "benchmark_antiforensics_last_day": "structured_antiforensics",
}


def _resolve_evidence_results(
    case: Case,
    db: CaseDB,
    *,
    keypoints: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Resolve named keypoints against the database and return structured evidence result dicts."""
    results: list[dict[str, Any]] = []
    seen_keypoints: set[str] = set()
    for keypoint in (keypoints or []):
        normalized = str(keypoint or "").strip()
        if not normalized or normalized in seen_keypoints:
            continue
        seen_keypoints.add(normalized)
        if normalized in {"top_keypoints", "memory_keypoint_cards"}:
            cards = _load_keypoint_cards(case)
            results.append(
                {
                    "keypoint": normalized,
                    "description": "Current memory keypoint cards derived from findings.",
                    "kind": "rows",
                    "source_kind": "keypoint",
                    "source_ref": normalized,
                    "row_count": len(cards),
                    "evidence_ids": [],
                    "finding_ids": [],
                    "hypothesis_ids": [],
                    "sample_rows": cards,
                }
            )
            continue
        resolved_name = REPORT_KEYPOINT_ALIASES.get(normalized, normalized)
        resolver_entry = REPORT_KEYPOINTS.get(resolved_name)
        if resolver_entry is None:
            raise ValueError(f"unknown report template keypoint: {normalized}")
        description, resolver = resolver_entry
        rows = resolver(db)
        results.append(
            _summarize_rows(
                source_type="keypoint",
                source_id=normalized,
                description=description,
                rows=rows,
            )
        )
    return results


def _load_keypoint_cards(case: Case, max_cards: int = 8, max_chars: int = 1200) -> list[dict[str, str]]:
    """Load keypoint card markdown files from the case memory directory."""
    cards: list[dict[str, str]] = []
    for path in sorted(case.memory_dir.glob("keypoints/KP-*.md"))[:max_cards]:
        text = path.read_text(encoding="utf-8").strip()
        if len(text) > max_chars:
            text = text[:max_chars].rstrip() + "\n..."
        cards.append({"card_id": path.stem, "content": text})
    return cards



_SCAFFOLD_PATTERNS = [
    re.compile(r"\*\*Status:\*\*.*"),
    re.compile(r"\*\*ID:\*\*.*"),
    re.compile(r"### Answer"),
    re.compile(r"### Missing Reason"),
    re.compile(r"### Queries Run"),
    re.compile(r"\*Block skipped:\*.*"),
    re.compile(r"\*Section block failed:\*.*"),
    re.compile(r"### Structured Data"),
    re.compile(r"^-?\s*(JSON|CSV):\s+.*", re.IGNORECASE),
    re.compile(r"^-\s*structured:.*", re.IGNORECASE),
    re.compile(r"^\|[-:|\s]+\|$"),
]


def _extract_claim_texts(body: str) -> list[str]:
    """Extract distinct claim-paragraph texts from a section body, skipping headings and gap markers."""
    lines = body.splitlines()
    filtered_lines = []
    skip_metadata_block = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            skip_metadata_block = False
        if stripped in {"### Missing Reason", "### Queries Run", "### Structured Data"}:
            skip_metadata_block = True
        if stripped.startswith("### ") and stripped not in {"### Missing Reason", "### Queries Run", "### Structured Data"}:
            skip_metadata_block = False
        if stripped and not skip_metadata_block and not any(p.match(stripped) for p in _SCAFFOLD_PATTERNS):
            filtered_lines.append(line)
        else:
            filtered_lines.append("")
    body = "\n".join(filtered_lines)
    claims: list[str] = []
    seen: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", body):
        text = paragraph.strip()
        if not text or text.startswith("#") or GAP_PATTERN.search(text):
            continue
        normalized = " ".join(line.strip("- ").strip() for line in text.splitlines() if line.strip())
        key = _claim_text_key(normalized)
        if normalized and normalized not in ("[]", "{}", "<!--", "-->") and key not in seen:
            seen.add(key)
            claims.append(normalized)
    return claims


def _claim_text_key(text: str) -> str:
    return " ".join(text.lower().split())


def _collect_claim_provenance(evidence_results: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Aggregate all evidence, finding, and hypothesis IDs referenced across a list of evidence result dicts."""
    max_evidence_ids = 25
    max_other_ids = 25
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    hypothesis_ids: list[str] = []
    seen_evidence_ids: set[str] = set()
    seen_finding_ids: set[str] = set()
    seen_hypothesis_ids: set[str] = set()
    for result in evidence_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        row_evidence_ids: list[str] = []
        for row in (result.get("sample_rows") or []) + (result.get("head_rows") or []) + (result.get("tail_rows") or []):
            row_evidence_ids.extend(_extract_evidence_ids_from_value(row))
        for evidence_id in [*(result.get("evidence_ids") or []), *row_evidence_ids]:
            value = str(evidence_id)
            if value and value not in seen_evidence_ids and len(evidence_ids) < max_evidence_ids:
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        for finding_id in result.get("finding_ids") or []:
            value = str(finding_id)
            if value and value not in seen_finding_ids and len(finding_ids) < max_other_ids:
                seen_finding_ids.add(value)
                finding_ids.append(value)
        for hypothesis_id in result.get("hypothesis_ids") or []:
            value = str(hypothesis_id)
            if value and value not in seen_hypothesis_ids and len(hypothesis_ids) < max_other_ids:
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
    }


def _render_timestamp_with_timezone(timestamp_str: str, case: Case) -> str:
    """Render timestamp with timezone qualifier."""
    if not timestamp_str:
        return "unknown"
    tz = getattr(case, 'source_timezone', 'UTC')
    return f"{timestamp_str} {tz}"


def _query_top_findings(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT finding_id, title, severity, confidence, summary, evidence
        FROM findings
        WHERE COALESCE(status, 'accepted') != 'suppressed'
          AND severity IN ('critical','high','medium')
          AND COALESCE(title, '') != ''
          AND title NOT LIKE '%:  @%'
        ORDER BY
          CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
          confidence DESC,
          created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    normalized: list[dict[str, Any]] = []
    for row in rows:
        item = normalize_value(row)
        if isinstance(item, dict):
            evidence_ids = _extract_evidence_ids_from_value(item.get("evidence"))
            if evidence_ids:
                item["evidence_ids"] = evidence_ids[:5]
        normalized.append(item)
    return normalized


def _query_hypotheses_by_status(db: CaseDB, status: str, limit: int = 8) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids, required_entities
        FROM hypotheses
        WHERE status = ?
        ORDER BY updated_at DESC, hypothesis_id
        LIMIT ?
        """,
        (status, limit),
    )


def _query_prior_sections(db: CaseDB) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT section_key, title, LEFT(body, 400) AS body_excerpt, confidence, status
        FROM report_sections
        WHERE COALESCE(body, '') != ''
        ORDER BY section_key
        """,
    )


def _query_existing_claims(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    return fetch_records(
        db,
        """
        SELECT section_key, claim_text, support_status
        FROM claims
        ORDER BY updated_at DESC, claim_id DESC
        LIMIT ?
        """,
        (limit,),
    )


def _dedupe_claims(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        key = _claim_text_key(str(item.get("claim_text") or ""))
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(normalize_value(item))
    return deduped


def _query_evtx_time_range(db: CaseDB, case: Case | None = None) -> dict[str, str]:
    rows = fetch_records(
        db,
        "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM evtx_events",
    )
    time_range: dict[str, str] = {}
    if rows:
        first = str(rows[0].get("first_event") or "")
        last = str(rows[0].get("last_event") or "")
        if first or last:
            time_range = {
                "first_event": _render_timestamp_with_timezone(first, case) if first else "unknown",
                "last_event": _render_timestamp_with_timezone(last, case) if last else "unknown",
            }
    return time_range


def _summarize_section_coverage(db: CaseDB) -> dict[str, Any]:
    coverage_map = _collect_section_coverage(db)
    return {
        "sections": coverage_map,
        "section_count": len(coverage_map),
        "total_sources": sum(len(items) for items in coverage_map.values()),
    }


def _build_report_brief(db: CaseDB, case: Case | None = None) -> dict[str, Any]:
    """Assemble a structured brief of top findings, hypotheses, section excerpts, and coverage data for LLM context."""
    return {
        "top_findings": [normalize_value(item) for item in _query_top_findings(db)],
        "active_hypotheses": [normalize_value(item) for item in _query_hypotheses_by_status(db, "active")],
        "confirmed_hypotheses": [normalize_value(item) for item in _query_hypotheses_by_status(db, "confirmed")],
        "refuted_hypotheses": [normalize_value(item) for item in _query_hypotheses_by_status(db, "refuted")],
        "prior_sections": _query_prior_sections(db),
        "existing_claims": _dedupe_claims(_query_existing_claims(db)),
        "evidence_coverage": _summarize_section_coverage(db),
        "source_timezone": getattr(case, "source_timezone", "UTC") if case else "UTC",
        "time_range": _query_evtx_time_range(db, case),
    }


def write_report_brief(case: Case, db: CaseDB) -> dict[str, Any]:
    """Write the report brief to reports/report_brief.json and return the dict."""
    brief = _build_report_brief(db, case)
    overview_path = case.memory_dir / "overview.md"
    if overview_path.exists():
        overview_text = overview_path.read_text(encoding="utf-8")
        match = re.search(r"## Investigation Objective\s+-\s+(.+)", overview_text)
        if match:
            brief["investigation_objective"] = match.group(1).strip()
    path = case.reports_dir / "report_brief.json"
    path.write_text(json.dumps(brief, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return brief


def _claim_support_status(
    db: CaseDB,
    evidence_ids: list[str],
    finding_ids: list[str],
    hypothesis_ids: list[str],
) -> str:
    """Determine whether a set of evidence/finding/hypothesis IDs are all present in their respective tables."""
    if not evidence_ids and not finding_ids and not hypothesis_ids:
        return "unsupported"
    if finding_ids:
        placeholders = ", ".join("?" for _ in finding_ids)
        found_finding_ids = {
            str(row[0])
            for row in db.execute(
                f"SELECT finding_id FROM findings WHERE finding_id IN ({placeholders})",
                tuple(finding_ids),
            ).fetchall()
        }
        if any(finding_id not in found_finding_ids for finding_id in finding_ids):
            return "orphaned_reference"
    if hypothesis_ids:
        placeholders = ", ".join("?" for _ in hypothesis_ids)
        found_hypothesis_ids = {
            str(row[0])
            for row in db.execute(
                f"SELECT hypothesis_id FROM hypotheses WHERE hypothesis_id IN ({placeholders})",
                tuple(hypothesis_ids),
            ).fetchall()
        }
        if any(hypothesis_id not in found_hypothesis_ids for hypothesis_id in hypothesis_ids):
            return "orphaned_reference"
    if evidence_ids:
        placeholders = ", ".join("?" for _ in evidence_ids)
        found_evidence_ids = {
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
        if any(evidence_id not in found_evidence_ids for evidence_id in evidence_ids):
            return "orphaned_reference"
    return "supported"


def _upsert_claims(
    db: CaseDB,
    section_key: str,
    body: str,
    evidence_results: list[dict[str, Any]],
) -> list[str]:
    """Extract claims from a section body, delete stale rows, and insert fresh claim records with provenance."""
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
        return []
    text_groups = fetch_records(
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
                    "finding_ids": normalize_value(row.get("finding_ids")) or [],
                    "hypothesis_ids": normalize_value(row.get("hypothesis_ids")) or [],
                    "evidence_ids": normalize_value(row.get("evidence_ids")) or [],
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
    statuses = fetch_records(
        db,
        "SELECT DISTINCT support_status FROM claims WHERE section_key = ?",
        (section_key,),
    )
    return [str(row.get("support_status") or "") for row in statuses if str(row.get("support_status") or "")]


def _update_section_quality_only(
    db: CaseDB,
    section_key: str,
    confidence: float,
    gaps: list[str],
) -> None:
    """Update confidence and gaps for a section without overwriting body or status history."""
    row = db.execute(
        "SELECT status FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(row[0] or "draft") if row else "draft"
    if gaps or confidence < 0.9:
        next_status = existing_status if existing_status in {"ai_exhausted", "human_reviewed"} else "draft"
    else:
        next_status = existing_status
    db.execute(
        """
        UPDATE report_sections
        SET confidence = ?, gaps = ?, status = ?
        WHERE section_key = ?
        """,
        (confidence, json.dumps(gaps, ensure_ascii=False), next_status, section_key),
    )


def _upsert_report_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    confidence: float,
    gaps: list[str],
    session_id: str | None = None,
) -> bool:
    """Insert or update a report_sections row, skipping if the section is human_reviewed with existing content."""
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        "SELECT status, update_count, body FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    existing_status = str(existing[0] or "draft") if existing else "draft"
    if existing_status == "human_reviewed" and str(existing[2] or "").strip():
        return False
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
            section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at, stale
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (section_key) DO UPDATE SET
            title = excluded.title,
            body = excluded.body,
            confidence = excluded.confidence,
            status = excluded.status,
            update_count = excluded.update_count,
            gaps = excluded.gaps,
            last_filled_session = excluded.last_filled_session,
            last_filled_at = excluded.last_filled_at,
            stale = FALSE
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
            False,
        ),
    )
    return True


def mark_report_sections_ai_exhausted(db: CaseDB) -> None:
    """Mark all report sections that have body content as ai_exhausted."""
    db.execute(
        """
        UPDATE report_sections
        SET status = 'ai_exhausted'
        WHERE COALESCE(body, '') != ''
        """
    )


def set_report_section_status(db: CaseDB, section_key: str, status: str) -> None:
    """Set a report section's status after validating it is a supported value."""
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
    """Fetch all report section rows ordered by section_key."""
    return fetch_records(
        db,
        """
        SELECT section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
        FROM report_sections
        ORDER BY section_key
        """,
    )


def load_report_sections_map(db: CaseDB) -> dict[str, str]:
    """Load report sections as a dict mapping section_key to body."""
    return {
        str(row.get("section_key")): str(row.get("body") or "")
        for row in fetch_report_sections(db)
    }


@lru_cache(maxsize=None)
def _load_template_meta(section_key: str) -> TemplateMeta:
    """Load template frontmatter metadata for a section key from the packaged template."""
    from importlib import resources
    try:
        text = resources.files("forensia").joinpath(f"report_template/{section_key}.md").read_text(encoding="utf-8")
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
        if re.match(r"^\*\*Status:\*\*\s*(answered|partial|not_found|not_searched|wrong_query|insufficient_evidence|error)\b", stripped, flags=re.IGNORECASE):
            continue
        lines.append(line)
    text = "\n".join(lines)
    text = text.replace("raw_sql", "evidence query")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _final_report_section_body(section_key: str, body: str) -> str:
    """Return the Markdown body intended for report.md, leaving debug metadata out."""
    text = str(body or "").strip()
    if section_key != "6_appendix":
        text = _strip_narrative_status_lines(text)
    return text


def build_report_markdown_from_db(db: CaseDB) -> str:
    """Reassemble the full report Markdown from persisted report sections.

    Coverage remains available through debug/API artifacts. The final Markdown
    should read as an investigation report, not as execution telemetry.
    """
    sections = fetch_report_sections(db)
    ordered: list[str] = []
    for row in sections:
        section_key = str(row.get("section_key") or "")
        body = str(row.get("body") or "").strip()
        if not body:
            continue
        ordered.append(_final_report_section_body(section_key, body))
    if not ordered:
        return ""
    return "\n\n".join(ordered).strip() + "\n"


def prepare_section_request(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read template + evidence and build the LLM messages.

    Pure I/O against DuckDB; safe to call from the main thread before
    dispatching parallel LLM workers.
    """
    template_body, template_meta = _parse_template(str(template_path))
    section_key = Path(template_path).stem
    title = _title_from_template_body(template_body, section_key)
    template_preamble, blocks = _split_template_body(template_body)
    if not blocks:
        blocks = [{
            "heading": "",
            "template_body": template_body,
            "evidence_keypoints": [],
            "mode": "",
            "benchmark_id": "",
            "answer_id": "",
            "answer_spec": "",
            "question": "",
        }]
    block_requests = [
        {
            "heading": block["heading"],
            "template_body": block["template_body"],
            "evidence_keypoints": list(block.get("evidence_keypoints") or []),
            "mode": str(block.get("mode") or ""),
            "benchmark_id": str(block.get("benchmark_id") or ""),
            "answer_id": str(block.get("answer_id") or block.get("benchmark_id") or ""),
            "answer_spec": str(block.get("answer_spec") or ""),
            "question": str(block.get("question") or ""),
        }
        for block in blocks
    ]
    return {
        "case": case,
        "section_key": section_key,
        "title": title,
        "template_path": str(template_path),
        "template_preamble": template_preamble,
        "block_requests": block_requests,
        "context_sections": dict(context_sections),
        "report_brief": report_brief or {},
        "template_meta": template_meta,
    }


def _body_starts_with_heading(body: str, heading: str) -> bool:
    text = body.lstrip()
    if text.startswith("**Status:**"):
        nl = text.find("\n")
        text = text[nl:].lstrip() if nl != -1 else ""
    return text.startswith(f"## {heading}")


def _assemble_section_body(template_preamble: str, rendered_blocks: list[str]) -> str:
    """Join a section preamble and rendered blocks consistently across sync/async paths."""
    parts = [str(template_preamble or "").strip(), *[item.strip() for item in rendered_blocks if item.strip()]]
    return "\n\n".join(part for part in parts if part).strip()


def _render_section_from_request(
    *,
    db: CaseDB,
    request: dict[str, Any],
    base_url: str,
    model: str,
    max_queries_per_section: int = 3,
    audit_callback: Callable[[list[dict[str, str]], str], None] | None = None,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Iterate block requests through the section agent and stitch them into a single section body with evidence results."""
    from forensia.ai.section_agent import run_section_block_agent

    memory = MemoryManager(request["case"])
    rendered_blocks: list[str] = []
    block_gaps: list[str] = []
    block_outline: list[dict] = []
    all_evidence_results: list[dict[str, Any]] = []
    for block in request.get("block_requests") or []:
        block_mode = str(block.get("mode") or "").strip().casefold()
        is_structured_mode = block_mode in {"benchmark", "structured"} or bool(block.get("answer_spec") or block.get("question"))
        block_result = run_section_block_agent(
            case=request["case"],
            db=db,
            section_key=str(request["section_key"]),
            title=str(request["title"]),
            block_heading=str(block.get("heading") or ""),
            template_body=str(block.get("template_body") or ""),
            context_sections={} if is_structured_mode else (request.get("context_sections") or {}),
            current_section_outline=[] if is_structured_mode else block_outline,
            report_brief=request.get("report_brief") or {},
            base_url=base_url,
            model=model,
            memory=memory_for_section(memory, structured_mode=is_structured_mode),
            max_queries_per_section=max_queries_per_section,
            evidence_keypoints=list(block.get("evidence_keypoints") or []),
            benchmark_mode=is_structured_mode,
            benchmark_id=str(block.get("benchmark_id") or block.get("answer_id") or ""),
            answer_id=str(block.get("answer_id") or block.get("benchmark_id") or ""),
            answer_spec=str(block.get("answer_spec") or ""),
            question=str(block.get("question") or ""),
            audit_callback=audit_callback,
        )
        block_body = block_result.body
        heading = str(block.get("heading") or "").strip()
        if heading and not _body_starts_with_heading(block_body, heading):
            block_body = f"## {heading}\n\n{block_body}"
        rendered_blocks.append(block_body)
        if heading:
            block_outline.append({
                "heading": heading,
                "summary": (block_body.split("\n", 1)[0])[:120],
            })
        all_evidence_results.extend(block_result.evidence_results)
        block_level_gaps, _ = _verify_block_output(db, block_body)
        for gap in block_level_gaps:
            label = f"{heading}: {gap}" if heading else gap
            if label not in block_gaps:
                block_gaps.append(label)
    body = _assemble_section_body(str(request.get("template_preamble") or ""), rendered_blocks)
    return body, all_evidence_results, block_gaps


def _preprocess_section_body(section_key: str, body: str, *, template_meta: TemplateMeta | None = None) -> tuple[str, bool]:
    sanitized_body, removed_raw_evidence = _sanitize_raw_evidence_body(section_key, body)
    if sanitized_body != body:
        body = sanitized_body
    if template_meta and "require_chronological_table" in template_meta.behaviors:
        body = _sort_markdown_table_by_first_column(body)
    return body, removed_raw_evidence


def _collect_initial_gaps(
    db: CaseDB,
    section_key: str,
    body: str,
    extra_gaps: list[str] | None = None,
) -> tuple[list[str], float]:
    candidate_gaps = collect_gaps({section_key: body})
    candidate_confidence = _section_confidence(body)
    for gap in extra_gaps or []:
        if gap not in candidate_gaps:
            candidate_gaps.append(gap)
    missing_evidence_ids = _validate_body_evidence_ids(db, body)
    if missing_evidence_ids:
        candidate_gaps.append(
            f"Referenced evidence_id values not found in database: {', '.join(missing_evidence_ids[:5])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    return candidate_gaps, candidate_confidence


def _run_post_upsert_gap_checks(
    db: CaseDB,
    body: str,
    evidence_results: list[dict[str, Any]] | None,
    claim_statuses: list[str],
    candidate_gaps: list[str],
    candidate_confidence: float,
) -> tuple[list[str], float, bool]:
    needs_update = False
    referenced_finding_ids = sorted(set(FINDING_ID_PATTERN.findall(body)))
    correlation_ids = _correlation_finding_ids(referenced_finding_ids, db)
    if correlation_ids and "confirmed" in body.casefold() and not EVIDENCE_ID_PATTERN.search(body):
        note = "Correlation-rule findings are described as confirmed without direct evidence_id support; rewrite as hypothesis."
        if note not in candidate_gaps:
            candidate_gaps.append(note)
        candidate_confidence = min(candidate_confidence, 0.55)
        needs_update = True
    if any(status in {"unsupported", "orphaned_reference", "needs_review"} for status in claim_statuses):
        note = "One or more claims require support review due to unsupported, orphaned, or conflicting provenance."
        if note not in candidate_gaps:
            candidate_gaps.append(note)
        candidate_confidence = min(candidate_confidence, 0.65)
        needs_update = True
    event_gaps = _event_claim_gaps(body, evidence_results)
    if event_gaps:
        for gap in event_gaps:
            if gap not in candidate_gaps:
                candidate_gaps.append(gap)
        candidate_confidence = min(candidate_confidence, 0.7)
        needs_update = True
    return candidate_gaps, candidate_confidence, needs_update


def _read_persisted_section(db: CaseDB, section_key: str) -> dict[str, Any]:
    row = db.execute(
        "SELECT body, confidence, gaps FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    persisted_confidence = float(row[1] or 0.0)
    persisted_gaps = normalize_value(row[2]) or []
    if not isinstance(persisted_gaps, list):
        persisted_gaps = []
    return {"gaps": persisted_gaps, "confidence": persisted_confidence}


def finalize_section(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]] | None = None,
    session_id: str | None = None,
    extra_gaps: list[str] | None = None,
    template_meta: TemplateMeta | None = None,
) -> dict[str, Any]:
    """UPSERT the section into DuckDB. Returns gap list and confidence."""
    body, removed_raw = _preprocess_section_body(section_key, body, template_meta=template_meta)
    candidate_gaps, candidate_confidence = _collect_initial_gaps(db, section_key, body, extra_gaps)
    candidate_gaps, candidate_confidence = _quality_gate_section(
        section_key,
        title,
        body,
        candidate_gaps,
        candidate_confidence,
        evidence_results,
        db=db,
        behaviors=template_meta.behaviors if template_meta else (),
    )
    if removed_raw:
        note = "Raw evidence rows were moved to reports/evidence JSON and replaced with normalized summaries in the section body."
        if note not in candidate_gaps:
            candidate_gaps.append(note)
        candidate_confidence = min(candidate_confidence, 0.7)
    duplicate_titles = _duplicate_finding_titles(db, body)
    if duplicate_titles:
        candidate_gaps.append(
            f"Finding titles are repeated too often in this section: {', '.join(duplicate_titles[:3])}"
        )
        candidate_confidence = min(candidate_confidence, 0.6)
    updated = _upsert_report_section(
        db=db,
        section_key=section_key,
        title=title,
        body=body,
        confidence=candidate_confidence,
        gaps=candidate_gaps,
        session_id=session_id,
    )
    if not updated:
        return _read_persisted_section(db, section_key)
    claim_statuses = _upsert_claims(db, section_key, body, evidence_results or [])
    candidate_gaps, candidate_confidence, needs_update = _run_post_upsert_gap_checks(
        db, body, evidence_results, claim_statuses, candidate_gaps, candidate_confidence,
    )
    if needs_update:
        _update_section_quality_only(
            db=db,
            section_key=section_key,
            confidence=candidate_confidence,
            gaps=candidate_gaps,
        )
    if updated and evidence_results:
        is_benchmark = any(
            str(r.get("mode") or "").strip().casefold() == "benchmark"
            for r in (evidence_results if isinstance(evidence_results, list) else [])
        )
        if is_benchmark and candidate_confidence and candidate_confidence >= 0.8:
            db.execute("UPDATE report_sections SET stale = FALSE WHERE section_key = ?", [section_key])
    return {"gaps": candidate_gaps, "confidence": candidate_confidence}


def _collect_flat_evidence_rows(
    evidence_results: list[dict[str, Any]],
    max_rows: int = 80,
    min_filled_cols: float = 0.5,
) -> list[dict[str, Any]]:
    """Collect unique, non-sparse evidence rows from evidence results, filtering by minimum filled-column ratio."""
    seen: set[str] = set()
    flat: list[dict[str, Any]] = []
    for result in evidence_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        for row in result.get("sample_rows") or []:
            if not isinstance(row, dict):
                continue
            non_empty = 0
            total = 0
            for value in row.values():
                total += 1
                if value is None:
                    continue
                text = str(value).strip()
                if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
                    continue
                non_empty += 1
            if total and (non_empty / total) < min_filled_cols:
                continue
            key = json.dumps(row, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            flat.append(row)
            if len(flat) >= max_rows:
                return flat
    return flat


def _row_to_summary_line(row: dict[str, Any]) -> str:
    """Convert a single evidence row dict into a compact one-line summary string."""
    if not row:
        return "no fields"
    preferred_fields = (
        "timestamp",
        "event_id",
        "record_id",
        "computer",
        "user_name",
        "target_user",
        "subject_user",
        "process_name",
        "service_name",
        "file_path",
        "file_name",
        "src_ip",
        "dst_ip",
        "message",
        "description",
        "command_line",
        "evidence_id",
    )
    parts: list[str] = []
    remaining_keys = [key for key in row.keys() if key not in preferred_fields]
    for key in preferred_fields:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
            continue
        if key == "timestamp":
            parts.append(text)
        elif key in {"message", "description"} and len(text) > 120:
            parts.append(text[:117].rstrip() + "...")
        else:
            parts.append(f"{key}={text}")
    if not parts:
        for key in remaining_keys:
            value = row.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if not text or text in {"-", "None", "NULL", "null", "N/A", "n/a"}:
                continue
            parts.append(f"{key}={text}")
            if len(parts) >= 4:
                break
    return " ".join(parts) if parts else "no usable summary"


def _summarize_flat_evidence_rows(rows: list[dict[str, Any]], max_rows: int = 30) -> list[dict[str, Any]]:
    summarized: list[dict[str, Any]] = []
    for row in rows[:max_rows]:
        summarized.append({"summary": _row_to_summary_line(row)})
    return summarized


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
                if next_line.strip().startswith("## ") and not next_line.strip().startswith("### "):
                    break
                if next_line.strip().startswith("### ") and not next_line.strip().startswith("#### "):
                    break
                index += 1
            continue
        out.append(line)
        index += 1
    sanitized = "\n".join(out).strip()
    if removed and ("| None |" in text or "| NULL |" in text or "| - |" in text or "None" in text or "NULL" in text):
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized)
    return sanitized, removed


def _dump_section_trace_json(case: Case, section_key: str, evidence_results: list[dict[str, Any]]) -> None:
    """Write non-row evidence results to reports/debug/<section_key>_trace.json."""
    trace_rows = [normalize_value(result) for result in evidence_results if str(result.get("kind") or "rows") != "rows"]
    if not trace_rows:
        return
    debug_dir = case.reports_dir / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    out_path = debug_dir / f"{section_key}_trace.json"
    out_path.write_text(json.dumps(trace_rows, ensure_ascii=False, default=str, indent=2), encoding="utf-8")


def _dump_section_questions_json(case: Case, db: CaseDB, section_key: str) -> None:
    """Write resolved QuestionSpec rows to reports/debug/<section_key>_questions.json."""
    rows = fetch_records(
        db,
        """
        SELECT question_id, section_key, block_heading, question_text, question_type,
               answer_spec, intent, confidence, matched_rule, required_evidence,
               status, created_at, updated_at
        FROM section_questions
        WHERE section_key = ?
        ORDER BY block_heading, question_id
        """,
        (section_key,),
    )
    if not rows:
        return
    debug_dir = case.reports_dir / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    out_path = debug_dir / f"{section_key}_questions.json"
    normalized = [normalize_value(row) for row in rows]
    out_path.write_text(json.dumps(normalized, ensure_ascii=False, default=str, indent=2), encoding="utf-8")


def _dump_section_evidence_json(case: Case, section_key: str, rows: list[dict[str, Any]]) -> None:
    """Write flat evidence rows to reports/evidence/<section_key>.json."""
    if not rows:
        return
    evidence_dir = case.reports_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / f"{section_key}.json"
    out_path.write_text(json.dumps(rows, ensure_ascii=False, default=str, indent=2), encoding="utf-8")


def _structured_block_id(block_heading: str) -> str:
    """Derive a stable structured question ID (e.g. Q1) from the block heading's leading number."""
    match = re.match(r"\s*(\d+)", str(block_heading or ""))
    if match:
        return f"Q{match.group(1)}"
    return "Q0"


def _benchmark_block_id(block_heading: str) -> str:
    """Compatibility wrapper for older benchmark terminology."""
    return _structured_block_id(block_heading)


def _coerce_string_list(value: Any) -> list[str]:
    """Normalize a value to a list of non-empty stripped strings."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _coerce_answer_items(value: Any) -> list[Any]:
    """Preserve dict items (rendered as a Markdown table), coerce others to strings."""
    if isinstance(value, list):
        out: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                if any(str(v).strip() for v in item.values()):
                    out.append(item)
            else:
                text = str(item).strip()
                if text:
                    out.append(text)
        return out
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _answer_columns(items: list[Any], preferred: Any = None) -> list[str]:
    """Return a stable column order for structured answer rows."""
    columns = _coerce_string_list(preferred)
    seen = set(columns)
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in item.keys():
            key_text = str(key)
            if key_text not in seen:
                seen.add(key_text)
                columns.append(key_text)
    return columns


def _normalize_benchmark_answer(
    answer: dict[str, Any],
    *,
    section_key: str,
    block_heading: str,
    status: str,
) -> dict[str, Any]:
    """Normalize and validate a structured answer dict, coercing status to a valid verdict."""
    normalized_id = str(answer.get("id") or _structured_block_id(block_heading)).strip() or _structured_block_id(block_heading)
    normalized_status = str(answer.get("status") or status or "insufficient_evidence").strip().lower()
    from forensia.core.verdicts import assert_valid_verdict
    try:
        assert_valid_verdict(normalized_status, "structured_status")
    except ValueError:
        normalized_status = status or "insufficient_evidence"
        try:
            assert_valid_verdict(normalized_status, "structured_status")
        except ValueError:
            normalized_status = "insufficient_evidence"
    normalized_answer = _coerce_answer_items(answer.get("answer"))
    normalized_missing = _coerce_string_list(answer.get("missing_reason"))
    normalized_queries = _coerce_string_list(answer.get("queries_run"))
    normalized_columns = _answer_columns(normalized_answer, answer.get("columns"))
    normalized: dict[str, Any] = {
        "id": normalized_id,
        "status": normalized_status,
        "answer": normalized_answer,
        "missing_reason": normalized_missing,
        "queries_run": normalized_queries,
    }
    if normalized_columns:
        normalized["columns"] = normalized_columns
    for key in ("source", "csv_path", "json_path"):
        value = str(answer.get(key) or "").strip()
        if value:
            normalized[key] = value
    return normalized


def _normalize_structured_answer(
    answer: dict[str, Any],
    *,
    section_key: str,
    block_heading: str,
    status: str,
) -> dict[str, Any]:
    """Neutral name for structured question answers; kept compatible with older benchmark naming."""
    return _normalize_benchmark_answer(
        answer,
        section_key=section_key,
        block_heading=block_heading,
        status=status,
    )


def _structured_answers_path(case: Case) -> Path:
    return case.reports_dir / "structured" / "answers.json"


def _load_structured_answers(case: Case) -> list[dict[str, Any]]:
    """Load persisted structured answers from reports/structured/answers.json."""
    path = _structured_answers_path(case)
    if not path.exists():
        return []
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _safe_answer_filename(answer_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(answer_id or "answer")).strip("._")
    return safe or "answer"


def _write_structured_answer_csv(case: Case, answer: dict[str, Any]) -> str:
    """Write the structured answer rows for one report/evaluation question as CSV."""
    items = [item for item in answer.get("answer") or [] if isinstance(item, dict)]
    columns = _answer_columns(items, answer.get("columns"))
    if not columns:
        return ""
    path = case.reports_dir / "structured" / f"{_safe_answer_filename(str(answer.get('id') or 'answer'))}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in items:
            row = {}
            for key in columns:
                value = item.get(key, "")
                if isinstance(value, (list, tuple)):
                    row[key] = "; ".join(str(part) for part in value if str(part).strip())
                elif isinstance(value, dict):
                    row[key] = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
                else:
                    row[key] = "" if value is None else str(value)
            writer.writerow(row)
    return f"structured/{path.name}"


def _persist_structured_answer(case: Case, answer: dict[str, Any]) -> None:
    """Persist a single structured answer to reports/structured/answers.json, deduplicating by ID."""
    path = _structured_answers_path(case)
    path.parent.mkdir(parents=True, exist_ok=True)
    answer["json_path"] = "structured/answers.json"
    csv_path = _write_structured_answer_csv(case, answer)
    if csv_path:
        answer["csv_path"] = csv_path
    answers = _load_structured_answers(case)
    answers = [item for item in answers if str(item.get("id") or "") != str(answer.get("id") or "")]
    answers.append(answer)
    answers.sort(key=lambda item: str(item.get("id") or ""))
    path.write_text(json.dumps(answers, ensure_ascii=False, default=str, indent=2), encoding="utf-8")


STRUCTURED_MARKDOWN_MAX_ROWS = 25
STRUCTURED_MARKDOWN_MAX_LIST_ITEMS = 5
STRUCTURED_MARKDOWN_MAX_CELL_CHARS = 240


def _render_answer_cell(value: Any) -> str:
    """Render one structured-answer preview cell without dumping huge lists into HTML."""
    if isinstance(value, (list, tuple)):
        parts = [str(part).strip() for part in value if str(part).strip()]
        extra = max(len(parts) - STRUCTURED_MARKDOWN_MAX_LIST_ITEMS, 0)
        value = "; ".join(parts[:STRUCTURED_MARKDOWN_MAX_LIST_ITEMS])
        if extra:
            value = f"{value}; ... (+{extra} more)" if value else f"... (+{extra} more)"
    elif isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    text = str(value if value is not None else "").replace("|", "\\|").replace("\n", " ").strip()
    if len(text) > STRUCTURED_MARKDOWN_MAX_CELL_CHARS:
        return text[: STRUCTURED_MARKDOWN_MAX_CELL_CHARS - 15].rstrip() + " ... [truncated]"
    return text


def _render_answer_block(items: list[Any], columns: Any = None, *, max_rows: int = STRUCTURED_MARKDOWN_MAX_ROWS) -> list[str]:
    """Render answer items as a Markdown table when every item is a dict; otherwise bullets."""
    if not items:
        return ["- no answer"]
    dicts = [item for item in items if isinstance(item, dict)]
    if dicts and len(dicts) == len(items):
        keys = _answer_columns(dicts, columns)
        if not keys:
            return ["- no answer"]

        header = "| " + " | ".join(keys) + " |"
        divider = "| " + " | ".join(["---"] * len(keys)) + " |"
        preview = dicts[:max_rows] if max_rows > 0 else dicts
        body_rows = [
            "| " + " | ".join(_render_answer_cell(item.get(key)) for key in keys) + " |"
            for item in preview
        ]
        lines = [header, divider, *body_rows]
        if len(dicts) > len(preview):
            lines.extend(["", f"_Showing {len(preview)} of {len(dicts)} rows. Full data is available in the structured JSON/CSV export._"])
        return lines
    return [f"- {str(item).strip()}" for item in items if not isinstance(item, dict) and str(item).strip()]


_MISSING_REASON_NOOP_VALUES = frozenset({"none", "n/a", "na", "-", "該当なし", "なし"})


def _meaningful_missing_reason_items(value: Any) -> list[str]:
    """Drop sentinel values (`none` / `該当なし` / blanks) used by upstream to mean "nothing missing"."""
    return [item for item in _coerce_string_list(value) if item.strip().lower() not in _MISSING_REASON_NOOP_VALUES]


def _render_structured_answer_markdown(answer: dict[str, Any], block_heading: str) -> str:
    """Render a single structured answer as Markdown using persisted data rows."""
    answer_block = _render_answer_block(list(answer.get("answer") or []), answer.get("columns"))
    missing_lines = [f"- {item}" for item in _meaningful_missing_reason_items(answer.get("missing_reason"))]
    query_lines = [f"- {item}" for item in _coerce_string_list(answer.get("queries_run"))]
    data_lines = [f"- JSON: {answer.get('json_path')}"] if answer.get("json_path") else []
    if answer.get("csv_path"):
        data_lines.append(f"- CSV: {answer.get('csv_path')}")
    if not data_lines:
        data_lines = ["- none"]
    if not query_lines:
        query_lines = ["- none"]
    lines = [
        f"## {block_heading}",
        "",
        f"**ID:** {str(answer.get('id') or _structured_block_id(block_heading))}",
        f"**Status:** {str(answer.get('status') or 'insufficient_evidence')}",
        "",
        "### Answer",
        *answer_block,
        "",
    ]
    status = str(answer.get("status") or "").strip().lower()
    if status != "answered" or missing_lines:
        lines.append("### Missing Reason")
        lines.extend(missing_lines if missing_lines else ["- none"])
        lines.append("")
    lines.extend([
        "### Queries Run",
        *query_lines,
        "",
        "### Structured Data",
        *data_lines,
    ])
    return "\n".join(lines).strip() + "\n"


def _benchmark_answers_path(case: Case) -> Path:
    """Compatibility path for older callers; new structured answers use reports/structured."""
    return _structured_answers_path(case)


def _load_benchmark_answers(case: Case) -> list[dict[str, Any]]:
    """Compatibility wrapper for older tests/callers."""
    return _load_structured_answers(case)


def _persist_benchmark_answer(case: Case, answer: dict[str, Any]) -> None:
    """Compatibility wrapper; prefer _persist_structured_answer."""
    _persist_structured_answer(case, answer)


def _render_benchmark_answer_markdown(answer: dict[str, Any], block_heading: str) -> str:
    """Compatibility wrapper; prefer _render_structured_answer_markdown."""
    return _render_structured_answer_markdown(answer, block_heading)


def _structured_rows(db: CaseDB, query: str) -> list[dict[str, Any]]:
    return [normalize_value(row) for row in _report_keypoint_rows(db, query)]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower_blob(row: dict[str, Any]) -> str:
    return " ".join(_text(value).casefold() for value in row.values() if value is not None)


def _dedupe_dict_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        fingerprint = tuple(_text(row.get(key)).casefold() for key in keys)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        out.append(row)
    return out


def _structured_answer(
    case: Case,
    *,
    answer_id: str,
    section_key: str,
    block_heading: str,
    rows: list[dict[str, Any]],
    columns: list[str],
    queries_run: list[str],
    status: str | None = None,
    missing_reason: list[str] | None = None,
    source: str = "deterministic_sql",
) -> dict[str, Any]:
    resolved_status = status or ("answered" if rows else "not_found")
    answer = _normalize_structured_answer(
        {
            "id": answer_id,
            "status": resolved_status,
            "answer": rows,
            "columns": columns,
            "missing_reason": missing_reason or ([] if rows else ["No matching structured database rows were found."]),
            "queries_run": queries_run,
            "source": source,
        },
        section_key=section_key,
        block_heading=block_heading,
        status=resolved_status,
    )
    _persist_structured_answer(case, answer)
    return answer


def _prefetch_executable_from_filename(file_name: Any) -> str:
    name = _text(file_name)
    if not name:
        return ""
    upper = name.upper()
    if upper.endswith(".PF"):
        name = name[:-3]
    return re.sub(r"-[A-Fa-f0-9]{8}$", "", name)


def _human_user_predicate(column: str = "target_user") -> str:
    return f"""
        {column} IS NOT NULL
        AND TRIM({column}) <> ''
        AND {column} NOT LIKE '%$'
        AND UPPER({column}) NOT IN ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')
        AND UPPER({column}) NOT LIKE 'DWM-%'
        AND UPPER({column}) NOT LIKE 'UMFD-%'
    """


def _build_host_identity(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            computer AS host_id,
            COUNT(*) AS evidence_count,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM evtx_events
        WHERE computer IS NOT NULL AND TRIM(computer) <> ''
        GROUP BY computer
        ORDER BY evidence_count DESC, host_id
        """,
    )
    rows = _dedupe_dict_rows(rows, ("host_id",))
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["host_id", "evidence_count", "first_seen", "last_seen"],
        queries_run=["structured:host_identity:evtx_distinct_hosts"],
    )


def _build_last_human_logon(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    interactive_rows = _structured_rows(
        db,
        f"""
        SELECT
            timestamp AS logon_time,
            computer,
            target_user AS user_name,
            logon_type,
            process_name,
            src_ip,
            evidence_id
        FROM evtx_events
        WHERE event_id = 4624
          AND {_human_user_predicate("target_user")}
          AND CAST(COALESCE(logon_type, '') AS VARCHAR) IN ('2', '7', '10', '11')
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    if interactive_rows:
        rows = interactive_rows
        status = "answered"
        missing: list[str] = []
        label = "structured:last_human_logon:last_interactive_user_logon"
    else:
        rows = _structured_rows(
            db,
            f"""
            SELECT
                timestamp AS logon_time,
                computer,
                target_user AS user_name,
                logon_type,
                process_name,
                src_ip,
                evidence_id
            FROM evtx_events
            WHERE event_id = 4624
              AND {_human_user_predicate("target_user")}
            ORDER BY timestamp DESC
            LIMIT 1
            """,
        )
        status = "partial" if rows else "not_found"
        missing = [] if rows else ["No human-user 4624 logon events were found."]
        if rows:
            missing = ["No interactive logon type was found; returned the latest human-user 4624 logon event."]
        label = "structured:last_human_logon:last_human_user_logon_fallback"
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["logon_time", "computer", "user_name", "logon_type", "process_name", "src_ip", "evidence_id"],
        queries_run=[label],
        status=status,
        missing_reason=missing,
    )


def _build_last_shutdown_event(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            timestamp AS shutdown_time,
            event_id,
            computer,
            evidence_id,
            message
        FROM evtx_events
        WHERE event_id IN (1074, 6006, 6008)
        ORDER BY timestamp DESC
        LIMIT 1
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["shutdown_time", "event_id", "computer", "evidence_id", "message"],
        queries_run=["structured:last_shutdown_event:1074_6006_6008"],
    )


def _build_application_execution_history(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE executable_name IS NOT NULL AND TRIM(executable_name) <> ''
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        LIMIT 200
        """,
    )
    if rows:
        return _structured_answer(
            case,
            answer_id=answer_id,
            section_key=section_key,
            block_heading=block_heading,
            rows=rows,
            columns=["executable_name", "exec_count", "last_exec_time", "evidence_id", "source_file"],
            queries_run=["structured:application_execution_history:prefetch_executions"],
        )

    mft_rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(extension, '')) = 'pf'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.pf'
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 200
        """,
    )
    rows = [
        {
            "executable_name": _prefetch_executable_from_filename(row.get("file_name")),
            "exec_count": "",
            "last_exec_time": "",
            "artifact_time": row.get("artifact_time"),
            "artifact_path": row.get("file_path"),
            "evidence_id": row.get("evidence_id"),
        }
        for row in mft_rows
    ]
    rows = [row for row in rows if _text(row.get("executable_name"))]
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["executable_name", "exec_count", "last_exec_time", "artifact_time", "artifact_path", "evidence_id"],
        queries_run=["structured:application_execution_history:mft_prefetch_file_fallback"],
        status="partial" if rows else "not_found",
        missing_reason=[] if not rows else ["prefetch_executions was empty; returned MFT Prefetch files without execution counts."],
    )


def _build_daily_session_activity(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            SUM(CASE WHEN event_id IN (6005, 4608) THEN 1 ELSE 0 END) AS startup,
            SUM(CASE WHEN event_id = 4624 THEN 1 ELSE 0 END) AS logons,
            SUM(CASE WHEN event_id IN (4634, 4647) THEN 1 ELSE 0 END) AS logoff,
            SUM(CASE WHEN event_id IN (1074, 6006, 6008) THEN 1 ELSE 0 END) AS shutdown
        FROM evtx_events
        WHERE timestamp IS NOT NULL
          AND event_id IN (4608, 4624, 4634, 4647, 6005, 6006, 6008, 1074)
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["date", "startup", "logons", "logoff", "shutdown"],
        queries_run=["structured:daily_session_activity:startup_logon_logoff_shutdown"],
    )


_BROWSER_MARKERS: dict[str, tuple[str, ...]] = {
    "Google Chrome": ("chrome.exe", "google/chrome", "google\\chrome"),
    "Microsoft Internet Explorer": ("iexplore.exe", "internet explorer"),
    "Mozilla Firefox": ("firefox.exe", "mozilla/firefox", "mozilla\\firefox"),
    "Microsoft Edge": ("msedge.exe", "microsoft/edge", "microsoft\\edge"),
    "Brave": ("brave.exe", "bravesoftware"),
    "Opera": ("opera.exe",),
}


def _browser_name_for_row(row: dict[str, Any]) -> str:
    text = _lower_blob(row).replace("\\", "/")
    for name, markers in _BROWSER_MARKERS.items():
        if any(marker.replace("\\", "/") in text for marker in markers):
            return name
    return ""


def _build_browser_usage(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    prefetch_rows = _structured_rows(
        db,
        """
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE LOWER(COALESCE(executable_name, '')) IN (
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'brave.exe', 'opera.exe'
        )
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    mft_rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(file_name, '')) IN (
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'brave.exe', 'opera.exe'
        )
           OR LOWER(COALESCE(file_path, '')) LIKE '%google/chrome%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%google\\chrome%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%internet explorer%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%mozilla/firefox%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%mozilla\\firefox%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%microsoft/edge%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%microsoft\\edge%'
        ORDER BY si_modified DESC NULLS LAST, file_name
        LIMIT 100
        """,
    )
    grouped: dict[str, dict[str, Any]] = {}

    def group_for(browser_name: str) -> dict[str, Any]:
        return grouped.setdefault(browser_name, {
            "browser_name": browser_name,
            "prefetch_records": 0,
            "total_exec_count": 0,
            "last_exec_time": "",
            "mft_artifacts": 0,
            "first_artifact_time": "",
            "last_artifact_time": "",
            "sample_paths": [],
            "evidence_ids": [],
        })

    def append_unique(values: list[Any], value: Any, limit: int) -> None:
        text = _text(value)
        if text and text not in values and len(values) < limit:
            values.append(text)

    def max_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return max(left_text, right_text) if left_text and right_text else (left_text or right_text)

    def min_text_time(left: Any, right: Any) -> str:
        left_text = _text(left)
        right_text = _text(right)
        return min(left_text, right_text) if left_text and right_text else (left_text or right_text)

    for row in prefetch_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["prefetch_records"] = int(item.get("prefetch_records") or 0) + 1
        try:
            item["total_exec_count"] = int(item.get("total_exec_count") or 0) + int(row.get("exec_count") or 0)
        except (TypeError, ValueError):
            pass
        item["last_exec_time"] = max_text_time(item.get("last_exec_time"), row.get("last_exec_time"))
        append_unique(item["sample_paths"], row.get("source_file") or row.get("executable_name"), 10)
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    for row in mft_rows:
        browser_name = _browser_name_for_row(row)
        if not browser_name:
            continue
        item = group_for(browser_name)
        item["mft_artifacts"] = int(item.get("mft_artifacts") or 0) + 1
        item["first_artifact_time"] = min_text_time(item.get("first_artifact_time"), row.get("artifact_time"))
        item["last_artifact_time"] = max_text_time(item.get("last_artifact_time"), row.get("artifact_time"))
        append_unique(item["sample_paths"], row.get("file_path") or row.get("file_name"), 10)
        append_unique(item["evidence_ids"], row.get("evidence_id"), 20)
    rows = sorted(grouped.values(), key=lambda item: str(item.get("browser_name") or ""))
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["browser_name", "prefetch_records", "total_exec_count", "last_exec_time", "mft_artifacts", "first_artifact_time", "last_artifact_time", "sample_paths", "evidence_ids"],
        queries_run=["structured:browser_usage:browser_prefetch", "structured:browser_usage:browser_mft_artifacts"],
    )


def _mail_application_name(row: dict[str, Any]) -> str:
    text = _lower_blob(row)
    if "outlook" in text or ".ost" in text or ".pst" in text:
        return "Microsoft Outlook"
    if "thunderbird" in text:
        return "Mozilla Thunderbird"
    return ""


def _build_email_application_usage(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows_raw = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            extension,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(file_name, '')) LIKE '%.ost'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.pst'
           OR LOWER(COALESCE(file_path, '')) LIKE '%/outlook/%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%\\outlook\\%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%thunderbird%'
        ORDER BY si_modified DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    rows: list[dict[str, Any]] = []
    for row in rows_raw:
        app = _mail_application_name(row)
        if not app:
            continue
        rows.append({
            "application_name": app,
            "version": "",
            "evidence_type": "mft",
            "artifact_path": row.get("file_path"),
            "artifact_time": row.get("artifact_time"),
            "evidence_id": row.get("evidence_id"),
        })
    rows = _dedupe_dict_rows(rows, ("application_name", "artifact_path", "evidence_id"))
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["application_name", "version", "evidence_type", "artifact_path", "artifact_time", "evidence_id"],
        queries_run=["structured:email_application_usage:mail_application_artifacts"],
    )


def _build_email_data_files(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            extension,
            si_created,
            si_modified,
            si_accessed,
            fn_created,
            fn_modified,
            fn_accessed,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(extension, '')) IN ('ost', 'pst', 'mbox')
           OR LOWER(COALESCE(file_name, '')) LIKE '%.ost'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.pst'
           OR LOWER(COALESCE(file_name, '')) LIKE '%.mbox'
        ORDER BY COALESCE(fn_modified, si_modified, fn_created, si_created) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["file_name", "file_path", "extension", "si_created", "si_modified", "si_accessed", "fn_created", "fn_modified", "fn_accessed", "evidence_id"],
        queries_run=["structured:email_data_files:mft"],
    )


def _recent_lnk_base_name(file_name: Any) -> str:
    text = _text(file_name)
    if text.lower().endswith(".lnk"):
        text = text[:-4]
    return text.strip()


def _recent_lnk_tokens(file_name: Any) -> set[str]:
    base = _recent_lnk_base_name(file_name).lower()
    base = re.sub(r"\.[a-z0-9]{1,8}$", "", base)
    tokens = {token for token in re.split(r"[^a-z0-9]+", base) if len(token) >= 3}
    return tokens - {"lnk", "desktop", "templates", "drive"}


def _row_time_text(row: dict[str, Any]) -> str:
    for key in ("fn_created", "si_created", "fn_modified", "si_modified"):
        value = _text(row.get(key))
        if value:
            return value
    return ""


def _parse_iso_datetime(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _infer_recent_lnk_rename_candidates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Infer rename candidates from near-time Windows Recent LNK alias pairs."""
    candidates: list[dict[str, Any]] = []
    for left_index, left in enumerate(rows):
        left_tokens = _recent_lnk_tokens(left.get("file_name"))
        left_time = _parse_iso_datetime(_row_time_text(left))
        if not left_tokens or left_time is None:
            continue
        for right in rows[left_index + 1:]:
            right_tokens = _recent_lnk_tokens(right.get("file_name"))
            right_time = _parse_iso_datetime(_row_time_text(right))
            if not right_tokens or right_time is None:
                continue
            delta_s = abs((right_time - left_time).total_seconds())
            if delta_s > 120:
                continue
            shared = left_tokens & right_tokens
            if not shared:
                continue
            shorter, longer = (left, right)
            shorter_tokens, longer_tokens = left_tokens, right_tokens
            if len(_recent_lnk_base_name(left.get("file_name"))) > len(_recent_lnk_base_name(right.get("file_name"))):
                shorter, longer = right, left
                shorter_tokens, longer_tokens = right_tokens, left_tokens
            if not shorter_tokens <= longer_tokens:
                continue
            candidates.append({
                "original_name": _recent_lnk_base_name(shorter.get("file_name")),
                "new_name": _recent_lnk_base_name(longer.get("file_name")),
                "timestamp": max(_row_time_text(left), _row_time_text(right)),
                "basis": "Windows Recent LNK files created/modified within 120 seconds with overlapping filename tokens",
                "source_paths": [_text(shorter.get("file_path")), _text(longer.get("file_path"))],
                "evidence_ids": [_text(shorter.get("evidence_id")), _text(longer.get("evidence_id"))],
            })
    deduped = _dedupe_dict_rows(candidates, ("original_name", "new_name", "timestamp"))
    return sorted(deduped, key=lambda row: str(row.get("timestamp") or ""), reverse=True)[:50]


def _build_desktop_rename_candidates(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            json_extract_string(raw_json, '$.fn_filename') AS original_name,
            file_name AS new_name,
            file_path,
            si_modified,
            fn_modified,
            evidence_id
        FROM mft_entries
        WHERE (
            LOWER(COALESCE(file_path, '')) LIKE '%/desktop/%'
            OR LOWER(COALESCE(file_path, '')) LIKE '%\\desktop\\%'
        )
          AND json_extract_string(raw_json, '$.fn_filename') IS NOT NULL
          AND json_extract_string(raw_json, '$.fn_filename') != file_name
        ORDER BY COALESCE(fn_modified, si_modified) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    queries_run = ["structured:desktop_rename_candidates:mft_filename_pairs"]
    if not rows:
        recent_rows = _structured_rows(
            db,
            """
            SELECT
                file_name,
                file_path,
                si_created,
                si_modified,
                fn_created,
                fn_modified,
                evidence_id
            FROM mft_entries
            WHERE (
                LOWER(COALESCE(file_path, '')) LIKE '%/windows/recent/%'
                OR LOWER(COALESCE(file_path, '')) LIKE '%\\windows\\recent\\%'
            )
              AND LOWER(COALESCE(file_name, '')) LIKE '%.lnk'
            ORDER BY COALESCE(fn_created, si_created, fn_modified, si_modified) NULLS LAST, file_name
            LIMIT 500
            """,
        )
        rows = _infer_recent_lnk_rename_candidates(recent_rows)
        queries_run.append("structured:desktop_rename_candidates:recent_lnk_temporal_alias_pairs")
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["original_name", "new_name", "timestamp", "basis", "source_paths", "evidence_ids"],
        queries_run=queries_run,
        status="partial" if rows else "not_found",
        missing_reason=[] if not rows else ["MFT filename-pair evidence was not available; returned Recent LNK temporal alias candidates."],
    )


_CLOUD_MARKERS: dict[str, tuple[str, ...]] = {
    "Google Drive": ("googledrive", "google drive", "google/drive", "google\\drive"),
    "iCloud": ("icloud", "apple computer"),
    "OneDrive": ("onedrive",),
    "Dropbox": ("dropbox", "config.dbx"),
}


def _build_cloud_service_traces(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    mft_rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            is_deleted,
            si_modified AS artifact_time,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(file_path, '')) LIKE '%google/drive%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%google\\drive%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%apple computer%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%icloud%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%onedrive%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%dropbox%'
           OR LOWER(COALESCE(file_name, '')) IN ('googledrivesync.exe', 'icloudsetup.exe', 'onedrive.exe', 'dropbox.exe', 'sync_config.db', 'snapshot.db', 'config.dbx')
        ORDER BY si_modified DESC NULLS LAST, file_path
        LIMIT 200
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        """
        SELECT
            executable_name,
            exec_count,
            last_exec_time,
            evidence_id,
            source_file
        FROM prefetch_executions
        WHERE LOWER(COALESCE(executable_name, '')) IN ('googledrivesync.exe', 'icloudsetup.exe', 'onedrive.exe', 'dropbox.exe')
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        """,
    )
    rows: list[dict[str, Any]] = []
    for service_name, markers in _CLOUD_MARKERS.items():
        service_mft = [row for row in mft_rows if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)]
        service_prefetch = [row for row in prefetch_rows if any(marker in _lower_blob(row).replace("\\", "/") for marker in markers)]
        if not service_mft and not service_prefetch:
            continue
        paths = [_text(row.get("file_path")) for row in service_mft if _text(row.get("file_path"))]
        paths.extend(_text(row.get("source_file")) for row in service_prefetch if _text(row.get("source_file")))
        evidence_ids = [_text(row.get("evidence_id")) for row in [*service_mft, *service_prefetch] if _text(row.get("evidence_id"))]
        rows.append({
            "service_name": service_name,
            "exe_found": "yes" if service_prefetch or any(".exe" in _lower_blob(row) or ".pf" in _lower_blob(row) for row in service_mft) else "no",
            "paths_found": paths[:20],
            "config_found": "yes" if any(marker in _lower_blob(row) for row in service_mft for marker in ("config", ".db", "snapshot")) else "no",
            "evidence_ids": evidence_ids[:20],
        })
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["service_name", "exe_found", "paths_found", "config_found", "evidence_ids"],
        queries_run=["structured:cloud_service_traces:mft_artifacts", "structured:cloud_service_traces:prefetch"],
    )


def _build_resignation_file_timestamps(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    rows = _structured_rows(
        db,
        """
        SELECT
            file_name,
            file_path,
            extension,
            is_deleted,
            si_created,
            si_modified,
            si_accessed,
            fn_created,
            fn_modified,
            fn_accessed,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(file_name, '')) LIKE '%resign%'
           OR LOWER(COALESCE(file_name, '')) LIKE '%resignation%'
           OR LOWER(COALESCE(file_name, '')) LIKE '%retire%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%resign%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%resignation%'
           OR LOWER(COALESCE(file_path, '')) LIKE '%retire%'
        ORDER BY COALESCE(fn_modified, si_modified, fn_created, si_created) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["file_name", "file_path", "extension", "is_deleted", "si_created", "si_modified", "si_accessed", "fn_created", "fn_modified", "fn_accessed", "evidence_id"],
        queries_run=["structured:resignation_file_timestamps:mft"],
    )


def _build_antiforensic_activity(case: Case, db: CaseDB, answer_id: str, section_key: str, block_heading: str) -> dict[str, Any]:
    event_rows = _structured_rows(
        db,
        """
        SELECT
            'event_log' AS evidence_type,
            timestamp,
            event_id,
            channel,
            computer,
            target_user,
            evidence_id,
            message
        FROM evtx_events
        WHERE event_id = 1102
           OR (event_id = 104 AND LOWER(COALESCE(channel, '')) LIKE '%eventlog%')
        ORDER BY timestamp DESC NULLS LAST
        LIMIT 100
        """,
    )
    prefetch_rows = _structured_rows(
        db,
        """
        SELECT
            'tool_execution' AS evidence_type,
            last_exec_time AS timestamp,
            executable_name AS file_name,
            source_file AS file_path,
            evidence_id
        FROM prefetch_executions
        WHERE LOWER(COALESCE(executable_name, '')) IN (
            'eraser.exe', 'ccleaner.exe', 'ccleaner64.exe', 'bleachbit.exe', 'sdelete.exe', 'cipher.exe'
        )
        ORDER BY last_exec_time DESC NULLS LAST, executable_name
        LIMIT 50
        """,
    )
    tool_rows = _structured_rows(
        db,
        """
        SELECT
            'tool_or_cleanup_artifact' AS evidence_type,
            file_name,
            file_path,
            is_deleted,
            si_created,
            si_modified,
            evidence_id
        FROM mft_entries
        WHERE LOWER(COALESCE(file_name, '')) LIKE 'eraser%.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'ccleaner%.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'ccsetup%.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'bleachbit%.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'sdelete%.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'cipher.exe'
           OR LOWER(COALESCE(file_name, '')) LIKE 'eraser%.lnk'
           OR LOWER(COALESCE(file_name, '')) LIKE 'ccleaner%.lnk'
           OR LOWER(COALESCE(file_name, '')) LIKE '%eraser%.pf'
           OR LOWER(COALESCE(file_name, '')) LIKE '%ccleaner%.pf'
           OR LOWER(COALESCE(file_name, '')) = 'task list.ersy'
           OR LOWER(COALESCE(file_path, '')) LIKE '%/eraser 6/logs/%'
        ORDER BY COALESCE(si_modified, si_created) DESC NULLS LAST, file_path
        LIMIT 100
        """,
    )
    rows = event_rows + prefetch_rows + tool_rows
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=["evidence_type", "timestamp", "event_id", "channel", "computer", "target_user", "file_name", "file_path", "is_deleted", "si_created", "si_modified", "evidence_id", "message"],
        queries_run=["structured:antiforensic_activity:event_log_clear_events", "structured:antiforensic_activity:prefetch_tool_execution", "structured:antiforensic_activity:tool_artifacts"],
    )


def _build_generic_question_spec_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    """Execute a YAML-declared QuestionSpec when no Python builder is needed."""
    spec = question_spec_for_answer_spec(answer_spec)
    if spec is None or not spec.evidence_chain:
        return None

    rows: list[dict[str, Any]] = []
    queries_run: list[str] = []
    errors: list[str] = []
    for index, entry in enumerate(spec.evidence_chain, start=1):
        query = str(entry.get("query") or "").strip()
        if not query:
            continue
        source = str(entry.get("source") or f"query_{index}").strip()
        label = f"structured:{spec.semantic_id}:{source}"
        queries_run.append(label)
        try:
            source_rows = _structured_rows(db, query)
        except Exception as exc:
            errors.append(f"{source}: {str(exc)[:120]}")
            continue
        for row in source_rows:
            rows.append({**row, "_question_source": source})

    rows = project_rows_for_question_spec(spec, rows)
    status, reasons = evaluate_question_spec_status(spec, rows, queries_run=queries_run)
    if errors:
        reasons.extend(errors)
        if status == "answered":
            status = "partial"
    columns = list(spec.render_columns)
    if not columns and rows:
        columns = [str(key) for key in rows[0].keys() if not str(key).startswith("_")]
    return _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=columns,
        queries_run=queries_run,
        status=status,
        missing_reason=reasons,
        source="question_spec",
    )


StructuredAnswerBuilder = Callable[[Case, CaseDB, str, str, str], dict[str, Any]]

_STRUCTURED_ANSWER_BUILDERS: dict[str, StructuredAnswerBuilder] = {
    "host_identity": _build_host_identity,
    "last_human_logon": _build_last_human_logon,
    "last_shutdown_event": _build_last_shutdown_event,
    "application_execution_history": _build_application_execution_history,
    "daily_session_activity": _build_daily_session_activity,
    "browser_usage": _build_browser_usage,
    "email_application_usage": _build_email_application_usage,
    "email_data_files": _build_email_data_files,
    "desktop_rename_candidates": _build_desktop_rename_candidates,
    "cloud_service_traces": _build_cloud_service_traces,
    "resignation_file_timestamps": _build_resignation_file_timestamps,
    "antiforensic_activity": _build_antiforensic_activity,
}


def build_structured_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    """Build, persist, and return deterministic structured answer data for a semantic spec."""
    normalized_spec = str(answer_spec or "").strip().casefold().replace("-", "_")
    if not normalized_spec:
        return None
    builder = _STRUCTURED_ANSWER_BUILDERS.get(normalized_spec)
    if builder is None:
        return _build_generic_question_spec_answer(
            case,
            db,
            answer_spec=normalized_spec,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
        )
    resolved_id = str(answer_id or normalized_spec).strip() or normalized_spec
    answer = builder(case, db, resolved_id, section_key, block_heading)
    spec = question_spec_for_answer_spec(normalized_spec)
    if spec is not None:
        status, reasons = evaluate_question_spec_status(
            spec,
            [item for item in answer.get("answer") or [] if isinstance(item, dict)],
            queries_run=_coerce_string_list(answer.get("queries_run")),
            fallback_status=str(answer.get("status") or ""),
        )
        if status != answer.get("status") or reasons:
            answer["status"] = status
            missing = _coerce_string_list(answer.get("missing_reason"))
            for reason in reasons:
                if reason and reason not in missing:
                    missing.append(reason)
            answer["missing_reason"] = missing
            _persist_structured_answer(case, answer)
    return answer


UNIVERSAL_QUESTION_SPECS: tuple[str, ...] = (
    "host_identity",
    "last_human_logon",
    "last_shutdown_event",
    "application_execution_history",
    "daily_session_activity",
    "browser_usage",
    "email_data_files",
    "cloud_service_traces",
    "antiforensic_activity",
)


def _collect_answer_evidence_ids(value: Any) -> list[str]:
    """Extract evidence_id/evidence_ids from a structured answer payload."""
    found: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            single = item.get("evidence_id")
            if single is not None:
                text = str(single).strip()
                if text:
                    found.append(text)
            many = item.get("evidence_ids")
            if isinstance(many, (list, tuple, set)):
                for part in many:
                    text = str(part).strip()
                    if text:
                        found.append(text)
            elif many is not None:
                text = str(many).strip()
                if text:
                    found.append(text)
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return list(dict.fromkeys(found))


def ensure_universal_question_probes(case: Case, db: CaseDB) -> None:
    """Populate durable case-wide structured facts independent of report templates."""
    try:
        existing = db.execute(
            """
            SELECT COUNT(*)
            FROM section_questions
            WHERE section_key = '__case_probe__'
              AND status = 'case_probe'
            """
        ).fetchone()
        if existing is not None and int(existing[0] or 0) >= len(UNIVERSAL_QUESTION_SPECS):
            return
    except Exception:
        return

    now = datetime.now(UTC).replace(tzinfo=None)
    for answer_spec in UNIVERSAL_QUESTION_SPECS:
        spec = question_spec_for_answer_spec(answer_spec)
        if spec is None:
            continue
        try:
            answer = build_structured_answer(
                case,
                db,
                answer_spec=answer_spec,
                answer_id=f"probe_{answer_spec}",
                section_key="__case_probe__",
                block_heading=spec.intent or spec.name,
            )
        except Exception:
            answer = None
        question_id = hashlib.sha1(f"__case_probe__\n{answer_spec}".encode("utf-8")).hexdigest()[:20]
        required_evidence = {
            "required_fields": list(spec.required_fields),
            "required_sources": list(spec.required_sources),
            "keypoints": list(spec.keypoints),
            "render_columns": list(spec.render_columns),
            "status_rules": spec.status_rules,
        }
        db.execute(
            """
            INSERT INTO section_questions (
                question_id, section_key, block_heading, question_text, question_type,
                answer_spec, intent, confidence, matched_rule, required_evidence,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (question_id) DO UPDATE SET
                confidence = excluded.confidence,
                required_evidence = excluded.required_evidence,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                question_id,
                "__case_probe__",
                spec.intent or spec.name,
                spec.intent or spec.name,
                spec.name,
                spec.answer_spec,
                spec.intent,
                1.0,
                spec.name,
                json.dumps(required_evidence, ensure_ascii=False, default=str),
                "case_probe",
                now,
                now,
            ),
        )
        if answer is not None:
            evidence_ids = _collect_answer_evidence_ids(answer.get("answer"))
            fact_value = {
                "status": answer.get("status"),
                "answer": answer.get("answer"),
                "columns": answer.get("columns"),
                "evidence_ids": evidence_ids,
            }
            fact_id = hashlib.sha1(f"universal_question:{answer_spec}".encode("utf-8")).hexdigest()[:20]
            db.execute(
                """
                INSERT INTO section_facts (
                    fact_id, fact_type, fact_key, fact_value, evidence_ids,
                    source_query, source_section, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fact_id) DO UPDATE SET
                    fact_value = excluded.fact_value,
                    evidence_ids = excluded.evidence_ids,
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at
                """,
                (
                    fact_id,
                    "universal_question",
                    answer_spec,
                    json.dumps(fact_value, ensure_ascii=False, default=str),
                    json.dumps(evidence_ids, ensure_ascii=False),
                    f"structured:{answer_spec}",
                    "__case_probe__",
                    0.9 if answer.get("status") == "answered" else 0.5,
                    now,
                    now,
                ),
            )


def fill_section(
    case: Case,
    db: CaseDB,
    template_path: str | Path,
    context_sections: dict[str, str],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    max_queries_per_section: int = 3,
    session_id: str | None = None,
    audit_callback: Callable[[list[dict[str, str]], str], None] | None = None,
) -> str:
    """Prepare, render, and finalize a single report section, dispatching block agents and persisting evidence."""
    ensure_universal_question_probes(case, db)
    request = prepare_section_request(case, db, template_path, context_sections, report_brief=report_brief)
    body, evidence_results, block_gaps = _render_section_from_request(
        db=db,
        request=request,
        base_url=base_url,
        model=model,
        max_queries_per_section=max_queries_per_section,
        audit_callback=audit_callback,
    )
    flat_rows = _collect_flat_evidence_rows(evidence_results)
    _dump_section_evidence_json(case, request["section_key"], flat_rows)
    _dump_section_trace_json(case, request["section_key"], evidence_results)
    _dump_section_questions_json(case, db, request["section_key"])
    finalize_section(
        db=db,
        section_key=request["section_key"],
        title=request["title"],
        body=body,
        evidence_results=evidence_results,
        session_id=session_id,
        extra_gaps=block_gaps,
        template_meta=request.get("template_meta"),
    )
    return body


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


def write_report(case: Case, filled_sections: dict[str, str]) -> Path:
    """Write the concatenated filled sections to reports/report.md in section-key order."""
    ordered = [filled_sections[key].strip() for key in sorted(filled_sections) if filled_sections[key].strip()]
    report_md = "\n\n".join(ordered).strip() + "\n"
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def write_report_from_db(case: Case, db: CaseDB) -> Path:
    """Read report sections from the database and write the full report to reports/report.md."""
    report_md = build_report_markdown_from_db(db)
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def render_written_report(
    case: Case,
    db: CaseDB,
    filled_sections: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    """Write report Markdown (from sections or DB) and generate the corresponding HTML report."""
    report_md = write_report(case, filled_sections) if filled_sections is not None else write_report_from_db(case, db)
    report_html = render_html_report(case, db)
    return report_md, report_html
