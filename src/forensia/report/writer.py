from __future__ import annotations

import csv
from functools import lru_cache
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensia.core.case import Case, detect_epochs
from forensia.core.memory import MemoryManager, memory_for_section
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.questions import (
    evaluate_question_spec_status,
    project_rows_for_question_spec,
    question_spec_for_answer_spec,
)
from forensia.report.html import render_html_report
from forensia.report.quality_gates import (
    PLACEHOLDER_ENTITY_PATTERN,
    HEADING_PATTERN,
    HTML_FILL_PATTERN,
    FINDING_ID_PATTERN,
    _first_heading_text,
    _timeline_rows_are_chronological,
    _title_matches_body_heading,
    _normalized_text_key,
    _detect_body_language,
    _GateCtx,
    _QUALITY_CHECKS,
    _SEVERE_GATE_SUBSTRINGS,
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
    _check_kp_citation,
    _check_hedge_no_citation,
    _check_citation_token_no_finding_id,
    _check_duplicate_paragraph,
    _check_out_of_range_timestamp,
    _check_overused_evidence_id,
    _check_json_object_leak,
    _check_failure_spam,
    _quality_gate_section,
)
from forensia.knowledge import (
    catalog_artifact_names,
    catalog_exe_globs,
    catalog_names,
    catalog_path_terms,
    exe_glob_sql,
    ioc_catalog as _ioc_catalog,
    matches_exe_globs,
)
from forensia.report.keypoints import (
    EVIDENCE_ID_PATTERN,
    REPORT_KEYPOINTS,
    REPORT_KEYPOINT_ALIASES,
    _default_keypoints_for_section,
    _extract_evidence_ids_from_value,
    _extract_needed_evidence,
    _report_keypoint_rows,
    _resolve_evidence_results,
    _sql_like_any,
)
from forensia.report.structured_answers import (  # noqa: F401
    _add_local_time_columns,
    _answer_columns,
    _benchmark_block_id,
    _benchmark_answers_path,
    _build_antiforensic_activity,
    _build_application_execution_history,
    _build_browser_usage,
    _build_cloud_service_traces,
    _build_daily_session_activity,
    _build_daily_session_timeline,
    _build_daily_session_timeline_rows,
    _build_desktop_rename_candidates,
    _build_email_application_usage,
    _build_email_data_files,
    _build_generic_question_spec_answer,
    _build_host_identity,
    _build_last_human_logon,
    _build_last_shutdown_event,
    _build_resignation_file_timestamps,
    _coerce_answer_items,
    _coerce_string_list,
    _collect_answer_evidence_ids,
    _dedupe_dict_rows,
    _feed_structured_to_timeline,
    _human_user_predicate,
    _is_human_report_hidden_column,
    _load_benchmark_answers,
    _load_interpretation_templates,
    _load_structured_answers,
    _local_time_from_utc,
    _lower_blob,
    _meaningful_missing_reason_items,
    _normalize_benchmark_answer,
    _normalize_structured_answer,
    _persist_benchmark_answer,
    _persist_structured_answer,
    _prefetch_executable_from_filename,
    _render_answer_block,
    _render_answer_cell,
    _render_benchmark_answer_markdown,
    _render_interpretation_template,
    _render_structured_answer_markdown,
    _safe_answer_filename,
    _structured_answer,
    _structured_answer_interpretation,
    _structured_answers_path,
    _structured_block_id,
    _structured_rows,
    _text,
    _TIMESTAMP_COLUMN_SUFFIXES,
    _HUMAN_REPORT_HIDDEN_COLUMNS,
    _MISSING_REASON_NOOP_VALUES,
    _STRUCTURED_ANSWER_BUILDERS,
    STRUCTURED_MARKDOWN_MAX_CELL_CHARS,
    STRUCTURED_MARKDOWN_MAX_LIST_ITEMS,
    STRUCTURED_MARKDOWN_MAX_ROWS,
    StructuredAnswerBuilder,
    UNIVERSAL_QUESTION_SPECS,
    build_structured_answer,
    ensure_universal_question_probes,
)

from forensia.report import probes as _probes  # noqa: F401 — re-export below, lazy import used internally

from forensia.report.probes import (  # noqa: F401 — re-export for backward compat
    # Used directly by core writer.py functions
    _collect_flat_evidence_rows,
    _correlation_finding_ids,
    _dump_section_evidence_json,
    _dump_section_questions_json,
    _dump_section_trace_json,
    _duplicate_finding_titles,
    _event_claim_gaps,
    _final_report_section_body,
    _markdown_table,
    _sanitize_raw_evidence_body,
    _section_confidence,
    _sort_markdown_table_by_first_column,
    _table_block_columns,
    _TABLE_BLOCK_BUILDERS,
    _TABLE_COLUMNS,
    _title_from_template_body,
    _update_section_quality_only,
    _upsert_claims,
    _upsert_report_section,
    _validate_body_evidence_ids,
    _verify_block_output,
    # Re-exported for backward compat
    _build_host_note,
    _build_report_brief,
    _dump_section_questions_json,
    _extract_claim_texts,
    _host_summary_rows,
    _hypothesis_rows,
    _query_top_findings,
    _query_evtx_time_range,
    _query_prior_sections,
    _render_timestamp_with_timezone,
    _strip_narrative_status_lines,
    _summarize_flat_evidence_rows,
    _tz_offset_str,
    collect_gaps,
    fetch_report_sections,
    load_report_sections_map,
    mark_report_sections_ai_exhausted,
    set_report_section_status,
    write_report_brief,
)

# Re-export aliases so existing internal callers keep working
_catalog_exe_globs = catalog_exe_globs
_catalog_names = catalog_names
_catalog_path_terms = catalog_path_terms
_catalog_artifact_names = catalog_artifact_names
_exe_glob_sql = exe_glob_sql
_matches_exe_globs = matches_exe_globs

__all__ = [
    # Public API (defined here)
    "build_report_markdown_from_db",
    "fill_section",
    "finalize_section",
    "write_report",
    "write_report_from_db",
    "render_written_report",
    "prepare_section_request",
    # Re-exported from probes
    "build_structured_answer",
    "ensure_universal_question_probes",
    "fetch_report_sections",
    "load_report_sections_map",
    "set_report_section_status",
    "mark_report_sections_ai_exhausted",
    "write_report_brief",
    "collect_gaps",
    # Internal re-exports
    "_assemble_section_body",
    "_body_starts_with_heading",
    "_build_report_brief",
    "_collect_flat_evidence_rows",
    "_default_keypoints_for_section",
    "_dump_section_evidence_json",
    "_dump_section_questions_json",
    "_dump_section_trace_json",
    "_extract_claim_texts",
    "_extract_needed_evidence",
    "_feed_structured_to_timeline",
    "_final_report_section_body",
    "_hypothesis_rows",
    "_load_structured_answers",
    "_normalize_structured_answer",
    "_persist_structured_answer",
    "_preprocess_section_body",
    "_quality_gate_section",
    "_render_structured_answer_markdown",
    "_resolve_evidence_results",
    "_section_confidence",
    "_sort_markdown_table_by_first_column",
    "_strip_narrative_status_lines",
    "_summarize_flat_evidence_rows",
    "_verify_block_output",
    "EVIDENCE_ID_PATTERN",
    "_GateCtx",
    "REPORT_KEYPOINTS",
    "REPORT_KEYPOINT_ALIASES",
    "_TABLE_BLOCK_BUILDERS",
    "_TABLE_COLUMNS",
]

# Canonical TemplateMeta lives in report.probes (single class shared by both
# template parsers; duplicating the dataclass made identity/typing fragile).
from forensia.report.probes import TemplateMeta  # noqa: E402


GAP_PATTERN = re.compile(
    r"\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]|【調査不足:\s*([^】]+)】",
    re.IGNORECASE,
)
BLOCK_HINT_PATTERN = re.compile(
    r"<!--\s*(?P<name>evidence_keypoints|mode|benchmark_id|answer_id|answer_spec|builder)\s*:\s*(?P<value>.*?)\s*-->",
    re.IGNORECASE,
)
QUESTION_HINT_PATTERN = re.compile(r"<!--\s*question(?:\s*:\s*(?P<value>.*?))?\s*-->", re.IGNORECASE)
RAW_EVIDENCE_HEADING_PATTERN = re.compile(r"^#{2,6}\s*Raw Evidence\s*$", re.IGNORECASE)


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
        "builder": "",
    }
    def _iter_hint_pairs(name: str, value: str):
        """Yield (name, value) pairs, expanding the combined one-comment syntax
        ``<!-- mode: table; builder: X -->`` into separate directives.
        Fragments without a colon (free-text guidance) are dropped."""
        parts = [part.strip() for part in value.split(";")]
        yield name, parts[0]
        for part in parts[1:]:
            if ":" in part:
                sub_name, sub_value = part.split(":", 1)
                yield sub_name.strip().lower(), sub_value.strip()

    seen_keypoints: set[str] = set()
    pairs: list[tuple[str, str]] = []
    for match in BLOCK_HINT_PATTERN.finditer(block_body):
        raw_name = str(match.group("name") or "").strip().lower()
        raw_value = str(match.group("value") or "").strip()
        if not raw_name or not raw_value:
            continue
        pairs.extend(_iter_hint_pairs(raw_name, raw_value))
    for name, value in pairs:
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
        elif name == "builder":
            hints["builder"] = value.strip()
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
            "builder": "",
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
            "builder": str(block.get("builder") or ""),
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

# ====================================================================
# ORCHESTRATION — fill_section, finalize_section, build_report_markdown_from_db
# Lines: ~3848-4110, 5923-6001
# ====================================================================


def _preprocess_section_body(section_key: str, body: str, *, template_meta: TemplateMeta | None = None) -> tuple[str, bool]:
    body = re.sub(r"^\*\*Status:\*\*.*$", "", body, flags=re.MULTILINE).strip()
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


_EVIDENCE_ID_RE = re.compile(r"\b(?:evtx|mft|prefetch)-[a-z0-9-]+\b")


def _validate_section_evidence_ids(db: CaseDB, body: str) -> tuple[str, list[str]]:
    """Validate evidence IDs in body against DB. Return (cleaned_body, gaps)."""
    ids_found = set(_EVIDENCE_ID_RE.findall(body))
    if not ids_found:
        return body, []

    # Check existence in evtx_events, mft_entries, prefetch_executions
    invalid: list[str] = []
    for eid in ids_found:
        prefix = eid.split("-")[0] if "-" in eid else ""
        table_map = {
            "evtx": "evtx_events",
            "mft": "mft_entries",
            "prefetch": "prefetch_executions",
        }
        table = table_map.get(prefix)
        if not table:
            invalid.append(eid)
            continue
        try:
            row = db.execute(
                f"SELECT 1 FROM {table} WHERE evidence_id = ? LIMIT 1",
                (eid,),
            ).fetchone()
            if not row:
                invalid.append(eid)
        except Exception:
            invalid.append(eid)

    if not invalid:
        return body, []

    # Strip invalid IDs from body
    cleaned = body
    for inv in invalid:
        cleaned = re.sub(rf"\b{re.escape(inv)}\b", "", cleaned)
    # Trim comma debris at citation-group edges without touching surviving
    # valid IDs in the same group, then drop now-empty shells.
    cleaned = re.sub(r"([（(])\s*(?:,\s*)+", r"\1", cleaned)  # leading commas
    cleaned = re.sub(r"(?:\s*,)+\s*([)）])", r"\1", cleaned)  # trailing commas
    cleaned = re.sub(r"（\s*）|\(\s*\)", "", cleaned)          # empty shells
    # Clean up double spaces, double commas, etc.
    cleaned = re.sub(r"  +", " ", cleaned)
    cleaned = re.sub(r",\s*,", ",", cleaned)
    cleaned = cleaned.strip().strip(",").strip()

    gaps = [f"cited evidence ids not found: {', '.join(invalid)}"]
    return cleaned, gaps


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
    # R3-03: Validate evidence IDs against DB
    if db is not None and body:
        body, id_gaps = _validate_section_evidence_ids(db, body)
    else:
        id_gaps = []
    candidate_gaps, candidate_confidence = _collect_initial_gaps(db, section_key, body, extra_gaps)
    if id_gaps:
        candidate_gaps.extend(id_gaps)
        candidate_confidence = min(candidate_confidence, 0.5)
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
    # Lazy import: section rendering is ai-side orchestration; report stays passive.
    from forensia.ai.section_refresher import _render_section_from_request

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


def write_report(case: Case, filled_sections: dict[str, str]) -> Path:
    """Write the concatenated filled sections to reports/report.md in section-key order."""
    ordered = [filled_sections[key].strip() for key in sorted(filled_sections) if filled_sections[key].strip()]
    report_md = "\n\n".join(ordered).strip() + "\n"
    report_path = case.reports_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_path


def write_report_from_db(case: Case, db: CaseDB) -> Path:
    """Read report sections from the database and write the full report to reports/report.md."""
    report_md = build_report_markdown_from_db(db, case=case)
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
