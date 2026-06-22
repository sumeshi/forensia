from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

from forensia.core.case import Case, detect_epochs
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, normalize_value
from forensia.knowledge import (
    catalog_artifact_names,
    catalog_exe_globs,
    catalog_names,
    catalog_path_terms,
    exe_glob_sql,
    matches_exe_globs,
)
from forensia.report.keypoints import (
    EVIDENCE_ID_PATTERN,
    _extract_evidence_ids_from_value,
    _extract_needed_evidence,
    _sql_like_any,
)
from forensia.report.markdown import (  # noqa: F401
    _build_host_note,
    _markdown_table,
    _render_timestamp_with_timezone,
    _sort_markdown_table_by_first_column,
    _strip_hidden_report_columns_from_markdown_tables,
    _tz_offset_str,
    render_rows_template,
)
from forensia.report.quality_gates import (
    HTML_FILL_PATTERN,
    _first_heading_text,
)
from forensia.report.ranking import (
    load_top_findings_priority_keywords,
    priority_rank,
)
from forensia.report.structured_answers import (  # noqa: F401
    _HUMAN_REPORT_HIDDEN_COLUMNS,
    _MISSING_REASON_NOOP_VALUES,
    _STRUCTURED_ANSWER_BUILDERS,
    _TIMESTAMP_COLUMN_SUFFIXES,
    STRUCTURED_MARKDOWN_MAX_CELL_CHARS,
    STRUCTURED_MARKDOWN_MAX_LIST_ITEMS,
    STRUCTURED_MARKDOWN_MAX_ROWS,
    UNIVERSAL_QUESTION_SPECS,
    StructuredAnswerBuilder,
    _add_local_time_columns,
    _answer_columns,
    _benchmark_answers_path,
    _benchmark_block_id,
    _build_antiforensic_activity,
    _build_application_execution_history,
    _build_browser_usage,
    _build_cloud_service_traces,
    _build_daily_session_activity,
    _build_daily_session_timeline,
    _build_daily_session_timeline_rows,
    _build_desktop_rename_candidates,
    _build_generic_question_spec_answer,
    _build_host_identity,
    _build_last_human_logon,
    _build_last_shutdown_event,
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
    build_structured_answer,
    ensure_universal_question_probes,
)

# Re-export aliases so existing internal callers keep working
_catalog_exe_globs = catalog_exe_globs
_catalog_names = catalog_names
_catalog_path_terms = catalog_path_terms
_catalog_artifact_names = catalog_artifact_names
_exe_glob_sql = exe_glob_sql
_matches_exe_globs = matches_exe_globs


@dataclass(frozen=True)
class TemplateMeta:
    behaviors: tuple[str, ...] = ()


GAP_PATTERN = re.compile(
    r"\[INSUFFICIENT EVIDENCE:\s*([^\]]+)\]",
    re.IGNORECASE,
)
BLOCK_HINT_PATTERN = re.compile(
    r"<!--\s*(?P<name>evidence_keypoints|mode|benchmark_id|answer_id|answer_spec|builder)\s*:\s*(?P<value>.*?)\s*-->",
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
    re.compile(r"^\|.*\|$"),
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
        if stripped.startswith("### ") and stripped not in {
            "### Missing Reason",
            "### Queries Run",
            "### Structured Data",
        }:
            skip_metadata_block = False
        if (
            stripped
            and not skip_metadata_block
            and not any(p.match(stripped) for p in _SCAFFOLD_PATTERNS)
        ):
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
        normalized = " ".join(
            line.strip("- ").strip() for line in text.splitlines() if line.strip()
        )
        key = _claim_text_key(normalized)
        if (
            normalized
            and normalized not in ("[]", "{}", "<!--", "-->")
            and key not in seen
        ):
            seen.add(key)
            claims.append(normalized)
    return claims


def _claim_text_key(text: str) -> str:
    return " ".join(text.lower().split())


def _collect_claim_provenance(
    evidence_results: list[dict[str, Any]],
) -> dict[str, list[str]]:
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
        for row in (
            (result.get("sample_rows") or [])
            + (result.get("head_rows") or [])
            + (result.get("tail_rows") or [])
        ):
            row_evidence_ids.extend(_extract_evidence_ids_from_value(row))
        for evidence_id in [*(result.get("evidence_ids") or []), *row_evidence_ids]:
            value = str(evidence_id)
            if (
                value
                and value not in seen_evidence_ids
                and len(evidence_ids) < max_evidence_ids
            ):
                seen_evidence_ids.add(value)
                evidence_ids.append(value)
        for finding_id in result.get("finding_ids") or []:
            value = str(finding_id)
            if (
                value
                and value not in seen_finding_ids
                and len(finding_ids) < max_other_ids
            ):
                seen_finding_ids.add(value)
                finding_ids.append(value)
        for hypothesis_id in result.get("hypothesis_ids") or []:
            value = str(hypothesis_id)
            if (
                value
                and value not in seen_hypothesis_ids
                and len(hypothesis_ids) < max_other_ids
            ):
                seen_hypothesis_ids.add(value)
                hypothesis_ids.append(value)
    return {
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "hypothesis_ids": hypothesis_ids,
    }


# ====================================================================
# RENDER HELPERS — markdown table rendering, timestamp formatting
# Lines: ~2206-2910
# ====================================================================


def _query_top_findings(
    db: CaseDB,
    limit: int = 8,
    *,
    priority_keywords: list[list[str]] | None = None,
) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT
          finding_id, title, severity, confidence, summary, evidence,
          CASE
            -- Report-worthiness is decided generically: a finding mapped to an
            -- ATT&CK technique leads over an unmapped one at the same severity.
            -- There is intentionally no keyword bias toward any particular
            -- case's event IDs, applications, or tooling, so the leading thesis
            -- generalizes across cases. The single finding-id-specific entry
            -- below only demotes a known-noisy correlation rule.
            WHEN finding_id LIKE 'windows-corr-logon-then-service%' THEN 9
            WHEN attack IS NOT NULL
              AND TRIM(CAST(attack AS VARCHAR)) NOT IN ('', '[]', 'null', '{}') THEN 0
            ELSE 1
          END AS signal_rank
        FROM findings
        WHERE COALESCE(status, 'accepted') != 'suppressed'
          AND severity IN ('critical','high','medium')
          AND confidence >= 0.5
          AND COALESCE(title, '') != ''
          AND title NOT LIKE '%:  @%'
          AND NOT (finding_id LIKE 'windows-corr-logon-then-service%' AND confidence < 0.7)
        ORDER BY
          signal_rank,
          CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
          confidence DESC,
          created_at DESC
        LIMIT ?
        """,
        (max(limit * 6, limit),),
    )
    # Presentation policy supplied by the active template set (report/ranking.py):
    # when it declares a priority-keyword ordering, regroup the severity-ranked
    # rows into those narrative tiers. The stable sort keeps the generic
    # severity / confidence order within each tier, and with no policy the rows
    # keep the case-agnostic default order — so the benchmark's narrative order
    # lives in its overview template's frontmatter, not in this core query.
    if priority_keywords:
        rows = sorted(
            rows,
            key=lambda r: priority_rank(
                f"{r.get('finding_id', '')} {r.get('title', '')} "
                f"{r.get('summary', '')}",
                priority_keywords,
            ),
        )
    # RPT-04: a self-referential machine account ("<COMPUTER>$") using explicit
    # credentials (4648) locally on its own host is normal Windows behavior
    # (e.g. winlogon.exe credential prompts), not a lateral-movement signal.
    # Demote such rows below genuinely cross-host candidates instead of
    # letting them dominate the top slots.
    local_machine_rows: list[dict[str, Any]] = []
    other_rows: list[dict[str, Any]] = []
    for row in rows:
        if _is_local_machine_account_4648(row):
            local_machine_rows.append(row)
        else:
            other_rows.append(row)
    rows = [*other_rows, *local_machine_rows]

    normalized: list[dict[str, Any]] = []
    family_counts: dict[str, int] = {}
    seen_titles: set[str] = set()
    for row in rows:
        item = normalize_value(row)
        if isinstance(item, dict):
            title_key = _claim_text_key(str(item.get("title") or ""))
            if title_key and title_key in seen_titles:
                continue
            finding_id = str(item.get("finding_id") or "")
            family = re.sub(r"-\d{3,}$", "", finding_id) or finding_id
            if family_counts.get(family, 0) >= 3:
                continue
            family_counts[family] = family_counts.get(family, 0) + 1
            if title_key:
                seen_titles.add(title_key)
            evidence_ids = _extract_evidence_ids_from_value(item.get("evidence"))
            if evidence_ids:
                item["evidence_ids"] = evidence_ids[:5]
            item.pop("signal_rank", None)
        normalized.append(item)
        if len(normalized) >= limit:
            break
    return normalized


def _is_local_machine_account_4648(row: dict[str, Any]) -> bool:
    """True when a 4648 finding's subject is the host's own machine account.

    A computer authenticating to itself as "<COMPUTERNAME>$" (e.g. a
    winlogon.exe credential prompt) is routine local activity, not a
    lateral-movement indicator.
    """
    if (
        "4648" not in str(row.get("finding_id") or "").lower()
        and "4648" not in str(row.get("title") or "").lower()
    ):
        return False
    evidence = row.get("evidence")
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = []
    if not isinstance(evidence, list):
        return False
    for entry in evidence:
        if not isinstance(entry, dict):
            continue
        subject = str(entry.get("subject_user") or "").strip()
        computer = str(entry.get("computer") or "").strip()
        if (
            subject.endswith("$")
            and computer
            and subject[:-1].casefold() == computer.casefold()
        ):
            return True
    return False


def _query_hypotheses_by_status(
    db: CaseDB, status: str, limit: int = 8
) -> list[dict[str, Any]]:
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
                "first_event": _render_timestamp_with_timezone(first, case)
                if first
                else "unknown",
                "last_event": _render_timestamp_with_timezone(last, case)
                if last
                else "unknown",
            }
    return time_range


def _summarize_section_coverage(db: CaseDB) -> dict[str, Any]:
    coverage_map = _collect_section_coverage(db)
    return {
        "sections": coverage_map,
        "section_count": len(coverage_map),
        "total_sources": sum(len(items) for items in coverage_map.values()),
    }


def _hypothesis_source_rule_ids(item: dict[str, Any]) -> list[str]:
    raw = item.get("source_rule_ids")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = []
    if not isinstance(raw, list):
        return []
    return [str(rule_id).strip() for rule_id in raw if str(rule_id or "").strip()]


def _rule_ids_have_benign_context(db: CaseDB, rule_ids: list[str]) -> bool:
    """True when every finding produced by these rule_ids is benign-context tagged.

    A hypothesis whose only rule-seeded evidence is downgraded to a known-benign
    pattern should not be treated as strong narrative support (RPT-02).
    """
    if not rule_ids:
        return False
    placeholders = ", ".join("?" for _ in rule_ids)
    rows = fetch_records(
        db,
        f"SELECT tags FROM findings WHERE rule_id IN ({placeholders})",
        tuple(rule_ids),
    )
    if not rows:
        return False
    return all(_has_benign_context_tag(row) for row in rows)


def _annotate_confirmed_hypotheses(
    db: CaseDB, items: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Annotate confirmed hypotheses with provenance flags for narrative weighting.

    - `rule_seeded`: the hypothesis was seeded from a detection rule
      (`source_rule_ids` non-empty) rather than derived from a generic gap.
    - `benign_context`: every rule-seeded finding behind this hypothesis was
      itself downgraded to a known-benign pattern.
    - `narrative_strength`: "strong" only when rule-seeded AND not
      benign-context; otherwise "weak". Narrative sections should not treat
      "weak" confirmed hypotheses as the backbone of the main storyline.
    """
    annotated: list[dict[str, Any]] = []
    for item in items:
        rule_ids = _hypothesis_source_rule_ids(item)
        rule_seeded = bool(rule_ids)
        benign_context = _rule_ids_have_benign_context(db, rule_ids)
        item = dict(item)
        item["rule_seeded"] = rule_seeded
        item["benign_context"] = benign_context
        item["narrative_strength"] = (
            "strong" if rule_seeded and not benign_context else "weak"
        )
        annotated.append(item)
    return annotated


def _build_report_brief(
    db: CaseDB,
    case: Case | None = None,
    *,
    template_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Assemble a structured brief of top findings, hypotheses, section excerpts, and coverage data for LLM context."""
    tz_name = getattr(case, "source_timezone", "UTC") if case else "UTC"
    tz_offset = _tz_offset_str(tz_name) if tz_name != "UTC" else ""
    # The leading-thesis ordering policy travels with the active template set,
    # not with this core builder (report/ranking.py). Fall back to the case's
    # bundled templates when an explicit dir is not threaded in.
    resolved_template_dir = template_dir or (
        getattr(case, "report_template_dir", None) if case else None
    )
    priority_keywords = load_top_findings_priority_keywords(resolved_template_dir)
    return {
        "top_findings": [
            normalize_value(item)
            for item in _query_top_findings(db, priority_keywords=priority_keywords)
        ],
        "active_hypotheses": [
            normalize_value(item) for item in _query_hypotheses_by_status(db, "active")
        ],
        "confirmed_hypotheses": [
            normalize_value(item)
            for item in _annotate_confirmed_hypotheses(
                db, _query_hypotheses_by_status(db, "confirmed")
            )
        ],
        "refuted_hypotheses": [
            normalize_value(item) for item in _query_hypotheses_by_status(db, "refuted")
        ],
        "untestable_hypotheses": [
            normalize_value(item)
            for item in _query_hypotheses_by_status(db, "untestable")
        ],
        "prior_sections": _query_prior_sections(db),
        "existing_claims": _dedupe_claims(_query_existing_claims(db)),
        "evidence_coverage": _summarize_section_coverage(db),
        "source_timezone": tz_name,
        "timezone_offset": tz_offset,
        "time_range": _query_evtx_time_range(db, case),
    }


def write_report_brief(
    case: Case, db: CaseDB, *, template_dir: Path | str | None = None
) -> dict[str, Any]:
    """Write the report brief to reports/report_brief.json and return the dict."""
    brief = _build_report_brief(db, case, template_dir=template_dir)
    overview_path = case.memory_dir / "overview.md"
    if overview_path.exists():
        overview_text = overview_path.read_text(encoding="utf-8")
        match = re.search(r"## Investigation Objective\s+-\s+(.+)", overview_text)
        if match:
            brief["investigation_objective"] = match.group(1).strip()
    path = case.reports_dir / "report_brief.json"
    path.write_text(
        json.dumps(brief, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
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
        if any(
            hypothesis_id not in found_hypothesis_ids
            for hypothesis_id in hypothesis_ids
        ):
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
        claim_id = hashlib.sha1(
            f"{section_key}-{index}-{claim_text}".encode()
        ).hexdigest()[:16]
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
        grouped.setdefault(
            _claim_text_key(str(row.get("claim_text") or "")), []
        ).append(row)
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
    return [
        str(row.get("support_status") or "")
        for row in statuses
        if str(row.get("support_status") or "")
    ]


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
        next_status = (
            existing_status
            if existing_status in {"ai_exhausted", "human_reviewed"}
            else "draft"
        )
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


def _count_table(db: CaseDB) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT
          (SELECT COUNT(*) FROM evtx_events) AS evtx_events,
          (SELECT COUNT(*) FROM mft_entries) AS mft_entries,
          (SELECT COUNT(*) FROM prefetch_executions) AS prefetch_executions,
          (SELECT COUNT(DISTINCT UPPER(TRIM(computer))) FROM evtx_events WHERE COALESCE(computer, '') != '') AS hosts,
          (SELECT COUNT(DISTINCT channel) FROM evtx_events WHERE COALESCE(channel, '') != '') AS channels
        """,
    )
    if not rows:
        return []
    row = rows[0]
    time_range = _query_evtx_time_range(db)
    return [
        {
            "metric": "EVTX events",
            "value": row.get("evtx_events"),
            "scope": f"{time_range.get('first_event', 'unknown')} to {time_range.get('last_event', 'unknown')}",
        },
        {
            "metric": "MFT entries",
            "value": row.get("mft_entries"),
            "scope": "Filesystem metadata",
        },
        {
            "metric": "Prefetch executions",
            "value": row.get("prefetch_executions"),
            "scope": "Application execution artifacts",
        },
        {
            "metric": "Hosts",
            "value": row.get("hosts"),
            "scope": "Distinct EVTX computer names",
        },
        {
            "metric": "EVTX channels",
            "value": row.get("channels"),
            "scope": "Distinct channels",
        },
    ]


def _host_summary_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        WITH raw AS (
          SELECT computer, COUNT(*) AS cnt, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
          FROM evtx_events
          WHERE COALESCE(computer, '') != ''
          GROUP BY computer
        )
        SELECT
          ARG_MAX(computer, cnt) AS host,
          SUM(cnt) AS events,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen
        FROM raw
        GROUP BY UPPER(TRIM(computer))
        ORDER BY events DESC
        LIMIT ?
        """,
        (limit,),
    )
    # Annotate each row with pre-deployment note when applicable
    try:
        epochs = detect_epochs(db)
        for row in rows:
            host_key = str(row.get("host") or "").strip().upper()
            host_epochs = epochs.get(host_key) or []
            if host_epochs:
                row["note"] = _build_host_note(host_epochs)
        # Only keep note when at least one host is pre-deployment
        if not any(
            r.get("note") == "pre-deployment"
            or "pre-deployment" in (r.get("note") or "")
            for r in rows
        ):
            for row in rows:
                row.pop("note", None)
    except Exception:
        pass
    return rows


def _account_summary_rows(db: CaseDB, limit: int = 10) -> list[dict[str, Any]]:
    """Per-account/host authentication summary.

    RPT-09: 4625 (failed logon) rows commonly have a NULL actor (the target
    account could not be resolved); these are kept as account='-' instead of
    being dropped, so failed-logon totals are visible. Hosts are grouped
    case-insensitively (UPPER(TRIM(computer))) since the same host can appear
    with mixed case across event sources.
    """
    return fetch_records(
        db,
        """
        SELECT
          COALESCE(NULLIF(target_user, ''), NULLIF(user_name, ''), NULLIF(subject_user, ''), '-') AS account,
          ANY_VALUE(computer) AS computer,
          COUNT(*) FILTER (WHERE event_id = 4624) AS logons,
          COUNT(*) FILTER (WHERE event_id = 4625) AS failed_logons,
          COUNT(*) FILTER (WHERE event_id = 4648) AS explicit_credential_events,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen
        FROM evtx_events
        WHERE event_id IN (4624, 4625, 4648)
        GROUP BY account, UPPER(TRIM(COALESCE(computer, '')))
        ORDER BY explicit_credential_events DESC, failed_logons DESC, logons DESC
        LIMIT ?
        """,
        (limit,),
    )


def _has_benign_context_tag(row: dict[str, Any]) -> bool:
    tags = row.get("tags")
    if not tags:
        return False
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except json.JSONDecodeError, TypeError:
            return False
    if isinstance(tags, list):
        return any("benign-context:" in str(t).lower() for t in tags)
    return False


_FINDING_THEME_FILTER_SQL = """
    SELECT finding_id, rule_id, title, summary, tags
    FROM findings
    WHERE COALESCE(status, 'accepted') != 'suppressed'
      AND severity IN ('critical','high','medium')
      AND confidence >= 0.5
      AND COALESCE(title, '') != ''
      AND title NOT LIKE '%:  @%'
"""


def _finding_theme_counts(db: CaseDB) -> dict[str, int]:
    """Single-source theme counts over the same finding population as `_query_top_findings`.

    Excludes benign-context tagged findings, matching `_signal_finding_rows`'s
    existing exclusion (R3-04). Both the Key Findings table and the Action Plan
    table read from this function so theme `(N)` counts stay consistent.
    """
    counts: dict[str, int] = {}
    for row in fetch_records(db, _FINDING_THEME_FILTER_SQL):
        if _has_benign_context_tag(row):
            continue
        theme = _finding_theme(row)
        counts[theme] = counts.get(theme, 0) + 1
    return counts


def _signal_finding_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    theme_counts = _finding_theme_counts(db)
    grouped: dict[str, dict[str, Any]] = {}
    for item in _query_top_findings(db, max(limit * 4, limit)):
        # R3-04: Exclude benign-context tagged findings from top findings
        if _has_benign_context_tag(item):
            continue
        theme = _finding_theme(item)
        target = grouped.setdefault(
            theme,
            {
                "theme": theme,
                "count": 0,
                "severity": "low",
                "confidence": 0.0,
                "evidence_ids": [],
                "finding_ids": [],
            },
        )
        target["count"] = int(target["count"]) + 1
        target["severity"] = _max_severity(
            str(target.get("severity") or "low"), str(item.get("severity") or "low")
        )
        try:
            target["confidence"] = max(
                float(target.get("confidence") or 0), float(item.get("confidence") or 0)
            )
        except TypeError, ValueError:
            pass
        for evidence_id in item.get("evidence_ids") or []:
            text = str(evidence_id or "").strip()
            if text and text not in target["evidence_ids"]:
                target["evidence_ids"].append(text)
        finding_id = str(item.get("finding_id") or "").strip()
        if finding_id and finding_id not in target["finding_ids"]:
            target["finding_ids"].append(finding_id)

    candidates = [
        item for item in grouped.values() if str(item.get("theme") or "") != "other"
    ] or list(grouped.values())
    rows: list[dict[str, Any]] = []
    for item in sorted(
        candidates,
        key=lambda row: (
            _finding_theme_rank(str(row.get("theme") or "")),
            _severity_rank(str(row.get("severity") or "")),
            -float(row.get("confidence") or 0),
        ),
    )[:limit]:
        confidence = item.get("confidence")
        try:
            confidence = f"{float(confidence):.2f}"
        except TypeError, ValueError:
            confidence = str(confidence or "-")
        theme = str(item.get("theme") or "")
        rows.append(
            {
                "finding": _finding_theme_title(
                    theme, theme_counts.get(theme, int(item.get("count") or 0))
                ),
                "severity": item.get("severity"),
                "confidence": confidence,
                "why_it_matters": _finding_theme_summary(str(item.get("theme") or "")),
                "reference": "; ".join((item.get("evidence_ids") or [])[:3])
                or "; ".join((item.get("finding_ids") or [])[:2]),
            }
        )
    return rows


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(severity.lower(), 4)


def _max_severity(left: str, right: str) -> str:
    return left if _severity_rank(left) <= _severity_rank(right) else right


def _finding_theme(item: dict[str, Any]) -> str:
    blob = " ".join(
        str(item.get(key) or "").lower()
        for key in ("finding_id", "rule_id", "title", "summary")
    )
    if "4648" in blob or "explicit credential" in blob:
        return "explicit_credentials"
    if (
        "4722" in blob
        or "4724" in blob
        or "account lifecycle" in blob
        or "account" in blob
        and "user" in blob
    ):
        return "account_lifecycle"
    if "4616" in blob or "system time" in blob:
        return "time_change"
    if (
        "event log service stopped" in blob
        or " log clear" in blob
        or "1100" in blob
        or "1102" in blob
    ):
        return "log_integrity"
    if (
        "anti-forensic" in blob
        or "antiforensic" in blob
        or any(name.lower() in blob for name in _catalog_names("antiforensic_tools"))
    ):
        return "antiforensic_tools"
    if (
        "ost" in blob
        or "outlook" in blob
        or "browser" in blob
        or "cloud" in blob
        or "drive" in blob
    ):
        return "data_access"
    return "other"


def _finding_theme_rank(theme: str) -> int:
    return {
        "explicit_credentials": 0,
        "account_lifecycle": 1,
        "time_change": 2,
        "log_integrity": 3,
        "antiforensic_tools": 4,
        "data_access": 5,
        "other": 9,
    }.get(theme, 9)


def _finding_theme_title(theme: str, count: int) -> str:
    suffix = f" ({count})" if count > 1 else ""
    return {
        "explicit_credentials": f"Explicit credential usage observed{suffix}",
        "account_lifecycle": f"User account change events{suffix}",
        "time_change": f"System time change observed{suffix}",
        "log_integrity": f"Log stop / clear candidate events{suffix}",
        "antiforensic_tools": f"Wiping / cleaning tool traces{suffix}",
        "data_access": f"Mail / browser / cloud-related traces{suffix}",
        "other": f"Other priority findings{suffix}",
    }.get(theme, f"Priority findings{suffix}")


def _finding_theme_summary(theme: str) -> str:
    return {
        "explicit_credentials": "Credentials were used explicitly (not standard logon); correlate target user, host, and time.",
        "account_lifecycle": "Account creation, activation, or password changes may enable privilege use or trace manipulation.",
        "time_change": "Time changes affect timeline interpretation; correlate with surrounding auth and file events.",
        "log_integrity": "Log stop/clear candidates alone do not confirm wiping; check proximity to cleaning tools and shutdown.",
        "antiforensic_tools": "Cleaning tool traces do not reveal what was deleted, but are central supporting evidence for a wiping hypothesis.",
        "data_access": "Mail/browser/cloud traces show information access and sync environment; confirm destinations and target files.",
        "other": "Detailed conclusions require correlating individual evidence with surrounding events.",
    }.get(
        theme,
        "Detailed conclusions require correlating individual evidence with surrounding events.",
    )


def _event_interpretation(event_id: Any) -> str:
    try:
        event = int(event_id)
    except TypeError, ValueError:
        return "Event"
    return {
        4624: "Successful logon",
        4625: "Failed logon",
        4648: "Explicit credentials",
        1100: "Event log service stopped",
        104: "Event log cleared",
        1074: "Shutdown/restart initiated",
        6006: "Event log service stopped",
    }.get(event, f"Event {event}")


def _timeline_rows(db: CaseDB, limit: int = 18) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    evtx_rows = fetch_records(
        db,
        """
        SELECT timestamp, computer, event_id,
               COALESCE(NULLIF(target_user, ''), NULLIF(user_name, ''), NULLIF(subject_user, ''), '-') AS actor,
               COALESCE(NULLIF(process_name, ''), NULLIF(service_name, ''), '-') AS object,
               evidence_id
        FROM evtx_events
        WHERE (
            (event_id IN (1074))
            OR (event_id = 1100 AND (channel IS NULL OR LOWER(channel) LIKE '%security%'))
            OR (event_id = 6006 AND (channel IS NULL OR LOWER(channel) LIKE '%system%'))
            OR (event_id IN (4648, 4625) AND LOWER(COALESCE(channel, '')) LIKE '%security%')
            OR (event_id = 104 AND LOWER(COALESCE(channel, '')) LIKE '%eventlog%')
        )
        ORDER BY timestamp
        LIMIT 80
        """,
    )
    for row in evtx_rows:
        rows.append(
            {
                "time": row.get("timestamp"),
                "host": row.get("computer"),
                "activity": _event_interpretation(row.get("event_id")),
                "subject": row.get("actor"),
                "artifact": row.get("object"),
                "evidence_id": row.get("evidence_id"),
            }
        )
    notable_exe_sql = _exe_glob_sql(
        "executable_name",
        _catalog_exe_globs(
            "antiforensic_tools",
            "cloud_sync_artifacts",
            "browser_artifacts",
            "email_artifacts",
        ),
    )
    prefetch_rows = fetch_records(
        db,
        f"""
        SELECT last_exec_time AS timestamp, executable_name, exec_count, evidence_id
        FROM prefetch_executions
        WHERE {notable_exe_sql}
        ORDER BY last_exec_time DESC
        LIMIT 12
        """,
    )
    for row in prefetch_rows:
        rows.append(
            {
                "time": row.get("timestamp"),
                "host": "-",
                "activity": "Application execution",
                "subject": row.get("executable_name"),
                "artifact": f"exec_count={row.get('exec_count')}",
                "evidence_id": row.get("evidence_id"),
            }
        )
    rows = sorted(rows, key=lambda item: str(item.get("time") or ""))
    if len(rows) > limit:
        early_count = max(4, limit // 3)
        late_count = max(limit - early_count, 0)
        rows = sorted(
            [*rows[:early_count], *rows[-late_count:]],
            key=lambda item: str(item.get("time") or ""),
        )
    return rows


def _execution_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    rows = fetch_records(
        db,
        """
        SELECT executable_name, exec_count, last_exec_time, evidence_id, source_file
        FROM prefetch_executions
        WHERE UPPER(executable_name) NOT IN (
          'DLLHOST.EXE', 'CONHOST.EXE', 'AUDIODG.EXE', 'SEARCHFILTERHOST.EXE',
          'SEARCHPROTOCOLHOST.EXE', 'WMIPRVSE.EXE'
        )
        ORDER BY last_exec_time DESC
        LIMIT ?
        """,
        (max(limit * 4, 48),),
    )
    # One row per executable name: prefetch keeps one record per .pf file,
    # which rendered duplicates (e.g. IEXPLORE.EXE twice).
    aggregated: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = str(row.get("executable_name") or "")
        existing = aggregated.get(name)
        if existing is None:
            aggregated[name] = dict(row)
            continue
        existing["exec_count"] = int(existing.get("exec_count") or 0) + int(
            row.get("exec_count") or 0
        )
        if str(row.get("last_exec_time") or "") > str(
            existing.get("last_exec_time") or ""
        ):
            existing["last_exec_time"] = row.get("last_exec_time")
    rows = list(aggregated.values())

    antiforensic_globs = _catalog_exe_globs("antiforensic_tools")
    user_app_globs = _catalog_exe_globs(
        "cloud_sync_artifacts", "browser_artifacts", "email_artifacts"
    )

    def _rank(row: dict[str, Any]) -> int:
        name = str(row.get("executable_name") or "")
        if _matches_exe_globs(name, antiforensic_globs):
            return 0
        if _matches_exe_globs(name, user_app_globs):
            return 1
        return 2

    # Rank ascending; within a rank keep most-recent first (stable sorts).
    rows.sort(key=lambda row: str(row.get("last_exec_time") or ""), reverse=True)
    rows.sort(key=_rank)
    return rows[:limit]


def _file_artifact_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    """Notable user-data file artifacts: mail data, cloud sync state, cleanup tools.

    Path families come from the IOC catalog and the user's Recent folder —
    no case-specific filename keywords (Rule 16).
    """
    path_terms = _catalog_path_terms(
        "email_artifacts", "cloud_sync_artifacts", "antiforensic_tools"
    )
    tool_globs = _catalog_exe_globs("antiforensic_tools")
    path_sql = (
        _sql_like_any("file_path", *[f"%{term}%" for term in path_terms])
        if path_terms
        else "FALSE"
    )
    tool_name_sql = _exe_glob_sql("file_name", tool_globs)
    recent_lnk_sql = "(LOWER(COALESCE(file_path, '')) LIKE '%/recent/%' AND LOWER(COALESCE(file_name, '')) LIKE '%.lnk')"
    return fetch_records(
        db,
        f"""
        SELECT file_name, file_path,
               COALESCE(si_modified, si_created, fn_modified, fn_created) AS timestamp,
               evidence_id
        FROM mft_entries
        WHERE ({path_sql} OR {tool_name_sql} OR {recent_lnk_sql})
          AND COALESCE(is_directory, FALSE) = FALSE
          AND LENGTH(COALESCE(file_name, '')) > 3
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (limit,),
    )


def _antiforensic_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    tool_globs = _catalog_exe_globs("antiforensic_tools")
    tool_exe_sql = _exe_glob_sql("executable_name", tool_globs)
    tool_file_sql = _exe_glob_sql("file_name", tool_globs)
    artifact_names = _catalog_artifact_names("antiforensic_tools")
    artifact_name_sql = (
        _sql_like_any("file_name", *artifact_names) if artifact_names else "FALSE"
    )
    tool_name_terms = [name.lower() for name in _catalog_names("antiforensic_tools")]
    prefetch_path_sql = (
        _sql_like_any("file_path", *[f"%prefetch%{term}%" for term in tool_name_terms])
        if tool_name_terms
        else "FALSE"
    )
    rows: list[dict[str, Any]] = []
    for row in fetch_records(
        db,
        f"""
        SELECT last_exec_time AS timestamp, executable_name AS artifact, exec_count, evidence_id
        FROM prefetch_executions
        WHERE {tool_exe_sql}
        ORDER BY last_exec_time DESC
        LIMIT 6
        """,
    ):
        rows.append({"type": "tool execution", **row})
    for row in fetch_records(
        db,
        """
        SELECT timestamp, CAST(event_id AS VARCHAR) AS artifact, computer, evidence_id
        FROM evtx_events
        WHERE (event_id = 1100 AND (channel IS NULL OR channel ILIKE '%security%' OR channel ILIKE '%system%'))
           OR (event_id = 104 AND LOWER(COALESCE(channel, '')) LIKE '%eventlog%')
        ORDER BY timestamp DESC
        LIMIT 6
        """,
    ):
        rows.append({"type": "log integrity event", **row})
    for row in fetch_records(
        db,
        f"""
        SELECT COALESCE(si_modified, si_created, fn_modified, fn_created) AS timestamp,
               file_name AS artifact, file_path, evidence_id
        FROM mft_entries
        WHERE ({tool_file_sql} OR {artifact_name_sql} OR {prefetch_path_sql})
          AND LOWER(COALESCE(file_name, '')) NOT IN ('lang', 'logs')
        ORDER BY timestamp DESC
        LIMIT 6
        """,
    ):
        rows.append({"type": "tool artifact", **row})
    return sorted(
        rows, key=lambda item: str(item.get("timestamp") or ""), reverse=True
    )[:limit]


def _network_summary_rows(db: CaseDB) -> list[dict[str, Any]]:
    row = db.execute(
        """
        SELECT
          COUNT(*) FILTER (WHERE COALESCE(src_ip, '') NOT IN ('', '-', '127.0.0.1', '::1')) AS external_src_ip_rows,
          COUNT(*) FILTER (WHERE COALESCE(dst_ip, '') NOT IN ('', '-', '127.0.0.1', '::1')) AS external_dst_ip_rows,
          COUNT(*) FILTER (WHERE COALESCE(src_ip, '') != '' OR COALESCE(dst_ip, '') != '') AS rows_with_ip
        FROM evtx_events
        """
    ).fetchone()
    if not row:
        return []
    return [
        {
            "area": "Network indicators in normalized EVTX",
            "observed_rows": int(row[2] or 0),
            "external_src_rows": int(row[0] or 0),
            "external_dst_rows": int(row[1] or 0),
            "interpretation": "No strong external network row was normalized"
            if not (row[0] or row[1])
            else "Review rows with non-loopback IP values",
        }
    ]


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except TypeError, ValueError:
        return 0


def _first_nonempty(rows: list[dict[str, Any]], key: str) -> str:
    for row in rows:
        text = str(row.get(key) or "").strip()
        if text and text != "-":
            return text
    return ""


def _sample_labels(rows: list[dict[str, Any]], key: str, limit: int = 3) -> list[str]:
    labels: list[str] = []
    for row in rows:
        text = str(row.get(key) or "").strip()
        if text and text != "-" and text not in labels:
            labels.append(text)
        if len(labels) >= limit:
            break
    return labels


def _sentence_list(items: list[str]) -> str:
    clean = [item for item in items if item]
    if not clean:
        return ""
    if len(clean) == 1:
        return clean[0]
    return ", ".join(clean[:-1]) + ", and " + clean[-1]


def _signal_executable_labels(rows: list[dict[str, Any]], limit: int = 4) -> list[str]:
    """Pick high-signal executable labels, catalog families first (wipers, cloud, browsers)."""
    glob_groups = (
        _catalog_exe_globs("antiforensic_tools"),
        _catalog_exe_globs("cloud_sync_artifacts"),
        _catalog_exe_globs("browser_artifacts", "email_artifacts"),
    )
    labels: list[str] = []
    for globs in glob_groups:
        for row in rows:
            for key in ("executable_name", "file_name", "artifact"):
                text = str(row.get(key) or "").strip()
                if text and text not in labels and _matches_exe_globs(text, globs):
                    labels.append(text)
                    break
            if len(labels) >= limit:
                return labels
    return labels or (
        _sample_labels(rows, "executable_name", limit)
        or _sample_labels(rows, "file_name", limit)
    )


def _timeline_phase_rows(db: CaseDB, limit: int = 8) -> list[dict[str, Any]]:
    evtx_rows = fetch_records(
        db,
        """
        SELECT
          CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
          COUNT(*) FILTER (WHERE event_id = 4648) AS explicit_credentials,
          COUNT(*) FILTER (WHERE event_id IN (1100, 104)
            AND NOT (event_id = 104 AND channel NOT ILIKE '%System%' AND channel NOT ILIKE '%Security%')
            AND NOT (event_id = 1100 AND channel NOT ILIKE '%Security%' AND channel NOT ILIKE '%System%')
          ) AS log_integrity_events,
          COUNT(*) FILTER (WHERE event_id IN (1074, 6006, 6008)
            AND NOT (event_id = 6006 AND channel NOT ILIKE '%System%')
            AND NOT (event_id = 6008 AND channel NOT ILIKE '%System%')
          ) AS shutdown_events,
          MIN(timestamp) AS first_seen,
          MAX(timestamp) AS last_seen
        FROM evtx_events
        WHERE timestamp IS NOT NULL
          AND event_id IN (4648, 1100, 104, 1074, 6006, 6008)
          AND NOT (event_id = 104 AND channel NOT ILIKE '%System%' AND channel NOT ILIKE '%Security%')
          AND NOT (event_id = 1100 AND channel NOT ILIKE '%Security%' AND channel NOT ILIKE '%System%')
          AND NOT (event_id = 6006 AND channel NOT ILIKE '%System%')
          AND NOT (event_id = 6008 AND channel NOT ILIKE '%System%')
        GROUP BY CAST(timestamp AS DATE)
        ORDER BY CAST(timestamp AS DATE)
        """,
    )
    notable_exe_sql = _exe_glob_sql(
        "executable_name",
        _catalog_exe_globs(
            "antiforensic_tools",
            "cloud_sync_artifacts",
            "browser_artifacts",
            "email_artifacts",
        ),
    )
    exec_rows = fetch_records(
        db,
        f"""
        SELECT
          CAST(CAST(last_exec_time AS DATE) AS VARCHAR) AS date,
          COUNT(*) AS executions,
          string_agg(DISTINCT executable_name, ', ' ORDER BY executable_name) AS executables
        FROM prefetch_executions
        WHERE last_exec_time IS NOT NULL
          AND {notable_exe_sql}
        GROUP BY CAST(last_exec_time AS DATE)
        ORDER BY CAST(last_exec_time AS DATE)
        """,
    )
    by_date: dict[str, dict[str, Any]] = {}
    for row in evtx_rows:
        date = str(row.get("date") or "")
        if date:
            by_date.setdefault(date, {"date": date}).update(row)
    for row in exec_rows:
        date = str(row.get("date") or "")
        if date:
            by_date.setdefault(date, {"date": date}).update(row)

    phases: list[dict[str, Any]] = []
    for date in sorted(by_date):
        row = by_date[date]
        points: list[str] = []
        if _as_int(row.get("explicit_credentials")):
            points.append(
                f"{_as_int(row.get('explicit_credentials'))} explicit-credential logon events (4648)"
            )
        if _as_int(row.get("log_integrity_events")):
            points.append(
                f"{_as_int(row.get('log_integrity_events'))} log integrity events"
            )
        if _as_int(row.get("shutdown_events")):
            points.append(
                f"{_as_int(row.get('shutdown_events'))} shutdown/log-stop events"
            )
        if _as_int(row.get("executions")):
            executables = str(row.get("executables") or "").strip()
            points.append(
                f"Notable application executions: {executables}"
                if executables
                else "Notable application executions detected"
            )
        if not points:
            continue
        phases.append(
            {
                "date": date,
                "phase": " / ".join(points),
                "interpretation": _phase_interpretation(row),
                "window": f"{row.get('first_seen') or '-'} to {row.get('last_seen') or '-'}",
            }
        )
    return phases[:limit]


def _phase_interpretation(row: dict[str, Any]) -> str:
    executables = [
        item.strip()
        for item in str(row.get("executables") or "").split(",")
        if item.strip()
    ]
    tool_globs = _catalog_exe_globs("antiforensic_tools")
    cloud_globs = _catalog_exe_globs("cloud_sync_artifacts")
    has_tools = any(_matches_exe_globs(name, tool_globs) for name in executables)
    has_cloud = any(_matches_exe_globs(name, cloud_globs) for name in executables)
    if has_tools and _as_int(row.get("log_integrity_events")):
        return "Cleaning tools and log integrity events on the same day; prioritize anti-forensic hypothesis"
    if has_cloud and has_tools:
        return "Cloud sync traces and cleaning tools on the same day; check for post-exfiltration wiping"
    if _as_int(row.get("explicit_credentials")):
        return "Explicit credential usage detected; check relationship with standard logons per user"
    if _as_int(row.get("log_integrity_events")):
        return "Log stop/clear candidates detected; check the actor and surrounding events at the same time"
    return "Notable events clustered on this day; correlate with surrounding file and execution traces"


def _forensic_gap_rows(db: CaseDB) -> list[dict[str, Any]]:
    """Evidence-gap rows derived from what the case actually contains.

    Each row is emitted only when the corresponding artifact family or signal
    is present in the evidence — no fixed scenario assumptions (Rule 16).
    """
    from forensia.rules.loader import detect_artifact_families

    active_count = _hypothesis_count(db, "active")
    network = _network_summary_rows(db)
    try:
        families = detect_artifact_families(db)
    except Exception:
        families = set()

    gaps: list[dict[str, Any]] = []
    if active_count:
        gaps.append(
            {
                "gap": "Resolve or refute outstanding hypotheses",
                "why_it_matters": f"{active_count} active hypotheses remain; mixing them into conclusions risks overstatement.",
                "next_step": "Prioritize uninvestigated hypotheses and classify them as confirmed/refuted/needs_data.",
            }
        )
    if "cloud_sync" in families:
        gaps.append(
            {
                "gap": "Direct evidence of cloud sync destinations and targets",
                "why_it_matters": "Cloud sync client traces show the environment exists but do not directly show sync targets, destinations, or completion status.",
                "next_step": "Correlate sync client logs, local DB, and network logs.",
            }
        )
    if "mailbox" in families:
        gaps.append(
            {
                "gap": "Email content and send/receive verification",
                "why_it_matters": "Email data file existence shows client usage but content and attachment movement need other evidence.",
                "next_step": "Correlate email data file analysis results and server-side logs if available.",
            }
        )
    antiforensic_findings = _count_findings_with_tag(
        db, "benign-context:", negate=True, tag_like="%antiforensic%"
    )
    if antiforensic_findings or _has_antiforensic_executions(db):
        gaps.append(
            {
                "gap": "Scope of wiping tool execution",
                "why_it_matters": "Cleaning tool execution traces are a strong candidate but do not reveal deletion targets or execution details alone.",
                "next_step": "Correlate tool settings, task files, deleted MFT entries, and log stop times.",
            }
        )
    if network and not (
        _as_int(network[0].get("external_src_rows"))
        or _as_int(network[0].get("external_dst_rows"))
    ):
        gaps.append(
            {
                "gap": "Insufficient normalized network evidence",
                "why_it_matters": "EVTX alone is insufficient to determine external communication.",
                "next_step": "Ingest firewall/proxy/DNS/cloud client logs if available.",
            }
        )
    return gaps


def _count_findings_with_tag(
    db: CaseDB, exclude_prefix: str, *, negate: bool, tag_like: str
) -> int:
    """Count non-suppressed findings whose tags match tag_like, excluding benign-context ones."""
    try:
        row = db.execute(
            """
            SELECT COUNT(*) FROM findings
            WHERE COALESCE(status, 'new') != 'suppressed'
              AND LOWER(COALESCE(tags, '')) LIKE ?
              AND LOWER(COALESCE(tags, '')) NOT LIKE ?
            """,
            (tag_like.lower(), f"%{exclude_prefix.lower()}%"),
        ).fetchone()
        return int(row[0] or 0)
    except Exception:
        return 0


def _has_antiforensic_executions(db: CaseDB) -> bool:
    """True when prefetch shows execution of a catalog-listed cleanup tool."""
    tool_sql = _exe_glob_sql(
        "executable_name", _catalog_exe_globs("antiforensic_tools")
    )
    try:
        row = db.execute(
            f"SELECT COUNT(*) FROM prefetch_executions WHERE {tool_sql}"
        ).fetchone()
        return bool(row and row[0])
    except Exception:
        return False


def _hypothesis_rows(
    db: CaseDB, status: str | None = None, limit: int = 12
) -> list[dict[str, Any]]:
    where = "WHERE h.status = ?" if status else ""
    params: tuple[Any, ...] = (status, limit) if status else (limit,)
    return fetch_records(
        db,
        f"""
        WITH latest AS (
          SELECT *, ROW_NUMBER() OVER (
            PARTITION BY hypothesis_id ORDER BY created_at DESC, entry_id DESC
          ) AS rn
          FROM hypothesis_reasoning
        )
        SELECT h.hypothesis_id, h.status, h.verdict, h.description, h.summary,
               COUNT(r.entry_id) AS reasoning_count,
               MAX(r.iteration) AS latest_iteration,
               l.verdict AS latest_verdict,
               l.body AS latest_reasoning
        FROM hypotheses h
        LEFT JOIN hypothesis_reasoning r ON r.hypothesis_id = h.hypothesis_id
        LEFT JOIN latest l ON l.hypothesis_id = h.hypothesis_id AND l.rn = 1
        {where}
        GROUP BY h.hypothesis_id, h.status, h.verdict, h.description, h.summary, l.verdict, l.body
        ORDER BY
          CASE WHEN COUNT(r.entry_id) = 0 THEN 0 ELSE 1 END,
          MAX(r.iteration) DESC NULLS LAST,
          h.hypothesis_id
        LIMIT ?
        """,
        params,
    )


def _hypothesis_count(db: CaseDB, status: str) -> int:
    row = db.execute(
        "SELECT COUNT(*) FROM hypotheses WHERE status = ?", (status,)
    ).fetchone()
    return int(row[0] or 0) if row else 0


def _section_gap_rows(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in fetch_records(
        db, "SELECT section_key, gaps FROM report_sections ORDER BY section_key"
    ):
        gaps = normalize_value(row.get("gaps")) or []
        if not isinstance(gaps, list):
            continue
        for gap in gaps:
            text = str(gap or "").strip()
            if text:
                rows.append(
                    {
                        "section": row.get("section_key"),
                        "gap": text,
                        "next_step": "Regenerate or verify this section with supporting evidence.",
                    }
                )
    return rows[:limit]


def _build_evidence_scope_table(db: CaseDB) -> list[dict[str, Any]]:
    return _count_table(db)


def _build_systems_observed_table(db: CaseDB) -> list[dict[str, Any]]:
    return _host_summary_rows(db, 5)


def _build_key_findings_table(db: CaseDB) -> list[dict[str, Any]]:
    return _signal_finding_rows(db, 8)


def _build_timeline_phase_table(db: CaseDB) -> list[dict[str, Any]]:
    return _timeline_phase_rows(db)


def _build_timeline_chronological_table(db: CaseDB) -> list[dict[str, Any]]:
    return _timeline_rows(db)


def _build_accounts_table(db: CaseDB) -> list[dict[str, Any]]:
    return _account_summary_rows(db)


def _build_execution_table(db: CaseDB) -> list[dict[str, Any]]:
    return _execution_rows(db)


def _build_file_artifacts_table(db: CaseDB) -> list[dict[str, Any]]:
    return _file_artifact_rows(db)


def _build_antiforensic_table(db: CaseDB) -> list[dict[str, Any]]:
    return _antiforensic_rows(db)


def _build_network_table(db: CaseDB) -> list[dict[str, Any]]:
    return _network_summary_rows(db)


def _build_gaps_unresolved_table(db: CaseDB) -> list[dict[str, Any]]:
    all_rows = _hypothesis_rows(db, "active", 20)
    investigated = [r for r in all_rows if int(r.get("reasoning_count") or 0) > 0]
    untouched = [r for r in all_rows if int(r.get("reasoning_count") or 0) == 0]

    result: list[dict[str, Any]] = []
    for row in investigated:
        description = str(row.get("description") or row.get("hypothesis_id") or "")[
            :120
        ]
        latest = str(row.get("latest_reasoning") or "").strip()
        needed = _extract_needed_evidence(row.get("latest_reasoning"))
        if latest and latest[:80] == description[:80]:
            latest = ""
        result.append(
            {
                "hypothesis": description,
                "state": str(
                    row.get("latest_verdict") or row.get("verdict") or "inconclusive"
                ),
                "reasoning": row.get("reasoning_count"),
                "latest": latest,
                "needed": needed if needed else "",
            }
        )

    if untouched:
        result.append(
            {
                "hypothesis": f"{len(untouched)} drafted hypotheses not yet investigated",
                "state": "not started",
                "reasoning": 0,
                "latest": "",
                "needed": "",
            }
        )

    return result


def _build_gaps_untestable_table(db: CaseDB) -> list[dict[str, Any]]:
    return _hypothesis_rows(db, "untestable", 8)


def _build_gaps_confirmed_table(db: CaseDB) -> list[dict[str, Any]]:
    """RPT-05: surface confirmed hypotheses for audit, including their basis.

    Each row shows whether the confirmation was seeded by a detection rule or
    derived from a generic gap (`source_rule_ids` empty), and whether the
    rule-seeded findings were themselves downgraded to a benign-context
    pattern. This makes mis-confirmations visible to the reader instead of
    silently driving the narrative.
    """
    rows: list[dict[str, Any]] = []
    for item in _annotate_confirmed_hypotheses(
        db, _query_hypotheses_by_status(db, "confirmed", 20)
    ):
        rule_ids = _hypothesis_source_rule_ids(item)
        if rule_ids:
            basis = "rule-seeded: " + ", ".join(rule_ids[:2])
        else:
            basis = "gap-derived"
        rows.append(
            {
                "hypothesis": str(
                    item.get("description") or item.get("hypothesis_id") or ""
                )[:120],
                "verdict": str(item.get("verdict") or item.get("status") or ""),
                "basis": basis,
                "benign_context": "yes" if item.get("benign_context") else "no",
                "summary": str(item.get("summary") or "")[:160],
            }
        )
    return rows


def _build_evidence_gaps_table(db: CaseDB) -> list[dict[str, Any]]:
    return _forensic_gap_rows(db)


def _build_recommendations_table(db: CaseDB) -> list[dict[str, Any]]:
    """Action plan rows derived from the case's own findings and hypotheses.

    No fixed scenario actions: every row is conditional on data present in
    this case (Rule 16). Top finding themes drive correlation actions.
    """
    rows: list[dict[str, Any]] = []
    active_count = len(_hypothesis_rows(db, "active", 20))
    if active_count:
        rows.append(
            {
                "priority": "High",
                "action": "Triage outstanding hypotheses into terminal states",
                "rationale": f"{active_count} active hypotheses remain; classify each as needs_data, refuted, or confirmed with additional investigation.",
                "evidence_or_gap": "hypotheses",
            }
        )

    # Correlation actions for the top finding themes actually observed.
    # RPT-03: counts come from the same single-source `_finding_theme_counts`
    # used by the Key Findings table, so `(N)` matches across sections.
    theme_counts = _finding_theme_counts(db)
    ranked_themes = sorted(
        (theme for theme in theme_counts if theme != "other"),
        key=lambda theme: (_finding_theme_rank(theme), -theme_counts[theme]),
    )
    for theme in ranked_themes[:3]:
        rows.append(
            {
                "priority": "High" if _finding_theme_rank(theme) <= 2 else "Medium",
                "action": f"Correlate {_finding_theme_title(theme, theme_counts[theme])} by user, host, and time",
                "rationale": _finding_theme_summary(theme),
                "evidence_or_gap": theme,
            }
        )

    benign_count = _count_findings_with_tag(
        db, "", negate=False, tag_like="%benign-context:%"
    )
    if benign_count:
        rows.append(
            {
                "priority": "Low",
                "action": "Manually review findings auto-downgraded as benign-context if needed",
                "rationale": f"{benign_count} findings matched known benign patterns and were auto-downgraded.",
                "evidence_or_gap": "finding ranking",
            }
        )
    return rows


_TABLE_BLOCK_BUILDERS: dict[str, Callable[[CaseDB], list[dict[str, Any]]]] = {
    "overview_evidence_scope": _build_evidence_scope_table,
    "overview_systems_observed": _build_systems_observed_table,
    "overview_key_findings": _build_key_findings_table,
    "timeline_phase_summary": _build_timeline_phase_table,
    "timeline_chronological": _build_timeline_chronological_table,
    "technical_accounts": _build_accounts_table,
    "technical_execution": _build_execution_table,
    "technical_files": _build_file_artifacts_table,
    "technical_antiforensic": _build_antiforensic_table,
    "technical_network": _build_network_table,
    "gaps_unresolved": _build_gaps_unresolved_table,
    "gaps_untestable": _build_gaps_untestable_table,
    "gaps_confirmed": _build_gaps_confirmed_table,
    "gaps_evidence": _build_evidence_gaps_table,
    "recommendations_action_plan": _build_recommendations_table,
}

_TABLE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "overview_evidence_scope": [
        ("metric", "Metric"),
        ("value", "Value"),
        ("scope", "Scope"),
    ],
    "overview_systems_observed": [
        ("host", "Host"),
        ("events", "EVTX rows"),
        ("first_seen", "First seen"),
        ("last_seen", "Last seen"),
    ],
    "overview_key_findings": [
        ("finding", "Finding"),
        ("severity", "Severity"),
        ("confidence", "Confidence"),
        ("why_it_matters", "Why it matters"),
    ],
    "timeline_phase_summary": [
        ("date", "Date"),
        ("phase", "Observed activity"),
        ("interpretation", "Interpretation"),
        ("window", "Event window"),
    ],
    "timeline_chronological": [
        ("time", "Time"),
        ("host", "Host"),
        ("activity", "Activity"),
        ("subject", "Subject"),
        ("artifact", "Artifact"),
        ("evidence_id", "Ref"),
    ],
    "technical_accounts": [
        ("account", "Account"),
        ("computer", "Host"),
        ("logons", "4624"),
        ("failed_logons", "4625"),
        ("explicit_credential_events", "4648"),
        ("first_seen", "First seen"),
        ("last_seen", "Last seen"),
    ],
    "technical_execution": [
        ("executable_name", "Executable"),
        ("exec_count", "Exec count"),
        ("last_exec_time", "Last execution"),
        ("evidence_id", "Ref"),
    ],
    "technical_files": [
        ("timestamp", "Timestamp"),
        ("file_name", "File"),
        ("file_path", "Path"),
        ("evidence_id", "Ref"),
    ],
    "technical_antiforensic": [
        ("type", "Type"),
        ("timestamp", "Timestamp"),
        ("artifact", "Artifact"),
        ("computer", "Host"),
        ("evidence_id", "Ref"),
    ],
    "technical_network": [
        ("area", "Area"),
        ("observed_rows", "Rows with IP"),
        ("external_src_rows", "External source rows"),
        ("external_dst_rows", "External destination rows"),
        ("interpretation", "Interpretation"),
    ],
    "gaps_unresolved": [
        ("hypothesis", "Hypothesis"),
        ("state", "State"),
        ("reasoning", "Reasoning rows"),
        ("latest", "Latest rationale"),
        ("needed", "Needed evidence"),
    ],
    "gaps_untestable": [
        ("hypothesis", "Hypothesis"),
        ("missing_telemetry", "Missing telemetry"),
        ("rationale", "Rationale"),
        ("next_step", "Next step"),
    ],
    "gaps_confirmed": [
        ("hypothesis", "Hypothesis"),
        ("verdict", "Verdict"),
        ("basis", "Basis"),
        ("benign_context", "Benign context"),
        ("summary", "Summary"),
    ],
    "gaps_evidence": [
        ("gap", "Gap"),
        ("why_it_matters", "Why it matters"),
        ("next_step", "Next step"),
    ],
    "recommendations_action_plan": [
        ("priority", "Priority"),
        ("action", "Action"),
        ("rationale", "Rationale"),
        ("evidence_or_gap", "Evidence/Gap"),
    ],
}


def _table_block_columns(
    builder_name: str, rows: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """Return column definitions for a table builder, with dynamic adjustments."""
    base = _TABLE_COLUMNS.get(builder_name, [("key", "Key"), ("value", "Value")])
    if builder_name == "overview_systems_observed" and any("note" in r for r in rows):
        return [
            ("host", "Host"),
            ("note", "Note"),
            ("events", "EVTX rows"),
            ("first_seen", "First seen"),
            ("last_seen", "Last seen"),
        ]
    return base


@lru_cache(maxsize=1)
def _load_table_captions() -> dict[str, dict[str, str]]:
    """Load per-builder caption/empty templates from rulepacks/_schema/report_tables.yaml."""
    import yaml

    path = (
        Path(__file__).resolve().parent.parent
        / "rulepacks"
        / "_schema"
        / "report_tables.yaml"
    )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    tables = data.get("tables") if isinstance(data, dict) else None
    if not isinstance(tables, dict):
        return {}
    return {
        str(name): {str(k): str(v) for k, v in spec.items() if isinstance(v, str)}
        for name, spec in tables.items()
        if isinstance(spec, dict)
    }


def render_table_block(
    db: CaseDB, builder_name: str, *, max_rows: int | None = None
) -> str | None:
    """Render a `mode: table` block deterministically: caption paragraph + table.

    ``max_rows`` controls the number of table rows shown in the Markdown output.
    ``0`` means unlimited. When *None*, the value is read from the per-builder
    ``max_rows:`` key in *report_tables.yaml*; if absent, defaults to ``0``
    (unlimited).

    Returns None when the builder name is unknown (caller falls back to the
    LLM agent). Empty result sets render the declared ``empty`` text instead of
    a bare empty table.
    """
    builder_fn = _TABLE_BLOCK_BUILDERS.get(builder_name)
    if builder_fn is None:
        return None
    rows = builder_fn(db)
    spec = _load_table_captions().get(builder_name) or {}
    if not rows:
        return str(spec.get("empty") or "").strip() or "_No rows available._"
    if max_rows is None:
        try:
            max_rows = int(spec.get("max_rows") or 0)
        except TypeError, ValueError:
            max_rows = 0
    caption = render_rows_template(str(spec.get("caption") or "").strip(), rows).strip()
    table = _markdown_table(
        rows, _table_block_columns(builder_name, rows), max_rows=max_rows
    )
    return f"{caption}\n\n{table}" if caption else table


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


def _summarize_flat_evidence_rows(
    rows: list[dict[str, Any]], max_rows: int = 30
) -> list[dict[str, Any]]:
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


def _dump_section_trace_json(
    case: Case, section_key: str, evidence_results: list[dict[str, Any]]
) -> None:
    """Write non-row evidence results to reports/debug/<section_key>_trace.json."""
    trace_rows = [
        normalize_value(result)
        for result in evidence_results
        if str(result.get("kind") or "rows") != "rows"
    ]
    if not trace_rows:
        return
    debug_dir = case.reports_dir / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    out_path = debug_dir / f"{section_key}_trace.json"
    out_path.write_text(
        json.dumps(trace_rows, ensure_ascii=False, default=str, indent=2),
        encoding="utf-8",
    )


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
    out_path.write_text(
        json.dumps(normalized, ensure_ascii=False, default=str, indent=2),
        encoding="utf-8",
    )


def _dump_section_evidence_json(
    case: Case, section_key: str, rows: list[dict[str, Any]]
) -> None:
    """Write flat evidence rows to reports/evidence/<section_key>.json."""
    if not rows:
        return
    evidence_dir = case.reports_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out_path = evidence_dir / f"{section_key}.json"
    out_path.write_text(
        json.dumps(rows, ensure_ascii=False, default=str, indent=2), encoding="utf-8"
    )


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
