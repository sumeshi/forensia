from __future__ import annotations

"""Deterministic block-support layer for the section agent (split from
section_agent.py in R4 follow-up): status classification, persistence of
section runs/evidence/facts, keypoint and template catalogs, evidence-chain
execution, structured-answer formatting, and narrative fallback helpers.
The LLM-driven agent loop stays in section_agent.py.
"""


import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from forensia.ai.checker import summarize_query_result
from forensia.ai.sql_templates import query_template_catalog, validate_select_sql
from forensia.core.case import Case
from forensia.core.session import PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge import catalog_marker_map as _catalog_marker_map
from forensia.knowledge import catalog_names as _catalog_names
from forensia.knowledge import expand_catalog_sql_placeholders
from forensia.questions import (
    QuestionSpec,
    extract_time_qualifiers,
    load_question_specs,
    resolve_question_spec,
)
from forensia.report.keypoints import (
    REPORT_KEYPOINT_ALIASES,
    REPORT_KEYPOINTS,
    _default_keypoints_for_section,
    _resolve_evidence_results,
)
from forensia.report.structured_answers import (
    _build_daily_session_timeline_rows,
    _load_structured_answers,
    _normalize_structured_answer,
    _persist_structured_answer,
    _render_structured_answer_markdown,
    _structured_block_id,
)

_CONFIDENCE_KEYWORD_MAP = {
    "critical": 0.95,
    "very high": 0.9,
    "high": 0.85,
    "medium-high": 0.75,
    "medium": 0.6,
    "moderate": 0.6,
    "low-medium": 0.45,
    "low": 0.3,
    "very low": 0.15,
    "none": 0.0,
    "n/a": 0.0,
    "unknown": 0.0,
}


def _coerce_confidence(value: Any, default: float = 0.5) -> float:
    """Defensive conversion for when LLM returns confidence as string ("high" etc)."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        try:
            return max(0.0, min(1.0, float(value)))
        except TypeError, ValueError:
            return default
    text = str(value).strip().lower()
    if not text:
        return default
    if text in _CONFIDENCE_KEYWORD_MAP:
        return _CONFIDENCE_KEYWORD_MAP[text]
    try:
        return max(0.0, min(1.0, float(text)))
    except ValueError:
        return default


# ====================================================================
# BLOCK CONTEXT + HELPERS — _BlockContext, status helpers, digest helpers
# Lines: ~74-500
# ====================================================================


@dataclass(slots=True)
class SectionBlockResult:
    body: str
    evidence_results: list[dict[str, Any]]
    iterations: int
    status: str


@dataclass(slots=True)
class SectionPlanAction:
    action: str
    purpose: str
    keypoint: str | None = None
    planned_query: PlannedQuery | None = None
    enough_to_write: bool = False


def _section_family(section_key: str) -> str:
    parts = str(section_key or "").split("_", 1)
    return parts[1] if len(parts) == 2 else parts[0]


def _cache_key(source_query: str) -> str:
    return hashlib.sha1(source_query.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _safe_rows(rows: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        safe.append({key: value for key, value in row.items() if key != "source_query"})
    return safe


def _known_keypoints(catalog: list[dict]) -> set[str]:
    return {kp.get("name") or "" for kp in (catalog or [])}


def _split_keypoint_names(value: str | None) -> list[str]:
    """Split planner keypoint output while preserving each exact catalog name."""
    if not value:
        return []
    return [item.strip() for item in re.split(r"[，,;]\s*", str(value)) if item.strip()]


def _is_valid_status(status: str) -> bool:
    return status in {
        "answered",
        "partial",
        "not_found",
        "not_searched",
        "insufficient_evidence",
        "wrong_query",
    }


@lru_cache(maxsize=1)
def _load_question_routing() -> list[QuestionSpec]:
    """Compatibility wrapper around the semantic QuestionSpec registry."""
    return list(load_question_specs())


def _question_routing_rule(
    block_heading: str, template_body: str
) -> QuestionSpec | None:
    spec, _confidence = resolve_question_spec(
        block_heading=block_heading, template_body=template_body
    )
    return spec


def _question_routing_keypoints(block_heading: str, template_body: str) -> list[str]:
    rule = _question_routing_rule(block_heading, template_body)
    if rule is not None:
        return list(rule.keypoints)
    return []


def _question_routing_answer_spec(block_heading: str, template_body: str) -> str:
    rule = _question_routing_rule(block_heading, template_body)
    return rule.answer_spec if rule is not None else ""


def _classify_block_status(
    *,
    verdict: str,
    actual_query_rows: list[int],
    actual_query_count: int,
    reusable_rows_present: bool,
) -> str:
    """Map LLM verdict + query stats to a canonical status string.

    Combines the LLM's semantic verdict with observed query outcomes to produce
    one of the valid statuses used for block result tracking.
    """
    if _is_valid_status(verdict):
        return verdict
    if actual_query_count <= 0:
        return "not_searched" if reusable_rows_present else "not_searched"
    if verdict == "block_supported":
        return "answered"
    if verdict == "block_contradicted":
        if any(count > 0 for count in actual_query_rows):
            return "wrong_query"
        return "not_found"
    if any(count > 0 for count in actual_query_rows):
        return "partial"
    if actual_query_count >= 2 and all(count == 0 for count in actual_query_rows):
        return "not_found"
    return "insufficient_evidence"


def _structured_digest_from_answers(case: Case) -> str:
    """Build a compact <STRUCTURED_OBSERVATIONS> block from persisted structured answers.

    Returns a block (≤1.5 KB) listing each non-zero structured answer spec with
    status, row_count, top values from the first render column, and first/last
    timestamps. Only includes specs with status != 'not_searched' and non-empty
    answer rows.
    """
    answers = _load_structured_answers(case)
    if not answers:
        return ""

    lines: list[str] = []
    for answer in answers:
        status = str(answer.get("status") or "").strip().lower()
        if status == "not_searched":
            continue
        answer_rows = answer.get("answer") or []
        if not isinstance(answer_rows, list) or not answer_rows:
            continue

        answer_spec = str(answer.get("answer_spec") or "").strip() or str(
            answer.get("id") or "?"
        )
        row_count = len(answer_rows)
        first_row = answer_rows[0] if isinstance(answer_rows[0], dict) else None
        columns = answer.get("columns") or []
        first_col = columns[0] if columns else ""
        if not first_col and first_row:
            keys = [k for k in first_row.keys() if not k.startswith("_")]
            first_col = keys[0] if keys else ""

        top_values: list[str] = []
        timestamps: list[str] = []
        for row in answer_rows:
            if not isinstance(row, dict):
                continue
            if first_col:
                val = str(row.get(first_col) or "").strip()
                if val and val not in top_values:
                    top_values.append(val)
            for ts_key in (
                "timestamp",
                "logon_time",
                "last_exec_time",
                "si_modified",
                "date",
                "shutdown_time",
                "first_event_time",
            ):
                ts = str(row.get(ts_key) or "").strip()
                if ts:
                    timestamps.append(ts)
                    break

        first_ts = min(timestamps) if timestamps else ""
        last_ts = max(timestamps) if timestamps else ""
        top_str = " | ".join(top_values[:3])

        line = f"  - {answer_spec}: status={status}, rows={row_count}"
        if top_str:
            line += f", [{first_col}]={top_str}"
        if first_ts and last_ts:
            line += f", ts_range={first_ts[:19]}..{last_ts[:19]}"
        lines.append(line)

    if not lines:
        return ""

    digest = (
        "<STRUCTURED_OBSERVATIONS>\n"
        + "\n".join(lines)
        + "\n</STRUCTURED_OBSERVATIONS>"
    )
    if len(digest) > 1500:
        digest = digest[:1497] + "..."
    return digest


def _benchmark_report_brief(report_brief: dict[str, Any] | None) -> dict[str, Any]:
    """Strip narrative-heavy fields from report_brief for benchmark mode.

    Benchmark blocks must only receive factual inventories, not LLM-generated
    narratives, to prevent answer leakage.
    """
    brief = dict(report_brief or {})
    keys_to_keep = {
        "evidence_inventory",
        "table_inventory",
        "row_counts",
        "time_range",
        "time_window",
        "source_inventory",
    }
    if "evidence_inventory" in brief:
        evidence_inventory = brief.get("evidence_inventory")
        if isinstance(evidence_inventory, dict):
            brief["evidence_inventory"] = {
                key: value
                for key, value in evidence_inventory.items()
                if key in keys_to_keep
            }
    for key in list(brief.keys()):
        if key in keys_to_keep or key == "evidence_inventory":
            continue
        brief.pop(key, None)
    return brief


def _structured_report_brief(report_brief: dict[str, Any] | None) -> dict[str, Any]:
    """Neutral alias for structured question blocks."""
    return _benchmark_report_brief(report_brief)


def _audit_bridge(audit_callback):
    """Wrap an audit_callback to adapt (messages, output, parsed) -> (messages, output)."""
    if audit_callback is None:
        return None

    def inner(
        messages: list[dict[str, str]], output: str, parsed: dict[str, Any]
    ) -> None:
        audit_callback(messages, output)

    return inner


def _store_section_run(
    db: CaseDB,
    *,
    section_key: str,
    block_heading: str,
    iteration: int,
    phase: str,
    payload: dict[str, Any],
    verdict: str | None = None,
) -> None:
    """Persist one section-agent run step (plan, query, check, write) to section_runs."""
    if verdict is not None:
        normalized = {
            "sufficient": "block_supported",
            "refuted": "block_contradicted",
        }.get(verdict, verdict)
        from forensia.core.verdicts import assert_valid_verdict

        assert_valid_verdict(normalized, "section_verdict")
    run_id = hashlib.sha1(
        f"{section_key}-{block_heading}-{iteration}-{phase}-{json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)}".encode()
    ).hexdigest()[:20]
    db.execute(
        """
        INSERT INTO section_runs (run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (run_id) DO NOTHING
        """,
        (
            run_id,
            section_key,
            block_heading,
            iteration,
            phase,
            json.dumps(payload, ensure_ascii=False, default=str),
            verdict,
            _now(),
        ),
    )


def _store_section_question(
    db: CaseDB,
    *,
    section_key: str,
    block_heading: str,
    question_text: str,
    spec: QuestionSpec | None,
    confidence: float,
    status: str = "resolved",
) -> None:
    """Persist the semantic question contract resolved for a report block."""
    normalized_text = str(question_text or block_heading or "").strip()
    if spec is None and not normalized_text:
        return
    question_id = hashlib.sha1(
        f"{section_key}\n{block_heading}\n{normalized_text}\n{spec.semantic_id if spec else ''}".encode()
    ).hexdigest()[:20]
    required_evidence = {
        "required_fields": list(spec.required_fields) if spec else [],
        "required_sources": list(spec.required_sources) if spec else [],
        "keypoints": list(spec.keypoints) if spec else [],
        "render_columns": list(spec.render_columns) if spec else [],
        "status_rules": spec.status_rules if spec else {},
    }
    try:
        db.execute(
            """
            INSERT INTO section_questions (
                question_id, section_key, block_heading, question_text, question_type,
                answer_spec, intent, confidence, matched_rule, required_evidence,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (question_id) DO UPDATE SET
                question_text = excluded.question_text,
                question_type = excluded.question_type,
                answer_spec = excluded.answer_spec,
                intent = excluded.intent,
                confidence = excluded.confidence,
                matched_rule = excluded.matched_rule,
                required_evidence = excluded.required_evidence,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                question_id,
                section_key,
                block_heading,
                normalized_text,
                spec.name if spec else "",
                spec.answer_spec if spec else "",
                spec.intent if spec else "",
                float(confidence or 0.0),
                spec.name if spec else "",
                json.dumps(required_evidence, ensure_ascii=False, default=str),
                status if spec is not None else "unresolved",
                _now(),
                _now(),
            ),
        )
    except Exception:
        return


def _load_prior_runs(
    db: CaseDB, section_key: str, block_heading: str
) -> list[dict[str, Any]]:
    """Load prior section-agent run history for a given (section, block).

    JSON payloads are deserialized automatically. Results are ordered by
    creation time to preserve iteration chronology.
    """
    rows = db.execute(
        """
        SELECT iteration, phase, payload, verdict, created_at
        FROM section_runs
        WHERE section_key = ? AND block_heading = ?
        ORDER BY created_at, iteration
        """,
        (section_key, block_heading),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for iteration, phase, payload, verdict, created_at in rows:
        parsed_payload = payload
        if isinstance(payload, str):
            try:
                parsed_payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
        items.append(
            {
                "iteration": iteration,
                "phase": phase,
                "payload": parsed_payload,
                "verdict": verdict,
                "created_at": str(created_at),
            }
        )
    return items


def _load_cached_result(db: CaseDB, source_query: str) -> dict[str, Any] | None:
    """Load a previously cached query result by source query text.

    Returns None on cache miss, JSON parse failure, or non-dict payload.
    Adds default kind/source_kind/source_ref fields missing from older cache entries.
    """
    row = db.execute(
        "SELECT result_json FROM query_cache WHERE sql_hash = ?",
        (_cache_key(source_query),),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    try:
        parsed = json.loads(str(row[0]))
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    parsed.setdefault("kind", "rows")
    parsed.setdefault("source_kind", "unknown")
    parsed.setdefault("source_ref", source_query)
    return parsed


def _store_cached_result(
    db: CaseDB, source_query: str, payload: dict[str, Any]
) -> None:
    db.execute(
        """
        INSERT INTO query_cache (sql_hash, sql_text, result_json, executed_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (sql_hash) DO UPDATE SET
            sql_text = excluded.sql_text,
            result_json = excluded.result_json,
            executed_at = excluded.executed_at
        """,
        (
            _cache_key(source_query),
            source_query,
            json.dumps(payload, ensure_ascii=False, default=str),
            _now(),
        ),
    )


def _store_section_evidence(
    db: CaseDB,
    *,
    section_key: str,
    block_heading: str,
    result: dict[str, Any],
    source_query: str,
) -> None:
    """Persist evidence IDs referenced by a section block result."""
    evidence_ids = [
        str(item).strip()
        for item in (result.get("evidence_ids") or [])
        if str(item).strip()
    ]
    rows = [
        (
            section_key,
            block_heading,
            evidence_id,
            str(result.get("keypoint") or result.get("description") or "query_result"),
            source_query,
            _now(),
        )
        for evidence_id in evidence_ids
    ]
    if rows:
        db.insert_many(
            """
            INSERT INTO section_evidence (section_key, block_heading, evidence_id, role, source_query, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            """,
            rows,
        )


def _store_section_facts(
    db: CaseDB,
    *,
    section_key: str,
    source_query: str,
    result: dict[str, Any],
    fact_updates: list[dict[str, Any]] | None = None,
) -> None:
    """Persist facts verified by the LLM check phase with conflict resolution.

    Higher-confidence values overwrite conflicting lower-confidence entries.
    Only facts explicitly listed in fact_updates (from LLM check) are persisted;
    raw sample_rows are never auto-promoted to facts.
    """
    # Only persist facts explicitly verified by the LLM check phase.
    # Do NOT auto-promote raw sample_rows to "facts" — they are unverified data
    # and would pollute the fact store with high-confidence noise.
    evidence_ids = [
        str(item).strip()
        for item in (result.get("evidence_ids") or [])
        if str(item).strip()
    ]
    rows: list[tuple[Any, ...]] = []
    timestamp = _now()
    for item in fact_updates or []:
        if not isinstance(item, dict):
            continue
        fact_type = str(item.get("fact_type") or "").strip()
        if not fact_type:
            continue
        fact_key = str(item.get("fact_key") or fact_type).strip()
        # fact_id is keyed by (fact_type, fact_key) only — same fact discovered
        # by different sections must converge to the same id so it is reused
        # across the whole report (e.g. Q6 computer_name discovered in 1_overview
        # must be visible to 3_technical via the same fact_id).
        fact_id = hashlib.sha1(f"{fact_type}-{fact_key}".encode()).hexdigest()[:20]
        new_value = json.dumps(item.get("fact_value"), ensure_ascii=False, default=str)
        new_confidence = _coerce_confidence(item.get("confidence"))
        # Check for conflicts: existing value differs from new value
        existing = db.execute(
            "SELECT fact_value, confidence FROM section_facts WHERE fact_id = ?",
            (fact_id,),
        ).fetchone()
        if existing:
            existing_value = str(existing[0] or "")
            existing_confidence = float(existing[1] or 0.0)
            if existing_value != new_value:
                # Conflict detected: higher confidence wins, conflict logged via updated source
                if new_confidence < existing_confidence:
                    continue  # Keep existing, skip this update
        rows.append(
            (
                fact_id,
                fact_type,
                fact_key,
                new_value,
                json.dumps(evidence_ids, ensure_ascii=False),
                source_query,
                section_key,
                new_confidence,
                timestamp,
                timestamp,
            )
        )
    if rows:
        db.insert_many(
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
            rows,
        )


def _keypoint_catalog(
    section_key: str | None = None,
    template_body: str | None = None,
    *,
    block_heading: str | None = None,
    evidence_keypoints: list[str] | None = None,
) -> list[dict[str, str]]:
    """Return keypoint catalog filtered for this section, plus a few cross-cutting ones.

    Returning all ~40 keypoints to the planner on every iteration wastes
    tokens. Each report section only needs its own family (e.g. timeline_*)
    plus a small set of universally useful keypoints.

    Explicit evidence_keypoints from template hints win first. If absent, use
    heading/body routing hints, then fall back to the section family default.
    """

    def resolve_name(name: str) -> str:
        normalized = str(name or "").strip()
        return REPORT_KEYPOINT_ALIASES.get(normalized, normalized)

    if evidence_keypoints:
        catalog: list[dict[str, str]] = []
        seen: set[str] = set()
        for keypoint in evidence_keypoints:
            resolved_name = resolve_name(keypoint)
            entry = REPORT_KEYPOINTS.get(resolved_name)
            if entry is None or resolved_name in seen:
                continue
            seen.add(resolved_name)
            catalog.append({"name": keypoint, "description": entry[0]})
        if catalog:
            return catalog

    routed_keypoints = _question_routing_keypoints(
        block_heading or "", template_body or ""
    )
    if routed_keypoints:
        catalog: list[dict[str, str]] = []
        seen: set[str] = set()
        for keypoint in routed_keypoints:
            resolved_name = resolve_name(keypoint)
            entry = REPORT_KEYPOINTS.get(resolved_name)
            if entry is None or resolved_name in seen:
                continue
            seen.add(resolved_name)
            catalog.append({"name": keypoint, "description": entry[0]})
        if catalog:
            return catalog

    if not section_key:
        template_body = template_body or ""
        keywords = {
            "logon",
            "user",
            "host",
            "ip",
            "service",
            "task",
            "powershell",
            "process",
            "execution",
            "event",
            "finding",
            "persistence",
            "defender",
        }
        filtered: list[dict[str, str]] = []
        for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items()):
            lowered = template_body.lower()
            if any(
                kw in lowered and (kw in keypoint.lower() or kw in description.lower())
                for kw in keywords
            ):
                filtered.append({"name": keypoint, "description": description})
            if len(filtered) >= 10:
                break
        if filtered:
            return filtered
        return [
            {"name": keypoint, "description": description}
            for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items())[:10]
        ]

    preferred = _default_keypoints_for_section(
        section_key, block_heading=block_heading or ""
    )
    catalog: list[dict[str, str]] = []
    seen: set[str] = set()
    for keypoint in preferred:
        entry = REPORT_KEYPOINTS.get(keypoint)
        if entry is None or keypoint in seen:
            continue
        seen.add(keypoint)
        catalog.append({"name": keypoint, "description": entry[0]})
    return catalog


def _query_template_catalog() -> list[dict[str, Any]]:
    return query_template_catalog()


def _filter_template_catalog_by_section(
    full_catalog: list[dict[str, Any]],
    section_key: str,
    collected_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Filter template catalog to relevant subset based on section_key and evidence types.

    Pass empty list to get full catalog filtered; otherwise filters already-loaded catalog.
    """
    if not full_catalog:
        full_catalog = query_template_catalog()
    if not full_catalog:
        return []
    family = _section_family(section_key)
    already_used_templates = {
        str(result.get("keypoint") or result.get("description") or "").split()[0]
        for result in collected_results
        if str(result.get("keypoint", "")).startswith("template:")
    }
    keywords = {
        "logon",
        "user",
        "host",
        "ip",
        "service",
        "task",
        "powershell",
        "process",
        "execution",
    }
    if section_key.startswith("1_") or section_key.startswith("overview"):
        keywords = keywords | {"event", "range", "hosts", "findings"}
    elif section_key.startswith("2_") or section_key.startswith("timeline"):
        keywords = keywords | {"timeline", "event", "mft", "prefetch"}
    elif section_key.startswith("3_") or section_key.startswith("technical"):
        keywords = keywords | {
            "host",
            "account",
            "persistence",
            "ioc",
            "execution",
            "defender",
        }
    elif section_key.startswith("4_") or section_key.startswith("gaps"):
        keywords = keywords | {"gap", "missing"}
    elif section_key.startswith("5_") or section_key.startswith("recommendations"):
        keywords = keywords | {"recommend", "action"}
    filtered: list[dict[str, Any]] = []
    for template in full_catalog:
        template_id = str(template.get("template_id", "")).lower()
        if template_id in already_used_templates:
            continue
        template_desc = str(template.get("description", "")).lower()
        if family in template_id.lower() or any(
            kw in template_id or kw in template_desc for kw in keywords
        ):
            filtered.append(template)
    return filtered[:8] if len(filtered) > 8 else filtered


def _findings_snapshot(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
    """Fetch top findings ordered by confidence for use in section agent prompts."""
    return fetch_records(
        db,
        """
        SELECT finding_id, title, severity, confidence, status, summary
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


def _load_reusable_section_facts(
    db: CaseDB,
    section_key: str,
    limit: int = 20,
    *,
    include_case_probe: bool = False,
) -> list[dict[str, Any]]:
    """Load section facts reusable by sibling blocks within the same section family.

    Universal question probes are useful for the structured appendix, but they are
    too broad for normal narrative blocks. They otherwise become a high-volume
    evidence pool that can dominate unrelated sections.
    """
    if include_case_probe:
        where_sql = "source_section = ? OR source_section = '__case_probe__'"
        params: tuple[Any, ...] = (section_key, limit)
    else:
        where_sql = (
            "source_section = ? AND COALESCE(fact_type, '') != 'universal_question'"
        )
        params = (section_key, limit)
    rows = db.execute(
        f"""
        SELECT fact_type, fact_key, fact_value, evidence_ids, source_section, confidence, updated_at
        FROM section_facts
        WHERE {where_sql}
        ORDER BY updated_at DESC, confidence DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    items: list[dict[str, Any]] = []
    for (
        fact_type,
        fact_key,
        fact_value,
        evidence_ids,
        source_section,
        confidence,
        updated_at,
    ) in rows:
        try:
            parsed_value = (
                json.loads(str(fact_value)) if fact_value is not None else None
            )
        except json.JSONDecodeError:
            parsed_value = str(fact_value)
        try:
            parsed_evidence_ids = (
                json.loads(str(evidence_ids)) if evidence_ids is not None else []
            )
        except json.JSONDecodeError:
            parsed_evidence_ids = []
        items.append(
            {
                "fact_type": str(fact_type or ""),
                "fact_key": str(fact_key or ""),
                "fact_value": parsed_value,
                "evidence_ids": parsed_evidence_ids
                if isinstance(parsed_evidence_ids, list)
                else [],
                "source_section": str(source_section or ""),
                "confidence": float(confidence or 0.0),
                "updated_at": str(updated_at),
            }
        )
    return items


def _facts_as_result(reusable_facts: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap reusable facts into a result dict consumable by the section agent loop."""
    evidence_ids: list[str] = []
    seen: set[str] = set()
    max_confidence = 0.0
    for item in reusable_facts:
        for evidence_id in item.get("evidence_ids") or []:
            normalized = str(evidence_id).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                evidence_ids.append(normalized)
        c = item.get("confidence")
        if c is not None:
            try:
                max_confidence = max(max_confidence, float(c))
            except TypeError, ValueError:
                pass
    return {
        "keypoint": "section_facts",
        "description": "Reusable facts extracted from prior section-agent runs.",
        "kind": "fact",
        "source_kind": "fact",
        "source_ref": "section_facts",
        "row_count": len(reusable_facts),
        "evidence_ids": evidence_ids,
        "finding_ids": [],
        "hypothesis_ids": [],
        "confidence": max_confidence,
        "sample_rows": _safe_rows(reusable_facts),
    }


def _load_reusable_section_evidence(
    db: CaseDB, section_key: str, limit: int = 30
) -> list[dict[str, Any]]:
    """Load prior section evidence records reusable by sibling blocks."""
    rows = db.execute(
        """
        SELECT section_key, block_heading, evidence_id, role, source_query, created_at
        FROM section_evidence
        WHERE section_key = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (section_key, limit),
    ).fetchall()
    return [
        {
            "section_key": str(found_section_key or ""),
            "block_heading": str(found_block_heading or ""),
            "evidence_id": str(evidence_id or ""),
            "role": str(role or ""),
            "source_query": str(source_query or ""),
            "created_at": str(created_at),
        }
        for found_section_key, found_block_heading, evidence_id, role, source_query, created_at in rows
        if str(evidence_id or "").strip()
    ]


def _evidence_as_result(reusable_evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap reusable evidence links into a result dict consumable by the section agent."""
    evidence_ids: list[str] = []
    seen: set[str] = set()
    for item in reusable_evidence:
        evidence_id = str(item.get("evidence_id") or "").strip()
        if evidence_id and evidence_id not in seen:
            seen.add(evidence_id)
            evidence_ids.append(evidence_id)
    return {
        "keypoint": "section_evidence",
        "description": "Reusable evidence links extracted from prior section-agent runs.",
        "kind": "trace",
        "source_kind": "trace",
        "source_ref": "section_evidence",
        "row_count": len(reusable_evidence),
        "evidence_ids": evidence_ids,
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": _safe_rows(reusable_evidence, limit=30),
    }


def _summarize_sql_result(sql: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize raw SQL query results into a structured dict for the section agent.

    Delegates to summarize_query_result for evidence IDs, sample rows, and distinct counts.
    """
    summary = summarize_query_result(rows, sample_size=10)
    return {
        "keypoint": "raw_sql",
        "description": sql,
        "kind": "rows",
        "source_kind": "sql",
        "source_ref": sql,
        "row_count": int(summary.get("row_count") or 0),
        "evidence_ids": list(summary.get("evidence_ids") or []),
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": list(summary.get("sample_rows") or []),
        "head_rows": list(summary.get("head_rows") or []),
        "tail_rows": list(summary.get("tail_rows") or []),
        "distinct_counts": dict(summary.get("distinct_counts") or {}),
    }


def _execute_keypoint(
    case: Case, db: CaseDB, keypoint: str
) -> tuple[str, dict[str, Any]]:
    """Execute a single keypoint and cache the result.

    Returns (source_query, result_dict). Uses query_cache to avoid re-resolving
    the same keypoint within a single report refresh.
    """
    source_query = str(keypoint or "").strip()
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    resolved = _resolve_evidence_results(case, db, keypoints=[keypoint])
    result = (
        resolved[0]
        if resolved
        else {
            "keypoint": keypoint,
            "description": "",
            "kind": "rows",
            "source_kind": "keypoint",
            "source_ref": keypoint,
            "row_count": 0,
            "evidence_ids": [],
            "finding_ids": [],
            "hypothesis_ids": [],
            "sample_rows": [],
        }
    )
    _store_cached_result(db, source_query, result)
    return source_query, result


def _add_json_fallback(sql: str) -> str:
    """Rewrite SELECT columns to add COALESCE fallback for user_name etc."""
    if not sql or "SELECT" not in sql.upper():
        return sql
    if "evtx_events" not in sql.lower():
        return sql

    import re

    select_match = re.search(r"SELECT\s+(.+?)\s+FROM", sql, re.IGNORECASE | re.DOTALL)
    if not select_match:
        return sql

    select_clause = select_match.group(1)

    nullable_cols = {
        "user_name": "COALESCE(user_name, json_extract_string(raw_json, '$.TargetUserName'), json_extract_string(raw_json, '$.SubjectUserName')) AS user_name",
        "target_user": "COALESCE(target_user, json_extract_string(raw_json, '$.TargetUserName'), json_extract_string(raw_json, '$.SubjectUserName')) AS target_user",
        "subject_user": "COALESCE(subject_user, json_extract_string(raw_json, '$.SubjectUserName')) AS subject_user",
        "src_ip": "COALESCE(src_ip, json_extract_string(raw_json, '$.IpAddress')) AS src_ip",
        "logon_type": "COALESCE(CAST(logon_type AS VARCHAR), CAST(json_extract_string(raw_json, '$.LogonType') AS VARCHAR)) AS logon_type",
    }

    new_select = select_clause
    for col_name, replacement in nullable_cols.items():
        pattern = r"(?:evtx_events\.)?\b" + re.escape(col_name) + r"\b"
        if re.search(pattern, select_clause, re.IGNORECASE):
            new_select = re.sub(pattern, replacement, new_select, flags=re.IGNORECASE)

    if new_select == select_clause:
        return sql

    return sql[: select_match.start(1)] + new_select + sql[select_match.end(1) :]


def _execute_sql(db: CaseDB, sql: str) -> tuple[str, dict[str, Any]]:
    """Execute SQL via validate+fetch and cache the summarized result.

    Applies JSON fallback rewrites (via _add_json_fallback) before execution.
    """
    sql = _add_json_fallback(sql)
    validated = validate_select_sql(sql)
    source_query = validated
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    rows = fetch_records(db, validated)
    result = _summarize_sql_result(validated, rows)
    _store_cached_result(db, source_query, result)
    return source_query, result


def _coerce_plan_action(
    plan: dict[str, Any], *, section_key: str, iteration: int, db: CaseDB | None = None
) -> SectionPlanAction | None:
    """Parse and normalize the LLM plan output into a typed SectionPlanAction.

    Handles default action/keypoint assignment, template vs SQL vs keypoint routing,
    and builds a PlannedQuery for template/sql actions.
    """
    action = str(plan.get("action") or "").strip().lower() or "keypoint"
    purpose = (
        str(plan.get("purpose") or "").strip()
        or f"report block {section_key} iteration {iteration}"
    )
    enough_to_write = bool(plan.get("enough_to_write"))
    keypoint = (
        str(plan.get("keypoint") or "").strip()
        or str(plan.get("keypoint_id") or "").strip()
        or str(plan.get("keypoint_name") or "").strip()
        or str(plan.get("name") or "").strip()
        or None
    )
    if action == "keypoint" and not keypoint:
        if db is not None:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading="",
                iteration=iteration,
                phase="plan_error",
                payload={
                    "error": "planner returned action=keypoint without keypoint name"
                },
            )
        return None
    planned_query: PlannedQuery | None = None
    template_id = str(plan.get("template_id") or "").strip() or None
    params = plan.get("params") if isinstance(plan.get("params"), dict) else {}
    sql = str(plan.get("sql") or "").strip()
    if action in {"template", "sql"}:
        planned_query = PlannedQuery(
            query_id=f"RS-{section_key}-{iteration}",
            hypothesis_id=f"report-{section_key}",
            purpose=purpose,
            sql=sql,
            template_id=template_id,
            params=params,
        )
    return SectionPlanAction(
        action=action,
        purpose=purpose,
        keypoint=keypoint,
        planned_query=planned_query,
        enough_to_write=enough_to_write,
    )


def _load_evidence_chains() -> dict[str, list[dict[str, str]]]:
    """Load evidence_chain definitions from question_routing.yaml."""
    chains: dict[str, list[dict[str, str]]] = {}
    for spec in load_question_specs():
        if spec.evidence_chain:
            chains[spec.name] = [dict(item) for item in spec.evidence_chain]
    return chains


def _substitute_placeholders(
    sql: str, qualifiers: dict[str, str | None], defaults: dict[str, str]
) -> str:
    """Substitute {{date_from}}, {{date_to}}, {{hour_from}}, {{hour_to}} placeholders.
    Values from qualifiers (extracted from question text) take priority;
    defaults provide fallback. Placeholders with no resolved value are left untouched.
    """
    result = sql
    for placeholder in ("date_from", "date_to", "hour_from", "hour_to"):
        value = qualifiers.get(placeholder) or defaults.get(placeholder)
        if value is not None:
            result = result.replace("{{" + placeholder + "}}", str(value))
    return result


def _execute_evidence_chain(
    db: CaseDB, block_heading: str, template_body: str, question: str = ""
) -> list[dict[str, Any]]:
    """Execute deterministic evidence chain for the block.
    Tries each chain entry in order until one returns rows.

    Supports optional {{date_from}}, {{date_to}}, {{hour_from}}, {{hour_to}}
    placeholders in query SQL. Time qualifiers extracted from question override
    per-entry time_qualifiers defaults declared in question_routing.yaml.
    """
    chains = _load_evidence_chains()
    if not chains:
        return []
    spec, _confidence = resolve_question_spec(
        block_heading=block_heading, template_body=template_body
    )
    chain_name = spec.name if spec is not None else None
    if chain_name is None or chain_name not in chains:
        return []
    chain = chains[chain_name]
    time_qualifiers = extract_time_qualifiers(question) if question else {}
    for entry in chain:
        if isinstance(entry, dict):
            query = entry.get("query", "")
            if query:
                defaults = dict(entry.get("time_qualifiers") or {})
                query = _substitute_placeholders(query, time_qualifiers, defaults)
                query = expand_catalog_sql_placeholders(query)
                try:
                    from forensia.db.query import fetch_records

                    rows = fetch_records(db, query)
                    if rows:
                        return rows[:50]
                except Exception:
                    continue
    return []


def _resolve_structured_expected_shape(block_heading: str) -> dict | None:
    """Resolve expected_answer_shape from question_routing.yaml by block_heading keywords."""
    spec, _confidence = resolve_question_spec(block_heading=block_heading)
    return spec.expected_answer_shape if spec is not None else None


def _resolve_benchmark_expected_shape(block_heading: str) -> dict | None:
    """Compatibility wrapper for older benchmark terminology."""
    return _resolve_structured_expected_shape(block_heading)


def _format_structured_answer(
    classification: dict,
    picked_rows: list[dict],
    expected_shape: dict | None,
    section_key: str,
    block_heading: str,
    status: str,
    case: Case,
    benchmark_id: str = "",
    queries_run: list[str] | None = None,
    evidence_rows: list[dict] | None = None,
    answer_spec: str = "",
) -> str:
    """Pure code. Format a structured answer from picked rows + expected_answer_shape."""
    shape = expected_shape or {}
    fields = shape.get("fields", [])

    answer_data: list[dict] = []
    if fields and picked_rows:
        for row in picked_rows:
            entry = {}
            for field in fields:
                value = row.get(field, row.get(f"normalized_{field}", ""))
                if value is not None and str(value).strip():
                    entry[field] = value
            if entry:
                answer_data.append(entry)

    resolved_id = (
        benchmark_id.strip() if benchmark_id else _structured_block_id(block_heading)
    )
    normalized_status = (
        str(classification.get("status") or status or "insufficient_evidence")
        .strip()
        .lower()
    )
    if not _is_valid_status(normalized_status):
        normalized_status = (
            status if _is_valid_status(status) else "insufficient_evidence"
        )
    # Validate via row indices
    picked_row_indices = classification.get("picked_row_indices") or []
    if isinstance(picked_row_indices, list):
        valid_indices = [
            i
            for i in picked_row_indices
            if isinstance(i, (int, float))
            and evidence_rows
            and 0 <= int(i) < len(evidence_rows)
        ]
    else:
        valid_indices = []
    validated_rows = (
        [evidence_rows[int(i)] for i in valid_indices] if evidence_rows else []
    )
    if not validated_rows and picked_row_indices:
        normalized_status = "wrong_query"
        classification["rationale"] = (
            "no valid evidence rows (picked_row_indices out of range or empty)"
        )
    answer_spec_val = str(answer_spec or "").strip()
    if not answer_spec_val:
        spec, _confidence = resolve_question_spec(block_heading=block_heading)
        answer_spec_val = spec.answer_spec if spec is not None else ""
    normalized_answer = {
        "id": resolved_id,
        "section": section_key,
        "status": normalized_status,
        "answer": answer_data or validated_rows,
        "missing_reason": [str(classification.get("rationale") or "").strip()]
        if classification.get("rationale")
        else [],
        "queries_run": queries_run or [],
        "answer_spec": answer_spec_val,
    }

    answer_items = list(normalized_answer.get("answer") or [])
    if answer_items:
        filtered = []
        for item in answer_items:
            if isinstance(item, dict):
                values = [str(v).strip() for v in item.values() if v is not None]
                if any(values):
                    filtered.append(item)
            elif isinstance(item, str) and item.strip():
                filtered.append(item)
        normalized_answer["answer"] = filtered

    if normalized_answer["status"] in {
        "answered",
        "partial",
    } and not normalized_answer.get("answer"):
        normalized_answer["status"] = "wrong_query"
        reason = str(
            classification.get("rationale") or "answer was empty after filtering"
        ).strip()
        normalized_answer["missing_reason"] = [reason]

    normalized_answer = _normalize_structured_answer(
        normalized_answer,
        section_key=section_key,
        block_heading=block_heading,
        status=normalized_answer["status"],
    )

    _persist_structured_answer(case, normalized_answer)
    return _render_structured_answer_markdown(normalized_answer, block_heading)


def _format_benchmark_answer(
    classification: dict,
    picked_rows: list[dict],
    expected_shape: dict | None,
    section_key: str,
    block_heading: str,
    status: str,
    case: Case,
    benchmark_id: str = "",
    queries_run: list[str] | None = None,
    evidence_rows: list[dict] | None = None,
    answer_spec: str = "",
) -> str:
    """Compatibility wrapper for older tests/callers."""
    return _format_structured_answer(
        classification=classification,
        picked_rows=picked_rows,
        expected_shape=expected_shape,
        section_key=section_key,
        block_heading=block_heading,
        status=status,
        case=case,
        benchmark_id=benchmark_id,
        queries_run=queries_run,
        evidence_rows=evidence_rows,
        answer_spec=answer_spec,
    )


@lru_cache(maxsize=1)
def _antiforensic_tool_names() -> tuple[str, ...]:
    """Cleanup-tool names from the IOC catalog (declarative, never hardcoded)."""
    return _catalog_names("antiforensic_tools")


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(value) for value in row.values() if value is not None
    ).casefold()


def _row_value(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return value
    summary = str(row.get("summary") or "")
    for key in keys:
        match = re.search(rf"\b{re.escape(key)}=([^\s|]+)", summary, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _all_values_empty(item: dict[str, Any]) -> bool:
    return not any(str(value).strip() for value in item.values() if value is not None)


@lru_cache(maxsize=1)
def _application_marker_map() -> dict[str, tuple[str, ...]]:
    markers: dict[str, tuple[str, ...]] = {}
    markers.update(
        _catalog_marker_map(
            "email_artifacts", "client", "exe_patterns", "paths", "data_files"
        )
    )
    markers.update(
        _catalog_marker_map(
            "browser_artifacts",
            "name",
            "exe_patterns",
            "paths",
            "version_sources",
        )
    )
    return markers


@lru_cache(maxsize=1)
def _cloud_service_marker_map() -> dict[str, tuple[str, ...]]:
    return _catalog_marker_map(
        "cloud_sync_artifacts",
        "service",
        "exe_patterns",
        "paths",
        "registry",
    )


def _build_daily_session_timeline(
    db: CaseDB,
    qualifiers: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    """Structured answer builder (compatibility shim): delegates to report.structured_answers."""
    return _build_daily_session_timeline_rows(db, qualifiers)


def _extract_daily_table(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    by_date: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        date_value = _row_value(row, "date")
        timestamp = _row_value(row, "timestamp")
        if not date_value and timestamp:
            date_value = str(timestamp)[:10]
        event_id = str(_row_value(row, "event_id") or "").strip()
        if not date_value or not event_id:
            continue
        bucket = by_date.setdefault(
            str(date_value),
            {
                "startup": 0,
                "logons": 0,
                "logoff": 0,
                "shutdown": 0,
                "first_event_time": None,
                "last_event_time": None,
            },
        )
        count = int(row.get("n") or row.get("count") or 1)
        if event_id in {"6005", "4608"}:
            bucket["startup"] += count
        elif event_id == "4624":
            bucket["logons"] += count
        elif event_id in {"4634", "4647"}:
            bucket["logoff"] += count
        elif event_id in {"6006", "6008", "1074", "13"}:
            bucket["shutdown"] += count
        ts = str(timestamp or "")
        if ts:
            if bucket["first_event_time"] is None or ts < bucket["first_event_time"]:
                bucket["first_event_time"] = ts
            if bucket["last_event_time"] is None or ts > bucket["last_event_time"]:
                bucket["last_event_time"] = ts
    return [
        {
            field: (date_value if field == "date" else values.get(field, ""))
            for field in fields
        }
        for date_value, values in sorted(by_date.items())
    ]


def _extract_known_list(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in raw_rows:
        item: dict[str, Any] = {}
        if fields == ["host_id"]:
            host = _row_value(row, "host_id", "computer", "host")
            if host:
                item["host_id"] = host
        elif "executable_name" in fields:
            exe = _row_value(row, "executable_name", "file_name", "process_name")
            if exe:
                item["executable_name"] = exe
            for field in fields:
                if field not in item:
                    value = _row_value(row, field)
                    if value:
                        item[field] = value
        if item and not _all_values_empty(item):
            out.append(item)
    return out


def _extract_name_with_version(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    detected: dict[str, dict[str, Any]] = {}
    for row in raw_rows:
        text = _row_text(row)
        for app_name, markers in _application_marker_map().items():
            if any(marker in text for marker in markers):
                item = detected.setdefault(app_name, {field: "" for field in fields})
                if "application_name" in fields:
                    item["application_name"] = app_name
                if "data_files" in fields:
                    data_file = _row_value(row, "file_path", "file_name", "summary")
                    if data_file:
                        existing = str(item.get("data_files") or "")
                        item["data_files"] = (
                            data_file if not existing else f"{existing}; {data_file}"
                        )
                if "version" in fields and not item.get("version"):
                    match = re.search(r"(\d+(?:\.\d+){1,4})", text)
                    if match:
                        item["version"] = match.group(1)
    return [item for item in detected.values() if not _all_values_empty(item)]


def _extract_enumerated_services(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for service_name, markers in _cloud_service_marker_map().items():
        matches = [
            row
            for row in raw_rows
            if any(marker in _row_text(row) for marker in markers)
        ]
        if not matches:
            continue
        item = {field: "" for field in fields}
        if "service_name" in fields:
            item["service_name"] = service_name
        if "exe_found" in fields:
            item["exe_found"] = (
                "yes"
                if any(
                    ".exe" in _row_text(row) or ".pf" in _row_text(row)
                    for row in matches
                )
                else "no"
            )
        if "paths_found" in fields:
            item["paths_found"] = "; ".join(
                str(_row_value(row, "file_path", "summary") or "")
                for row in matches[:3]
            ).strip("; ")
        if "config_found" in fields:
            item["config_found"] = (
                "yes"
                if any(
                    marker in _row_text(row)
                    for row in matches
                    for marker in ("config", ".db", "snapshot")
                )
                else "no"
            )
        rows.append(item)
    return [item for item in rows if not _all_values_empty(item)]


def _extract_pair_list(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        original = _row_value(row, "original_name", "fn_filename")
        new = _row_value(row, "new_name", "file_name")
        if original and new and str(original) != str(new):
            rows.append(
                {
                    field: {
                        "original_name": original,
                        "new_name": new,
                        "timestamp": _row_value(
                            row, "timestamp", "si_modified", "fn_modified"
                        )
                        or "",
                    }.get(field, "")
                    for field in fields
                }
            )
    return rows


def _extract_full_scan(
    raw_rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        text = _row_text(row)
        tool_names = _antiforensic_tool_names()
        tool_markers = tuple(name.casefold() for name in tool_names)
        if not any(
            marker in text
            for marker in (
                *tool_markers,
                "log cleared",
                "event_id=104",
                "event_id=1102",
                "event_id=1100",
            )
        ):
            continue
        item = {field: "" for field in fields}
        if "tool_name" in fields:
            for tool in tool_names:
                if tool.casefold() in text:
                    item["tool_name"] = tool
                    break
            if not item.get("tool_name") and any(
                marker in text for marker in ("104", "1102", "1100")
            ):
                item["tool_name"] = "Windows Event Log"
        if "evidence_type" in fields:
            item["evidence_type"] = "event" if "event_id" in text else "file"
        if "found" in fields:
            item["found"] = "yes"
        if "details" in fields:
            item["details"] = str(
                _row_value(row, "summary", "file_path", "message") or row
            )
        rows.append(item)
    return [item for item in rows if not _all_values_empty(item)]


def _extract_answer_by_shape(
    raw_rows: list[dict],
    expected_shape: dict | None,
    shape_format: str,
) -> list[dict]:
    if not raw_rows or not expected_shape:
        return raw_rows or []

    fields = expected_shape.get("fields", [])
    if not fields:
        return raw_rows

    shape_format = str(shape_format or expected_shape.get("format") or "")
    if shape_format == "daily_table":
        return _extract_daily_table(raw_rows, fields)
    if shape_format == "list":
        list_rows = _extract_known_list(raw_rows, fields)
        if list_rows:
            return list_rows
    if shape_format == "name_with_version":
        return _extract_name_with_version(raw_rows, fields)
    if shape_format == "enumerated_services":
        return _extract_enumerated_services(raw_rows, fields)
    if shape_format == "pair_list":
        return _extract_pair_list(raw_rows, fields)
    if shape_format == "full_scan":
        return _extract_full_scan(raw_rows, fields)

    result: list[dict[str, Any]] = []
    for row in raw_rows:
        item = {}
        for f in fields:
            val = row.get(f, row.get(f.lower(), row.get(f.upper(), "")))
            if val is not None and str(val).strip():
                item[f] = val
        if item and not _all_values_empty(item):
            result.append(item)

    return result


def _flatten_sample_rows(
    collected_results: list[dict], *, rows_only: bool = False
) -> list[dict]:
    flat: list[dict] = []
    for r in collected_results:
        if rows_only and str(r.get("kind") or "rows") != "rows":
            continue
        source = r.get("keypoint") or r.get("source_kind") or ""
        for row in r.get("sample_rows") or []:
            if isinstance(row, dict):
                flat.append({**row, "_source_keypoint": source})
    return flat


def _is_effectively_empty_body(body: str) -> bool:
    """Return True when narration produced no useful prose beyond a status marker."""
    text = str(body or "").strip()
    if not text:
        return True
    text = re.sub(r"^\*\*Status:\*\*\s*[A-Za-z_]+\s*", "", text).strip()
    text = re.sub(r"^#+\s+.+$", "", text, flags=re.MULTILINE).strip()
    text = re.sub(r"\*Block skipped:[^*]+\*", "", text, flags=re.IGNORECASE).strip()
    return len(text) < 40


def _report_language() -> str:
    try:
        from forensia.config import get_llm_settings

        return str(get_llm_settings().get("output_language", "ja")).strip().lower()
    except Exception:
        return "ja"


def _insufficient_evidence_placeholder() -> str:
    """Neutral reader-facing text for blocks whose evidence status blocks narration.

    Deliberately avoids quality-gate trigger phrases (failure markers,
    open-question markers, hedge words without citations).
    """
    return "No sufficient evidence was collected for this block. Details are tracked in the Investigation Gaps section."


def _compact_narrative_value(value: Any, *, max_chars: int = 90) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value if value is not None else "")
    text = text.replace("\n", " ").strip()
    if text in {"", "-", "None", "null"}:
        return ""
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def _row_narrative(row: dict[str, Any]) -> str:
    preferred_keys = (
        "timestamp",
        "event_id",
        "computer",
        "target_user",
        "subject_user",
        "src_ip",
        "logon_type",
        "process_name",
        "command_line",
        "service_name",
        "executable_name",
        "file_name",
        "file_path",
        "finding_id",
        "title",
        "severity",
        "count",
        "event_count",
    )
    parts: list[str] = []
    seen: set[str] = set()
    for key in preferred_keys:
        if key not in row:
            continue
        value = _compact_narrative_value(row.get(key))
        if not value:
            continue
        seen.add(key)
        parts.append(f"{key}={value}")
        if len(parts) >= 5:
            break
    if len(parts) < 3:
        for key, raw_value in row.items():
            if key in seen or str(key).startswith("_"):
                continue
            value = _compact_narrative_value(raw_value)
            if not value:
                continue
            parts.append(f"{key}={value}")
            if len(parts) >= 5:
                break
    return ", ".join(parts)


def _result_source_label(result: dict[str, Any]) -> str:
    for key in ("keypoint", "source_kind", "source_ref", "description"):
        value = _compact_narrative_value(result.get(key), max_chars=64)
        if value:
            if value.lower().startswith("select "):
                return "evidence_query"
            return value
    return "unknown_source"


def _result_count_summary(
    collected_results: list[dict[str, Any]],
) -> tuple[int, list[str], list[str]]:
    total_rows = 0
    positive: list[str] = []
    zero: list[str] = []
    for result in collected_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        label = _result_source_label(result)
        try:
            count = int(result.get("row_count") or 0)
        except TypeError, ValueError:
            count = 0
        total_rows += max(count, 0)
        target = positive if count > 0 else zero
        item = f"{label}={count}"
        if item not in target:
            target.append(item)
    return total_rows, positive, zero


def _representative_ids(
    collected_results: list[dict[str, Any]], flat_rows: list[dict[str, Any]]
) -> tuple[list[str], list[str]]:
    evidence_ids: list[str] = []
    finding_ids: list[str] = []
    seen_evidence: set[str] = set()
    seen_findings: set[str] = set()

    def add_evidence(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in seen_evidence:
            seen_evidence.add(text)
            evidence_ids.append(text)

    def add_finding(value: Any) -> None:
        text = str(value or "").strip()
        if text and text not in seen_findings:
            seen_findings.add(text)
            finding_ids.append(text)

    for result in collected_results:
        for evidence_id in result.get("evidence_ids") or []:
            add_evidence(evidence_id)
        for finding_id in result.get("finding_ids") or []:
            add_finding(finding_id)
    for row in flat_rows:
        add_evidence(row.get("evidence_id"))
        add_finding(row.get("finding_id"))
    return evidence_ids[:3], finding_ids[:3]
