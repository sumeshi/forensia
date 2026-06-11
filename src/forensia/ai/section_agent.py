from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from forensia.ai.checker import summarize_query_result
from forensia.ai.json_response import async_request_llm_json, request_llm_json
from forensia.ai.prompts import (
    _enforce_system_budget,
    build_paragraph_narrate_messages,
    build_report_section_messages,
    build_section_agent_check_messages,
    build_section_agent_plan_messages,
    build_section_outline_messages,
    build_structured_classify_messages,
)
from forensia.ai.question_registry import (
    QuestionSpec,
    extract_time_qualifiers,
    load_question_specs,
    resolve_question_spec,
)
from forensia.ai.sql_templates import query_template_catalog, render_query_template, validate_select_sql
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.writer import _default_keypoints_for_section, _feed_structured_to_timeline


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
        except (TypeError, ValueError):
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


def _question_routing_rule(block_heading: str, template_body: str) -> QuestionSpec | None:
    spec, _confidence = resolve_question_spec(block_heading=block_heading, template_body=template_body)
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
    from forensia.report.writer import _load_structured_answers

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

        answer_spec = str(answer.get("answer_spec") or "").strip() or str(answer.get("id") or "?")
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
            for ts_key in ("timestamp", "logon_time", "last_exec_time", "si_modified", "date", "shutdown_time", "first_event_time"):
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

    digest = "<STRUCTURED_OBSERVATIONS>\n" + "\n".join(lines) + "\n</STRUCTURED_OBSERVATIONS>"
    if len(digest) > 1500:
        digest = digest[:1497] + "..."
    return digest


def _benchmark_report_brief(report_brief: dict[str, Any] | None) -> dict[str, Any]:
    """Strip narrative-heavy fields from report_brief for benchmark mode.

    Benchmark blocks must only receive factual inventories, not LLM-generated
    narratives, to prevent answer leakage.
    """
    brief = dict(report_brief or {})
    keys_to_keep = {"evidence_inventory", "table_inventory", "row_counts", "time_range", "time_window", "source_inventory"}
    if "evidence_inventory" in brief:
        evidence_inventory = brief.get("evidence_inventory")
        if isinstance(evidence_inventory, dict):
            brief["evidence_inventory"] = {
                key: value for key, value in evidence_inventory.items() if key in keys_to_keep
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

    def inner(messages: list[dict[str, str]], output: str, parsed: dict[str, Any]) -> None:
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
        normalized = {"sufficient": "block_supported", "refuted": "block_contradicted"}.get(verdict, verdict)
        from forensia.core.verdicts import assert_valid_verdict
        assert_valid_verdict(normalized, "section_verdict")
    run_id = hashlib.sha1(
        f"{section_key}-{block_heading}-{iteration}-{phase}-{json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)}".encode(
            "utf-8"
        )
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
        f"{section_key}\n{block_heading}\n{normalized_text}\n{spec.semantic_id if spec else ''}".encode("utf-8")
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


def _load_prior_runs(db: CaseDB, section_key: str, block_heading: str) -> list[dict[str, Any]]:
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


def _store_cached_result(db: CaseDB, source_query: str, payload: dict[str, Any]) -> None:
    db.execute(
        """
        INSERT INTO query_cache (sql_hash, sql_text, result_json, executed_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT (sql_hash) DO UPDATE SET
            sql_text = excluded.sql_text,
            result_json = excluded.result_json,
            executed_at = excluded.executed_at
        """,
        (_cache_key(source_query), source_query, json.dumps(payload, ensure_ascii=False, default=str), _now()),
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
    evidence_ids = [str(item).strip() for item in (result.get("evidence_ids") or []) if str(item).strip()]
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
    evidence_ids = [str(item).strip() for item in (result.get("evidence_ids") or []) if str(item).strip()]
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
        fact_id = hashlib.sha1(f"{fact_type}-{fact_key}".encode("utf-8")).hexdigest()[:20]
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
    from forensia.report.writer import REPORT_KEYPOINTS, REPORT_KEYPOINT_ALIASES, _default_keypoints_for_section

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

    routed_keypoints = _question_routing_keypoints(block_heading or "", template_body or "")
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
        keywords = {"logon", "user", "host", "ip", "service", "task", "powershell", "process", "execution", "event", "finding", "persistence", "defender"}
        filtered: list[dict[str, str]] = []
        for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items()):
            lowered = template_body.lower()
            if any(kw in lowered and (kw in keypoint.lower() or kw in description.lower()) for kw in keywords):
                filtered.append({"name": keypoint, "description": description})
            if len(filtered) >= 10:
                break
        if filtered:
            return filtered
        return [{"name": keypoint, "description": description} for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items())[:10]]

    preferred = _default_keypoints_for_section(section_key, block_heading=block_heading or "")
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
    full_catalog: list[dict[str, Any]], section_key: str, collected_results: list[dict[str, Any]]
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
    keywords = {"logon", "user", "host", "ip", "service", "task", "powershell", "process", "execution"}
    if section_key.startswith("1_") or section_key.startswith("overview"):
        keywords = keywords | {"event", "range", "hosts", "findings"}
    elif section_key.startswith("2_") or section_key.startswith("timeline"):
        keywords = keywords | {"timeline", "event", "mft", "prefetch"}
    elif section_key.startswith("3_") or section_key.startswith("technical"):
        keywords = keywords | {"host", "account", "persistence", "ioc", "execution", "defender"}
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
        if family in template_id.lower() or any(kw in template_id or kw in template_desc for kw in keywords):
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
        where_sql = "source_section = ? AND COALESCE(fact_type, '') != 'universal_question'"
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
    for fact_type, fact_key, fact_value, evidence_ids, source_section, confidence, updated_at in rows:
        try:
            parsed_value = json.loads(str(fact_value)) if fact_value is not None else None
        except json.JSONDecodeError:
            parsed_value = str(fact_value)
        try:
            parsed_evidence_ids = json.loads(str(evidence_ids)) if evidence_ids is not None else []
        except json.JSONDecodeError:
            parsed_evidence_ids = []
        items.append(
            {
                "fact_type": str(fact_type or ""),
                "fact_key": str(fact_key or ""),
                "fact_value": parsed_value,
                "evidence_ids": parsed_evidence_ids if isinstance(parsed_evidence_ids, list) else [],
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
    for item in reusable_facts:
        for evidence_id in item.get("evidence_ids") or []:
            normalized = str(evidence_id).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                evidence_ids.append(normalized)
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
        "sample_rows": _safe_rows(reusable_facts),
    }


def _load_reusable_section_evidence(db: CaseDB, section_key: str, limit: int = 30) -> list[dict[str, Any]]:
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


def _execute_keypoint(case: Case, db: CaseDB, keypoint: str) -> tuple[str, dict[str, Any]]:
    """Execute a single keypoint and cache the result.

    Returns (source_query, result_dict). Uses query_cache to avoid re-resolving
    the same keypoint within a single report refresh.
    """
    from forensia.report.writer import _resolve_evidence_results

    source_query = str(keypoint or "").strip()
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    resolved = _resolve_evidence_results(case, db, keypoints=[keypoint])
    result = resolved[0] if resolved else {
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
    _store_cached_result(db, source_query, result)
    return source_query, result


def _add_json_fallback(sql: str) -> str:
    """Rewrite SELECT columns to add COALESCE fallback for user_name etc."""
    if not sql or "SELECT" not in sql.upper():
        return sql
    if "evtx_events" not in sql.lower():
        return sql

    import re

    select_match = re.search(r'SELECT\s+(.+?)\s+FROM', sql, re.IGNORECASE | re.DOTALL)
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
        pattern = r'(?:evtx_events\.)?\b' + re.escape(col_name) + r'\b'
        if re.search(pattern, select_clause, re.IGNORECASE):
            new_select = re.sub(pattern, replacement, new_select, flags=re.IGNORECASE)

    if new_select == select_clause:
        return sql

    return sql[:select_match.start(1)] + new_select + sql[select_match.end(1):]


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


def _coerce_plan_action(plan: dict[str, Any], *, section_key: str, iteration: int, db: CaseDB | None = None) -> SectionPlanAction | None:
    """Parse and normalize the LLM plan output into a typed SectionPlanAction.

    Handles default action/keypoint assignment, template vs SQL vs keypoint routing,
    and builds a PlannedQuery for template/sql actions.
    """
    action = str(plan.get("action") or "").strip().lower() or "keypoint"
    purpose = str(plan.get("purpose") or "").strip() or f"report block {section_key} iteration {iteration}"
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
                payload={"error": "planner returned action=keypoint without keypoint name"},
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


def _substitute_placeholders(sql: str, qualifiers: dict[str, str | None], defaults: dict[str, str]) -> str:
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


def _execute_evidence_chain(db: CaseDB, block_heading: str, template_body: str, question: str = "") -> list[dict[str, Any]]:
    """Execute deterministic evidence chain for the block.
    Tries each chain entry in order until one returns rows.

    Supports optional {{date_from}}, {{date_to}}, {{hour_from}}, {{hour_to}}
    placeholders in query SQL. Time qualifiers extracted from question override
    per-entry time_qualifiers defaults declared in question_routing.yaml.
    """
    chains = _load_evidence_chains()
    if not chains:
        return []
    spec, _confidence = resolve_question_spec(block_heading=block_heading, template_body=template_body)
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
                try:
                    from forensia.db.query import fetch_records
                    rows = fetch_records(db, query)
                    if rows:
                        return rows[:50]
                except Exception:
                    continue
    return []



@dataclass(slots=True)
class _BlockContext:
    case: Case
    db: CaseDB
    section_key: str
    title: str
    block_heading: str
    template_body: str
    base_url: str
    model: str
    audit: Callable | None
    keypoint_catalog: list[dict]
    template_catalog: list[dict]
    reusable_facts: list[dict[str, Any]]
    reusable_evidence: list[dict[str, Any]]
    memory_context_md: str
    benchmark_mode: bool
    max_queries: int
    findings_snapshot: list[dict[str, Any]]
    prompt_report_brief: dict[str, Any]
    question_spec: QuestionSpec | None = None
    question_confidence: float = 0.0
    evidence_keypoints: list[str] | None = None
    benchmark_id: str = ""
    answer_id: str = ""
    answer_spec: str = ""
    question: str = ""
    structured_digest: str = ""


def _prepare_block_context(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    base_url: str,
    model: str,
    memory: MemoryManager | None,
    max_queries: int,
    evidence_keypoints: list[str] | None,
    benchmark_mode: bool,
    benchmark_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    audit_callback=None,
    report_brief: dict[str, Any] | None = None,
) -> _BlockContext:
    routing_text = f"{question}\n{template_body}".strip() if question else template_body
    question_spec, question_confidence = resolve_question_spec(
        block_heading=block_heading,
        template_body=routing_text,
        question=question,
        answer_spec=answer_spec,
    )
    resolved_answer_spec = answer_spec or (question_spec.answer_spec if question_spec is not None else "")
    _store_section_question(
        db,
        section_key=section_key,
        block_heading=block_heading,
        question_text=question or block_heading or template_body[:200],
        spec=question_spec,
        confidence=question_confidence,
    )
    memory_context_md = ""
    if memory is not None:
        memory_context_md = memory.load_investigation_context(
            None,
            max_bytes=max(1024, memory.max_bytes // 2),
            include_overview=False,
            include_scratch=False,
        )
    findings_snapshot = _findings_snapshot(db)
    keypoint_catalog = _keypoint_catalog(
        section_key,
        template_body,
        block_heading=block_heading,
        evidence_keypoints=evidence_keypoints,
    )
    template_catalog = _filter_template_catalog_by_section([], section_key, [])
    reusable_facts = _load_reusable_section_facts(
        db,
        section_key,
        include_case_probe=section_key == "6_appendix",
    )
    reusable_evidence = _load_reusable_section_evidence(db, section_key)
    if benchmark_mode:
        reusable_facts = []
        reusable_evidence = []
    audit = _audit_bridge(audit_callback)
    prompt_report_brief = _structured_report_brief(report_brief) if benchmark_mode else (report_brief or {})
    structured_digest = _structured_digest_from_answers(case) if section_key in {"1_overview", "2_timeline"} else ""
    return _BlockContext(
        case=case,
        db=db,
        section_key=section_key,
        title=title,
        block_heading=block_heading,
        template_body=template_body,
        base_url=base_url,
        model=model,
        audit=audit,
        keypoint_catalog=keypoint_catalog,
        template_catalog=template_catalog,
        reusable_facts=reusable_facts,
        reusable_evidence=reusable_evidence,
        memory_context_md=memory_context_md,
        benchmark_mode=benchmark_mode,
        max_queries=max_queries,
        findings_snapshot=findings_snapshot,
        prompt_report_brief=prompt_report_brief,
        question_spec=question_spec,
        question_confidence=question_confidence,
        evidence_keypoints=evidence_keypoints,
        benchmark_id=benchmark_id,
        answer_id=answer_id,
        answer_spec=resolved_answer_spec,
        question=question,
        structured_digest=structured_digest,
    )

# ====================================================================
# PLAN/CHECK — plan and check phase logic
# Lines: ~1177-1400
# ====================================================================


def _run_block_plan(
    ctx: _BlockContext,
    iteration: int,
    prior_runs: list[dict[str, Any]],
    template_catalog: list[dict[str, Any]],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
) -> SectionPlanAction | None:
    plan_messages, plan_schema = build_section_agent_plan_messages(
        section_key=ctx.section_key,
        section_title=ctx.title,
        block_heading=ctx.block_heading,
        template_body=ctx.template_body,
        report_brief=ctx.prompt_report_brief,
        context_sections=context_sections,
        current_section_outline=current_section_outline,
        findings_snapshot=ctx.findings_snapshot,
        keypoint_catalog=ctx.keypoint_catalog,
        query_template_catalog=template_catalog,
        prior_runs=prior_runs,
        reusable_facts=ctx.reusable_facts,
        reusable_evidence=ctx.reusable_evidence,
        memory_context_md=ctx.memory_context_md,
        evidence_keypoints=ctx.evidence_keypoints,
        question_spec=ctx.question_spec.to_prompt_dict() if ctx.question_spec is not None else None,
        db=ctx.db,
    )
    # R3-07: Enforce system message budget at message assembly level
    if plan_messages and plan_messages[0].get("role") == "system":
        plan_messages[0]["content"] = _enforce_system_budget(plan_messages[0]["content"])
    try:
        plan = request_llm_json(
            messages=plan_messages,
            model=ctx.model,
            base_url=ctx.base_url,
            json_schema=plan_schema,
            audit_callback=ctx.audit,
        )
    except Exception as exc:
        _store_section_run(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            iteration=iteration,
            phase="plan_error",
            payload={"error": str(exc)},
        )
        return None
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="plan",
        payload=plan,
    )
    return _coerce_plan_action(plan, section_key=ctx.section_key, iteration=iteration, db=ctx.db)


def _execute_block_plan(
    ctx: _BlockContext,
    plan_action: SectionPlanAction,
    iteration: int,
) -> tuple[str, dict[str, Any]] | None:
    if plan_action.action == "keypoint":
        keypoint = plan_action.keypoint
        if not keypoint:
            if ctx.benchmark_mode:
                _store_section_run(ctx.db, section_key=ctx.section_key, block_heading=ctx.block_heading,
                                   iteration=iteration, phase="plan_error",
                                   payload={"error": "benchmark_mode: no keypoint name and default not allowed"})
                return None
            defaults = _default_keypoints_for_section(ctx.section_key, block_heading=ctx.block_heading)
            keypoint = defaults[0] if defaults else None
        if not keypoint:
            _store_section_run(ctx.db, section_key=ctx.section_key, block_heading=ctx.block_heading,
                               iteration=iteration, phase="plan_error",
                               payload={"error": "planner returned action=keypoint without keypoint name and no default available"})
            return None
        kp_parts = _split_keypoint_names(keypoint)
        source_query = None
        result = None
        for kp in kp_parts:
            sq, res = _execute_keypoint(ctx.case, ctx.db, kp)
            if result is None:
                source_query, result = sq, res
            else:
                for eid in (res.get("evidence_ids") or []):
                    sid = str(eid).strip()
                    if sid and sid not in {str(e).strip() for e in (result.get("evidence_ids") or [])}:
                        result.setdefault("evidence_ids", []).append(sid)
                if res.get("sample_rows"):
                    result.setdefault("sample_rows", []).extend(res["sample_rows"])
                if res.get("row_count"):
                    result["row_count"] = (result.get("row_count") or 0) + int(res["row_count"])
        if result is None:
            _store_section_run(ctx.db, section_key=ctx.section_key, block_heading=ctx.block_heading,
                               iteration=iteration, phase="query_error",
                               payload={"error": "all keypoint parts returned None"})
            return None
    elif plan_action.action in {"template", "sql"}:
        planned_query = plan_action.planned_query
        if planned_query is None or not planned_query.sql:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": "No SQL in planned_query"},
            )
            return None
        try:
            source_query, result = _execute_sql(ctx.db, planned_query.sql)
        except Exception as exc:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": str(exc), "sql": planned_query.sql},
            )
            return None
    else:
        return None
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="query",
        payload={
            "source_kind": str(result.get("source_kind") or "unknown"),
            "source_ref": str(result.get("source_ref") or source_query),
            "result": result,
        },
    )
    if str(result.get("kind") or "rows") == "rows":
        _store_section_evidence(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            result=result,
            source_query=source_query,
        )
    return source_query, result


def _select_columns_by_template(
    raw_rows: list[dict[str, Any]],
    section_key: str,
    template_body: str,
) -> list[dict[str, Any]]:
    if not raw_rows:
        return raw_rows
    headers = list(raw_rows[0].keys())
    tpl_cf = template_body.casefold()
    mentioned = [h for h in headers if h.casefold() in tpl_cf]
    if mentioned:
        return [{c: row[c] for c in mentioned} for row in raw_rows]
    return raw_rows


def _run_block_check(
    ctx: _BlockContext,
    iteration: int,
    result: dict[str, Any],
    collected_results: list[dict[str, Any]],
    prior_runs: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    source_query: str,
) -> tuple[str, str, list[Any], str] | None:
    check_messages, check_schema = build_section_agent_check_messages(
        section_key=ctx.section_key,
        section_title=ctx.title,
        block_heading=ctx.block_heading,
        template_body=ctx.template_body,
        collected_results=collected_results,
        latest_result=result,
        prior_runs=prior_runs,
        reusable_facts=ctx.reusable_facts,
        reusable_evidence=ctx.reusable_evidence,
        memory_context_md=ctx.memory_context_md,
        question_spec=ctx.question_spec.to_prompt_dict() if ctx.question_spec is not None else None,
    )
    # R3-07: Enforce system message budget at message assembly level
    if check_messages and check_messages[0].get("role") == "system":
        check_messages[0]["content"] = _enforce_system_budget(check_messages[0]["content"])
    try:
        check = request_llm_json(
            messages=check_messages,
            model=ctx.model,
            base_url=ctx.base_url,
            json_schema=check_schema,
            audit_callback=ctx.audit,
        )
    except Exception as exc:
        _store_section_run(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            iteration=iteration,
            phase="check_error",
            payload={"error": str(exc)},
        )
        return None
    verdict = str(check.get("verdict") or "block_needs_more").strip().lower()
    rationale = str(check.get("rationale") or "")
    missing_questions = check.get("missing_questions") if isinstance(check.get("missing_questions"), list) else []
    status = str(check.get("status") or "").strip().lower()
    result["source_verdict"] = verdict
    if not _is_valid_status(status):
        reusable_rows_present = any(str(item.get("kind") or "rows") != "rows" for item in collected_results)
        status = _classify_block_status(
            verdict=verdict,
            actual_query_rows=actual_query_row_counts,
            actual_query_count=actual_query_count,
            reusable_rows_present=reusable_rows_present,
        )
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="check",
        payload={**check, "status": status},
        verdict=verdict,
    )
    _store_section_facts(
        ctx.db,
        section_key=ctx.section_key,
        source_query=source_query,
        result=result,
        fact_updates=check.get("fact_updates") if isinstance(check.get("fact_updates"), list) else None,
    )
    return verdict, rationale, missing_questions, status


def _try_evidence_chain_fallback(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    *,
    force: bool = False,
) -> int:
    if not force and actual_query_count > 0 and any(c > 0 for c in actual_query_row_counts):
        return actual_query_count
    chain_rows = _execute_evidence_chain(ctx.db, ctx.block_heading, ctx.template_body, question=ctx.question)
    if chain_rows:
        chain_result = _summarize_sql_result("evidence_chain_fallback", chain_rows)
        chain_result["source_kind"] = "evidence_chain"
        collected_results.append(chain_result)
        actual_query_row_counts.append(int(chain_result.get("row_count") or len(chain_rows)))
        return actual_query_count + 1
    return actual_query_count


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
    from forensia.report.writer import _normalize_structured_answer, _persist_structured_answer, _render_structured_answer_markdown, _structured_block_id

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

    resolved_id = benchmark_id.strip() if benchmark_id else _structured_block_id(block_heading)
    normalized_status = str(classification.get("status") or status or "insufficient_evidence").strip().lower()
    if not _is_valid_status(normalized_status):
        normalized_status = status if _is_valid_status(status) else "insufficient_evidence"
    # Validate via row indices
    picked_row_indices = classification.get("picked_row_indices") or []
    if isinstance(picked_row_indices, list):
        valid_indices = [i for i in picked_row_indices if isinstance(i, (int, float)) and evidence_rows and 0 <= int(i) < len(evidence_rows)]
    else:
        valid_indices = []
    validated_rows = [evidence_rows[int(i)] for i in valid_indices] if evidence_rows else []
    if not validated_rows and picked_row_indices:
        normalized_status = "wrong_query"
        classification["rationale"] = "no valid evidence rows (picked_row_indices out of range or empty)"
    answer_spec_val = str(answer_spec or "").strip()
    if not answer_spec_val:
        spec, _confidence = resolve_question_spec(block_heading=block_heading)
        answer_spec_val = spec.answer_spec if spec is not None else ""
    normalized_answer = {
        "id": resolved_id,
        "section": section_key,
        "status": normalized_status,
        "answer": answer_data or validated_rows,
        "missing_reason": [str(classification.get("rationale") or "").strip()] if classification.get("rationale") else [],
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

    if normalized_answer["status"] in {"answered", "partial"} and not normalized_answer.get("answer"):
        normalized_answer["status"] = "wrong_query"
        reason = str(classification.get("rationale") or "answer was empty after filtering").strip()
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
    from forensia.report.writer import _catalog_names

    return _catalog_names("antiforensic_tools")


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(str(value) for value in row.values() if value is not None).casefold()


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
def _load_event_class_definitions() -> dict[str, dict[str, Any]]:
    """Load event_class groupings from event_ids.yaml.

    Returns dict like:
    {
        "startup": {"event_ids": [6005, 12]},
        "shutdown": {"event_ids": [6006, 13, 1074]},
        "logon": {"event_ids": [4624], "logon_types": [2, 10, 11]},
        "logoff": {"event_ids": [4634, 4647]},
    }
    """
    from forensia.ai.question_registry import _schema_dir
    import yaml
    path = _schema_dir() / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    classes = data.get("event_classes") if isinstance(data, dict) else {}
    if not isinstance(classes, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for class_name, class_def in classes.items():
        if not isinstance(class_def, dict):
            continue
        event_ids = class_def.get("event_ids", [])
        if isinstance(event_ids, list) and event_ids:
            entry: dict[str, Any] = {"event_ids": [int(eid) for eid in event_ids]}
            logon_types = class_def.get("logon_types")
            if logon_types and isinstance(logon_types, list):
                entry["logon_types"] = [int(lt) for lt in logon_types]
            result[class_name] = entry
    return result


def _build_daily_session_timeline(
    db: CaseDB,
    qualifiers: dict[str, str | None] | None = None,
) -> list[dict[str, Any]]:
    """Structured answer builder: per-day session timeline with actual trace times.

    Returns one row per calendar date:
      {date, first_startup, first_logon, last_logoff, last_shutdown,
       logon_users (distinct ≤5 listed), interactive_logon_count}

    Event classes (startup/logon/logoff/shutdown) are read from
    _schema/event_ids.yaml event_classes — no hardcoded IDs in Python.

    qualifiers may contain hour_from/hour_to to restrict to a time-of-day window.
    """
    classes = _load_event_class_definitions()
    startup_ids = tuple(classes.get("startup", {}).get("event_ids", [6005, 12]))
    shutdown_ids = tuple(classes.get("shutdown", {}).get("event_ids", [6006, 13, 1074]))
    logon_ids = tuple(classes.get("logon", {}).get("event_ids", [4624]))
    logon_types = tuple(classes.get("logon", {}).get("logon_types", [2, 10, 11]))
    logoff_ids = tuple(classes.get("logoff", {}).get("event_ids", [4634, 4647]))

    all_event_ids = sorted(set(startup_ids + shutdown_ids + logon_ids + logoff_ids))
    if not all_event_ids:
        return []

    id_list = ", ".join(str(eid) for eid in all_event_ids)
    startup_list = ", ".join(str(e) for e in startup_ids)
    shutdown_list = ", ".join(str(e) for e in shutdown_ids)
    logon_id_list = ", ".join(str(eid) for eid in logon_ids)
    logon_type_list = ", ".join(str(lt) for lt in logon_types)
    logoff_list = ", ".join(str(e) for e in logoff_ids)

    hour_filter = ""
    qual = qualifiers or {}
    hour_from = qual.get("hour_from")
    hour_to = qual.get("hour_to")
    if hour_from and hour_to:
        hour_filter = (
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) >= '{hour_from}'\n"
            f"  AND CAST(STRFTIME(timestamp, '%H:%M') AS VARCHAR) <= '{hour_to}'\n"
        )

    sql = f"""
    WITH sessions AS (
        SELECT
            CAST(CAST(timestamp AS DATE) AS VARCHAR) AS date,
            timestamp,
            event_id,
            logon_type,
            target_user
        FROM evtx_events
        WHERE event_id IN ({id_list})
          AND timestamp IS NOT NULL
{hour_filter}
    ),
    daily_agg AS (
        SELECT
            date,
            MIN(CASE WHEN event_id IN ({startup_list}) THEN timestamp END) AS first_startup,
            MIN(CASE WHEN event_id IN ({logon_id_list}) AND logon_type IN ({logon_type_list}) THEN timestamp END) AS first_logon,
            MAX(CASE WHEN event_id IN ({logoff_list}) THEN timestamp END) AS last_logoff,
            MAX(CASE WHEN event_id IN ({shutdown_list}) THEN timestamp END) AS last_shutdown
        FROM sessions
        GROUP BY date
    ),
    daily_logon_users AS (
        SELECT
            date,
            LIST(DISTINCT target_user) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS logon_users_raw,
            COUNT(*) FILTER (WHERE target_user IS NOT NULL AND TRIM(target_user) <> '') AS interactive_logon_count
        FROM sessions
        WHERE event_id IN ({logon_id_list})
          AND logon_type IN ({logon_type_list})
        GROUP BY date
    )
    SELECT
        d.date,
        d.first_startup,
        d.first_logon,
        d.last_logoff,
        d.last_shutdown,
        CASE
            WHEN LEN(u.logon_users_raw) > 5
            THEN u.logon_users_raw[1:5]
            ELSE u.logon_users_raw
        END AS logon_users,
        u.interactive_logon_count
    FROM daily_agg d
    LEFT JOIN daily_logon_users u ON d.date = u.date
    ORDER BY d.date

    """

    from forensia.db.query import fetch_records
    try:
        rows = fetch_records(db, sql)
    except Exception:
        return []

    result: list[dict[str, Any]] = []
    for row in rows:
        entry: dict[str, Any] = {
            "date": str(row.get("date") or ""),
            "first_startup": str(row.get("first_startup") or ""),
            "first_logon": str(row.get("first_logon") or ""),
            "last_logoff": str(row.get("last_logoff") or ""),
            "last_shutdown": str(row.get("last_shutdown") or ""),
            "logon_users": "",
            "interactive_logon_count": int(row.get("interactive_logon_count") or 0),
        }
        raw_users = row.get("logon_users")
        if isinstance(raw_users, list):
            entry["logon_users"] = ", ".join(str(u) for u in raw_users if u)
        result.append(entry)
    return result


def _extract_daily_table(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
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
            {"startup": 0, "logons": 0, "logoff": 0, "shutdown": 0, "first_event_time": None, "last_event_time": None},
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
        {field: (date_value if field == "date" else values.get(field, "")) for field in fields}
        for date_value, values in sorted(by_date.items())
    ]


def _extract_known_list(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
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


def _extract_name_with_version(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    detected: dict[str, dict[str, Any]] = {}
    app_markers = {
        "Microsoft Outlook": ("outlook", ".ost", ".pst"),
        "Google Chrome": ("chrome.exe", "google/chrome", "google\\chrome"),
        "Microsoft Internet Explorer": ("iexplore.exe", "internet explorer"),
        "Mozilla Firefox": ("firefox.exe", "mozilla/firefox", "mozilla\\firefox"),
        "Microsoft Edge": ("msedge.exe", "microsoft/edge", "microsoft\\edge"),
    }
    for row in raw_rows:
        text = _row_text(row)
        for app_name, markers in app_markers.items():
            if any(marker in text for marker in markers):
                item = detected.setdefault(app_name, {field: "" for field in fields})
                if "application_name" in fields:
                    item["application_name"] = app_name
                if "data_files" in fields:
                    data_file = _row_value(row, "file_path", "file_name", "summary")
                    if data_file:
                        existing = str(item.get("data_files") or "")
                        item["data_files"] = data_file if not existing else f"{existing}; {data_file}"
                if "version" in fields and not item.get("version"):
                    match = re.search(r"(\d+(?:\.\d+){1,4})", text)
                    if match:
                        item["version"] = match.group(1)
    return [item for item in detected.values() if not _all_values_empty(item)]


def _extract_enumerated_services(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    services = {
        "Google Drive": ("googledrive", "google drive", "googledrivesync"),
        "iCloud": ("icloud",),
        "OneDrive": ("onedrive",),
        "Dropbox": ("dropbox",),
    }
    rows: list[dict[str, Any]] = []
    for service_name, markers in services.items():
        matches = [row for row in raw_rows if any(marker in _row_text(row) for marker in markers)]
        if not matches:
            continue
        item = {field: "" for field in fields}
        if "service_name" in fields:
            item["service_name"] = service_name
        if "exe_found" in fields:
            item["exe_found"] = "yes" if any(".exe" in _row_text(row) or ".pf" in _row_text(row) for row in matches) else "no"
        if "paths_found" in fields:
            item["paths_found"] = "; ".join(str(_row_value(row, "file_path", "summary") or "") for row in matches[:3]).strip("; ")
        if "config_found" in fields:
            item["config_found"] = "yes" if any(marker in _row_text(row) for row in matches for marker in ("config", ".db", "snapshot")) else "no"
        rows.append(item)
    return [item for item in rows if not _all_values_empty(item)]


def _extract_pair_list(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        original = _row_value(row, "original_name", "fn_filename")
        new = _row_value(row, "new_name", "file_name")
        if original and new and str(original) != str(new):
            rows.append({
                field: {
                    "original_name": original,
                    "new_name": new,
                    "timestamp": _row_value(row, "timestamp", "si_modified", "fn_modified") or "",
                }.get(field, "")
                for field in fields
            })
    return rows


def _extract_full_scan(raw_rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw_rows:
        text = _row_text(row)
        tool_names = _antiforensic_tool_names()
        tool_markers = tuple(name.casefold() for name in tool_names)
        if not any(marker in text for marker in (*tool_markers, "log cleared", "event_id=104", "event_id=1102", "event_id=1100")):
            continue
        item = {field: "" for field in fields}
        if "tool_name" in fields:
            for tool in tool_names:
                if tool.casefold() in text:
                    item["tool_name"] = tool
                    break
            if not item.get("tool_name") and any(marker in text for marker in ("104", "1102", "1100")):
                item["tool_name"] = "Windows Event Log"
        if "evidence_type" in fields:
            item["evidence_type"] = "event" if "event_id" in text else "file"
        if "found" in fields:
            item["found"] = "yes"
        if "details" in fields:
            item["details"] = str(_row_value(row, "summary", "file_path", "message") or row)
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


def _flatten_sample_rows(collected_results: list[dict], *, rows_only: bool = False) -> list[dict]:
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
    if _report_language() in {"ja", "jp", "japanese"}:
        return "本ブロックを裏付ける十分な証拠は得られていない。詳細は Investigation Gaps の節に記載する。"
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


def _result_count_summary(collected_results: list[dict[str, Any]]) -> tuple[int, list[str], list[str]]:
    total_rows = 0
    positive: list[str] = []
    zero: list[str] = []
    for result in collected_results:
        if str(result.get("kind") or "rows") != "rows":
            continue
        label = _result_source_label(result)
        try:
            count = int(result.get("row_count") or 0)
        except (TypeError, ValueError):
            count = 0
        total_rows += max(count, 0)
        target = positive if count > 0 else zero
        item = f"{label}={count}"
        if item not in target:
            target.append(item)
    return total_rows, positive, zero


def _representative_ids(collected_results: list[dict[str, Any]], flat_rows: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
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

# ====================================================================
# BLOCK EXECUTION — _write_block_body, run_section_block_agent
# Lines: ~2082-2647
# ====================================================================


_NARRATE_RETRY_PROMPT = (
    "Your previous response had an empty or near-empty body. "
    "Retry: emit exactly one JSON object {\"body\": \"<paragraph>\"} "
    "where <paragraph> is at least 50 characters and cites the evidence_ids above. "
    "Do not return an empty string."
)


def _narrate_paragraph_with_retry(
    *,
    narrate_messages: list[dict[str, str]],
    narrate_schema: dict,
    model: str,
    base_url: str,
    audit_callback,
    target_language: str = "",
) -> str:
    """Call paragraph_narrate once; retry with language/empty-body coaching as needed.

    Language enforcement: if the body is in a language other than the target, retry
    once with a language-coaching turn.  If the second attempt still mismatches,
    return empty so the caller falls back to deterministic prose.

    Empty-body retry: if the body is effectively empty, retry once with _NARRATE_RETRY_PROMPT.
    """
    from forensia.report.writer import _detect_body_language

    target = target_language.strip().lower() if target_language else ""
    target = "ja" if target in {"ja", "jp", "japanese"} else "en" if target == "en" else ""

    def _call(messages: list[dict[str, str]]) -> str:
        parsed = request_llm_json(
            messages=messages, model=model, base_url=base_url,
            json_schema=narrate_schema, audit_callback=audit_callback,
        )
        return str(parsed.get("body", parsed.get("content", ""))).strip()

    if not target:
        body = _call(narrate_messages)
        if not _is_effectively_empty_body(body):
            return body
        retry_messages = list(narrate_messages)
        retry_messages.append({"role": "user", "content": _NARRATE_RETRY_PROMPT})
        return _call(retry_messages)

    body = _call(narrate_messages)
    if not _is_effectively_empty_body(body):
        detected = _detect_body_language(body)
        if detected not in ("unknown", target):
            # Language mismatch: retry once with coaching
            coaching = (
                "Write the entire paragraph in the target language. "
                f"Target language: {target}. "
                "Do not mix languages."
            )
            retry_messages = list(narrate_messages)
            retry_messages.append({"role": "user", "content": coaching})
            body = _call(retry_messages)
            if not _is_effectively_empty_body(body):
                detected2 = _detect_body_language(body)
                if detected2 not in ("unknown", target):
                    # second mismatch → return empty so caller falls back
                    return ""
                return body
            return ""
        return body
    # Empty body: retry with existing empty-body prompt
    retry_messages = list(narrate_messages)
    retry_messages.append({"role": "user", "content": _NARRATE_RETRY_PROMPT})
    body = _call(retry_messages)
    if not _is_effectively_empty_body(body):
        detected = _detect_body_language(body)
        if detected not in ("unknown", target):
            return ""  # Language mismatch, fall back
    return body


def _fallback_narrative_body(
    *,
    heading: str,
    status: str,
    collected_results: list[dict[str, Any]],
    flat_evidence: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
) -> str:
    """Build a deterministic paragraph when the LLM narrator returns an empty body."""
    language = _report_language()
    is_ja = language in {"ja", "jp", "japanese"}
    total_rows, positive_sources, _zero_sources = _result_count_summary(collected_results)
    evidence_ids, finding_ids = _representative_ids(collected_results, flat_evidence)
    example = ""
    for row in flat_evidence:
        if not isinstance(row, dict):
            continue
        ts = str(row.get("timestamp") or row.get("date") or "")
        eid = str(row.get("event_id") or "")
        evid = str(row.get("evidence_id") or "")
        parts = [p for p in [ts, eid, evid] if p]
        if parts:
            example = " / ".join(parts)
            break
    if status in {"not_found", "not_searched"} or (actual_query_count > 0 and not any(actual_query_row_counts)):
        if is_ja:
            paragraph = (
                f"{heading}について、関連する証拠検索を実行しましたが、該当する行は得られていません。"
                "この項目は現時点では証拠不足として扱い、結論本文には採用しません。"
            )
        else:
            paragraph = (
                f"For {heading}, the relevant evidence searches returned no matching rows. "
                "This item remains unsupported and should not be promoted into the incident narrative."
            )
        return paragraph

    sources = "取得済み証拠" if is_ja else "the collected evidence"
    ref_text = ""
    if evidence_ids:
        ref_text = ", ".join(evidence_ids)
        if is_ja:
            ref_text = f"代表証拠ID: {ref_text}。"
        else:
            ref_text = f"Representative evidence IDs: {ref_text}."
    elif finding_ids:
        ref_text = ", ".join(finding_ids)
        if is_ja:
            ref_text = f"代表 finding_id: {ref_text}。"
        else:
            ref_text = f"Representative finding IDs: {ref_text}."

    if is_ja:
        paragraph = (
            f"{heading}について、{sources}から合計 {total_rows} 件の関連行が得られました。"
        )
        if example:
            paragraph += f"代表行は {example} です。"
        if status == "partial":
            paragraph += "ただし、この記述は追加の相関確認が必要な暫定評価です。"
        if ref_text:
            paragraph += ref_text
    else:
        paragraph = (
            f"For {heading}, {sources} returned {total_rows} related rows. "
        )
        if example:
            paragraph += f"Representative row: {example}. "
        if status == "partial":
            paragraph += "Additional correlation is still needed before treating the block as fully answered. "
        if ref_text:
            paragraph += ref_text
    return paragraph.strip()


def _write_block_body(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    status: str,
    verdict: str,
    rationale: str,
    missing_questions: list[Any],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    audit_callback=None,
) -> tuple[str, str]:
    from forensia.report.writer import (
        _collect_flat_evidence_rows,
        _render_structured_answer_markdown,
        _summarize_flat_evidence_rows,
        build_structured_answer,
    )

    verification_notes: list[str] = []
    if status == "insufficient_evidence":
        reusable_rows_present = any(str(item.get("kind") or "rows") != "rows" for item in collected_results)
        status_inner = _classify_block_status(
            verdict=verdict,
            actual_query_rows=actual_query_row_counts,
            actual_query_count=actual_query_count,
            reusable_rows_present=reusable_rows_present,
        )
    else:
        status_inner = status
    if verdict == "block_contradicted":
        notes = [rationale] if rationale else ["Evidence contradicts the template claim"]
        notes.extend(str(q) for q in missing_questions if q)
        verification_notes = notes

    raw_rows = _collect_flat_evidence_rows(collected_results)
    if raw_rows:
        raw_rows = _select_columns_by_template(raw_rows, ctx.section_key, ctx.template_body)
    prompt_rows = _summarize_flat_evidence_rows(raw_rows) if raw_rows else None

    if ctx.benchmark_mode:
        structured_answer = build_structured_answer(
            ctx.case,
            ctx.db,
            answer_spec=ctx.answer_spec,
            answer_id=ctx.answer_id or ctx.benchmark_id,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
        )
        if structured_answer is not None:
            status_inner = str(structured_answer.get("status") or status_inner)
            body = _render_structured_answer_markdown(structured_answer, ctx.block_heading)
            messages = []
        else:
            expected_shape = _resolve_structured_expected_shape(ctx.block_heading)

            extracted_rows = (
                _extract_answer_by_shape(raw_rows, expected_shape, expected_shape.get("format", ""))
                if raw_rows and expected_shape
                else []
            )

            # BUG-030: Skip classify when rows already match expected_shape
            if (
                extracted_rows
                and expected_shape
                and all(field in extracted_rows[0] for field in expected_shape.get("fields") or [])
            ):
                # rows already match the expected shape — skip classify, use them directly
                picked_rows = extracted_rows
                classification = {"status": "answered", "picked_row_indices": [], "rationale": "rows match expected_shape"}
            else:
                classify_messages, classify_schema = build_structured_classify_messages(
                    question=ctx.template_body or ctx.block_heading,
                    block_heading=ctx.block_heading,
                    evidence_rows=prompt_rows or [],
                    expected_shape=expected_shape,
                    time_range=ctx.case.time_range,
                )
                classification = request_llm_json(
                    messages=classify_messages,
                    model=ctx.model,
                    base_url=ctx.base_url,
                    json_schema=classify_schema,
                    audit_callback=ctx.audit,
                )
                # Handle picked_row_indices (int array) instead of picked_row_ids
                picked_row_indices = classification.get("picked_row_indices") or []
                if isinstance(picked_row_indices, list):
                    valid_indices = [i for i in picked_row_indices if isinstance(i, int) and 0 <= i < len(raw_rows or [])]
                else:
                    valid_indices = []
                picked_rows = [raw_rows[i] for i in valid_indices] if raw_rows else []

            queries_run = [str(r.get("source_ref") or r.get("source_query") or "") for r in collected_results if r.get("source_ref") or r.get("source_query")]
            body = _format_structured_answer(
                classification=classification,
                picked_rows=picked_rows,
                expected_shape=expected_shape,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                status=status_inner,
                case=ctx.case,
                benchmark_id=ctx.benchmark_id,
                queries_run=queries_run,
                evidence_rows=prompt_rows or [],
                answer_spec=ctx.answer_spec or (ctx.question_spec.answer_spec if ctx.question_spec is not None else ""),
            )
            messages = classify_messages if not (extracted_rows and expected_shape and all(field in extracted_rows[0] for field in expected_shape.get("fields") or [])) else []
    else:
        if status_inner in {"not_searched", "not_found", "wrong_query"}:
            # Reader-facing insufficient-evidence placeholder. Must not contain
            # workflow markers ("Block skipped", "Section block failed") or
            # open-question markers — those trip the section quality gates and
            # would cap the whole section's confidence.
            body = _insufficient_evidence_placeholder()
            messages = []
        else:
            flat_evidence = _flatten_sample_rows(collected_results, rows_only=True)
            prior_section_keypoints = list(
                {
                    str(r.get("keypoint") or r.get("source_kind") or "")
                    for r in collected_results
                    if r.get("keypoint") or r.get("source_kind")
                }
            )
            outline_messages, outline_schema = build_section_outline_messages(
                template_body=ctx.template_body,
                relevant_evidence=flat_evidence,
                time_range=ctx.case.time_range,
                section_meta={"section": ctx.section_key, "title": ctx.title},
                prior_section_keypoints=prior_section_keypoints,
            )
            outline = request_llm_json(
                messages=outline_messages,
                model=ctx.model,
                base_url=ctx.base_url,
                json_schema=outline_schema,
                audit_callback=ctx.audit,
            )
            all_key_points: list[str] = []
            for item in outline.get("outline") or []:
                all_key_points.extend(item.get("key_points") or [])
            narrate_messages, narrate_schema = build_paragraph_narrate_messages(
                heading=ctx.block_heading,
                key_points=all_key_points,
                evidence_rows=flat_evidence[:10],
                template_body=ctx.template_body,
                structured_digest=ctx.structured_digest,
            )
            body = _narrate_paragraph_with_retry(
                narrate_messages=narrate_messages,
                narrate_schema=narrate_schema,
                model=ctx.model,
                base_url=ctx.base_url,
                audit_callback=ctx.audit,
                target_language=_report_language(),
            )
            if _is_effectively_empty_body(body):
                body = _fallback_narrative_body(
                    heading=ctx.block_heading,
                    status=status_inner,
                    collected_results=collected_results,
                    flat_evidence=flat_evidence,
                    actual_query_count=actual_query_count,
                    actual_query_row_counts=actual_query_row_counts,
                )
            messages = narrate_messages

    if audit_callback:
        audit_callback(messages, body)
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=max(len(collected_results), 1),
        phase="write",
        payload={"evidence_count": len(collected_results), "body_preview": body[:400]},
    )
    return body, status_inner


def run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    memory: MemoryManager | None = None,
    max_queries_per_section: int = 3,
    evidence_keypoints: list[str] | None = None,
    benchmark_mode: bool = False,
    benchmark_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    audit_callback=None,
) -> SectionBlockResult:
    """Run the complete plan->query->check->write loop for one report section block.

    Iterates up to max_queries_per_section times: LLM plans the next action
    (keypoint/template/sql/facts/write), executes it, LLM checks sufficiency,
    and either continues or finalizes with a written body. Falls back to evidence
    chains when all queries return zero rows.
    """
    max_queries = max(1, int(max_queries_per_section or 1))
    ctx = _prepare_block_context(
        case=case, db=db, section_key=section_key, title=title,
        block_heading=block_heading, template_body=template_body,
        base_url=base_url, model=model, memory=memory,
        max_queries=max_queries, evidence_keypoints=evidence_keypoints,
        benchmark_mode=benchmark_mode, benchmark_id=benchmark_id,
        answer_id=answer_id, answer_spec=answer_spec, question=question,
        audit_callback=audit_callback, report_brief=report_brief,
    )
    try:
        if ctx.benchmark_mode and ctx.answer_spec:
            from forensia.report.writer import _render_structured_answer_markdown, build_structured_answer

            structured_answer = build_structured_answer(
                ctx.case,
                ctx.db,
                answer_spec=ctx.answer_spec,
                answer_id=ctx.answer_id or ctx.benchmark_id or ctx.answer_spec,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
            )
            if structured_answer is not None:
                body = _render_structured_answer_markdown(structured_answer, ctx.block_heading)
                if audit_callback:
                    audit_callback([], body)
                _store_section_run(
                    ctx.db,
                    section_key=ctx.section_key,
                    block_heading=ctx.block_heading,
                    iteration=1,
                    phase="write",
                    payload={
                        "structured": True,
                        "answer_id": structured_answer.get("id"),
                        "answer_spec": ctx.answer_spec,
                        "status": structured_answer.get("status"),
                    },
                )
                if structured_answer.get("status") in {"answered", "partial"} and ctx.question_spec is not None and ctx.question_spec.timeline:
                    _feed_structured_to_timeline(ctx.db, ctx.answer_spec, structured_answer)
                return SectionBlockResult(
                    body=body,
                    evidence_results=[],
                    iterations=1,
                    status=str(structured_answer.get("status") or "insufficient_evidence"),
                )

        collected_results: list[dict[str, Any]] = []
        if ctx.reusable_facts:
            collected_results.append(_facts_as_result(ctx.reusable_facts))
        if ctx.reusable_evidence:
            collected_results.append(_evidence_as_result(ctx.reusable_evidence))
        verdict = "block_needs_more"
        rationale = ""
        missing_questions: list[Any] = []
        status = "insufficient_evidence"
        actual_query_count = 0
        actual_query_row_counts: list[int] = []
        template_catalog = ctx.template_catalog
        seed_keypoints = _default_keypoints_for_section(ctx.section_key, block_heading=ctx.block_heading)[:2] if not ctx.benchmark_mode else list(ctx.evidence_keypoints or [])[:3]
        executed_seed_keypoints: set[str] = set()
        for seed_index, kp in enumerate(seed_keypoints, start=0):
            if kp in _known_keypoints(ctx.keypoint_catalog):
                try:
                    source_query, result = _execute_keypoint(ctx.case, ctx.db, kp)
                    collected_results.append(result)
                    executed_seed_keypoints.add(kp)
                    _store_section_run(
                        ctx.db,
                        section_key=ctx.section_key,
                        block_heading=ctx.block_heading,
                        iteration=seed_index,
                        phase="query",
                        payload={
                            "seed": True,
                            "source_kind": str(result.get("source_kind") or "unknown"),
                            "source_ref": str(result.get("source_ref") or source_query),
                            "result": result,
                        },
                    )
                    if str(result.get("kind") or "rows") == "rows":
                        actual_query_count += 1
                        actual_query_row_counts.append(int(result.get("row_count") or 0))
                        _store_section_evidence(
                            ctx.db,
                            section_key=ctx.section_key,
                            block_heading=ctx.block_heading,
                            result=result,
                            source_query=source_query,
                        )
                except Exception:
                    _store_section_run(
                        ctx.db,
                        section_key=ctx.section_key,
                        block_heading=ctx.block_heading,
                        iteration=seed_index,
                        phase="query_error",
                        payload={"seed": True, "keypoint": kp},
                    )
        # R3-07: Fast path — skip plan loop if we already have evidence rows
        if collected_results and any(
            str(r.get("kind") or "rows") == "rows" and int(r.get("row_count") or 0) > 0
            for r in collected_results
        ):
            body, final_status = _write_block_body(
                ctx, collected_results,
                "answered", "block_supported", "", [],
                actual_query_count, actual_query_row_counts,
                audit_callback=audit_callback,
            )
            return SectionBlockResult(body=body, evidence_results=collected_results, iterations=max(len(collected_results), 1), status=final_status)

        for iteration in range(1, ctx.max_queries + 1):
            prior_runs = _load_prior_runs(db, section_key, block_heading)
            template_catalog = _filter_template_catalog_by_section(template_catalog, section_key, collected_results)
            plan_action = _run_block_plan(
                ctx, iteration, prior_runs, template_catalog,
                context_sections, current_section_outline,
            )
            if plan_action is None or plan_action.action == "write":
                break
            if plan_action.action == "keypoint":
                planned_keypoints = set(_split_keypoint_names(plan_action.keypoint))
                if planned_keypoints and planned_keypoints.issubset(executed_seed_keypoints):
                    continue
            outcome = _execute_block_plan(ctx, plan_action, iteration)
            if outcome is None:
                continue
            source_query, result = outcome
            collected_results.append(result)
            if str(result.get("kind") or "rows") == "rows":
                actual_query_count += 1
                actual_query_row_counts.append(int(result.get("row_count") or 0))
            check_result = _run_block_check(
                ctx, iteration, result, collected_results, prior_runs,
                actual_query_count, actual_query_row_counts, source_query,
            )
            if check_result is None:
                break
            verdict, rationale, missing_questions, status = check_result
            if verdict in {"block_supported", "block_contradicted"}:
                break
        force_chain = ctx.benchmark_mode and status in {"wrong_query", "insufficient_evidence", "not_searched"}
        actual_query_count = _try_evidence_chain_fallback(
            ctx,
            collected_results,
            actual_query_count,
            actual_query_row_counts,
            force=force_chain,
        )
        body, final_status = _write_block_body(
            ctx, collected_results,
            status, verdict, rationale, missing_questions,
            actual_query_count, actual_query_row_counts,
            audit_callback=audit_callback,
        )
        return SectionBlockResult(body=body, evidence_results=collected_results, iterations=max(len(collected_results), 1), status=final_status)
    except Exception as exc:
        return SectionBlockResult(
            body=f"**Status:** error\n\n*Section block failed: {str(exc)[:200]}*",
            evidence_results=[],
            iterations=0,
            status="error",
        )


async def async_run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    memory: MemoryManager | None = None,
    max_queries_per_section: int = 3,
    evidence_keypoints: list[str] | None = None,
    benchmark_mode: bool = False,
    benchmark_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    audit_callback=None,
) -> SectionBlockResult:
    """Async wrapper around run_section_block_agent using asyncio.to_thread."""
    return await asyncio.to_thread(
        run_section_block_agent,
        case=case, db=db, section_key=section_key, title=title,
        block_heading=block_heading, template_body=template_body,
        context_sections=context_sections, current_section_outline=current_section_outline,
        report_brief=report_brief, base_url=base_url, model=model,
        memory=memory, max_queries_per_section=max_queries_per_section,
        evidence_keypoints=evidence_keypoints, benchmark_mode=benchmark_mode,
        benchmark_id=benchmark_id, answer_id=answer_id, answer_spec=answer_spec,
        question=question,
        audit_callback=audit_callback,
    )
