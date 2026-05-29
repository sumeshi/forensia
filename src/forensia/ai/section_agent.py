from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import asyncio

from forensia.ai.checker import summarize_query_result


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
from forensia.ai.json_response import request_llm_json, async_request_llm_json
from forensia.ai.lmstudio import chat_completion, async_chat_completion
from forensia.ai.prompts import (
    build_benchmark_classify_messages,
    build_paragraph_narrate_messages,
    build_report_section_messages,
    build_section_agent_check_messages,
    build_section_agent_plan_messages,
    build_section_outline_messages,
)
from forensia.ai.sql_templates import query_template_catalog, render_query_template, validate_select_sql
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


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


def _is_valid_status(status: str) -> bool:
    return status in {
        "answered",
        "partial",
        "not_found",
        "not_searched",
        "insufficient_evidence",
        "wrong_query",
    }


@dataclass(slots=True)
class _RoutingRule:
    name: str
    keywords: tuple[str, ...]
    keypoints: tuple[str, ...]


@lru_cache(maxsize=1)
def _load_question_routing() -> list[_RoutingRule]:
    """Load and cache question routing rules from _schema/question_routing.yaml."""
    import yaml

    routing_path = Path(__file__).resolve().parent.parent / "rulepacks" / "_schema" / "question_routing.yaml"
    if not routing_path.exists():
        return []
    data = yaml.safe_load(routing_path.read_text(encoding="utf-8")) or {}
    rules: list[_RoutingRule] = []
    for entry in data.get("question_types", []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        keywords = tuple(str(item).strip().casefold() for item in entry.get("keywords") or [] if str(item).strip())
        keypoints = tuple(str(item).strip() for item in entry.get("keypoints") or [] if str(item).strip())
        if name and keypoints:
            rules.append(_RoutingRule(name=name, keywords=keywords, keypoints=keypoints))
    return rules


def _question_routing_keypoints(block_heading: str, template_body: str) -> list[str]:
    text = f"{block_heading}\n{template_body}".casefold()
    for rule in _load_question_routing():
        if any(keyword in text for keyword in rule.keywords):
            return list(rule.keypoints)
    return []


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


def _prepend_status_badge(body: str, status: str) -> str:
    status_line = f"**Status:** {status}"
    text = str(body or "").strip()
    if not text:
        return status_line
    if text.startswith("**Status:**"):
        return text
    return f"{status_line}\n\n{text}"


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

    preferred = _default_keypoints_for_section(section_key)
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


def _load_reusable_section_facts(db: CaseDB, section_key: str, limit: int = 20) -> list[dict[str, Any]]:
    """Load section facts reusable by sibling blocks within the same section family."""
    rows = db.execute(
        """
        SELECT fact_type, fact_key, fact_value, evidence_ids, source_section, confidence, updated_at
        FROM section_facts
        WHERE source_section = ?
        ORDER BY updated_at DESC, confidence DESC
        LIMIT ?
        """,
        (section_key, limit),
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
        "user_name": "COALESCE(user_name, json_extract(raw_json, '$.TargetUserName'), json_extract(raw_json, '$.SubjectUserName')) AS user_name",
        "target_user": "COALESCE(target_user, json_extract(raw_json, '$.TargetUserName'), json_extract(raw_json, '$.SubjectUserName')) AS target_user",
        "subject_user": "COALESCE(subject_user, json_extract(raw_json, '$.SubjectUserName')) AS subject_user",
        "src_ip": "COALESCE(src_ip, json_extract(raw_json, '$.IpAddress')) AS src_ip",
        "logon_type": "COALESCE(logon_type, CAST(json_extract(raw_json, '$.LogonType') AS INTEGER)) AS logon_type",
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


def _coerce_plan_action(plan: dict[str, Any], *, section_key: str, iteration: int) -> SectionPlanAction:
    """Parse and normalize the LLM plan output into a typed SectionPlanAction.

    Handles default action/keypoint assignment, template vs SQL vs keypoint routing,
    and builds a PlannedQuery for template/sql actions.
    """
    action = str(plan.get("action") or "").strip().lower() or "keypoint"
    purpose = str(plan.get("purpose") or "").strip() or f"report block {section_key} iteration {iteration}"
    enough_to_write = bool(plan.get("enough_to_write"))
    keypoint = str(plan.get("keypoint") or "").strip() or None
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
    import yaml
    from pathlib import Path

    routing_path = Path(__file__).resolve().parent.parent / "rulepacks" / "_schema" / "question_routing.yaml"
    if not routing_path.exists():
        return {}
    try:
        data = yaml.safe_load(routing_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    chains: dict[str, list[dict[str, str]]] = {}
    for qtype in data.get("question_types", []):
        if isinstance(qtype, dict):
            name = str(qtype.get("name", "")).strip()
            chain = qtype.get("evidence_chain", [])
            if name and isinstance(chain, list):
                chains[name] = chain
    return chains


def _execute_evidence_chain(db: CaseDB, block_heading: str, template_body: str) -> list[dict[str, Any]]:
    """Execute deterministic evidence chain for the block.
    Tries each chain entry in order until one returns rows.
    """
    chains = _load_evidence_chains()
    if not chains:
        return []
    text = f"{block_heading}\n{template_body}".casefold()
    chain_name = None
    for name in chains:
        if name.replace("_", " ").casefold() in text:
            chain_name = name
            break
    if chain_name is None:
        keyword_map = {
            "prefetch": "prefetch_recent", "execution": "prefetch_recent",
            "email": "email_ost", "mail": "email_ost", "outlook": "email_ost", "ost": "email_ost",
            "rename": "desktop_rename", "desktop": "desktop_rename",
            "browser": "browser_usage", "chrome": "browser_usage", "web": "browser_usage",
            "logon": "logon_history", "logoff": "logon_history", "shutdown": "logon_history", "startup": "logon_history",
            "cloud": "cloud_activity", "drive": "cloud_activity",
            "antiforensic": "antiforensics", "wipe": "antiforensics", "delete": "antiforensics", "clean": "antiforensics",
        }
        for keyword, cid in keyword_map.items():
            if keyword in text:
                chain_name = cid
                break
    if chain_name is None or chain_name not in chains:
        return []
    chain = chains[chain_name]
    for entry in chain:
        if isinstance(entry, dict):
            query = entry.get("query", "")
            if query:
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
    benchmark_id: str = ""


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
    audit_callback,
    report_brief: dict[str, Any] | None,
) -> _BlockContext:
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
    reusable_facts = _load_reusable_section_facts(db, section_key)
    reusable_evidence = _load_reusable_section_evidence(db, section_key)
    audit = _audit_bridge(audit_callback)
    prompt_report_brief = _benchmark_report_brief(report_brief) if benchmark_mode else (report_brief or {})
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
        benchmark_id=benchmark_id,
    )


def _run_block_plan(
    ctx: _BlockContext,
    iteration: int,
    prior_runs: list[dict[str, Any]],
    template_catalog: list[dict[str, Any]],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
) -> SectionPlanAction | None:
    plan_messages = build_section_agent_plan_messages(
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
    )
    try:
        plan = request_llm_json(
            messages=plan_messages,
            model=ctx.model,
            base_url=ctx.base_url,
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
    return _coerce_plan_action(plan, section_key=ctx.section_key, iteration=iteration)


def _execute_block_plan(
    ctx: _BlockContext,
    plan_action: SectionPlanAction,
    iteration: int,
) -> tuple[str, dict[str, Any]] | None:
    if plan_action.action == "keypoint":
        keypoint = plan_action.keypoint or ctx.block_heading
        source_query, result = _execute_keypoint(ctx.case, ctx.db, keypoint)
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
        source_query, result = _execute_sql(ctx.db, planned_query.sql)
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
    check_messages = build_section_agent_check_messages(
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
    )
    try:
        check = request_llm_json(
            messages=check_messages,
            model=ctx.model,
            base_url=ctx.base_url,
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
) -> int:
    if actual_query_count > 0:
        return actual_query_count
    chain_rows = _execute_evidence_chain(ctx.db, ctx.block_heading, ctx.template_body)
    if chain_rows:
        chain_result = _summarize_sql_result("evidence_chain_fallback", chain_rows)
        chain_result["source_kind"] = "evidence_chain"
        collected_results.append(chain_result)
        return actual_query_count + 1
    return actual_query_count


def _resolve_benchmark_expected_shape(block_heading: str) -> dict | None:
    """Resolve expected_answer_shape from question_routing.yaml by block_heading keywords."""
    import yaml
    from pathlib import Path
    routing_path = Path(__file__).resolve().parent.parent / "rulepacks" / "_schema" / "question_routing.yaml"
    try:
        raw = yaml.safe_load(routing_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return None
        block_cf = block_heading.casefold()
        for qtype in raw.get("question_types", []):
            if isinstance(qtype, dict) and any(kw in block_cf for kw in qtype.get("keywords", [])):
                return qtype.get("expected_answer_shape")
    except Exception:
        pass
    return None


def _format_benchmark_answer(
    classification: dict,
    picked_rows: list[dict],
    expected_shape: dict | None,
    section_key: str,
    block_heading: str,
    status: str,
    case: Case,
    benchmark_id: str = "",
) -> dict:
    """Pure code. Format benchmark answer from picked rows + expected_answer_shape."""
    from forensia.report.writer import _benchmark_block_id, _normalize_benchmark_answer, _persist_benchmark_answer, _render_benchmark_answer_markdown

    shape = expected_shape or {}
    fields = shape.get("fields", [])

    answer_data: list[dict] = []
    if fields and picked_rows:
        for row in picked_rows:
            entry = {}
            for field in fields:
                entry[field] = row.get(field, row.get(f"normalized_{field}", ""))
            answer_data.append(entry)

    resolved_id = benchmark_id.strip() if benchmark_id else _benchmark_block_id(block_heading)
    normalized_answer = {
        "id": resolved_id,
        "section": section_key,
        "status": status,
        "rationale": classification.get("rationale", ""),
        "answer": answer_data or classification.get("picked_row_ids", []),
    }

    _persist_benchmark_answer(case, normalized_answer)
    return _render_benchmark_answer_markdown(normalized_answer, block_heading)


def _write_block_body(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    prompt_report_brief: dict[str, Any],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    status: str,
    verdict: str,
    rationale: str,
    missing_questions: list[Any],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    audit_callback=None,
) -> tuple[str, str]:
    from forensia.report.writer import (
        _benchmark_block_id,
        _collect_flat_evidence_rows,
        _persist_benchmark_answer,
        _render_benchmark_answer_markdown,
        _summarize_flat_evidence_rows,
        _normalize_benchmark_answer,
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
        expected_shape = _resolve_benchmark_expected_shape(ctx.block_heading)
        classify_messages = build_benchmark_classify_messages(
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
            audit_callback=ctx.audit,
        )
        picked_row_ids = [str(item) for item in (classification.get("picked_row_ids") or [])]
        picked_rows = [r for r in (raw_rows or []) if str(r.get("evidence_id") or r.get("id") or "") in picked_row_ids]
        body = _format_benchmark_answer(
            classification=classification,
            picked_rows=picked_rows,
            expected_shape=expected_shape,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            status=status_inner,
            case=ctx.case,
            benchmark_id=ctx.benchmark_id,
        )
        messages = classify_messages
    else:
        outline_messages = build_section_outline_messages(
            template_body=ctx.template_body,
            relevant_evidence=collected_results,
            time_range=ctx.case.time_range,
            section_meta={"section": ctx.section_key, "title": ctx.title},
        )
        outline = request_llm_json(
            messages=outline_messages,
            model=ctx.model,
            base_url=ctx.base_url,
            audit_callback=ctx.audit,
        )
        all_key_points: list[str] = []
        for item in outline.get("outline") or []:
            all_key_points.extend(item.get("key_points") or [])
        narrate_messages = build_paragraph_narrate_messages(
            heading=ctx.block_heading,
            key_points=all_key_points,
            evidence_rows=prompt_rows or collected_results,
            template_body=ctx.template_body,
        )
        body = _prepend_status_badge(
            chat_completion(messages=narrate_messages, model=ctx.model, base_url=ctx.base_url).strip(),
            status_inner,
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
        audit_callback=audit_callback, report_brief=report_brief,
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
    for iteration in range(1, ctx.max_queries + 1):
        prior_runs = _load_prior_runs(db, section_key, block_heading)
        template_catalog = _filter_template_catalog_by_section(template_catalog, section_key, collected_results)
        plan_action = _run_block_plan(
            ctx, iteration, prior_runs, template_catalog,
            context_sections, current_section_outline,
        )
        if plan_action is None or plan_action.action == "write":
            break
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
    actual_query_count = _try_evidence_chain_fallback(ctx, collected_results, actual_query_count, actual_query_row_counts)
    body, final_status = _write_block_body(
        ctx, collected_results, ctx.prompt_report_brief,
        context_sections, current_section_outline,
        status, verdict, rationale, missing_questions,
        actual_query_count, actual_query_row_counts,
        audit_callback=audit_callback,
    )
    return SectionBlockResult(body=body, evidence_results=collected_results, iterations=max(len(collected_results), 1), status=final_status)


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
        benchmark_id=benchmark_id, audit_callback=audit_callback,
    )

