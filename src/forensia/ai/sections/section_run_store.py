"""Persistence and caching for section runs, questions, facts, and evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.questions import (
    QuestionSpec,
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


def _findings_snapshot(
    db: CaseDB, limit: int = 12, *, include_evidence: bool = False
) -> list[dict[str, Any]]:
    """Fetch top findings ordered by confidence for use in prompts and memory sync."""
    columns = "finding_id, title, severity, confidence, status, summary"
    if include_evidence:
        columns += ", evidence"
    return fetch_records(
        db,
        f"""
        SELECT {columns}
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


def load_reusable_section_facts(
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
