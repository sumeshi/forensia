from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

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
    build_column_selection_messages,
    build_report_section_messages,
    build_section_agent_check_messages,
    build_section_agent_plan_messages,
)
from forensia.ai.sql_templates import query_template_catalog, render_query_template, validate_select_sql
from forensia.core.case import Case
from forensia.core.session import PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


@dataclass(slots=True)
class SectionBlockResult:
    body: str
    evidence_results: list[dict[str, Any]]
    iterations: int


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


def _audit_bridge(audit_callback):
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
    return parsed if isinstance(parsed, dict) else None


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


def _keypoint_catalog(section_key: str | None = None) -> list[dict[str, str]]:
    """Return keypoint catalog filtered for this section, plus a few cross-cutting ones.

    Returning all ~40 keypoints to the planner on every iteration wastes
    tokens. Each report section only needs its own family (e.g. timeline_*)
    plus a small set of universally useful keypoints.
    """
    from forensia.report.writer import REPORT_KEYPOINTS, _default_keypoints_for_section

    if not section_key:
        return [
            {"name": keypoint, "description": description}
            for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items())
        ]
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


def _findings_snapshot(db: CaseDB, limit: int = 12) -> list[dict[str, Any]]:
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
    family = _section_family(section_key)
    rows = db.execute(
        """
        SELECT fact_type, fact_key, fact_value, evidence_ids, source_section, confidence, updated_at
        FROM section_facts
        WHERE source_section = ?
           OR source_section LIKE ?
           OR fact_type LIKE ?
        ORDER BY updated_at DESC, confidence DESC
        LIMIT ?
        """,
        (section_key, f"%{family}%", f"{family}%", limit),
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
        "row_count": len(reusable_facts),
        "evidence_ids": evidence_ids,
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": reusable_facts[:20],
    }


def _load_reusable_section_evidence(db: CaseDB, section_key: str, block_heading: str, limit: int = 30) -> list[dict[str, Any]]:
    family = _section_family(section_key)
    rows = db.execute(
        """
        SELECT section_key, block_heading, evidence_id, role, source_query, created_at
        FROM section_evidence
        WHERE section_key = ?
           OR block_heading = ?
           OR section_key LIKE ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (section_key, block_heading, f"%{family}%", limit),
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
        "row_count": len(reusable_evidence),
        "evidence_ids": evidence_ids,
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": reusable_evidence[:30],
    }


def _summarize_sql_result(sql: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize_query_result(rows, sample_size=10)
    return {
        "keypoint": "raw_sql",
        "description": sql,
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
    from forensia.report.writer import _resolve_evidence_results

    source_query = f"KEYPOINT::{keypoint}"
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    resolved = _resolve_evidence_results(case, db, keypoints=[keypoint])
    result = resolved[0] if resolved else {
        "keypoint": keypoint,
        "description": "",
        "row_count": 0,
        "evidence_ids": [],
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": [],
    }
    _store_cached_result(db, source_query, result)
    return source_query, result


def _execute_sql(db: CaseDB, sql: str) -> tuple[str, dict[str, Any]]:
    validated = validate_select_sql(sql)
    source_query = f"SQL::{validated}"
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    rows = fetch_records(db, validated)
    result = _summarize_sql_result(validated, rows)
    _store_cached_result(db, source_query, result)
    return source_query, result


def _coerce_plan_action(plan: dict[str, Any], *, section_key: str, iteration: int) -> SectionPlanAction:
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


def run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outputs: dict[str, str],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    max_queries_per_section: int = 3,
    audit_callback=None,
) -> SectionBlockResult:
    max_queries = max(1, int(max_queries_per_section or 1))
    collected_results: list[dict[str, Any]] = []
    findings_snapshot = _findings_snapshot(db)
    keypoint_catalog = _keypoint_catalog(section_key)
    template_catalog = _query_template_catalog()
    reusable_facts = _load_reusable_section_facts(db, section_key)
    reusable_evidence = _load_reusable_section_evidence(db, section_key, block_heading)
    audit = _audit_bridge(audit_callback)
    if reusable_facts:
        collected_results.append(_facts_as_result(reusable_facts))
    if reusable_evidence:
        collected_results.append(_evidence_as_result(reusable_evidence))
    verdict = "need_more"
    rationale = ""
    missing_questions: list[Any] = []
    for iteration in range(1, max_queries + 1):
        prior_runs = _load_prior_runs(db, section_key, block_heading)
        plan_messages = build_section_agent_plan_messages(
            section_key=section_key,
            section_title=title,
            block_heading=block_heading,
            template_body=template_body,
            report_brief=report_brief or {},
            context_sections=context_sections,
            current_section_outputs=current_section_outputs,
            findings_snapshot=findings_snapshot,
            keypoint_catalog=keypoint_catalog,
            query_template_catalog=template_catalog,
            prior_runs=prior_runs,
            reusable_facts=reusable_facts,
            reusable_evidence=reusable_evidence,
        )
        try:
            plan = request_llm_json(
                messages=plan_messages,
                model=model,
                base_url=base_url,
                audit_callback=audit,
            )
        except Exception as exc:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="plan_error",
                payload={"error": str(exc)},
            )
            break
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="plan",
            payload=plan,
        )
        plan_action = _coerce_plan_action(plan, section_key=section_key, iteration=iteration)
        if plan_action.action == "write":
            break
        source_query = ""
        result: dict[str, Any]
        try:
            if plan_action.action == "facts" and (reusable_facts or reusable_evidence):
                source_query = "STATE::facts"
                state_rows = reusable_facts if reusable_facts else reusable_evidence
                result = _facts_as_result(reusable_facts) if reusable_facts else _evidence_as_result(reusable_evidence)
                result["description"] = "Reused prior section-agent state."
                result["sample_rows"] = state_rows[:20]
            elif plan_action.action == "template" and plan_action.planned_query and plan_action.planned_query.template_id:
                rendered_sql = render_query_template(
                    plan_action.planned_query.template_id,
                    plan_action.planned_query.params,
                )
                source_query, result = _execute_sql(db, rendered_sql)
                result["keypoint"] = f"template:{plan_action.planned_query.template_id}"
                result["description"] = (
                    f"{plan_action.planned_query.template_id} {plan_action.planned_query.params}"
                )
                result["query_id"] = plan_action.planned_query.query_id
                result["purpose"] = plan_action.planned_query.purpose
            elif plan_action.action == "sql" and plan_action.planned_query and plan_action.planned_query.sql:
                source_query, result = _execute_sql(db, plan_action.planned_query.sql)
                result["query_id"] = plan_action.planned_query.query_id
                result["purpose"] = plan_action.planned_query.purpose
            else:
                keypoint = plan_action.keypoint or ""
                if not keypoint:
                    default_match = next(
                        (item["name"] for item in keypoint_catalog if item["name"].startswith(section_key.split("_", 1)[-1].split("-", 1)[0])),
                        keypoint_catalog[0]["name"] if keypoint_catalog else "top_keypoints",
                    )
                    keypoint = default_match
                source_query, result = _execute_keypoint(case, db, keypoint)
        except Exception as exc:
            # Don't crash the whole section because one query failed.
            # Record the error, skip this iteration, and let the loop try again
            # (or fall through to the final write phase with whatever data we have).
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": str(exc), "action": plan_action.action, "source_query": source_query},
            )
            continue
        collected_results.append(result)
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="query",
            payload={"source_query": source_query, "result": result},
        )
        _store_section_evidence(db, section_key=section_key, block_heading=block_heading, result=result, source_query=source_query)
        check_messages = build_section_agent_check_messages(
            section_key=section_key,
            section_title=title,
            block_heading=block_heading,
            template_body=template_body,
            collected_results=collected_results,
            latest_result=result,
            prior_runs=prior_runs,
            reusable_facts=reusable_facts,
            reusable_evidence=reusable_evidence,
        )
        try:
            check = request_llm_json(
                messages=check_messages,
                model=model,
                base_url=base_url,
                audit_callback=audit,
            )
        except Exception as exc:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="check_error",
                payload={"error": str(exc)},
            )
            # Treat as sufficient — we already have one query result; stop iterating.
            break
        verdict = str(check.get("verdict") or "need_more").strip().lower()
        rationale = str(check.get("rationale") or "")
        missing_questions = check.get("missing_questions") if isinstance(check.get("missing_questions"), list) else []
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="check",
            payload=check,
            verdict=verdict,
        )
        _store_section_facts(
            db,
            section_key=section_key,
            source_query=source_query,
            result=result,
            fact_updates=check.get("fact_updates") if isinstance(check.get("fact_updates"), list) else None,
        )
        if verdict in {"sufficient", "refuted"}:
            break

    verification_notes: list[str] = []
    if verdict == "refuted":
        notes = [rationale] if rationale else ["Evidence contradicts the template claim"]
        notes.extend(str(q) for q in missing_questions if q)
        verification_notes = notes

    from forensia.report.writer import _collect_flat_evidence_rows
    raw_rows = _collect_flat_evidence_rows(collected_results)
    if raw_rows:
        headers = list(raw_rows[0].keys())
        col_msgs = build_column_selection_messages(headers, section_key, template_body)
        col_resp = request_llm_json(messages=col_msgs, model=model, base_url=base_url)
        selected = [c for c in (col_resp.get("columns") or []) if c in headers]
        if selected:
            raw_rows = [{c: row[c] for c in selected if c in row} for row in raw_rows]
    messages = build_report_section_messages(
        section_meta={"section": section_key, "title": title},
        evidence_results=collected_results,
        context_sections=context_sections,
        template_body=template_body,
        report_brief=report_brief or {},
        section_heading=block_heading,
        current_section_outputs=current_section_outputs,
        verification_notes=verification_notes,
        raw_evidence_rows=raw_rows or None,
    )
    body = chat_completion(messages=messages, model=model, base_url=base_url).strip()
    if audit_callback:
        audit_callback(messages, body)
    _store_section_run(
        db,
        section_key=section_key,
        block_heading=block_heading,
        iteration=max(len(collected_results), 1),
        phase="write",
        payload={"evidence_count": len(collected_results), "body_preview": body[:400]},
    )
    return SectionBlockResult(body=body, evidence_results=collected_results, iterations=max(len(collected_results), 1))


async def async_run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outputs: dict[str, str],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    max_queries_per_section: int = 3,
    audit_callback=None,
) -> SectionBlockResult:
    max_queries = max(1, int(max_queries_per_section or 1))
    collected_results: list[dict[str, Any]] = []
    findings_snapshot = _findings_snapshot(db)
    keypoint_catalog = _keypoint_catalog(section_key)
    template_catalog = _query_template_catalog()
    reusable_facts = _load_reusable_section_facts(db, section_key)
    reusable_evidence = _load_reusable_section_evidence(db, section_key, block_heading)
    audit = _audit_bridge(audit_callback)
    if reusable_facts:
        collected_results.append(_facts_as_result(reusable_facts))
    if reusable_evidence:
        collected_results.append(_evidence_as_result(reusable_evidence))
    verdict = "need_more"
    rationale = ""
    missing_questions: list[Any] = []
    for iteration in range(1, max_queries + 1):
        prior_runs = _load_prior_runs(db, section_key, block_heading)
        plan_messages = build_section_agent_plan_messages(
            section_key=section_key,
            section_title=title,
            block_heading=block_heading,
            template_body=template_body,
            report_brief=report_brief or {},
            context_sections=context_sections,
            current_section_outputs=current_section_outputs,
            findings_snapshot=findings_snapshot,
            keypoint_catalog=keypoint_catalog,
            query_template_catalog=template_catalog,
            prior_runs=prior_runs,
            reusable_facts=reusable_facts,
            reusable_evidence=reusable_evidence,
        )
        try:
            plan = await async_request_llm_json(
                messages=plan_messages,
                model=model,
                base_url=base_url,
                audit_callback=audit,
            )
        except Exception as exc:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="plan_error",
                payload={"error": str(exc)},
            )
            break
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="plan",
            payload=plan,
        )
        plan_action = _coerce_plan_action(plan, section_key=section_key, iteration=iteration)
        if plan_action.action == "write":
            break
        source_query = ""
        result: dict[str, Any]
        try:
            if plan_action.action == "facts" and (reusable_facts or reusable_evidence):
                source_query = "STATE::facts"
                state_rows = reusable_facts if reusable_facts else reusable_evidence
                result = _facts_as_result(reusable_facts) if reusable_facts else _evidence_as_result(reusable_evidence)
                result["description"] = "Reused prior section-agent state."
                result["sample_rows"] = state_rows[:20]
            elif plan_action.action == "template" and plan_action.planned_query and plan_action.planned_query.template_id:
                rendered_sql = render_query_template(
                    plan_action.planned_query.template_id,
                    plan_action.planned_query.params,
                )
                source_query, result = _execute_sql(db, rendered_sql)
                result["keypoint"] = f"template:{plan_action.planned_query.template_id}"
                result["description"] = (
                    f"{plan_action.planned_query.template_id} {plan_action.planned_query.params}"
                )
                result["query_id"] = plan_action.planned_query.query_id
                result["purpose"] = plan_action.planned_query.purpose
            elif plan_action.action == "sql" and plan_action.planned_query and plan_action.planned_query.sql:
                source_query, result = _execute_sql(db, plan_action.planned_query.sql)
                result["query_id"] = plan_action.planned_query.query_id
                result["purpose"] = plan_action.planned_query.purpose
            else:
                keypoint = plan_action.keypoint or ""
                if not keypoint:
                    section_prefix = section_key.split("_", 1)[-1].split("-", 1)[0]
                    matching = [item["name"] for item in keypoint_catalog if item["name"].startswith(section_prefix)]
                    keypoint = matching[0] if matching else (keypoint_catalog[0]["name"] if keypoint_catalog else "top_keypoints")
                source_query, result = _execute_keypoint(case, db, keypoint)
        except Exception as exc:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": str(exc), "action": plan_action.action, "source_query": source_query},
            )
            continue
        collected_results.append(result)
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="query",
            payload={"source_query": source_query, "result": result},
        )
        _store_section_evidence(db, section_key=section_key, block_heading=block_heading, result=result, source_query=source_query)
        check_messages = build_section_agent_check_messages(
            section_key=section_key,
            section_title=title,
            block_heading=block_heading,
            template_body=template_body,
            collected_results=collected_results,
            latest_result=result,
            prior_runs=prior_runs,
            reusable_facts=reusable_facts,
            reusable_evidence=reusable_evidence,
        )
        try:
            check = await async_request_llm_json(
                messages=check_messages,
                model=model,
                base_url=base_url,
                audit_callback=audit,
            )
        except Exception as exc:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading=block_heading,
                iteration=iteration,
                phase="check_error",
                payload={"error": str(exc)},
            )
            break
        verdict = str(check.get("verdict") or "need_more").strip().lower()
        rationale = str(check.get("rationale") or "")
        missing_questions = check.get("missing_questions") if isinstance(check.get("missing_questions"), list) else []
        _store_section_run(
            db,
            section_key=section_key,
            block_heading=block_heading,
            iteration=iteration,
            phase="check",
            payload=check,
            verdict=verdict,
        )
        _store_section_facts(
            db,
            section_key=section_key,
            source_query=source_query,
            result=result,
            fact_updates=check.get("fact_updates") if isinstance(check.get("fact_updates"), list) else None,
        )
        if verdict in {"sufficient", "refuted"}:
            break

    verification_notes: list[str] = []
    if verdict == "refuted":
        notes = [rationale] if rationale else ["Evidence contradicts the template claim"]
        notes.extend(str(q) for q in missing_questions if q)
        verification_notes = notes

    from forensia.report.writer import _collect_flat_evidence_rows
    raw_rows = _collect_flat_evidence_rows(collected_results)
    if raw_rows:
        headers = list(raw_rows[0].keys())
        col_msgs = build_column_selection_messages(headers, section_key, template_body)
        col_resp = await async_request_llm_json(messages=col_msgs, model=model, base_url=base_url)
        selected = [c for c in (col_resp.get("columns") or []) if c in headers]
        if selected:
            raw_rows = [{c: row[c] for c in selected if c in row} for row in raw_rows]
    messages = build_report_section_messages(
        section_meta={"section": section_key, "title": title},
        evidence_results=collected_results,
        context_sections=context_sections,
        template_body=template_body,
        report_brief=report_brief or {},
        section_heading=block_heading,
        current_section_outputs=current_section_outputs,
        verification_notes=verification_notes,
        raw_evidence_rows=raw_rows or None,
    )
    body = (await async_chat_completion(messages=messages, model=model, base_url=base_url)).strip()
    if audit_callback:
        audit_callback(messages, body)
    _store_section_run(
        db,
        section_key=section_key,
        block_heading=block_heading,
        iteration=max(len(collected_results), 1),
        phase="write",
        payload={"evidence_count": len(collected_results), "body_preview": body[:400]},
    )
    return SectionBlockResult(body=body, evidence_results=collected_results, iterations=max(len(collected_results), 1))
