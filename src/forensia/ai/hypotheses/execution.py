"""Deterministic helpers for existing hypothesis SQL execution."""

from __future__ import annotations

import json
from typing import Any

from forensia.ai.retrieval_telemetry import ToolReceipt, coverage_snapshot
from forensia.core.log import log as _log
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.knowledge.rules.engine import (
    execute_event_keyword_fallback_search,
    execute_fallback_search,
)
from forensia.knowledge.rules.loader import load_rule_by_id


def resolve_zero_row_fallbacks(
    db: CaseDB,
    hypothesis: Hypothesis,
    planned_query: Any,
    rows: list[Any],
) -> tuple[list[Any], dict[str, Any] | None]:
    """Run the existing rule/event fallbacks after a zero-row primary query."""

    fallback_info = None
    if len(rows) == 0 and hypothesis.source_rule_ids:
        for source_rule_id in hypothesis.source_rule_ids:
            rule = load_rule_by_id(source_rule_id)
            if rule and rule.fallback_search:
                for fallback in rule.fallback_search:
                    if not isinstance(fallback, dict):
                        continue
                    phase = fallback.get("phase")
                    if phase not in {
                        "keyword_in_raw_json",
                        "related_event_ids",
                        "artifact_table",
                    }:
                        continue
                    fallback_rows = execute_fallback_search(db, fallback)
                    if not fallback_rows:
                        continue
                    _log(
                        "FALLBACK",
                        f"{hypothesis.id} — found {len(fallback_rows)} rows via {phase}",
                    )
                    for row in fallback_rows[:20]:
                        if isinstance(row, dict):
                            row["_fallback_phase"] = phase
                            row["_fallback_source_rule_id"] = source_rule_id
                    rows = fallback_rows[:20]
                    fallback_info = {
                        "phase": phase,
                        "source_rule_id": source_rule_id,
                        "original_row_count": len(fallback_rows),
                        "row_limit": 20,
                        "truncated": len(fallback_rows) > 20,
                    }
                    break
                if fallback_info:
                    break
    if len(rows) == 0 and fallback_info is None:
        fallback_rows, fallback_meta = execute_event_keyword_fallback_search(
            db, planned_query.sql
        )
        if fallback_rows:
            _log(
                "FALLBACK",
                f"{hypothesis.id} — found {len(fallback_rows)} rows via keyword_in_raw_json"
                + (
                    f" event_ids={fallback_meta.get('event_ids', [])} "
                    f"keywords={fallback_meta.get('keywords', [])}"
                    if fallback_meta
                    else ""
                ),
            )
            for row in fallback_rows[:20]:
                if isinstance(row, dict):
                    row["_fallback_phase"] = "keyword_in_raw_json"
                    row["_fallback_source_rule_id"] = "event_id_schema"
            rows = fallback_rows[:20]
            fallback_info = fallback_meta or {
                "phase": "keyword_in_raw_json",
                "source_rule_id": "event_id_schema",
            }
            fallback_info["query_sql"] = planned_query.sql
            fallback_info["original_row_count"] = len(fallback_rows)
            fallback_info["row_limit"] = 20
            fallback_info["truncated"] = len(fallback_rows) > 20
    return rows, fallback_info


def _row_source_refs(rows: list[dict[str, Any]]) -> set[str]:
    refs = {
        str(row.get(key)).strip()
        for row in rows
        for key in ("source_id", "source_file")
        if row.get(key)
    }
    for row in rows:
        source_ids = row.get("source_ids")
        if isinstance(source_ids, str):
            try:
                source_ids = json.loads(source_ids)
            except TypeError, ValueError:
                source_ids = None
        if isinstance(source_ids, (list, tuple, set)):
            refs.update(str(item).strip() for item in source_ids if item)
    return refs


def build_sql_receipt(
    *,
    db: CaseDB,
    session_id: str,
    plan_cycle: int,
    query_index: int,
    hypothesis: Hypothesis,
    planned_query: Any,
    query_hash: str,
    duration_ms: float,
    rows: list[dict[str, Any]] | None,
    original_row_count: int | None,
    fallback_info: dict[str, Any] | None = None,
    error: str | None = None,
) -> ToolReceipt:
    """Build a deterministic receipt from values observed by the runner."""

    is_error = error is not None
    used_fallback = fallback_info is not None
    result_summary = rows if rows is not None else []
    evidence_ids = [
        str(row.get("evidence_id")) for row in result_summary if row.get("evidence_id")
    ]
    source_refs = _row_source_refs(result_summary)
    derivation_refs = {
        str(row.get(key)).strip()
        for row in result_summary
        for key in ("derivation_group", "derivation_source")
        if row.get(key)
    }
    receipt_id = f"receipt-{session_id}-{plan_cycle}-{query_index}-{query_hash}"
    if is_error:
        status = "error"
        reason = error[:500] if error else None
        returned_count = sampled_count = truncated = None
        retry_hints = ["repair or pivot the SQL after reviewing the execution error"]
    elif used_fallback:
        fallback_row_count = fallback_info.get("original_row_count")
        status = "partial"
        reason = "bounded fallback result after empty primary query"
        returned_count = len(result_summary)
        sampled_count = min(len(result_summary), 10)
        truncated = bool(
            fallback_info.get("truncated")
            or (
                fallback_row_count is not None
                and int(fallback_row_count) > len(result_summary)
            )
        )
        retry_hints = [
            "inspect fallback provenance and verify Coverage before interpreting result"
        ]
    else:
        status = "empty" if not result_summary else "ok"
        reason = "no rows returned" if not result_summary else None
        returned_count = len(result_summary)
        sampled_count = None
        truncated = False
        retry_hints = (
            ["pivot retrieval or verify Coverage before interpreting empty results"]
            if not result_summary
            else []
        )
    return ToolReceipt(
        receipt_id=receipt_id,
        call_id=planned_query.query_id,
        session_id=session_id,
        hypothesis_id=hypothesis.id,
        phase="do",
        tool_id="sql.query",
        arguments={
            "query_id": planned_query.query_id,
            "template_id": planned_query.template_id,
            "params": planned_query.params,
            "normalized_sql": planned_query.sql,
            "original_returned_count": original_row_count,
            "fallback_row_count": fallback_info.get("original_row_count")
            if fallback_info
            else None,
            "fallback": fallback_info,
        },
        preconditions={
            "sql_validation": "planner_observed",
            "dry_run": "planner_observed",
        },
        coverage_snapshot=coverage_snapshot(db),
        query_hash=query_hash,
        cache={"status": "not_applicable"},
        duration_ms=round(duration_ms, 3),
        returned_count=returned_count,
        sampled_count=sampled_count,
        truncated=truncated,
        result_refs={
            "evidence_ids": evidence_ids,
            "finding_ids": [],
            "hypothesis_ids": [],
        },
        contributor_sources=sorted(source_refs),
        derivation_sources=sorted(derivation_refs),
        status=status,
        reason=reason,
        retry_hints=retry_hints,
        fingerprint=query_hash,
    )


def build_receipt_step_payload(
    receipt: ToolReceipt,
    evaluation: Any,
    result_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose trace JSON without adding assessment or verdict semantics."""

    return {
        **(result_summary or {}),
        "tool_receipt": receipt.model_dump(mode="json"),
        "retrieval_evaluation": evaluation.model_dump(mode="json"),
    }
