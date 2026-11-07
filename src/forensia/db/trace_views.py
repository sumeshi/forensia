"""Read-only navigation and bounded timelines over existing case records."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from forensia.db.database import CaseDB

_LINK_LIMIT = 50
_CAUSAL_LINK_LIMIT = 16
_SUMMARY_LIMIT = 320
_TIMELINE_LIMIT = 50

# These are persisted reference fields, never substrings found in model text,
# SQL, query labels, request bodies, or provider responses.
_REFERENCE_FIELDS = {
    "hypothesis_id": "hypothesis",
    "hypothesis_ids": "hypothesis",
    "task_id": "task",
    "task_ids": "task",
    "gap_id": "gap",
    "source_gap_id": "gap",
    "finding_id": "finding",
    "finding_ids": "finding",
    "evidence_id": "evidence",
    "evidence_ids": "evidence",
    "observed_evidence_ids": "evidence",
    "assessment_id": "assessment",
    "assessment_ids": "assessment",
    "step_id": "step",
    "plan_step_id": "step",
    "execution_step_id": "step",
    "fallback_start_step_id": "step",
    "fallback_step_ids": "step",
    "do_step_id": "step",
    "check_step_id": "step",
    "sufficiency_step_id": "step",
    "settlement_ref": "step",
    "contract_ref": "step",
    "logical_call_id": "llm_call",
    "parent_logical_call_id": "llm_call",
    "attempt_id": "llm_attempt",
    "attempt_ids": "llm_attempt",
    "parent_attempt_id": "llm_attempt",
    "provider_attempt_id": "llm_attempt",
    "provider_attempt_ids": "llm_attempt",
    "receipt_id": "query_receipt",
    "command_id": "command_receipt",
    "reasoning_entry_id": "reasoning",
    "section_key": "section",
    "section_id": "section",
    "retrieval_event_id": "retrieval",
}
_CONTAINERS = (
    "refs",
    "input_json",
    "output_json",
    "tool_receipt",
    "arguments",
    "result_refs",
    "attempt",
    "assessment",
    "settlement",
    "contract",
    "completion",
    "payload",
)


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError, TypeError:
            return {}
    return value if isinstance(value, dict) else {}


def _ids(value: Any) -> list[str]:
    values = value if isinstance(value, (list, tuple)) else [value]
    return [item for item in values[:_LINK_LIMIT] if isinstance(item, str) and item]


def _attempt_record(db: CaseDB, attempt_ref: str) -> str | None:
    """Resolve ambiguous legacy attempt refs by exact persisted identity only."""
    if db.execute(
        "SELECT 1 FROM trace.investigation_steps WHERE phase = 'do' AND "
        "json_extract_string(output_json, '$.tool_receipt.receipt_id') = ? LIMIT 1",
        (attempt_ref,),
    ).fetchone():
        return "query_receipt"
    if db.execute(
        "SELECT 1 FROM trace.investigation_steps WHERE step_id = ? LIMIT 1",
        (attempt_ref,),
    ).fetchone():
        return "step"
    return None


def related_records(db: CaseDB, kind: str, row: dict[str, Any]) -> list[dict[str, str]]:
    """Project typed links from known reference fields, with a finite fanout."""
    links: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    evidence_links: dict[str, str] = {}
    own_ids = {
        "step": row.get("step_id"),
        "hypothesis": row.get("hypothesis_id"),
        "task": row.get("task_id"),
        "gap": row.get("gap_id"),
        "llm_call": row.get("logical_call_id"),
        "llm_attempt": row.get("attempt_id"),
        "evidence": row.get("evidence_id"),
        "finding": row.get("finding_id"),
        "query_receipt": _object(
            _object(row.get("output_json")).get("tool_receipt")
        ).get("receipt_id"),
    }

    def add(target_kind: str, item_id: str, label: str) -> None:
        key = (target_kind, item_id)
        if key in seen or len(links) >= _LINK_LIMIT:
            return
        if target_kind == kind and item_id == own_ids.get(kind):
            return
        seen.add(key)
        links.append({"kind": target_kind, "id": item_id, "label": label})

    def visit(data: dict[str, Any], depth: int = 0) -> None:
        if not data or depth > 4 or len(links) >= _LINK_LIMIT:
            return
        for field, target_kind in _REFERENCE_FIELDS.items():
            for item_id in _ids(data.get(field)):
                label = field.replace("_", " ")
                if target_kind == "evidence":
                    label += " (current record; historical identity only)"
                    if len(evidence_links) < _LINK_LIMIT:
                        evidence_links.setdefault(item_id, label)
                else:
                    add(target_kind, item_id, label)
        for field in ("attempt_ref", "blocked_attempt_ref"):
            for item_id in _ids(data.get(field)):
                if target_kind := _attempt_record(db, item_id):
                    add(target_kind, item_id, field.replace("_", " "))
        contracts = _object(data.get("task_contract_refs"))
        for task_id, contract_ref in list(contracts.items())[:_LINK_LIMIT]:
            add("task", str(task_id), "task with recorded contract")
            for item_id in _ids(contract_ref):
                add("step", item_id, "task contract")
        for field in _CONTAINERS:
            visit(_object(data.get(field)), depth + 1)

    if kind in {"step", "llm_call"}:
        action_id = (
            _object(row.get("input_json")).get("action_id")
            if kind == "step"
            else row.get("action_id")
        ) or row.get("action_id")
        if isinstance(action_id, str) and action_id:
            # Null denotes an explicitly case-wide owner, never a wildcard.
            # In particular, matching action labels from another session or
            # hypothesis must not produce a causal link.
            scope = (action_id, row.get("session_id"), row.get("hypothesis_id"))
            if kind == "step":
                action_rows = db.execute(
                    "SELECT logical_call_id FROM trace.llm_logical_calls "
                    "WHERE action_id = ? AND session_id IS NOT DISTINCT FROM ? "
                    "AND hypothesis_id IS NOT DISTINCT FROM ? "
                    "ORDER BY created_at, logical_call_id LIMIT ?",
                    (*scope, _CAUSAL_LINK_LIMIT),
                ).fetchall()
                target_kind = "llm_call"
            else:
                action_rows = db.execute(
                    "SELECT step_id FROM trace.investigation_steps "
                    "WHERE json_extract_string(input_json, '$.action_id') = ? "
                    "AND session_id IS NOT DISTINCT FROM ? "
                    "AND hypothesis_id IS NOT DISTINCT FROM ? "
                    "ORDER BY created_at, step_id LIMIT ?",
                    (*scope, _CAUSAL_LINK_LIMIT),
                ).fetchall()
                target_kind = "step"
            for (item_id,) in action_rows:
                add(target_kind, item_id, "same recorded action and owner")
    if kind == "step" and isinstance(row.get("step_id"), str):
        # Follow explicit children as well as their recorded parent references.
        # This reveals branches without guessing causality from timestamps.
        paths = [
            ("input_json", field)
            for field in (
                "plan_step_id",
                "execution_step_id",
                "fallback_start_step_id",
                "do_step_id",
                "check_step_id",
                "sufficiency_step_id",
                "settlement_ref",
            )
        ] + [
            ("output_json", "settlement_ref"),
            ("output_json", "completion.settlement_ref"),
        ]
        conditions = " OR ".join(
            f"json_extract_string({column}, '$.{path}') = ?" for column, path in paths
        )
        children = db.execute(
            "SELECT step_id FROM trace.investigation_steps "
            "WHERE step_id != ? AND session_id IS NOT DISTINCT FROM ? "
            "AND hypothesis_id IS NOT DISTINCT FROM ? "
            f"AND ({conditions}) ORDER BY created_at, step_id LIMIT ?",
            (
                row["step_id"],
                row.get("session_id"),
                row.get("hypothesis_id"),
                *((row["step_id"],) * len(paths)),
                _CAUSAL_LINK_LIMIT,
            ),
        ).fetchall()
        for (item_id,) in children:
            add("step", item_id, "explicitly linked subsequent record")
    visit(row)
    if kind == "hypothesis":
        for item_id in _ids(row.get("hypothesis_id")):
            add("timeline", item_id, "recorded hypothesis timeline")
    if kind == "retrieval" and row.get("scope_kind") == "hypothesis":
        for item_id in _ids(row.get("scope_id")):
            add("hypothesis", item_id, "recorded retrieval scope")
    if kind == "llm_call":
        for item_id in _ids(row.get("attempt_ids")):
            add("llm_attempt", item_id, "provider attempt")
    # Preserve causal, contract and assessment navigation even if a result
    # references hundreds of evidence records. Evidence uses the remaining cap.
    for item_id, label in evidence_links.items():
        add("evidence", item_id, label)
    return links


_TIMELINE_SQL = """
    SELECT 'step' AS kind, step_id AS id, session_id, phase, iteration, created_at
    FROM trace.investigation_steps WHERE hypothesis_id = ?
    UNION ALL
    SELECT 'llm_call', logical_call_id, session_id, phase, iteration, created_at
    FROM trace.llm_logical_calls WHERE hypothesis_id = ?
    UNION ALL
    SELECT 'reasoning', entry_id, session_id, phase, iteration, created_at
    FROM trace.hypothesis_reasoning WHERE hypothesis_id = ?
"""


def _step_projection(db: CaseDB, step_id: str) -> dict[str, Any]:
    """Read selected reference fields and typed facts, never model prose."""
    # JSON extraction stays in the database so large check/provider payloads do
    # not become the timeline's input. Original data remains in step details.
    paths = {
        "purpose": ("input_json", "$.planned_query.purpose"),
        "action_id": ("input_json", "$.action_id"),
        "plan_step_id": ("input_json", "$.plan_step_id"),
        "execution_step_id": ("input_json", "$.execution_step_id"),
        "fallback_start_step_id": ("input_json", "$.fallback_start_step_id"),
        "do_step_id": ("input_json", "$.do_step_id"),
        "check_step_id": ("input_json", "$.check_step_id"),
        "sufficiency_step_id": ("input_json", "$.sufficiency_step_id"),
        "task_id": ("input_json", "$.task_id"),
        "contract_ref": ("input_json", "$.contract_ref"),
        "attempt_ref": ("output_json", "$.attempt_ref"),
        "receipt_id": ("output_json", "$.tool_receipt.receipt_id"),
        "receipt_status": ("output_json", "$.tool_receipt.status"),
        "returned_count": ("output_json", "$.tool_receipt.returned_count"),
        "attempt_status": ("output_json", "$.attempt.status"),
        "record_status": ("output_json", "$.status"),
        "error_type": ("output_json", "$.error_type"),
        "check_verdict": ("output_json", "$.check_verdict"),
        "retrieval_outcome": ("output_json", "$.attempt.retrieval_outcome"),
        "assessment_id": ("output_json", "$.assessment.assessment_id"),
        "settlement_verdict": ("output_json", "$.settlement.verdict"),
        "settlement_allowed": ("output_json", "$.settlement.allowed"),
        "completion_status": ("output_json", "$.completion.status"),
        "completion_reason": ("output_json", "$.completion.reason"),
        "settlement_ref": ("output_json", "$.completion.settlement_ref"),
        "contract_task_id": ("output_json", "$.contract.task_id"),
    }
    expressions = []
    for key, (column, path) in paths.items():
        expression = f"json_extract_string({column}, '{path}')"
        if key == "purpose":
            expression = f"coalesce(nullif({expression}, ''), json_extract_string(output_json, '$.materialized_query.purpose'))"
            expression = f"left({expression}, {_SUMMARY_LIMIT})"
        elif key == "attempt_ref":
            expression = (
                f"coalesce(nullif({expression}, ''), "
                "json_extract_string(input_json, '$.attempt_ref'), "
                "json_extract_string(output_json, '$.attempt.attempt_ref'), "
                "json_extract_string(output_json, '$.settlement.attempt_ref'))"
            )
        elif key == "settlement_ref":
            expression = (
                f"coalesce(nullif({expression}, ''), "
                "json_extract_string(input_json, '$.settlement_ref'), "
                "json_extract_string(output_json, '$.settlement_ref'))"
            )
        elif key == "retrieval_outcome":
            expression = (
                f"coalesce(nullif({expression}, ''), "
                "json_extract_string(output_json, '$.retrieval_evaluation.outcome'))"
            )
        expressions.append(f"{expression} AS {key}")
    result = db.execute(
        f"SELECT {', '.join(expressions)} FROM trace.investigation_steps WHERE step_id = ?",
        (step_id,),
    )
    row = result.fetchone()
    return dict(zip(paths, row, strict=True)) if row else {}


def _step_summary(phase: str | None, facts: dict[str, Any]) -> str:
    parts = [phase or "step"]
    if phase == "query-execution":
        parts.append("started (historical event)")
    if status := facts.get("receipt_status") or facts.get("attempt_status"):
        parts.append(f"execution {status}")
    elif phase != "query-execution" and (status := facts.get("record_status")):
        parts.append(f"recorded status {status}")
    if error_type := facts.get("error_type"):
        parts.append(f"error type {error_type}")
    if facts.get("returned_count") is not None:
        parts.append(f"returned {facts['returned_count']} rows")
    if outcome := facts.get("retrieval_outcome"):
        parts.append(f"retrieval {outcome}")
    if verdict := facts.get("settlement_verdict"):
        parts.append(
            f"host verdict {verdict}; allowed={facts.get('settlement_allowed')}"
        )
    if verdict := facts.get("check_verdict"):
        parts.append(f"checker proposal {verdict}")
    if status := facts.get("completion_status"):
        parts.append(
            f"task {status}: {facts.get('completion_reason') or 'unknown reason'}"
        )
    if purpose := facts.get("purpose"):
        parts.append(purpose[:160] + ("…" if len(purpose) > 160 else ""))
    text = " · ".join(" ".join(str(part).split()) for part in parts)
    return text[:_SUMMARY_LIMIT] + ("…" if len(text) > _SUMMARY_LIMIT else "")


def hypothesis_timeline(
    db: CaseDB, hypothesis_id: str, *, limit: int = 50, offset: int = 0
) -> dict[str, Any] | None:
    """Page records explicitly owned by one hypothesis across all sessions."""
    if limit < 1 or type(offset) is not int or offset < 0:
        raise ValueError(
            "timeline limit must be positive and offset a nonnegative integer"
        )
    page_size = min(limit, _TIMELINE_LIMIT)
    params = (hypothesis_id,) * 3
    total = int(
        db.execute(
            f"SELECT count(*) FROM ({_TIMELINE_SQL}) records", params
        ).fetchone()[0]
    )
    if (
        not total
        and not db.execute(
            "SELECT 1 FROM hypotheses WHERE hypothesis_id = ?", (hypothesis_id,)
        ).fetchone()
    ):
        return None
    result = db.execute(
        f"SELECT * FROM ({_TIMELINE_SQL}) records "
        "ORDER BY created_at NULLS LAST, kind, id LIMIT ? OFFSET ?",
        (*params, page_size, offset),
    )
    columns = [item[0] for item in result.description]
    items = []
    for values in result.fetchall():
        item = dict(zip(columns, values, strict=True))
        if isinstance(item["created_at"], datetime):
            item["created_at"] = item["created_at"].isoformat()
        kind, item_id = item["kind"], item["id"]
        refs = [{"kind": kind, "id": item_id, "label": "original record"}]
        metadata = {"hypothesis_id": hypothesis_id, "session_id": item["session_id"]}
        if kind == "step":
            metadata["step_id"] = item_id
            facts = _step_projection(db, item_id)
            metadata.update(facts)
            if facts.get("contract_task_id"):
                metadata["task_id"] = facts["contract_task_id"]
            item["summary"] = _step_summary(item["phase"], facts)
        elif kind == "llm_call":
            call = db.execute(
                "SELECT status, parent_logical_call_id, action_id FROM trace.llm_logical_calls "
                "WHERE logical_call_id = ?",
                (item_id,),
            ).fetchone()
            metadata["parent_logical_call_id"] = call[1]
            metadata["action_id"] = call[2]
            metadata["attempt_ids"] = [
                row[0]
                for row in db.execute(
                    "SELECT attempt_id FROM trace.llm_provider_attempts "
                    "WHERE logical_call_id = ? ORDER BY start_time NULLS LAST, attempt_id LIMIT ?",
                    (item_id, _LINK_LIMIT - 2),
                ).fetchall()
            ]
            item["summary"] = (
                f"LLM {item['phase'] or 'call'} · {call[0] or 'unknown status'}"
            )
        else:
            # Reasoning may contain model claims and raw errors. Its existence
            # and phase are useful here; the body requires opening the original.
            item["summary"] = (
                f"reasoning · {item['phase'] or 'unknown phase'} (open original)"
            )
        item["summary"] = item["summary"][:_SUMMARY_LIMIT]
        refs.extend(related_records(db, kind, metadata))
        item["related_records"] = refs[:_LINK_LIMIT]
        item["correlation_status"] = "recorded" if len(refs) > 2 else "unknown"
        items.append(item)
    session_ids = sorted(
        {str(item["session_id"]) for item in items if item["session_id"]}
    )
    provenance = []
    for session_id in session_ids:
        provenance.extend(
            {"kind": "step", "id": step_id, "label": f"{phase} · {session_id}"}
            for step_id, phase in db.execute(
                "SELECT step_id, phase FROM trace.investigation_steps "
                "WHERE session_id = ? AND phase IN ('runtime-provenance', 'session-settings') "
                "ORDER BY created_at, step_id LIMIT 4",
                (session_id,),
            ).fetchall()
        )
    return {
        "kind": "timeline",
        "id": hypothesis_id,
        "items": items,
        "offset": offset,
        "next_offset": offset + len(items) if offset + len(items) < total else None,
        "total_items": total,
        "related_records": [
            {"kind": "hypothesis", "id": hypothesis_id, "label": "current hypothesis"},
            *provenance,
        ][:_LINK_LIMIT],
    }
