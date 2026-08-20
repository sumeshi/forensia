"""Observational retrieval telemetry stored outside the evidence SSoT."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from forensia.db.database import CaseDB


class ResultRefs(BaseModel):
    """Stable result handles; Evidence roles are intentionally impossible here."""

    model_config = ConfigDict(extra="forbid")

    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)


class ToolReceipt(BaseModel):
    """Versioned observation of one existing tool/action execution.

    This is deliberately a trace contract, not an evidence-assessment model:
    it records result references and derivation provenance, but never assigns
    Evidence roles or interprets a checker verdict.
    """

    model_config = ConfigDict(extra="forbid")

    receipt_version: Literal["1"] = "1"
    receipt_id: str
    call_id: str
    session_id: str | None = None
    hypothesis_id: str | None = None
    phase: str
    tool_id: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    preconditions: dict[str, Any] = Field(default_factory=dict)
    coverage_snapshot: dict[str, Any] = Field(default_factory=dict)
    query_hash: str | None = None
    cache: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float | None = None
    returned_count: int | None = None
    sampled_count: int | None = None
    truncated: bool | None = None
    result_refs: ResultRefs = Field(default_factory=ResultRefs)
    contributor_sources: list[str] = Field(default_factory=list)
    derivation_sources: list[str] = Field(default_factory=list)
    status: Literal["ok", "empty", "partial", "unavailable", "error"]
    reason: str | None = None
    retry_hints: list[str] = Field(default_factory=list)
    fingerprint: str | None = None


class RetrievalEvaluation(BaseModel):
    """One-attempt retrieval adequacy, before Evidence Assessment."""

    model_config = ConfigDict(extra="forbid")

    evaluation_version: Literal["1"] = "1"
    receipt_id: str
    outcome: Literal["adequate", "needs-pivot", "unavailable", "partial", "invalid"]
    required_fields_missing: list[str] = Field(default_factory=list)
    scope_status: Literal["valid", "rejected", "unknown"] = "unknown"
    coverage_status: Literal["available", "partial", "unknown", "unavailable"] = (
        "unknown"
    )
    sampling: dict[str, Any] = Field(default_factory=dict)
    empty_semantics: Literal["not_empty", "observable", "unknown"] = "not_empty"
    retry_hints: list[str] = Field(default_factory=list)


def coverage_snapshot(db: CaseDB) -> dict[str, Any]:
    """Read the existing Coverage projection without changing its semantics."""

    try:
        rows = db.execute(
            "SELECT capability, state, reason_code, source_family "
            "FROM evidence_coverage ORDER BY source_family, capability"
        ).fetchall()
    except Exception:
        return {"status": "unknown", "reason": "coverage_unavailable"}
    return {
        "status": "observed",
        "capabilities": {
            f"{row[3] or ''}:{row[0] or ''}": {
                "state": row[1],
                "reason": row[2] or "",
                "source_family": row[3] or "",
            }
            for row in rows
        },
    }


def evaluate_retrieval(
    receipt: ToolReceipt,
    *,
    required_fields: list[str] | None = None,
    required_capabilities: list[str] | None = None,
    scope_status: Literal["valid", "rejected", "unknown"] = "unknown",
) -> RetrievalEvaluation:
    """Evaluate exactly one receipt; never infer role, sufficiency, or verdict."""

    missing = [
        field for field in (required_fields or []) if not receipt.arguments.get(field)
    ]
    coverage = str(receipt.coverage_snapshot.get("status") or "unknown")
    required = [str(item) for item in (required_capabilities or []) if item]
    if coverage == "observed" and required:
        all_capabilities = receipt.coverage_snapshot.get("capabilities") or {}
        states: list[str] = []
        for capability in required:
            matches = [
                str(value.get("state") or "unknown")
                for key, value in all_capabilities.items()
                if isinstance(value, dict) and str(key).endswith(f":{capability}")
            ]
            states.extend(matches or ["unknown"])
        state_set = set(states)
        if state_set == {"available"}:
            coverage_status: Literal[
                "available", "partial", "unknown", "unavailable"
            ] = "available"
        elif "unavailable" in state_set:
            coverage_status = "unavailable"
        elif state_set - {"unknown"}:
            coverage_status = "partial"
        else:
            coverage_status = "unknown"
    else:
        coverage_status = (
            coverage if coverage in {"partial", "unavailable"} else "unknown"
        )

    if missing or scope_status == "rejected":
        outcome: Literal[
            "adequate", "needs-pivot", "unavailable", "partial", "invalid"
        ] = "invalid"
    elif receipt.status in {"error", "unavailable"}:
        outcome = "unavailable"
    elif receipt.status == "partial":
        outcome = "partial"
    elif receipt.returned_count == 0 and coverage_status != "available":
        outcome = "partial"
    else:
        outcome = "adequate"

    empty_semantics: Literal["not_empty", "observable", "unknown"] = "not_empty"
    if receipt.status == "empty":
        empty_semantics = "observable" if coverage_status == "available" else "unknown"
    hints = list(receipt.retry_hints)
    if outcome in {"invalid", "needs-pivot", "partial"} and not hints:
        hints = ["narrow or pivot the retrieval scope"]
    return RetrievalEvaluation(
        receipt_id=receipt.receipt_id,
        outcome=outcome,
        required_fields_missing=missing,
        scope_status=scope_status,
        coverage_status=coverage_status,
        sampling={
            "returned_count": receipt.returned_count,
            "sampled_count": receipt.sampled_count,
            "truncated": receipt.truncated,
        },
        empty_semantics=empty_semantics,
        retry_hints=hints,
    )


def record_retrieval_event(
    db: CaseDB,
    *,
    session_id: str | None,
    scope_kind: str,
    scope_id: str | None,
    phase: str,
    source_kind: str,
    query_terms: list[str],
    candidate_count: int,
    selected_refs: list[str],
    selected_chars: int,
    budget: int,
    rejected_refs: list[str] | None = None,
) -> None:
    """Record what retrieval exposed; never feed observations into ranking."""
    db.execute(
        """
        INSERT INTO retrieval_events (
            event_id, session_id, scope_kind, scope_id, phase, source_kind,
            query_terms, candidate_count, selected_refs, rejected_refs,
            selected_chars, budget, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            session_id,
            scope_kind,
            scope_id,
            phase,
            source_kind,
            json.dumps(query_terms, ensure_ascii=False),
            candidate_count,
            json.dumps(selected_refs, ensure_ascii=False),
            json.dumps(rejected_refs or [], ensure_ascii=False),
            selected_chars,
            budget,
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
