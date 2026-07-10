"""Checker entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.checker.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forensia.ai import llm_gateway
from forensia.ai.check_apply import (
    apply_check_result,
)
from forensia.ai.check_guardrails import (
    _guardrail_check_payload,
    _verify_verdict_consistency,
    annotate_benign_context,
)
from forensia.ai.check_normalize import (
    CheckResult,
    _normalize_verdict,
    _parse_new_hypotheses,
)
from forensia.ai.prompt_investigation import (
    _load_benign_context_rules,
    build_finding_extractor_messages,
    build_memory_updater_messages,
    build_verdict_review_messages,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import (
    Hypothesis,
    PlannedQuery,
)
from forensia.db.database import CaseDB

CheckAuditCallback = Callable[
    [str, list[dict[str, str]], str, dict[str, Any]], None
]


def _load_check_context(
    memory: MemoryManager,
    hypothesis: Hypothesis | None,
    overview_md: str | None,
    memory_context_md: str | None,
) -> tuple[str, str]:
    overview = overview_md if overview_md is not None else memory.load_overview()
    if memory_context_md is not None:
        return overview, memory_context_md
    relevance = memory.build_relevance_terms_from_hypothesis(hypothesis)
    context = memory.load_compact_context(
        memory.investigation_context_files(
            hypothesis.id if hypothesis else None,
            relevance_terms=relevance or None,
            include_overview=False,
        ),
        max_bytes=max(1024, memory.max_bytes // 2),
    )
    return overview, context


def _phase_audit_callback(
    phase: str,
    audit_callback: CheckAuditCallback | None,
) -> Callable[[list[dict[str, str]], str, dict[str, Any]], None] | None:
    if audit_callback is None:
        return None

    return lambda msgs, out, parsed: audit_callback(phase, msgs, out, parsed)


def _request_check_json(
    *,
    phase: str,
    messages: list[dict[str, str]],
    schema: dict[str, Any],
    model: str,
    base_url: str,
    status_callback: Callable[[str], None] | None,
    audit_callback: CheckAuditCallback | None,
) -> dict[str, Any]:
    return llm_gateway.request_llm_json(
        messages=messages,
        model=model,
        base_url=base_url,
        json_schema=schema,
        status_callback=status_callback,
        audit_callback=_phase_audit_callback(phase, audit_callback),
    )


def _review_verdict(
    *,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    time_range: dict[str, str] | None,
    fallback_info: dict | None,
    benign_annotations: list[dict[str, Any]] | None,
    model: str,
    base_url: str,
    status_callback: Callable[[str], None] | None,
    audit_callback: CheckAuditCallback | None,
) -> tuple[str, dict[str, Any]]:
    verdict_messages, verdict_schema = build_verdict_review_messages(
        hypothesis=hypothesis,
        planned_query=planned_query,
        result_summary=result_summary,
        time_range=time_range or {},
        fallback_info=fallback_info,
        benign_annotations=benign_annotations,
    )
    verdict_parsed = _request_check_json(
        phase="check-verdict",
        messages=verdict_messages,
        schema=verdict_schema,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    verdict = _normalize_verdict(verdict_parsed.get("verdict"))
    return _apply_verdict_consistency_gate(
        verdict, verdict_parsed, hypothesis, result_summary
    )


def _apply_verdict_consistency_gate(
    verdict: str,
    verdict_parsed: dict[str, Any],
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    veto_verdict, veto_reason = _verify_verdict_consistency(
        verdict=verdict,
        rationale=verdict_parsed.get("rationale", ""),
        hypothesis=hypothesis,
        result_summary=result_summary,
    )
    if not veto_reason:
        return verdict, verdict_parsed
    verdict = veto_verdict
    existing_rationale = str(verdict_parsed.get("rationale") or "")
    verdict_parsed["rationale"] = (
        existing_rationale + " | " + veto_reason
        if existing_rationale
        else veto_reason
    )
    existing_notes = str(verdict_parsed.get("notes") or "")
    verdict_parsed["notes"] = (
        existing_notes + "; " + veto_reason if existing_notes else veto_reason
    )
    return verdict, verdict_parsed


def _extract_confirmed_findings(
    *,
    verdict: str,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    rationale: str,
    model: str,
    base_url: str,
    status_callback: Callable[[str], None] | None,
    audit_callback: CheckAuditCallback | None,
) -> list[dict[str, Any]]:
    if verdict != "confirmed":
        return []
    finding_messages, finding_schema = build_finding_extractor_messages(
        hypothesis=hypothesis,
        result_rows=result_summary.get("sample_rows") or [],
        verdict=verdict,
        rationale=rationale,
    )
    finding_parsed = _request_check_json(
        phase="check-finding-extract",
        messages=finding_messages,
        schema=finding_schema,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    return finding_parsed.get("findings") or []


def _propose_memory_updates(
    *,
    verdict: str,
    hypothesis: Hypothesis | None,
    result_summary: dict[str, Any],
    rationale: str,
    time_range: dict[str, str] | None,
    model: str,
    base_url: str,
    status_callback: Callable[[str], None] | None,
    audit_callback: CheckAuditCallback | None,
) -> dict[str, Any]:
    memory_messages, memory_schema = build_memory_updater_messages(
        hypothesis=hypothesis,
        verdict=verdict,
        rationale=rationale,
        result_summary=result_summary,
        time_range=time_range or {},
    )
    return _request_check_json(
        phase="check-memory-update",
        messages=memory_messages,
        schema=memory_schema,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )


def _build_guarded_check_result(
    *,
    planned_query: PlannedQuery,
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    fallback_info: dict | None,
    verdict: str,
    verdict_parsed: dict[str, Any],
    memory_parsed: dict[str, Any],
    extracted_findings: list[dict[str, Any]],
) -> tuple[CheckResult, dict[str, Any]]:
    merged = {
        "query_id": verdict_parsed.get("query_id") or planned_query.query_id,
        "verdict": verdict,
        "rationale": verdict_parsed.get("rationale", ""),
        "finding_updates": [],
        "suspicious_evidence": [],
        "new_hypotheses": memory_parsed.get("new_hypotheses") or [],
        "memory_updates": memory_parsed.get("memory_updates") or {},
        "report_text": verdict_parsed.get("rationale", "") or "",
        "missing_checks": [],
        "notes": "",
        "extracted_findings": extracted_findings,
    }
    guarded = _guardrail_check_payload(
        merged, finding_candidates, result_summary, fallback_info=fallback_info
    )
    result = CheckResult(
        query_id=guarded.get("query_id") or planned_query.query_id,
        verdict=str(guarded.get("verdict") or "inconclusive"),
        finding_updates=guarded.get("finding_updates") or [],
        suspicious_evidence=guarded.get("suspicious_evidence") or [],
        new_hypotheses=_parse_new_hypotheses(guarded.get("new_hypotheses")),
        memory_updates=guarded.get("memory_updates") or {},
        report_text=str(guarded.get("report_text") or ""),
        new_leads=0,
        progress=False,
        raw_response=merged,
    )
    return result, merged


def check_query_result(
    case: Case,
    db: CaseDB,
    session_id: str,
    planned_query: PlannedQuery,
    hypothesis: Hypothesis | None,
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    memory: MemoryManager,
    base_url: str,
    model: str,
    overview_md: str | None = None,
    memory_context_md: str | None = None,
    status_callback: Callable[[str], None] | None = None,
    time_range: dict[str, str] | None = None,
    fallback_info: dict | None = None,
    audit_callback: CheckAuditCallback | None = None,
) -> CheckResult:
    """Run the LLM-based query result check: verdict + memory + suspicious evidence.

    Uses phased checking (separate LLM calls for verdict, memory, and
    suspicious evidence). Applies guardrails via _guardrail_check_payload
    and persists results via apply_check_result.
    """
    overview_md, memory_context_md = _load_check_context(
        memory, hypothesis, overview_md, memory_context_md
    )
    benign_rules = _load_benign_context_rules()
    benign_annotations = (
        annotate_benign_context(result_summary.get("sample_rows") or [], benign_rules)
        if benign_rules
        else None
    )

    verdict, verdict_parsed = _review_verdict(
        planned_query=planned_query,
        hypothesis=hypothesis,
        result_summary=result_summary,
        time_range=time_range or {},
        fallback_info=fallback_info,
        benign_annotations=benign_annotations,
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    extracted_findings = _extract_confirmed_findings(
        verdict=verdict,
        hypothesis=hypothesis,
        result_summary=result_summary,
        rationale=verdict_parsed.get("rationale", ""),
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    memory_parsed = _propose_memory_updates(
        verdict=verdict,
        hypothesis=hypothesis,
        result_summary=result_summary,
        rationale=verdict_parsed.get("rationale", ""),
        time_range=time_range or {},
        model=model,
        base_url=base_url,
        status_callback=status_callback,
        audit_callback=audit_callback,
    )
    result, _merged = _build_guarded_check_result(
        planned_query=planned_query,
        finding_candidates=finding_candidates,
        result_summary=result_summary,
        fallback_info=fallback_info,
        verdict=verdict,
        verdict_parsed=verdict_parsed,
        memory_parsed=memory_parsed,
        extracted_findings=extracted_findings,
    )
    result.new_leads, result.progress = apply_check_result(
        case=case,
        db=db,
        session_id=session_id,
        planned_query=planned_query,
        hypothesis=hypothesis,
        result_summary=result_summary,
        check_result=result,
    )
    return result
