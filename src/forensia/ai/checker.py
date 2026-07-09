"""Checker entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.checker.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forensia.ai import llm_gateway
from forensia.ai.check_apply import (  # noqa: F401
    _insert_investigation_finding,
    _record_hypothesis_assessment,
    _upsert_ai_review,
    apply_check_result,
)
from forensia.ai.check_guardrails import (  # noqa: F401
    _co_observation_satisfied,
    _guardrail_check_payload,
    _verify_verdict_consistency,
    annotate_benign_context,
)
from forensia.ai.check_normalize import (  # noqa: F401
    _DURABLE_MEMORY_KEYS,
    _ENTITY_PLACEHOLDER_VALUES,
    SMALL_CONFIDENCE_DELTA,
    VALID_VERDICTS,
    CheckResult,
    _clamp_confidence,
    _coerce_float,
    _collect_observed_evidence_ids,
    _filter_evidence_references,
    _filter_memory_updates,
    _has_zero_evidence,
    _normalize_finding_updates,
    _normalize_status,
    _normalize_verdict,
    _parse_new_hypotheses,
    _parse_timestamp,
    _validate_extracted_findings,
    summarize_query_result,
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
    audit_callback: Callable[[str, list[dict[str, str]], str, dict[str, Any]], None]
    | None = None,
) -> CheckResult:
    """Run the LLM-based query result check: verdict + memory + suspicious evidence.

    Uses phased checking (separate LLM calls for verdict, memory, and
    suspicious evidence). Applies guardrails via _guardrail_check_payload
    and persists results via apply_check_result.
    """
    overview_md = overview_md if overview_md is not None else memory.load_overview()
    _relevance = memory.build_relevance_terms_from_hypothesis(hypothesis)
    memory_context_md = (
        memory_context_md
        if memory_context_md is not None
        else memory.load_compact_context(
            memory.investigation_context_files(
                hypothesis.id if hypothesis else None,
                relevance_terms=_relevance or None,
                include_overview=False,
            ),
            max_bytes=max(1024, memory.max_bytes // 2),
        )
    )
    benign_rules = _load_benign_context_rules()
    benign_annotations = (
        annotate_benign_context(result_summary.get("sample_rows") or [], benign_rules)
        if benign_rules
        else None
    )

    # Step 1: verdict_reviewer — classify result against hypothesis
    verdict_messages, verdict_schema = build_verdict_review_messages(
        hypothesis=hypothesis,
        planned_query=planned_query,
        result_summary=result_summary,
        time_range=time_range or {},
        fallback_info=fallback_info,
        benign_annotations=benign_annotations,
    )
    verdict_parsed = llm_gateway.request_llm_json(
        messages=verdict_messages,
        model=model,
        base_url=base_url,
        json_schema=verdict_schema,
        status_callback=status_callback,
        audit_callback=(
            lambda msgs, out, parsed, _p="check-verdict": audit_callback(
                _p, msgs, out, parsed
            )
        )
        if audit_callback
        else None,
    )
    verdict = _normalize_verdict(verdict_parsed.get("verdict"))

    # T-01: Deterministic claim–evidence consistency gate
    veto_verdict, veto_reason = _verify_verdict_consistency(
        verdict=verdict,
        rationale=verdict_parsed.get("rationale", ""),
        hypothesis=hypothesis,
        result_summary=result_summary,
    )
    if veto_reason:
        verdict = veto_verdict
        existing_rationale = str(verdict_parsed.get("rationale") or "")
        if existing_rationale:
            verdict_parsed["rationale"] = existing_rationale + " | " + veto_reason
        else:
            verdict_parsed["rationale"] = veto_reason
        existing_notes = str(verdict_parsed.get("notes") or "")
        if existing_notes:
            verdict_parsed["notes"] = existing_notes + "; " + veto_reason
        else:
            verdict_parsed["notes"] = veto_reason

    # Step 2: finding_extractor — extract structured findings (only for confirmed)
    extracted_findings: list[dict[str, Any]] = []
    if verdict == "confirmed":
        finding_messages, finding_schema = build_finding_extractor_messages(
            hypothesis=hypothesis,
            result_rows=result_summary.get("sample_rows") or [],
            verdict=verdict,
            rationale=verdict_parsed.get("rationale", ""),
        )
        finding_parsed = llm_gateway.request_llm_json(
            messages=finding_messages,
            model=model,
            base_url=base_url,
            json_schema=finding_schema,
            status_callback=status_callback,
            audit_callback=(
                lambda msgs, out, parsed, _p="check-finding-extract": audit_callback(
                    _p, msgs, out, parsed
                )
            )
            if audit_callback
            else None,
        )
        extracted_findings = finding_parsed.get("findings") or []

    # Step 3: memory_updater — propose durable memory writes
    memory_messages, memory_schema = build_memory_updater_messages(
        hypothesis=hypothesis,
        verdict=verdict,
        rationale=verdict_parsed.get("rationale", ""),
        result_summary=result_summary,
        time_range=time_range or {},
    )
    memory_parsed = llm_gateway.request_llm_json(
        messages=memory_messages,
        model=model,
        base_url=base_url,
        json_schema=memory_schema,
        status_callback=status_callback,
        audit_callback=(
            lambda msgs, out, parsed, _p="check-memory-update": audit_callback(
                _p, msgs, out, parsed
            )
        )
        if audit_callback
        else None,
    )

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

