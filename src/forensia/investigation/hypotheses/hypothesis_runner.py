"""Deep-dive execution of a single hypothesis across investigation steps."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from forensia.context.case_profile import CaseEvidenceProfile, observed_event_ids
from forensia.context.retrieval import evaluate_retrieval
from forensia.core.case import Case
from forensia.core.control import check_stop
from forensia.core.log import log as _log
from forensia.core.progress_event import progress_event
from forensia.core.session import (
    HistoryEntry,
    Hypothesis,
    LLMBudgetExceededError,
    SessionState,
)
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records, summarize_query_result
from forensia.evidence.content_identity import fingerprint_from_record
from forensia.evidence.links import verification_spec_fingerprint
from forensia.investigation.hypotheses.execution import (
    _evidence_scope_fingerprint,
    _query_artifact_families,
    _repeat_gate_decision,
    build_receipt_step_payload,
    build_sql_receipt,
    resolve_zero_row_fallbacks,
    sql_absence_scope,
)
from forensia.investigation.hypotheses.hypothesis_manager import (
    _guess_related_sections,
    _merge_active_hypotheses_in_transaction,
    _resolve_hypothesis_in_transaction,
    admit_new_hypothesis,
)
from forensia.investigation.hypotheses.hypothesis_store import (
    _upsert_hypothesis,
)
from forensia.investigation.hypotheses.relations import insert_relation
from forensia.investigation.investigation_session import (
    Ctx,
    _call_with_outage_recovery,
    _save_step,
    append_hypothesis_reasoning,
    append_settlement_feedback,
)
from forensia.investigation.planner import (
    persist_hypothesis_plan_result,
    plan_hypothesis_query,
    planner_retry_allowed,
)
from forensia.investigation.progress import (
    HypothesisProgressTracker,
    query_fingerprint,
)
from forensia.investigation.verification.assessment import (
    EvidenceAssessment,
    assess_evidence_group,
)
from forensia.investigation.verification.checker import check_query_result
from forensia.investigation.verification.settlement import (
    SettlementInput,
    build_settlement_input_from_confirm_when,
    judge_absence_scope,
    settle_hypothesis,
)
from forensia.investigation.verification.sufficiency import (
    SufficiencyResult,
    assess_and_persist_sufficiency,
    create_evidence_links_for_query,
    record_unlinkable_observation,
)
from forensia.knowledge.coverage import (
    derive_required_capabilities,
)


def _unavailable_missing_event_ids(
    missing_questions: list[Any],
    available_event_ids: set[int] | None,
) -> list[int]:
    """Return event IDs referenced by the check's missing_questions that the case
    telemetry cannot contain.

    Returns an empty list (i.e. "keep investigating") when:
    - no availability profile is set,
    - the missing questions reference no known event IDs,
    - at least one referenced event ID exists in the case, or
    - the missing questions also point at an artifact-table alternative
      (mft_*/prefetch_*), which remains testable without those event IDs.
    """
    if not available_event_ids or not missing_questions:
        return []
    from forensia.knowledge.catalog import load_event_id_hints

    vocabulary = set(load_event_id_hints().keys())
    if not vocabulary:
        return []
    missing_text = " ".join(str(q).lower() for q in missing_questions if q)
    referenced = {
        int(m) for m in re.findall(r"\b(\d{3,5})\b", missing_text)
    } & vocabulary
    if not referenced:
        return []
    if referenced & available_event_ids:
        return []
    if any(
        t in missing_text for t in ("mft_entries", "mft_timeline", "prefetch", "mft ")
    ):
        return []
    return sorted(referenced)


def _matching_findings(
    snapshot: list[dict[str, Any]], hypothesis: Hypothesis | None
) -> list[dict[str, Any]]:
    """Return findings whose title/summary/severity share tokens with the hypothesis description."""
    if hypothesis is None:
        return snapshot[:10]
    words = {
        token.lower() for token in hypothesis.description.split() if len(token) >= 3
    }
    if not words:
        return snapshot[:10]
    matched = []
    for finding in snapshot:
        haystack = " ".join(
            str(finding.get(key, "") or "")
            for key in ("title", "summary", "severity", "status")
        ).lower()
        if any(word in haystack for word in words):
            matched.append(finding)
    return matched[:10] if matched else snapshot[:10]


def _rationale_signature(rationale: str) -> str:
    text = rationale.lower()
    eids = sorted(set(re.findall(r"\b(?:event\s*id\s*)?(\d{3,5})\b", text)))
    keywords = sorted(
        set(
            re.findall(r"\b(missing|requires|correlation|not\s+present|absent)\b", text)
        )
    )
    return "eid:" + ",".join(eids) + "|kw:" + ",".join(keywords)


def _result_evidence_ids(rows: list[dict[str, Any]]) -> list[str]:
    """Return every linkable row identity, including Registry artifact IDs."""
    return list(
        dict.fromkeys(
            str(row.get("evidence_id") or row.get("artifact_id") or "").strip()
            for row in rows
            if row.get("evidence_id") or row.get("artifact_id")
        )
    )


def _canonical_evidence_rows(
    db: CaseDB, rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str], dict[str, str]]:
    """Hydrate canonical evidence rows and fingerprint the fetched records."""
    from forensia.db.evidence_lookup import fetch_evidence_records, routed_family

    observed_ids = _result_evidence_ids(rows)
    records = fetch_evidence_records(db, observed_ids)
    canonical_ids = sorted(
        evidence_id for evidence_id in observed_ids if evidence_id in records
    )
    fingerprints = {
        evidence_id: fingerprint_from_record(records[evidence_id])
        for evidence_id in canonical_ids
    }
    canonical_rows = []
    for evidence_id in canonical_ids:
        record = records[evidence_id]
        canonical_rows.append(
            {
                **record,
                "evidence_id": evidence_id,
                "raw_json": record.get("raw"),
                "source_family": routed_family(evidence_id) or "",
            }
        )
    return canonical_rows, canonical_ids, fingerprints


def _finding_ids_by_evidence(db: CaseDB, evidence_ids: list[str]) -> dict[str, str]:
    """Map canonical evidence IDs to persisted finding provenance."""
    ids = sorted(
        {str(evidence_id).strip() for evidence_id in evidence_ids if evidence_id}
    )
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    rows = db.execute(
        "SELECT f.finding_id, json_extract_string(j.value, '$.evidence_id') "
        "FROM findings f, json_each(f.evidence) j "
        f"WHERE json_extract_string(j.value, '$.evidence_id') IN ({placeholders}) "
        "ORDER BY 2, 1",
        ids,
    ).fetchall()
    finding_ids: dict[str, str] = {}
    for finding_id, evidence_id in rows:
        normalized_finding = str(finding_id or "").strip()
        normalized_evidence = str(evidence_id or "").strip()
        if normalized_finding and normalized_evidence:
            finding_ids.setdefault(normalized_evidence, normalized_finding)
    return finding_ids


def _canonical_query_summary(
    rows: list[dict[str, Any]],
    assessment: EvidenceAssessment,
    *,
    observed_row_count: int,
    sample_size: int = 10,
    finding_ids_by_evidence: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build evaluation summaries only from unique canonical records."""
    summary = summarize_query_result(rows, sample_size=sample_size)
    witness_ids: set[str] = set()
    if assessment.role in {"supporting", "contradictory"}:
        witness_ids = {
            evidence_id for group in assessment.witness_groups for evidence_id in group
        }
    rows_by_id = {
        str(row.get("evidence_id") or row.get("artifact_id") or "").strip(): row
        for row in rows
        if row.get("evidence_id") or row.get("artifact_id")
    }
    chosen_ids: list[str] = []
    for evidence_id in sorted(witness_ids):
        if evidence_id in rows_by_id:
            chosen_ids.append(evidence_id)
            if len(chosen_ids) >= sample_size:
                break
    for row in summary.get("sample_rows") or []:
        evidence_id = str(
            row.get("evidence_id") or row.get("artifact_id") or ""
        ).strip()
        if (
            evidence_id
            and evidence_id not in chosen_ids
            and len(chosen_ids) < sample_size
        ):
            chosen_ids.append(evidence_id)

    summary["sample_rows"] = [rows_by_id[evidence_id] for evidence_id in chosen_ids]
    summary["evidence_ids"] = chosen_ids
    row_finding_ids_by_evidence = {
        str(row.get("evidence_id") or row.get("artifact_id")): str(
            row.get("finding_id")
        )
        for row in summary["sample_rows"]
        if (row.get("evidence_id") or row.get("artifact_id")) and row.get("finding_id")
    }
    for evidence_id, finding_id in (finding_ids_by_evidence or {}).items():
        row_finding_ids_by_evidence.setdefault(evidence_id, finding_id)
    summary["finding_ids_by_evidence"] = {
        evidence_id: row_finding_ids_by_evidence[evidence_id]
        for evidence_id in chosen_ids
        if evidence_id in row_finding_ids_by_evidence
    }
    summary["finding_ids"] = list(
        dict.fromkeys(summary["finding_ids_by_evidence"].values())
    )
    summary["observed_row_count"] = observed_row_count
    return summary


def _is_transient_execution_error(error: str) -> bool:
    text = (error or "").casefold()
    return any(
        marker in text
        for marker in (
            "timed out",
            "timeout",
            "temporarily",
            "connection reset",
            "connection closed",
            "database is locked",
            "resource temporarily unavailable",
            "i/o error",
        )
    )


@dataclass
class _HypothesisRunState:
    """Mutable state shared across the phases of one hypothesis run."""

    hypothesis: Hypothesis
    state: SessionState
    ctx: Ctx
    db: CaseDB
    base_url: str
    model: str
    plan_cycle: int
    session_id: str
    case: Case
    emit_fn: Callable[..., None] | None
    llm_status_fn: Callable[[str], None] | None
    case_profile: CaseEvidenceProfile | None
    candidates: list[dict[str, Any]]
    tracker: HypothesisProgressTracker
    focus_sections: dict[str, str]
    query_index: int = 0
    hypothesis_plan: Any = None
    planned_query: Any = None
    rows: list[Any] | None = None
    canonical_evidence_ids: list[str] | None = None
    finding_ids_by_evidence: dict[str, str] | None = None
    observed_evidence_ids: list[str] | None = None
    canonicalization_error: str = ""
    fallback_info: dict[str, Any] | None = None
    result_summary: dict[str, Any] | None = None
    check_result: Any = None
    evidence_assessment: EvidenceAssessment | None = None
    missing_checks_raw: list[Any] | None = None
    retrieval_evaluation: Any = None
    sufficiency_result: SufficiencyResult | None = None
    planner_retry_granted: bool = False
    attempt_ref: str = ""
    attempt_fingerprints: dict[str, str] | None = None
    repeat_gate: dict[str, Any] | None = None


async def _phase_plan(rs: _HypothesisRunState) -> str:
    hypothesis, state = rs.hypothesis, rs.state
    db, case = rs.db, rs.case
    base_url, model, plan_cycle = rs.base_url, rs.model, rs.plan_cycle
    session_id = rs.session_id
    query_index, llm_status_fn = rs.query_index, rs.llm_status_fn
    case_profile = rs.case_profile
    try:
        hypothesis_plan = await _call_with_outage_recovery(
            plan_hypothesis_query,
            base_url=base_url,
            model=model,
            _outage_progress_callback=rs.ctx.progress_callback,
            state=state,
            hypothesis=hypothesis,
            db=db,
            status_callback=llm_status_fn or (lambda msg: _log("LLM", msg)),
            query_index=query_index,
            time_range=case.time_range,
            case_profile=case_profile,
            case_policy=rs.ctx.forensia_policy,
        )
    except LLMBudgetExceededError:
        raise
    except Exception as exc:
        err_msg = f"LLM failed for {hypothesis.id}: {exc}"
        _log("PLAN_HYPOTHESIS", err_msg, level="error")
        append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="error",
            body=f"[internal-error] {err_msg}",
        )
        return "break"
    flow = persist_hypothesis_plan_result(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        hypothesis=hypothesis,
        query_index=query_index,
        plan=hypothesis_plan,
        state=state,
        emit=rs.emit_fn,
    )
    if flow != "ok":
        return flow
    rs.hypothesis_plan = hypothesis_plan
    return "ok"


def _phase_execute(rs: _HypothesisRunState) -> str:
    """Query execution and result shaping, including zero-row fallbacks."""
    hypothesis, state, db = rs.hypothesis, rs.state, rs.db
    session_id, plan_cycle = rs.session_id, rs.plan_cycle
    query_index, emit_fn = rs.query_index, rs.emit_fn
    hypothesis_plan = rs.hypothesis_plan
    tracker = rs.tracker
    planned_query = hypothesis_plan.query
    reasoning_entry_id = append_hypothesis_reasoning(
        db=db,
        hypothesis_id=hypothesis.id,
        session_id=session_id,
        iteration=plan_cycle,
        phase="plan",
        body=planned_query.purpose,
        query_id=planned_query.query_id,
    )
    _log(
        "QUERY",
        f"{hypothesis.id} {planned_query.query_id} — {planned_query.purpose}",
    )
    if emit_fn:
        emit_fn(
            "investigate/do",
            f"[do] {planned_query.query_id}: {planned_query.purpose}",
            iteration=plan_cycle,
            kind="query.planned",
            status="completed",
            reason="focus_hypothesis_query_planned",
            query_id=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            reasoning_entry_id=reasoning_entry_id,
        )
    query_fp = query_fingerprint(planned_query.sql)
    verification_fp = verification_spec_fingerprint(hypothesis.verification_spec)
    scope_fp = _evidence_scope_fingerprint(db, planned_query.sql)
    rs.attempt_fingerprints = {
        "query_fingerprint": query_fp,
        "verification_spec_fingerprint": verification_fp,
        "evidence_scope_fingerprint": scope_fp,
    }
    rs.repeat_gate = _repeat_gate_decision(
        db,
        hypothesis,
        query_fp=query_fp,
        verification_fp=verification_fp,
        scope_fp=scope_fp,
    )
    if rs.repeat_gate["decision"] == "skip":
        gate_attempt_ref = (
            f"gate:{session_id}:{plan_cycle}:{query_index}:{query_fp[:12]}"
        )
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="do",
            hypothesis_id=hypothesis.id,
            input_json={
                "planned_query": planned_query.model_dump(),
                "query_index": query_index,
            },
            output_json={
                "repeat_gate": rs.repeat_gate,
                "attempt": {
                    "attempt_ref": gate_attempt_ref,
                    **rs.attempt_fingerprints,
                    "status": "skipped",
                    "reason": rs.repeat_gate["reason_code"],
                    "normalized_sql": planned_query.sql,
                    "purpose": planned_query.purpose,
                },
            },
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="repeat_gate",
            body=json.dumps(rs.repeat_gate, sort_keys=True),
            query_id=planned_query.query_id,
        )
        if rs.ctx.progress_callback:
            rs.ctx.progress_callback(
                progress_event(
                    "investigation.search",
                    "skipped",
                    severity="warning",
                    reason=rs.repeat_gate["reason_code"],
                    refs={
                        "hypothesis_id": hypothesis.id,
                        "query_id": planned_query.query_id,
                        "attempt_ref": gate_attempt_ref,
                        "blocked_attempt_ref": rs.repeat_gate.get("attempt_ref"),
                    },
                    stage="execute",
                    iteration=plan_cycle,
                    session_id=session_id,
                    summary="repeated SQL attempt skipped for unchanged verification and evidence scope",
                )
            )
        return "break"
    started = time.monotonic()
    required_capabilities = derive_required_capabilities(
        hypothesis.verification_spec.required_capabilities,
        hypothesis.verification_spec.support_conditions,
    )
    scope_status, source_families = sql_absence_scope(hypothesis, planned_query.sql)
    observation = hypothesis.verification_spec.support_conditions.get("observation")
    observation_family = (
        str(observation.get("family") or "").strip().lower()
        if isinstance(observation, dict)
        else ""
    )
    if observation_family:
        source_families = [observation_family]
    elif source_families is None:
        source_families = _query_artifact_families(planned_query.sql)
    try:
        rows = fetch_records(db, planned_query.sql)
        original_row_count = len(rows)
        _log("EXEC", f"{hypothesis.id} {planned_query.query_id} — {len(rows)} rows")
        rows, fallback_info = resolve_zero_row_fallbacks(
            db=db, hypothesis=hypothesis, planned_query=planned_query, rows=rows
        )
    except Exception as exc:
        err_msg = str(exc)
        tracker.record(verdict="exec_error", row_count=0)
        receipt = build_sql_receipt(
            db=db,
            session_id=session_id,
            plan_cycle=plan_cycle,
            query_index=query_index,
            hypothesis=hypothesis,
            planned_query=planned_query,
            query_hash=query_fp,
            duration_ms=(time.monotonic() - started) * 1000,
            rows=None,
            original_row_count=None,
            error=err_msg,
        )
        rs.attempt_ref = receipt.receipt_id
        evaluation = evaluate_retrieval(
            receipt,
            required_fields=["normalized_sql"],
            required_capabilities=required_capabilities,
        )
        rs.retrieval_evaluation = evaluation
        attempt = {
            "attempt_ref": receipt.receipt_id,
            **(rs.attempt_fingerprints or {}),
            "status": receipt.status,
            "retrieval_outcome": evaluation.outcome,
            "returned_count": receipt.returned_count,
            "evidence_ids": receipt.result_refs.evidence_ids,
            "purpose": planned_query.purpose,
            "normalized_sql": planned_query.sql,
            "template_id": planned_query.template_id,
            "params": planned_query.params,
            "reason": receipt.reason or "",
            "error": err_msg[:500],
            "retryable": _is_transient_execution_error(err_msg),
            "repeat_gate": rs.repeat_gate or {},
        }
        output = build_receipt_step_payload(receipt, evaluation)
        output["attempt"] = attempt
        output["repeat_gate"] = rs.repeat_gate or {}
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="do",
            hypothesis_id=hypothesis.id,
            input_json={
                "planned_query": planned_query.model_dump(),
                "query_index": query_index,
            },
            output_json=output,
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        _log(
            "EXEC",
            f"SQL execution error — {planned_query.query_id}: {err_msg}",
            level="error",
        )
        append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="error",
            body=f"[internal-error] SQL execution error: {err_msg}",
            query_id=planned_query.query_id,
        )
        state.last_execution_error = {
            "query_id": planned_query.query_id,
            "sql": planned_query.sql,
            "error": err_msg[:500],
        }
        if rs.ctx.progress_callback:
            rs.ctx.progress_callback(
                progress_event(
                    "investigation.search",
                    "failed",
                    severity="error",
                    reason="sql_execution_error",
                    refs={
                        "hypothesis_id": hypothesis.id,
                        "query_id": planned_query.query_id,
                        "receipt_id": receipt.receipt_id,
                    },
                    stage="execute",
                    iteration=plan_cycle,
                    session_id=session_id,
                    summary="evidence query failed during execution",
                )
            )
        return "continue"
    receipt = build_sql_receipt(
        db=db,
        session_id=session_id,
        plan_cycle=plan_cycle,
        query_index=query_index,
        hypothesis=hypothesis,
        planned_query=planned_query,
        query_hash=query_fp,
        duration_ms=(time.monotonic() - started) * 1000,
        rows=rows,
        original_row_count=original_row_count,
        fallback_info=fallback_info,
    )
    rs.attempt_ref = receipt.receipt_id
    evaluation = evaluate_retrieval(
        receipt,
        required_fields=["normalized_sql"],
        required_capabilities=required_capabilities,
        scope_status=scope_status,
        source_families=source_families,
    )
    rs.retrieval_evaluation = evaluation
    observed_evidence_ids = _result_evidence_ids(rows)
    canonicalization_error = ""
    canonical_content_fingerprints: dict[str, str] = {}
    try:
        (
            canonical_rows,
            canonical_evidence_ids,
            canonical_content_fingerprints,
        ) = _canonical_evidence_rows(db, rows)
    except Exception as exc:
        canonical_rows, canonical_evidence_ids = [], []
        canonicalization_error = str(exc)[:500]
        _log(
            "ASSESS",
            f"canonical evidence hydration failed for {planned_query.query_id}: {exc}",
            level="error",
        )
    assessment = assess_evidence_group(
        hypothesis=hypothesis,
        rows=canonical_rows,
        evidence_ids=canonical_evidence_ids,
        retrieval_outcome=evaluation.outcome,
        content_fingerprints=canonical_content_fingerprints,
    )
    finding_ids_by_evidence = _finding_ids_by_evidence(db, canonical_evidence_ids)
    result_summary = _canonical_query_summary(
        canonical_rows,
        assessment,
        observed_row_count=len(rows),
        finding_ids_by_evidence=finding_ids_by_evidence,
    )
    if fallback_info is not None:
        result_summary["original_row_count"] = fallback_info.get(
            "original_row_count", len(rows)
        )
        result_summary["truncated"] = bool(fallback_info.get("truncated"))
    if canonicalization_error:
        result_summary["canonicalization_error"] = canonicalization_error
    attempt = {
        "attempt_ref": receipt.receipt_id,
        **(rs.attempt_fingerprints or {}),
        "status": receipt.status,
        "retrieval_outcome": evaluation.outcome,
        "returned_count": receipt.returned_count,
        "evidence_ids": receipt.result_refs.evidence_ids,
        "purpose": planned_query.purpose,
        "normalized_sql": planned_query.sql,
        "template_id": planned_query.template_id,
        "params": planned_query.params,
        "reason": receipt.reason or "",
        "error": "",
        "retryable": False,
        "repeat_gate": rs.repeat_gate or {},
    }
    output = build_receipt_step_payload(receipt, evaluation, result_summary)
    output["observed_evidence_ids"] = observed_evidence_ids
    output["canonical_evidence_ids"] = canonical_evidence_ids
    output["attempt"] = attempt
    output["repeat_gate"] = rs.repeat_gate or {}
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="do",
        hypothesis_id=hypothesis.id,
        input_json={
            "planned_query": planned_query.model_dump(),
            "query_index": query_index,
        },
        output_json=output,
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
    rs.planned_query = planned_query
    rs.rows = canonical_rows
    rs.canonical_evidence_ids = canonical_evidence_ids
    rs.finding_ids_by_evidence = finding_ids_by_evidence
    rs.evidence_assessment = assessment
    rs.observed_evidence_ids = observed_evidence_ids
    rs.canonicalization_error = canonicalization_error
    rs.fallback_info = fallback_info
    rs.result_summary = result_summary
    if rs.ctx.progress_callback:
        rs.ctx.progress_callback(
            progress_event(
                "investigation.search",
                "completed",
                severity="success",
                refs={
                    "hypothesis_id": hypothesis.id,
                    "query_id": planned_query.query_id,
                    "receipt_id": receipt.receipt_id,
                },
                stage="execute",
                iteration=plan_cycle,
                session_id=session_id,
                summary=f"evidence query returned {len(rows)} rows",
            )
        )
    return "ok"


async def _phase_check(rs: _HypothesisRunState) -> str:
    """Check call and verdict recording (persistence, log, emit, history)."""
    hypothesis, state = rs.hypothesis, rs.state
    db, case = rs.db, rs.case
    base_url, model, plan_cycle = rs.base_url, rs.model, rs.plan_cycle
    session_id = rs.session_id
    query_index, llm_status_fn = rs.query_index, rs.llm_status_fn
    candidates, planned_query = rs.candidates, rs.planned_query
    result_summary, fallback_info = rs.result_summary, rs.fallback_info
    rows = rs.rows or []
    emit_fn = rs.emit_fn
    try:
        check_result = check_query_result(
            case=case,
            db=db,
            session_id=session_id,
            planned_query=planned_query,
            hypothesis=hypothesis,
            finding_candidates=candidates,
            result_summary=result_summary,
            base_url=base_url,
            model=model,
            status_callback=llm_status_fn or (lambda msg: _log("LLM", msg)),
            fallback_info=fallback_info,
        )
    except LLMBudgetExceededError:
        raise
    except Exception as exc:
        err_msg = f"LLM failed for {hypothesis.id}/{planned_query.query_id}: {exc}"
        _log("CHECK", err_msg, level="error")
        append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="error",
            body=f"[internal-error] {err_msg}",
            query_id=planned_query.query_id,
        )
        return "continue"
    reasoning_entry_id = append_hypothesis_reasoning(
        db=db,
        hypothesis_id=hypothesis.id,
        session_id=session_id,
        iteration=plan_cycle,
        phase="check",
        body=check_result.report_text,
        verdict=check_result.verdict,
        query_id=planned_query.query_id,
    )
    chk_txt = (check_result.report_text or "").strip().replace("\n", " ")
    if len(chk_txt) > 120:
        chk_txt = chk_txt[:117] + "..."
    _log(
        "CHECK",
        f"{hypothesis.id} {planned_query.query_id} — verdict={check_result.verdict}"
        + (f": {chk_txt}" if chk_txt else ""),
    )
    if emit_fn:
        emit_fn(
            "investigate/check",
            f"[check] {hypothesis.id}: verdict={check_result.verdict} query={planned_query.query_id}",
            iteration=plan_cycle,
            kind="hypothesis.check_completed",
            status="completed",
            reason=check_result.verdict,
            query_id=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            reasoning_entry_id=reasoning_entry_id,
            receipt_id=rs.attempt_ref,
            attempt_ref=rs.attempt_ref,
        )
    state.history.append(
        HistoryEntry(
            iteration=plan_cycle,
            query_id=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            verdict=check_result.verdict,
            summary=check_result.report_text,
            evidence_ids=result_summary.get("evidence_ids", []),
            template_id=planned_query.template_id,
            params=planned_query.params,
            purpose=planned_query.purpose,
        )
    )
    rs.check_result = check_result
    # Assess every evidence ID returned by an adequate validated query before
    # cumulative sufficiency. Checker selections and verdicts are not inputs.
    assessment_payload: dict[str, Any] | None = None
    evidence_link_writes: list[dict[str, Any]] = []
    unlinkable_reason = ""
    assessment_progress: dict[str, Any] | None = None
    if check_result:
        # Rows stay authoritative here. result_summary.evidence_ids is a
        # bounded LLM sample and must not decide which EvidenceLinks receive
        # a supporting/contradictory role.
        observed_evidence_ids = rs.observed_evidence_ids or _result_evidence_ids(rows)
        canonical_rows = rows
        evidence_ids = (
            rs.canonical_evidence_ids
            if rs.canonical_evidence_ids is not None
            else _result_evidence_ids(rows)
        )
        observed_row_count = int(result_summary.get("observed_row_count") or 0)
        retrieval_adequate = (
            rs.retrieval_evaluation is not None
            and rs.retrieval_evaluation.outcome == "adequate"
        )
        finding_ids_by_evidence = rs.finding_ids_by_evidence or {}
        assessment = rs.evidence_assessment
        if assessment is not None:
            assessment_payload = {
                "assessment_id": assessment.assessment_id,
                "hypothesis_id": hypothesis.id,
                "role": assessment.role,
                "reason": assessment.reason,
                "origin": assessment.origin,
                "spec_version": assessment.spec_version,
                "matched_conditions": list(assessment.matched_conditions),
                "evidence_ids": list(assessment.evidence_ids),
                "observed_evidence_ids": observed_evidence_ids,
                "canonical_evidence_ids": evidence_ids,
                "witness_evidence_ids": [
                    evidence_id
                    for group in assessment.witness_groups
                    for evidence_id in group
                ],
                "witness_groups": [],
                "content_fingerprints": dict(assessment.content_fingerprints),
                "contextual_evidence_ids": list(assessment.contextual_evidence_ids),
            }
        if evidence_ids and retrieval_adequate and assessment is not None:
            role = assessment.role
            witness_group_refs: list[dict[str, Any]] = []
            for witness_group in assessment.witness_groups:
                if not witness_group:
                    continue
                group_ids = sorted(set(witness_group))
                group_ref = (
                    "EA-group-"
                    + hashlib.sha256("\0".join(group_ids).encode("utf-8")).hexdigest()[
                        :20
                    ]
                )
                evidence_link_writes.append(
                    {
                        "evidence_ids": group_ids,
                        "query_id": planned_query.query_id if planned_query else "",
                        "role": role,
                        "created_session": session_id,
                        "assessment_id": assessment.assessment_id,
                        "assessment_reason": assessment.reason,
                        "matched_conditions": assessment.matched_conditions,
                        "derivation_group": group_ref,
                        "finding_ids_by_evidence": finding_ids_by_evidence,
                    }
                )
                witness_group_refs.append(
                    {"evidence_ids": group_ids, "derivation_group": group_ref}
                )
            if assessment.contextual_evidence_ids:
                evidence_link_writes.append(
                    {
                        "evidence_ids": list(assessment.contextual_evidence_ids),
                        "query_id": planned_query.query_id if planned_query else "",
                        "role": "contextual"
                        if role in {"supporting", "contradictory"}
                        else role,
                        "created_session": session_id,
                        "assessment_id": assessment.assessment_id,
                        "assessment_reason": (
                            "observed row did not witness the matched condition"
                            if role in {"supporting", "contradictory"}
                            else assessment.reason
                        ),
                        "matched_conditions": (),
                        "finding_ids_by_evidence": finding_ids_by_evidence,
                    }
                )
            assessment_payload["witness_groups"] = witness_group_refs
            assessment_progress = {
                "status": "completed",
                "severity": "success",
                "reason": role,
                "refs": {
                    "hypothesis_id": hypothesis.id,
                    "query_id": planned_query.query_id,
                    "assessment_id": assessment.assessment_id,
                    "evidence_ids": list(assessment.evidence_ids[:8]),
                    "observed_evidence_ids": observed_evidence_ids[:8],
                },
                "summary": f"assessed {len(canonical_rows)} evidence items as {role}",
            }
        elif observed_row_count:
            # Rows were observed but could not be turned into an admissible
            # EvidenceLink (retrieval not adequate, or no evidence_id could be
            # extracted).  Keep the retrieval_adequate gate, but record a
            # structured unlinkable reason so sufficiency does not misreport a
            # bare "No evidence links found" when rows did exist.
            if rs.canonicalization_error:
                reason = "canonical evidence hydration failed"
            elif not retrieval_adequate:
                reason = "retrieval outcome not adequate"
            else:
                reason = "no linkable evidence_id in observation"
            unlinkable_reason = reason
            assessment_progress = {
                "status": "skipped",
                "severity": "warning",
                "reason": "retrieval_not_adequate"
                if not retrieval_adequate
                else "no_linkable_evidence_id",
                "refs": {
                    "hypothesis_id": hypothesis.id,
                    "query_id": planned_query.query_id,
                    "receipt_id": rs.attempt_ref,
                    "attempt_ref": rs.attempt_ref,
                    "observed_evidence_ids": observed_evidence_ids[:8],
                },
                "summary": "observed rows did not produce eligible evidence links",
            }
    check_step_output = dict(check_result.raw_response or {})
    check_step_output["attempt_ref"] = rs.attempt_ref
    check_step_output["check_verdict"] = check_result.verdict
    check_step_output["check_summary"] = check_result.report_text or ""
    if assessment_payload is not None:
        check_step_output["assessment"] = assessment_payload
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="check",
        hypothesis_id=hypothesis.id,
        input_json={
            "planned_query": planned_query.model_dump(),
            "hypothesis": hypothesis.model_dump(),
            "result_summary": result_summary,
            "attempt_ref": rs.attempt_ref,
        },
        output_json=check_step_output,
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
    for link_write in evidence_link_writes:
        create_evidence_links_for_query(db, hypothesis_id=hypothesis.id, **link_write)
    if unlinkable_reason:
        record_unlinkable_observation(
            db,
            hypothesis_id=hypothesis.id,
            query_id=planned_query.query_id if planned_query else "",
            reason=unlinkable_reason,
            observed_rows=observed_row_count,
            created_session=session_id,
        )
    if rs.ctx.progress_callback and assessment_progress:
        rs.ctx.progress_callback(
            progress_event(
                "investigation.assessment",
                assessment_progress["status"],
                severity=assessment_progress["severity"],
                reason=assessment_progress["reason"],
                refs=assessment_progress["refs"],
                stage="assess",
                iteration=plan_cycle,
                session_id=session_id,
                summary=assessment_progress["summary"],
            )
        )
    return "ok"


def _apply_sufficiency_guard(rs: _HypothesisRunState) -> None:
    """Persist machine sufficiency and reconcile it before state settlement."""
    check_result = rs.check_result
    original_verdict = check_result.verdict
    suff_result, final_verdict, reason, required_capabilities = (
        assess_and_persist_sufficiency(
            rs.db,
            hypothesis_id=rs.hypothesis.id,
            evidence_requirements=rs.hypothesis.verification_spec.evidence_requirements,
            llm_verdict=original_verdict,
            verification_spec=rs.hypothesis.verification_spec,
            session_id=rs.session_id,
        )
    )
    rs.sufficiency_result = suff_result
    check_result.verdict = final_verdict
    append_hypothesis_reasoning(
        rs.db,
        rs.hypothesis.id,
        rs.session_id,
        rs.plan_cycle,
        "sufficiency",
        reason,
        verdict=final_verdict,
        query_id=rs.planned_query.query_id if rs.planned_query else None,
    )
    _save_step(
        rs.db,
        rs.session_id,
        rs.plan_cycle,
        "sufficiency",
        rs.hypothesis.id,
        {
            "llm_verdict": original_verdict,
            "required_capabilities": required_capabilities,
        },
        {
            "machine_status": suff_result.status,
            "score": suff_result.score,
            "final_verdict": final_verdict,
            "reasons": suff_result.reasons,
            "missing_requirements": suff_result.missing_requirements,
            "human_review_required": suff_result.human_review_required,
        },
        suffix=str(rs.query_index),
    )
    if final_verdict != original_verdict:
        _log(
            "SUFFICIENCY",
            f"{rs.hypothesis.id} {original_verdict} -> {final_verdict}: {reason}",
        )
    if rs.state.history and rs.state.history[-1].hypothesis_id == rs.hypothesis.id:
        rs.state.history[-1].verdict = final_verdict


def _build_settlement_input(rs: _HypothesisRunState) -> SettlementInput:
    """Construct the SettlementInput from current run state."""
    from forensia.report.benign_auth import is_benign_local_auth

    _scope_status, source_families = sql_absence_scope(
        rs.hypothesis, rs.planned_query.sql if rs.planned_query else ""
    )
    absence_scope, absence_note = judge_absence_scope(
        rs.db, rs.hypothesis, rs.retrieval_evaluation, source_families=source_families
    )

    rows = rs.rows or []
    unavailable_ids = _unavailable_missing_event_ids(
        rs.missing_checks_raw or [], observed_event_ids(rs.db)
    )
    si = build_settlement_input_from_confirm_when(
        hypothesis=rs.hypothesis,
        checker_verdict=rs.check_result.verdict,
        check_summary=rs.check_result.report_text or "",
        sample_rows=rows or None,
        has_rule_refute_when_zero_rows=bool(
            rs.hypothesis.verification_spec.refute_conditions.get("zero_rows")
        ),
        consecutive_zero_row_inconclusive=rs.tracker.zero_row_inconclusive_count,
        consecutive_same_missing=rs.tracker.consecutive_same_missing,
        unavailable_missing_event_ids=unavailable_ids or None,
        absence_scope=absence_scope,
        absence_note=absence_note,
        sufficiency_result=rs.sufficiency_result,
    )
    if rows and all(is_benign_local_auth(r) for r in rows):
        si = replace(si, is_benign_auth=True)
    return si


def _phase_apply_verdict(rs: _HypothesisRunState) -> None:
    """Hypothesis settlement and Case/Trace state updates for the check verdict.

    R8-01: For confirmed verdicts, ALL settlement must go through the unified
    ``settle_hypothesis`` gate.  The sufficiency guard is run for
    non-settlement paths (inconclusive/newlead) to persist sufficiency metadata.
    """
    check_result, state, db = rs.check_result, rs.state, rs.db
    session_id, hypothesis = rs.session_id, rs.hypothesis
    planned_query = rs.planned_query
    rows = rs.rows or []
    ctx = rs.ctx
    plan_cycle, query_index = rs.plan_cycle, rs.query_index
    emit_fn = rs.emit_fn
    state.history = state.history[-50:]

    _apply_sufficiency_guard(rs)
    final_verdict = check_result.verdict
    if final_verdict in {"confirmed", "refuted", "untestable"}:
        si = _build_settlement_input(rs)
        decision = settle_hypothesis(
            db=db,
            si=si,
            evidence_requirements=hypothesis.verification_spec.evidence_requirements,
        )
        pre_settlement_verdict = final_verdict
        _log(
            "SETTLEMENT",
            f"{hypothesis.id} verdict={decision.verdict} passed={decision.gates_passed} failed={decision.gates_failed}",
        )
        final_verdict = decision.verdict
        check_result.verdict = final_verdict
        append_settlement_feedback(
            db,
            hypothesis.id,
            session_id,
            plan_cycle,
            planned_query.query_id if planned_query else None,
            pre_settlement_verdict,
            decision,
        )
        if ctx.progress_callback:
            ctx.progress_callback(
                progress_event(
                    "investigation.settlement",
                    "completed",
                    severity="success" if decision.allowed else "warning",
                    reason=str(decision.reason or ""),
                    refs={
                        "hypothesis_id": hypothesis.id,
                        "query_id": planned_query.query_id if planned_query else "",
                    },
                    stage="settlement",
                    iteration=plan_cycle,
                    session_id=session_id,
                    summary=f"settlement retained verdict {decision.verdict}",
                )
            )
        if not decision.allowed:
            _log("SETTLEMENT", f"{hypothesis.id} confirmed BLOCKED: {decision.reason}")

    if check_result.new_hypotheses:
        admitted = []
        for hyp in check_result.new_hypotheses:
            ok, reason = admit_new_hypothesis(hyp, state)
            if ok:
                admitted.append(hyp)
            else:
                _log(
                    "HYPOTHESIS",
                    f"check_new rejected: '{hyp.description[:80]}' reason={reason}",
                )
        if admitted:
            previous_ids = {item.id for item in state.active_hypotheses}
            aliases: dict[str, str] = {}
            state.active_hypotheses = _merge_active_hypotheses_in_transaction(
                db=db,
                current=state.active_hypotheses,
                updates=admitted,
                resolved=state.resolved_hypotheses,
                session_id=session_id,
                origin="check_new",
                alias_map_out=aliases,
            )
            active_ids = {item.id for item in state.active_hypotheses}
            admitted_ids = sorted(
                {
                    canonical_id
                    for item in admitted
                    if (canonical_id := aliases.get(item.id)) in active_ids
                }
            )
            if admitted_ids and ctx.progress_callback:
                ctx.progress_callback(
                    progress_event(
                        "investigation.work_added",
                        "completed",
                        severity="info",
                        reason="checker_followup_hypotheses_admitted",
                        refs={
                            "parent_hypothesis_id": hypothesis.id,
                            "hypothesis_ids": admitted_ids[:8],
                        },
                        stage="admit",
                        iteration=plan_cycle,
                        session_id=session_id,
                        summary=f"admitted {len(admitted_ids)} follow-up hypotheses",
                    )
                )
            for child in state.active_hypotheses:
                if child.id in previous_ids or child.id == hypothesis.id:
                    continue
                from forensia.investigation.hypotheses.relations import (
                    relation_involves_unknown_claim,
                )

                if relation_involves_unknown_claim(
                    hypothesis.description, child.description
                ):
                    _log(
                        "RELATION",
                        f"skipped parent_of {hypothesis.id} -> {child.id}: "
                        f"endpoint carries material-unknown claim",
                    )
                    continue
                insert_relation(
                    db,
                    from_id=hypothesis.id,
                    to_id=child.id,
                    relation_type="parent_of",
                    origin="code",
                    confidence=1.0,
                    rationale="Checker-derived follow-up hypothesis",
                    created_session=session_id,
                )
    if final_verdict in {"confirmed", "refuted", "untestable"}:
        _resolve_hypothesis_in_transaction(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=final_verdict,
            summary=check_result.report_text,
            session_id=session_id,
            sample_rows=rows,
        )
        _log(
            "RESOLVE",
            f"{hypothesis.id} — {final_verdict} (resolved={len(state.resolved_hypotheses)})",
        )
    elif final_verdict == "newlead":
        _upsert_hypothesis(
            db=db,
            hypothesis=Hypothesis(
                id=hypothesis.id,
                description=hypothesis.description,
                status="active",
                verdict=None,
                summary=check_result.report_text,
                source_rule_ids=hypothesis.source_rule_ids,
                source_decl_id=hypothesis.source_decl_id,
                source_gap_id=hypothesis.source_gap_id,
                required_entities=hypothesis.required_entities,
                verification_spec=hypothesis.verification_spec,
                target_keypoint_id=hypothesis.target_keypoint_id,
            ),
            origin="check_new",
            session_id=session_id,
        )
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="act",
        hypothesis_id=hypothesis.id,
        input_json={
            "hypothesis_id": hypothesis.id,
            "query_id": planned_query.query_id,
        },
        output_json={
            "verdict": final_verdict,
            "active_hypotheses": [h.model_dump() for h in state.active_hypotheses],
            "resolved_hypotheses": [h.model_dump() for h in state.resolved_hypotheses],
        },
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
    if emit_fn:
        emit_fn(
            "investigate/act",
            f"[act] {hypothesis.id}: verdict={final_verdict} resolved={len(state.resolved_hypotheses)}",
            iteration=plan_cycle,
            kind="hypothesis.verdict_applied",
            status="completed",
            reason=final_verdict,
            hypothesis_id=hypothesis.id,
            query_id=planned_query.query_id if planned_query else None,
        )


def _phase_track_progress(rs: _HypothesisRunState) -> None:
    """Register check and retrieval feedback used by settlement."""
    check_result = rs.check_result
    result_summary, tracker = rs.result_summary, rs.tracker
    row_count = int(result_summary.get("row_count") or 0)
    tracker.record(check_result.verdict, row_count)
    missing_checks_raw = (
        check_result.raw_response.get("missing_questions")
        or check_result.raw_response.get("missing_checks")
        or []
    )
    missing_signature = "|".join(
        sorted(str(q).lower().strip() for q in missing_checks_raw if q)
    ) or _rationale_signature(
        str(check_result.report_text or check_result.raw_response.get("rationale", ""))
    )
    tracker.register_check(check_result.verdict, missing_signature)
    rs.missing_checks_raw = missing_checks_raw


def _phase_auto_resolve(rs: _HypothesisRunState) -> str:
    """Deterministic auto-resolution: untestable/auto-refute/confirm.

    R8-01: ALL settlement paths route through the unified ``settle_hypothesis``
    gate.  Direct calls to ``resolve_hypothesis`` are prohibited.
    """
    hypothesis = rs.hypothesis
    state, db, session_id = rs.state, rs.db, rs.session_id

    # Build the unified settlement input
    si = _build_settlement_input(rs)
    decision = settle_hypothesis(
        db=db,
        si=si,
        evidence_requirements=hypothesis.verification_spec.evidence_requirements,
    )

    if not decision.allowed:
        # No settlement conditions met — continue investigation
        return "ok"

    # Settlement approved — persist the decision
    _log(
        "SETTLEMENT",
        f"{hypothesis.id} auto-resolved: verdict={decision.verdict} "
        f"reason={decision.reason}",
    )

    with db.transaction():
        _resolve_hypothesis_in_transaction(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=decision.verdict,
            summary=decision.reason,
            session_id=session_id,
        )
        _save_step(
            db=db,
            session_id=session_id,
            iteration=rs.plan_cycle,
            phase="act",
            hypothesis_id=hypothesis.id,
            input_json={
                "hypothesis_id": hypothesis.id,
                "query_id": rs.planned_query.query_id if rs.planned_query else None,
            },
            output_json={
                "verdict": decision.verdict,
                "active_hypotheses": [
                    item.model_dump() for item in state.active_hypotheses
                ],
                "resolved_hypotheses": [
                    item.model_dump() for item in state.resolved_hypotheses
                ],
            },
            suffix=(
                f"{rs.planned_query.query_id}-{rs.query_index:02d}"
                if rs.planned_query
                else None
            ),
        )
    return "break"


async def _investigate_one_hypothesis(
    hypothesis: Hypothesis,
    state: SessionState,
    ctx: Ctx,
    db: CaseDB,
    base_url: str,
    model: str,
    plan_cycle: int,
    session_id: str,
    max_queries_per_hypothesis: int,
    case: Case,
    query_limit: int | None = None,
    emit_fn: Callable[..., None] | None = None,
    llm_status_fn: Callable[[str], None] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
) -> tuple[SessionState, dict[str, str]]:
    """Investigate a single hypothesis with full emit/save lifecycle."""
    rs = _HypothesisRunState(
        hypothesis=hypothesis,
        state=state,
        ctx=ctx,
        db=db,
        base_url=base_url,
        model=model,
        plan_cycle=plan_cycle,
        session_id=session_id,
        case=case,
        emit_fn=emit_fn,
        llm_status_fn=llm_status_fn,
        case_profile=case_profile,
        candidates=_matching_findings(state.findings_snapshot, hypothesis),
        tracker=HypothesisProgressTracker(),
        focus_sections=_guess_related_sections(hypothesis.description),
    )
    limit = query_limit if query_limit is not None else max_queries_per_hypothesis
    while rs.query_index < limit:
        check_stop()
        rs.query_index += 1
        query_index = rs.state.focus_depth = rs.query_index
        flow = await _phase_plan(rs)
        if flow == "break":
            break
        if flow == "continue":
            if planner_retry_allowed(state, hypothesis, rs.planner_retry_granted):
                if emit_fn:
                    emit_fn(
                        "investigate/plan",
                        f"[plan] retrying {hypothesis.id} after planner validation failure",
                        iteration=plan_cycle,
                        kind="hypothesis.plan_retry",
                        status="running",
                        severity="warning",
                        reason="planner_retry_granted",
                        hypothesis_id=hypothesis.id,
                        step_id=(
                            f"{session_id}-{plan_cycle:02d}-plan-hypothesis-"
                            f"{hypothesis.id}-{query_index:02d}"
                        ),
                    )
                limit += 1
                rs.planner_retry_granted = True
            continue
        execute_flow = _phase_execute(rs)
        if execute_flow == "break":
            break
        if execute_flow == "continue":
            continue
        if await _phase_check(rs) == "continue":
            continue
        with db.transaction():
            _phase_apply_verdict(rs)
        if rs.check_result.verdict in {"confirmed", "refuted", "untestable"}:
            break
        _phase_track_progress(rs)
        if _phase_auto_resolve(rs) == "break" or query_index >= limit:
            break
    return rs.state, rs.focus_sections
