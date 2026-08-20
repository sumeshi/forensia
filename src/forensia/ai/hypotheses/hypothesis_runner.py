"""Deep-dive execution of a single hypothesis across investigation steps."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    get_profile_event_ids,
)
from forensia.ai.checking.assessment import assess_evidence_group
from forensia.ai.checking.check_normalize import summarize_query_result
from forensia.ai.checking.checker import check_query_result
from forensia.ai.checking.settlement import (
    SettlementInput,
    build_settlement_input_from_confirm_when,
    settle_hypothesis,
)
from forensia.ai.checking.sufficiency import (
    assess_and_persist_sufficiency,
    create_evidence_links_for_query,
)
from forensia.ai.hypotheses.execution import (
    build_receipt_step_payload,
    build_sql_receipt,
    resolve_zero_row_fallbacks,
)
from forensia.ai.hypotheses.hypothesis_manager import (
    _guess_related_sections,
    admit_new_hypothesis,
    merge_active_hypotheses,
    resolve_hypothesis,
)
from forensia.ai.hypotheses.hypothesis_store import _upsert_hypothesis
from forensia.ai.hypotheses.relations import insert_relation
from forensia.ai.investigation.investigation_session import (
    Ctx,
    _call_with_outage_recovery,
    _save_step,
    append_hypothesis_reasoning,
    ctx_refresh_caches,
)
from forensia.ai.investigation.memory_sync import apply_memory_updates
from forensia.ai.investigation.planner import plan_hypothesis_query
from forensia.ai.investigation.progress import (
    HypothesisProgressTracker,
    query_fingerprint,
)
from forensia.ai.retrieval_telemetry import evaluate_retrieval
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.session import HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.rules.loader import load_rule_by_id


def _has_zero_rows_refute_condition(hypothesis: Hypothesis) -> bool:
    """Check whether a hypothesis has a rule-declared refute_when with zero_rows condition."""
    refute_when = hypothesis.refute_when or {}
    if refute_when.get("zero_rows"):
        return True
    for source_rule_id in hypothesis.source_rule_ids:
        rule = load_rule_by_id(source_rule_id)
        if rule and rule.hypotheses:
            for decl in rule.hypotheses:
                if (
                    decl.id == hypothesis.id
                    and decl.refute_when
                    and decl.refute_when.get("zero_rows")
                ):
                    return True
    return False


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
    from forensia.ai.prompts.prompt_context import _load_event_id_hints

    vocabulary = set(_load_event_id_hints().keys())
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


def _observed_keypoints_from_findings(
    snapshot: list[dict[str, Any]], limit: int = 20
) -> list[str]:
    """Format findings as human-readable keypoint labels for LLM context."""
    keypoints: list[str] = []
    for item in snapshot[:limit]:
        title = str(item.get("title") or "").strip()
        finding_id = str(item.get("finding_id") or "").strip()
        if not title:
            continue
        if finding_id:
            keypoints.append(f"{finding_id}: {title}")
        else:
            keypoints.append(title)
    return keypoints


def _rationale_signature(rationale: str) -> str:
    eids = sorted(
        set(re.findall(r"\b(?:event\s*id\s*)?(\d{3,5})\b", rationale.lower()))
    )
    keywords = sorted(
        set(
            re.findall(
                r"\b(missing|requires|correlation|not\s+present|absent)\b",
                rationale.lower(),
            )
        )
    )
    return "eid:" + ",".join(eids) + "|kw:" + ",".join(keywords)


@dataclass
class _HypothesisRunState:
    """Mutable state shared across the phases of one hypothesis run."""

    hypothesis: Hypothesis
    state: SessionState
    ctx: Ctx
    memory: MemoryManager
    db: CaseDB
    base_url: str
    model: str
    plan_cycle: int
    llm_logger: LLMCallLogger
    session_id: str
    case: Case
    emit_fn: Callable[..., None] | None
    llm_status_fn: Callable[[str], None] | None
    case_profile_str: str | None
    candidates: list[dict[str, Any]]
    tracker: HypothesisProgressTracker
    focus_sections: dict[str, str]
    cycle_progress: bool = False
    query_index: int = 0
    hypothesis_plan: Any = None
    planned_query: Any = None
    rows: list[Any] | None = None
    fallback_info: dict[str, Any] | None = None
    result_summary: dict[str, Any] | None = None
    check_result: Any = None
    missing_checks_raw: list[Any] | None = None
    retrieval_evaluation: Any = None


async def _phase_plan(rs: _HypothesisRunState) -> str:
    """Query planning: LLM plan call, step persistence, hypothesis upsert."""
    hypothesis, state, ctx = rs.hypothesis, rs.state, rs.ctx
    memory, db, case = rs.memory, rs.db, rs.case
    base_url, model, plan_cycle = rs.base_url, rs.model, rs.plan_cycle
    llm_logger, session_id = rs.llm_logger, rs.session_id
    query_index, llm_status_fn = rs.query_index, rs.llm_status_fn
    case_profile_str = rs.case_profile_str
    try:
        hypothesis_plan = await _call_with_outage_recovery(
            plan_hypothesis_query,
            base_url=base_url,
            model=model,
            state=state,
            hypothesis=hypothesis,
            memory=memory,
            db=db,
            overview_md=ctx.memory_overview,
            default_context_md=ctx.memory_plan,
            status_callback=llm_status_fn or (lambda msg: _log("LLM", msg)),
            audit_callback=lambda msgs, out, parsed, hid=hypothesis.id, qi=query_index: (
                llm_logger.write(
                    iteration=plan_cycle,
                    phase="plan-hypothesis",
                    input_messages=msgs,
                    output=parsed,
                    model=model,
                    base_url=base_url,
                    suffix=f"{hid}-{qi:02d}",
                )
            ),
            query_index=query_index,
            time_range=case.time_range,
            case_profile=case_profile_str,
        )
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
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="plan-hypothesis",
        hypothesis_id=hypothesis.id,
        input_json={
            "hypothesis": hypothesis.model_dump(),
            "query_index": query_index,
        },
        output_json=hypothesis_plan.raw_response,
        suffix=f"{hypothesis.id}-{query_index:02d}",
    )
    if hypothesis_plan.hypothesis is not None:
        hypothesis = rs.hypothesis = hypothesis_plan.hypothesis
        _upsert_hypothesis(db, hypothesis, origin="broad_plan", session_id=session_id)
    if not hypothesis_plan.query:
        if not hypothesis_plan.needs_more:
            return "break"
        return "continue"
    rs.hypothesis_plan = hypothesis_plan
    return "ok"


def _phase_execute(rs: _HypothesisRunState) -> str:
    """Query execution and result shaping, including zero-row fallbacks."""
    hypothesis, state, db = rs.hypothesis, rs.state, rs.db
    session_id, plan_cycle = rs.session_id, rs.plan_cycle
    query_index, emit_fn = rs.query_index, rs.emit_fn
    focus_sections, hypothesis_plan = rs.focus_sections, rs.hypothesis_plan
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
            report_kw={"focus_sections": focus_sections},
            current_query=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            reasoning_entry_id=reasoning_entry_id,
        )
    query_fp = query_fingerprint(planned_query.sql)
    started = time.monotonic()
    required_capabilities = list(
        getattr(hypothesis.verification_spec, "required_capabilities", []) or []
    )
    try:
        rows = fetch_records(db, planned_query.sql)
        original_row_count = len(rows)
        _log("EXEC", f"{hypothesis.id} {planned_query.query_id} — {len(rows)} rows")
        rows, fallback_info = resolve_zero_row_fallbacks(
            db=db, hypothesis=hypothesis, planned_query=planned_query, rows=rows
        )
    except Exception as exc:
        err_msg = str(exc)
        tracker.record(query_fp, verdict="exec_error", row_count=0)
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
        evaluation = evaluate_retrieval(
            receipt,
            required_fields=["normalized_sql"],
            required_capabilities=required_capabilities,
        )
        rs.retrieval_evaluation = evaluation
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
            output_json=build_receipt_step_payload(receipt, evaluation),
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        _log(
            "EXEC",
            f"SQL execution error — {planned_query.query_id}: {err_msg}",
            level="error",
        )
        if emit_fn:
            emit_fn(
                "investigate/do",
                f"[do] SQL execution error — {planned_query.query_id}: {err_msg}",
                iteration=plan_cycle,
                hypothesis_id=hypothesis.id,
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
        return "continue"
    result_summary = summarize_query_result(rows)
    if fallback_info is not None:
        # The checker receives the bounded rows, but must also know that the
        # fallback was capped before it interprets the observation.
        result_summary["original_row_count"] = fallback_info.get(
            "original_row_count", len(rows)
        )
        result_summary["truncated"] = bool(fallback_info.get("truncated"))
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
    evaluation = evaluate_retrieval(
        receipt,
        required_fields=["normalized_sql"],
        required_capabilities=required_capabilities,
    )
    rs.retrieval_evaluation = evaluation
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
        output_json=build_receipt_step_payload(receipt, evaluation, result_summary),
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
    rs.planned_query = planned_query
    rs.rows = rows
    rs.fallback_info = fallback_info
    rs.result_summary = result_summary
    return "ok"


async def _phase_check(rs: _HypothesisRunState) -> str:
    """Check call and verdict recording (persistence, log, emit, history)."""
    hypothesis, state, ctx = rs.hypothesis, rs.state, rs.ctx
    memory, db, case = rs.memory, rs.db, rs.case
    base_url, model, plan_cycle = rs.base_url, rs.model, rs.plan_cycle
    llm_logger, session_id = rs.llm_logger, rs.session_id
    query_index, llm_status_fn = rs.query_index, rs.llm_status_fn
    candidates, planned_query = rs.candidates, rs.planned_query
    result_summary, fallback_info = rs.result_summary, rs.fallback_info
    rows = rs.rows or []
    emit_fn, focus_sections = rs.emit_fn, rs.focus_sections
    try:
        check_result = check_query_result(
            case=case,
            db=db,
            session_id=session_id,
            planned_query=planned_query,
            hypothesis=hypothesis,
            finding_candidates=candidates,
            result_summary=result_summary,
            memory=memory,
            base_url=base_url,
            model=model,
            overview_md=ctx.memory_overview,
            memory_context_md=ctx.memory_check,
            status_callback=llm_status_fn or (lambda msg: _log("LLM", msg)),
            fallback_info=fallback_info,
            audit_callback=lambda phase, msgs, out, parsed: llm_logger.write(
                iteration=plan_cycle,
                phase=phase,
                input_messages=msgs,
                output=parsed,
                model=model,
                base_url=base_url,
            ),
        )
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
        },
        output_json=check_result.raw_response,
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
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
            report_kw={"focus_sections": focus_sections},
            current_query=planned_query.query_id,
            hypothesis_id=hypothesis.id,
            reasoning_entry_id=reasoning_entry_id,
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
    if check_result:
        evidence_ids = list(
            dict.fromkeys(
                str(evidence_id)
                for evidence_id in result_summary.get("evidence_ids", [])
                if evidence_id
            )
        )
        retrieval_adequate = (
            rs.retrieval_evaluation is not None
            and rs.retrieval_evaluation.outcome == "adequate"
        )
        if evidence_ids and retrieval_adequate:
            assessment = assess_evidence_group(
                hypothesis=hypothesis,
                rows=rows or [],
                evidence_ids=evidence_ids,
                query_id=planned_query.query_id if planned_query else "",
            )
            role = assessment.role
            create_evidence_links_for_query(
                db,
                hypothesis_id=hypothesis.id,
                evidence_ids=evidence_ids,
                query_id=planned_query.query_id if planned_query else "",
                role=role,
                created_session=session_id,
                assessment_id=assessment.assessment_id,
                # Every row from this query is one conservative observation
                # group; do not let evidence IDs manufacture independence.
                derivation_group=assessment.derivation_group,
            )
    return "ok"


def _apply_sufficiency_guard(rs: _HypothesisRunState) -> None:
    """Persist machine sufficiency and reconcile it before state settlement."""
    check_result = rs.check_result
    original_verdict = check_result.verdict
    investigation_text = " ".join(
        [
            rs.planned_query.sql if rs.planned_query else "",
            json.dumps(rs.hypothesis.confirm_when or {}, ensure_ascii=False),
        ]
    )
    suff_result, final_verdict, reason, required_capabilities = (
        assess_and_persist_sufficiency(
            rs.db,
            hypothesis_id=rs.hypothesis.id,
            investigation_text=investigation_text,
            evidence_requirements=rs.hypothesis.evidence_requirements,
            llm_verdict=original_verdict,
            verification_spec=rs.hypothesis.verification_spec,
        )
    )
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

    rows = rs.rows or []
    unavailable_ids = _unavailable_missing_event_ids(
        rs.missing_checks_raw or [], get_profile_event_ids()
    )
    si = build_settlement_input_from_confirm_when(
        hypothesis=rs.hypothesis,
        checker_verdict=rs.check_result.verdict,
        check_summary=rs.check_result.report_text or "",
        sample_rows=rows or None,
        has_rule_refute_when_zero_rows=_has_zero_rows_refute_condition(rs.hypothesis),
        consecutive_zero_row_inconclusive=rs.tracker.zero_row_inconclusive_count,
        consecutive_same_missing=rs.tracker.consecutive_same_missing,
        unavailable_missing_event_ids=unavailable_ids or None,
    )
    if rows and all(is_benign_local_auth(r) for r in rows):
        si = SettlementInput(
            hypothesis=si.hypothesis,
            checker_verdict=si.checker_verdict,
            check_summary=si.check_summary,
            sample_rows=si.sample_rows,
            co_observed_event_ids=si.co_observed_event_ids,
            co_observation_satisfied=si.co_observation_satisfied,
            co_observation_reason=si.co_observation_reason,
            same_host=si.same_host,
            within_minutes=si.within_minutes,
            is_benign_auth=True,
            has_rule_refute_when_zero_rows=si.has_rule_refute_when_zero_rows,
            consecutive_zero_row_inconclusive=si.consecutive_zero_row_inconclusive,
            consecutive_same_missing=si.consecutive_same_missing,
            unavailable_missing_event_ids=si.unavailable_missing_event_ids,
        )
    return si


def _phase_apply_verdict(rs: _HypothesisRunState) -> None:
    """Hypothesis settlement and memory reflection for the check verdict.

    R8-01: For confirmed verdicts, ALL settlement must go through the unified
    ``settle_hypothesis`` gate.  The sufficiency guard is run for
    non-settlement paths (inconclusive/newlead) to persist sufficiency metadata.
    """
    check_result, state, db = rs.check_result, rs.state, rs.db
    session_id, hypothesis, memory = rs.session_id, rs.hypothesis, rs.memory
    planned_query, rows = rs.planned_query, rs.rows
    base_url, model, ctx = rs.base_url, rs.model, rs.ctx
    plan_cycle, query_index = rs.plan_cycle, rs.query_index
    emit_fn, focus_sections = rs.emit_fn, rs.focus_sections
    state.history = state.history[-50:]

    # Persist and reconcile machine sufficiency exactly once before any
    # settlement decision.  In particular, a checker ``refuted`` verdict may
    # become inconclusive when no contradictory evidence supports it.
    _apply_sufficiency_guard(rs)
    final_verdict = check_result.verdict
    if final_verdict in {"confirmed", "refuted", "untestable"}:
        si = _build_settlement_input(rs)
        decision = settle_hypothesis(
            db=db,
            si=si,
            evidence_requirements=hypothesis.evidence_requirements,
        )
        _log(
            "SETTLEMENT",
            f"{hypothesis.id} verdict={decision.verdict} passed={decision.gates_passed} failed={decision.gates_failed}",
        )
        final_verdict = decision.verdict
        check_result.verdict = final_verdict
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
            state.active_hypotheses = merge_active_hypotheses(
                db=db,
                current=state.active_hypotheses,
                updates=admitted,
                resolved=state.resolved_hypotheses,
                session_id=session_id,
                origin="check_new",
            )
            for child in state.active_hypotheses:
                if child.id in previous_ids or child.id == hypothesis.id:
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
        with db.transaction():
            resolve_hypothesis(
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
        rs.cycle_progress = True
    elif final_verdict == "newlead" or check_result.progress:
        rs.cycle_progress = True
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
                confirm_when=hypothesis.confirm_when,
                refute_when=hypothesis.refute_when,
                evidence_requirements=hypothesis.evidence_requirements,
                verification_spec=hypothesis.verification_spec,
                target_keypoint_id=hypothesis.target_keypoint_id,
            ),
            origin="check_new",
            session_id=session_id,
        )
    apply_memory_updates(
        memory=memory,
        active_hypotheses=state.active_hypotheses,
        resolved_hypotheses=state.resolved_hypotheses,
        check_output={
            **check_result.raw_response,
            "memory_updates": check_result.memory_updates,
            "suspicious_evidence": check_result.suspicious_evidence,
        },
        current_hypothesis_id=hypothesis.id,
        db=db,
        query_id=planned_query.query_id,
        hypothesis_description=hypothesis.description,
    )
    # R3-09: Collapse refuted-template overview lines into counter
    memory.collapse_refuted_overview_lines()
    try:
        memory.compact_overview_if_needed(base_url=base_url, model=model)
        memory.compact_oversized_with_llm(base_url=base_url, model=model)
    except Exception as exc:
        _log("MEMORY", f"compaction failed: {exc}", level="warning")
    if final_verdict == "confirmed":
        memory.promote_hypothesis_scratch(hypothesis.id)
    elif final_verdict == "refuted":
        memory.archive_hypothesis_scratch(hypothesis.id)
    elif final_verdict == "untestable":
        memory.archive_untestable_hypothesis_scratch(hypothesis.id)
    ctx_refresh_caches(
        ctx,
        memory,
        base_url,
        model,
        hypothesis=hypothesis,
        db=db,
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
            report_kw={"focus_sections": focus_sections},
        )


def _phase_track_progress(rs: _HypothesisRunState) -> None:
    """Register query/check fingerprints on the progress tracker."""
    check_result, planned_query = rs.check_result, rs.planned_query
    result_summary, tracker = rs.result_summary, rs.tracker
    row_count = int(result_summary.get("row_count") or 0)
    query_fp = query_fingerprint(planned_query.sql)
    tracker.record(query_fp, check_result.verdict, row_count)
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
    tracker.register_check(check_result.verdict, row_count, missing_signature)
    rs.missing_checks_raw = missing_checks_raw


def _phase_auto_resolve(rs: _HypothesisRunState) -> str:
    """Deterministic auto-resolution: untestable/pivot/auto-refute/confirm.

    R8-01: ALL settlement paths route through the unified ``settle_hypothesis``
    gate.  Direct calls to ``resolve_hypothesis`` are prohibited.
    """
    tracker, hypothesis = rs.tracker, rs.hypothesis
    state, db, session_id = rs.state, rs.db, rs.session_id

    if tracker.should_pivot():
        _log(
            "PIVOT",
            f"{hypothesis.id} — duplicate query fingerprint detected, auto-exhausted",
        )
        return "break"

    # Build the unified settlement input
    si = _build_settlement_input(rs)
    decision = settle_hypothesis(
        db=db,
        si=si,
        evidence_requirements=hypothesis.evidence_requirements,
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
        resolve_hypothesis(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=decision.verdict,
            summary=decision.reason,
            session_id=session_id,
        )
    rs.cycle_progress = True
    return "break"


async def _investigate_one_hypothesis(
    hypothesis: Hypothesis,
    state: SessionState,
    ctx: Ctx,
    memory: MemoryManager,
    db: CaseDB,
    base_url: str,
    model: str,
    plan_cycle: int,
    llm_logger: LLMCallLogger,
    session_id: str,
    max_queries_per_hypothesis: int,
    case: Case,
    query_limit: int | None = None,
    emit_fn: Callable[..., None] | None = None,
    llm_status_fn: Callable[[str], None] | None = None,
    case_profile_str: str | None = None,
) -> tuple[bool, SessionState, dict[str, str]]:
    """Investigate a single hypothesis with full emit/save/memory lifecycle.
    Returns (cycle_progress, updated_state, focus_sections).
    """
    rs = _HypothesisRunState(
        hypothesis=hypothesis,
        state=state,
        ctx=ctx,
        memory=memory,
        db=db,
        base_url=base_url,
        model=model,
        plan_cycle=plan_cycle,
        llm_logger=llm_logger,
        session_id=session_id,
        case=case,
        emit_fn=emit_fn,
        llm_status_fn=llm_status_fn,
        case_profile_str=case_profile_str,
        candidates=_matching_findings(state.findings_snapshot, hypothesis),
        tracker=HypothesisProgressTracker(),
        focus_sections=_guess_related_sections(hypothesis.description),
    )
    limit = query_limit if query_limit is not None else max_queries_per_hypothesis
    for query_index in range(1, limit + 1):
        rs.query_index = query_index
        rs.state.focus_depth = query_index
        flow = await _phase_plan(rs)
        if flow == "break":
            break
        if flow == "continue":
            continue
        if _phase_execute(rs) == "continue":
            continue
        if await _phase_check(rs) == "continue":
            continue
        _phase_apply_verdict(rs)
        if rs.check_result.verdict in {"confirmed", "refuted", "untestable"}:
            break
        _phase_track_progress(rs)
        if _phase_auto_resolve(rs) == "break":
            break
        if query_index >= limit:
            break
    return rs.cycle_progress, rs.state, rs.focus_sections
