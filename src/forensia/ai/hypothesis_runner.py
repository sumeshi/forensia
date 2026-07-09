"""Deep-dive execution of a single hypothesis across investigation steps."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    get_profile_event_ids,
)
from forensia.ai.check_normalize import summarize_query_result
from forensia.ai.checker import check_query_result
from forensia.ai.hypothesis_manager import (
    _guess_related_sections,
    _merge_active_hypotheses,
    _resolve_hypothesis,
    admit_new_hypothesis,
)
from forensia.ai.hypothesis_store import _upsert_hypothesis
from forensia.ai.investigation_session import (
    _append_hypothesis_reasoning,
    _call_with_outage_recovery,
    _Ctx,
    _ctx_refresh_caches,
    _save_step,
)
from forensia.ai.memory_sync import _apply_memory_updates
from forensia.ai.planner import plan_hypothesis_query
from forensia.ai.progress import HypothesisProgressTracker, _query_fingerprint
from forensia.ai.prompt_playbook import resolve_rule_context
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.session import HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.rules.engine import (
    execute_event_keyword_fallback_search,
    execute_fallback_search,
)
from forensia.rules.loader import load_rule_by_id


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
    from forensia.ai.prompt_context import _load_event_id_hints

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
    ctx: _Ctx
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


def _resolve_zero_row_fallbacks(
    db: CaseDB,
    hypothesis: Hypothesis,
    planned_query: Any,
    rows: list[Any],
) -> tuple[list[Any], dict[str, Any] | None]:
    """Zero-row fallback searches: rule-declared, then event-keyword."""
    fallback_info = None
    if len(rows) == 0 and hypothesis.source_rule_ids:
        for source_rule_id in hypothesis.source_rule_ids:
            rule = load_rule_by_id(source_rule_id)
            if rule and rule.fallback_search:
                for fallback in rule.fallback_search:
                    if isinstance(fallback, dict):
                        ph = fallback.get("phase")
                        if ph not in {
                            "keyword_in_raw_json",
                            "related_event_ids",
                            "artifact_table",
                        }:
                            continue
                        fb_rows = execute_fallback_search(db, fallback)
                        if fb_rows:
                            _log(
                                "FALLBACK",
                                f"{hypothesis.id} — found {len(fb_rows)} rows via {ph}",
                            )
                            for r in fb_rows[:20]:
                                if isinstance(r, dict):
                                    r["_fallback_phase"] = ph
                                    r["_fallback_source_rule_id"] = (
                                        source_rule_id
                                    )
                            rows = fb_rows[:20]
                            fallback_info = {
                                "phase": ph,
                                "source_rule_id": source_rule_id,
                            }
                            break
                if fallback_info:
                    break
    if len(rows) == 0 and fallback_info is None:
        fb_rows, fb_info = execute_event_keyword_fallback_search(
            db, planned_query.sql
        )
        if fb_rows:
            _log(
                "FALLBACK",
                f"{hypothesis.id} — found {len(fb_rows)} rows via keyword_in_raw_json"
                + (
                    f" event_ids={fb_info.get('event_ids', [])} keywords={fb_info.get('keywords', [])}"
                    if fb_info
                    else ""
                ),
            )
            for r in fb_rows[:20]:
                if isinstance(r, dict):
                    r["_fallback_phase"] = "keyword_in_raw_json"
                    r["_fallback_source_rule_id"] = "event_id_schema"
            rows = fb_rows[:20]
            fallback_info = fb_info or {
                "phase": "keyword_in_raw_json",
                "source_rule_id": "event_id_schema",
            }
            fallback_info["query_sql"] = planned_query.sql
    return rows, fallback_info


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
            status_callback=llm_status_fn
            or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
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
        err_msg = f"[plan-hypothesis] LLM failed for {hypothesis.id}: {exc}"
        print(f"[red]{err_msg}[/red]")
        _append_hypothesis_reasoning(
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
        _upsert_hypothesis(
            db, hypothesis, origin="broad_plan", session_id=session_id
        )
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
    reasoning_entry_id = _append_hypothesis_reasoning(
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
    query_fp = _query_fingerprint(planned_query.sql)
    try:
        rows = fetch_records(db, planned_query.sql)
        _log("EXEC", f"{hypothesis.id} {planned_query.query_id} — {len(rows)} rows")
        rows, fallback_info = _resolve_zero_row_fallbacks(
            db=db, hypothesis=hypothesis, planned_query=planned_query, rows=rows
        )
    except Exception as exc:
        err_msg = str(exc)
        tracker.record(query_fp, verdict="exec_error", row_count=0)
        print(
            f"[red]SQL execution error — {planned_query.query_id}: {err_msg}[/red]"
        )
        if emit_fn:
            emit_fn(
                "investigate/do",
                f"[do] SQL execution error — {planned_query.query_id}: {err_msg}",
                iteration=plan_cycle,
                hypothesis_id=hypothesis.id,
            )
        _append_hypothesis_reasoning(
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
        output_json=result_summary,
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
            status_callback=llm_status_fn
            or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
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
        err_msg = f"[check] LLM failed for {hypothesis.id}/{planned_query.query_id}: {exc}"
        print(f"[red]{err_msg}[/red]")
        _append_hypothesis_reasoning(
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
    reasoning_entry_id = _append_hypothesis_reasoning(
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
    return "ok"


def _phase_apply_verdict(rs: _HypothesisRunState) -> None:
    """Hypothesis settlement and memory reflection for the check verdict."""
    check_result, state, db = rs.check_result, rs.state, rs.db
    session_id, hypothesis, memory = rs.session_id, rs.hypothesis, rs.memory
    planned_query, rows = rs.planned_query, rs.rows
    base_url, model, ctx = rs.base_url, rs.model, rs.ctx
    plan_cycle, query_index = rs.plan_cycle, rs.query_index
    emit_fn, focus_sections = rs.emit_fn, rs.focus_sections
    state.history = state.history[-50:]
    if check_result.new_hypotheses:
        # --- Unified admission gate (G-5) ---
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
            state.active_hypotheses = _merge_active_hypotheses(
                db=db,
                current=state.active_hypotheses,
                updates=admitted,
                resolved=state.resolved_hypotheses,
                session_id=session_id,
                origin="check_new",
            )
    if check_result.verdict in {"confirmed", "refuted", "untestable"}:
        _resolve_hypothesis(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=check_result.verdict,
            summary=check_result.report_text,
            session_id=session_id,
            sample_rows=rows,
        )
        _log(
            "RESOLVE",
            f"{hypothesis.id} — {check_result.verdict} (resolved={len(state.resolved_hypotheses)})",
        )
        rs.cycle_progress = True
    elif check_result.verdict == "newlead" or check_result.progress:
        rs.cycle_progress = True
        _upsert_hypothesis(
            db=db,
            hypothesis=Hypothesis(
                id=hypothesis.id,
                description=hypothesis.description,
                status="active",
                verdict=None,
                summary=check_result.report_text,
            ),
            origin="check_new",
            session_id=session_id,
        )
    _apply_memory_updates(
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
        print(f"[yellow][memory] compaction failed: {exc}[/yellow]")
    if check_result.verdict == "confirmed":
        memory.promote_hypothesis_scratch(hypothesis.id)
    elif check_result.verdict == "refuted":
        memory.archive_hypothesis_scratch(hypothesis.id)
    elif check_result.verdict == "untestable":
        memory.archive_untestable_hypothesis_scratch(hypothesis.id)
    _ctx_refresh_caches(ctx, memory, base_url, model, hypothesis=hypothesis)
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
            "verdict": check_result.verdict,
            "active_hypotheses": [h.model_dump() for h in state.active_hypotheses],
            "resolved_hypotheses": [
                h.model_dump() for h in state.resolved_hypotheses
            ],
        },
        suffix=f"{planned_query.query_id}-{query_index:02d}",
    )
    if emit_fn:
        emit_fn(
            "investigate/act",
            f"[act] {hypothesis.id}: verdict={check_result.verdict} resolved={len(state.resolved_hypotheses)}",
            iteration=plan_cycle,
            report_kw={"focus_sections": focus_sections},
        )


def _phase_track_progress(rs: _HypothesisRunState) -> None:
    """Register query/check fingerprints on the progress tracker."""
    check_result, planned_query = rs.check_result, rs.planned_query
    result_summary, tracker = rs.result_summary, rs.tracker
    row_count = int(result_summary.get("row_count") or 0)
    query_fp = _query_fingerprint(planned_query.sql)
    tracker.record(query_fp, check_result.verdict, row_count)
    missing_checks_raw = (
        check_result.raw_response.get("missing_questions")
        or check_result.raw_response.get("missing_checks")
        or []
    )
    missing_signature = "|".join(
        sorted(str(q).lower().strip() for q in missing_checks_raw if q)
    ) or _rationale_signature(
        str(
            check_result.report_text
            or check_result.raw_response.get("rationale", "")
        )
    )
    tracker.register_check(check_result.verdict, row_count, missing_signature)
    rs.missing_checks_raw = missing_checks_raw


def _phase_auto_resolve(rs: _HypothesisRunState) -> str:
    """Deterministic auto-resolution: untestable/pivot/auto-refute/confirm."""
    check_result, tracker, hypothesis = rs.check_result, rs.tracker, rs.hypothesis
    state, db, session_id = rs.state, rs.db, rs.session_id
    rows, missing_checks_raw = rs.rows, rs.missing_checks_raw
    # T-05b: when the only missing evidence is event IDs the case telemetry
    # cannot contain, resolve untestable now instead of looping 3 cycles.
    if check_result.verdict == "inconclusive":
        unavailable_ids = _unavailable_missing_event_ids(
            missing_checks_raw, get_profile_event_ids()
        )
        if unavailable_ids:
            id_list = ", ".join(str(eid) for eid in unavailable_ids)
            _log(
                "RESOLVE",
                f"{hypothesis.id} — untestable: missing event IDs [{id_list}] are not in case telemetry",
            )
            _resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hypothesis.id,
                verdict="untestable",
                summary=f"Untestable: verification requires event IDs [{id_list}] which are not present in the available telemetry — absence of telemetry is not a disproof.",
                session_id=session_id,
            )
            rs.cycle_progress = True
            return "break"
    if tracker.should_pivot():
        _log(
            "PIVOT",
            f"{hypothesis.id} — duplicate query fingerprint detected, auto-exhausted",
        )
        return "break"
    rule_context = resolve_rule_context(hypothesis)
    partial_confirm_signal = tracker.has_partial_confirm_signal(
        rule_context, rows, hypothesis
    )
    if (
        tracker.should_auto_refute(consecutive_threshold=3)
        and not partial_confirm_signal
    ):
        has_rule_refute = _has_zero_rows_refute_condition(hypothesis)
        if has_rule_refute:
            verdict = "refuted"
            summary = "Auto-refuted: repeated 0-row inconclusive results, consistent with rule-declared refute_when.zero_rows condition."
        else:
            verdict = "untestable"
            missing_eids = sorted(
                set(
                    re.findall(
                        r"event(?:\s+)?[iI][dD]\s*(\d{3,5})", hypothesis.description
                    )
                )
            )
            telemetry_hint = (
                f" (event IDs: {', '.join(missing_eids)})" if missing_eids else ""
            )
            summary = f"Untestable: repeated 0-row inconclusive results — available telemetry does not contain the event types required to verify this hypothesis{telemetry_hint}."
        _log(
            "RESOLVE",
            f"{hypothesis.id} — auto-{verdict} after 3+ consecutive 0-row inconclusive",
        )
        _resolve_hypothesis(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=verdict,
            summary=summary,
            session_id=session_id,
        )
        rs.cycle_progress = True
        return "break"
    if tracker.should_auto_refute_due_to_unobserved_events():
        has_rule_refute = _has_zero_rows_refute_condition(hypothesis)
        if has_rule_refute:
            verdict = "refuted"
            summary = "hypothesis requires evidence not present in current dataset (3+ consecutive same-missing check)"
        else:
            verdict = "untestable"
            summary = "Untestable: hypothesis requires evidence not present in current dataset (3+ consecutive same-missing check) — absence of telemetry is not a disproof."
        _log(
            "RESOLVE",
            f"{hypothesis.id} — auto-{verdict} after {tracker.consecutive_same_missing}+ consecutive same-missing checks",
        )
        _resolve_hypothesis(
            db=db,
            state=state,
            hypothesis_id=hypothesis.id,
            verdict=verdict,
            summary=summary,
            session_id=session_id,
        )
        rs.cycle_progress = True
        return "break"
    if check_result.verdict == "inconclusive":
        if tracker.should_auto_confirm(rule_context, rows, hypothesis):
            _log(
                "RESOLVE",
                f"{hypothesis.id} — auto-confirmed via co_observed_event_ids",
            )
            _resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hypothesis.id,
                verdict="confirmed",
                summary="Auto-confirmed: all co_observed_event_ids from rule context were found in query results.",
                session_id=session_id,
            )
            rs.cycle_progress = True
            return "break"
    return "ok"


async def _investigate_one_hypothesis(
    hypothesis: Hypothesis,
    state: SessionState,
    ctx: _Ctx,
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

