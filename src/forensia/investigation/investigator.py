"""Investigation entry point and session orchestration."""

from __future__ import annotations

import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensia.context.case_profile import (
    CaseEvidenceProfile,
    _format_case_profile,
    build_case_profile,
)
from forensia.core.case import Case
from forensia.core.control import InvestigationStopped, is_stopped
from forensia.core.log import log as _log
from forensia.core.progress_event import progress_event
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import save_stop_reason
from forensia.db.progress import record_progress_event
from forensia.investigation.case_policy import (
    CasePolicyInput,
    collect_policy_progress_event,
)
from forensia.investigation.hypotheses.hypothesis_store import _all_hypotheses
from forensia.investigation.investigation_cycle import (
    _run_cycle_body,
)
from forensia.investigation.investigation_session import (
    _call_with_outage_recovery,
    _ctx_get_report_status,
    _finding_snapshot,
    _init_session,
    persist_session_terminal_receipt,
    touch_session_heartbeat,
)
from forensia.investigation.report_gap import (
    evaluation_snapshot,
    inject_gap_hypotheses,
    report_cycle_progress,
)
from forensia.investigation.work_judgment import open_work_refs
from forensia.investigation.work_state import (
    broad_plan_terminal_facts,
    classify_active_hypotheses_on_stop,
    format_stop_reason,
    format_terminal_reason,
    stop_summary,
)
from forensia.knowledge.coverage import refresh_evidence_coverage
from forensia.llm.llm_client import (
    LLMServerUnavailableError,
    close_llm_clients,
    reset_llm_client_scope,
    set_llm_client_scope,
)
from forensia.llm.telemetry import (
    LLMBudgetExceededError,
    LLMTelemetry,
    reset_active_telemetry,
    set_active_telemetry,
    telemetry_scope,
)
from forensia.report.render.writer import render_written_report
from forensia.report.sections.report_input import (
    SectionSource,
    decide_report_sources,
    ensure_report_output_paths,
)
from forensia.report.sections.section_refresher import async_refresh_report_sections
from forensia.report.sections.section_store import mark_report_sections_ai_exhausted
from forensia.report.sections.status import build_report_status


def final_summary(state: SessionState) -> str:
    """Build a human-readable summary of the investigation outcome."""
    if state.resolved_hypotheses:
        lines = []
        for item in state.resolved_hypotheses[-5:]:
            verdict = item.verdict or item.status
            lines.append(
                f"[{verdict}] {item.description}: {item.summary or 'summary unavailable'}"
            )
        return "\n".join(lines)
    if state.history:
        return "\n".join(entry.summary for entry in state.history[-5:] if entry.summary)
    return "No additional progress was made during this investigation."


async def _run_report_phase(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    plan_cycle: int,
    report_every_n_cycles: int,
    report_sections: list[SectionSource],
    base_url: str,
    model: str,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str],
    state: SessionState,
) -> tuple[dict[str, Any], str]:
    """Run the report refresh phase.

    Returns (report_after, refresh_status) where refresh_status is "skipped"
    (off-cycle), "ok", or "failed: <type>: <msg>".  Cycle progress is not
    decided here: the loop compares evaluation snapshots at its state-commit
    point (after the Coverage refresh), so Coverage changes are visible to the
    comparison in the same cycle they commit.
    """
    if plan_cycle % max(1, report_every_n_cycles) != 0:
        return build_report_status(db), "skipped"
    report_result: dict[str, Any] | None = None
    try:
        # LLM-server outages get the same wait-for-recovery treatment as the
        # investigation loop (unattended multi-day runs must survive them);
        # only an exhausted outage budget propagates and stops the session.
        report_result = await _call_with_outage_recovery(
            async_refresh_report_sections,
            base_url=base_url,
            model=model,
            _outage_progress_callback=progress_callback,
            case=case,
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            sections=report_sections,
            progress_callback=progress_callback,
            focus_sections=focus_sections,
        )
    except LLMServerUnavailableError, LLMBudgetExceededError, InvestigationStopped:
        raise
    except Exception as exc:
        # Rule 12: loud, not dead. Log the full traceback and a typed progress
        # event, publish any sections that were persisted before the crash,
        # and let the investigation continue — stale flags stay in the DB, so
        # the next successful refresh catches up on everything missed.
        error_label = f"{type(exc).__name__}: {exc}"
        _log("REPORT", f"section refresh failed: {error_label}", level="error")
        print(traceback.format_exc())
        if progress_callback:
            progress_callback(
                progress_event(
                    "report.cycle",
                    "failed",
                    severity="error",
                    reason=f"exception:{type(exc).__name__}",
                    stage="render",
                    iteration=plan_cycle,
                    session_id=session_id,
                    summary="report section refresh failed",
                )
            )
        try:
            render_written_report(case, db)
        except Exception as render_exc:
            _log(
                "REPORT",
                f"fallback render failed: {render_exc}",
                level="warning",
            )
        return build_report_status(db), f"failed: {error_label}"
    if report_result is None:
        return build_report_status(db), "ok"
    report_after = report_result["report_status"]
    inject_gap_hypotheses(
        db=db,
        state=state,
        gaps=report_result["gaps"],
        session_id=session_id,
        progress_callback=progress_callback,
    )
    # Gap/Task/Hypothesis admission mutates Case State after section refresh;
    # rebuild the status after that mutation, while retaining the section body
    # for the report UI.
    refreshed_status = build_report_status(db, focus_sections=focus_sections)
    refreshed_status["current_section"] = report_after.get("current_section")
    report_after = refreshed_status
    render_written_report(case, db)
    return report_after, "ok"


def _durable_open_work_counts(db: CaseDB) -> tuple[int, int]:
    """Count durable unresolved work the completion gate must honor (T05).

    The report's prose gap array is an editorial projection: a section reword
    can drop every gap string while admitted work remains open.  Completion
    reads the shared per-work-ref read (``work_judgment.open_work_refs``):
    a linked Gap/Task pair is one work item counted once per column, so the
    gate stays "no open Gap and no open Task" without double counting the
    same work.  Returns (open-gap refs, open-task refs).
    """
    refs = open_work_refs(db)
    return (
        sum(1 for ref in refs if ref.gap_ids),
        sum(1 for ref in refs if ref.task_ids),
    )


def _check_termination(
    *,
    report_only: bool,
    broad_plan_stop: bool,
    active_hypotheses: list,
    durable_open_gaps: int,
    durable_open_tasks: int,
    no_progress_count: int,
    no_progress_limit: int,
    evaluation_changed: bool,
) -> tuple[str | None, int, str]:
    """Check if the investigation loop should stop. Returns (terminal_status or None, updated_no_progress_count, stop_reason_code)."""
    if report_only:
        # Report-only is a report job, not objective work (GOAL 9.4): it must
        # not claim Case completion while durable gaps/tasks remain open. The
        # caller keeps the terminal receipt at session level only (R07).
        return "completed", no_progress_count, "report_only_mode"
    # Completion reads durable admitted work, not the report prose (GOAL 9.4):
    # with prose gaps exhausted but durable gaps/tasks still open, the loop
    # falls through to the no-progress machinery instead of completing.
    if (
        broad_plan_stop
        and not active_hypotheses
        and durable_open_gaps == 0
        and durable_open_tasks == 0
    ):
        return "completed", no_progress_count, "no_gaps_no_hypotheses"
    no_progress_count = 0 if evaluation_changed else no_progress_count + 1
    if no_progress_count >= no_progress_limit:
        return "stopped", no_progress_count, "no_progress_limit"
    return None, no_progress_count, ""


def _planner_only_terminal_reason(db: CaseDB, session_id: str) -> str | None:
    """Return an explicit terminal code when planning never reached execution.

    This is deliberately scoped to one durable session.  A planner retry is
    operational activity, but it is not semantic investigation progress; a
    session containing only plan steps must not be reported as an ordinary
    no-progress stop.
    """
    row = db.execute(
        """
        SELECT
            SUM(CASE WHEN phase IN ('plan-hypothesis', 'plan-broad', 'plan-broad-candidate')
                THEN 1 ELSE 0 END) AS plan_steps,
            SUM(CASE WHEN phase IN ('do', 'check') THEN 1 ELSE 0 END) AS do_check_steps
        FROM trace.investigation_steps
        WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    if not row or int(row[0] or 0) == 0 or int(row[1] or 0) > 0:
        return None
    facts = broad_plan_terminal_facts(db, session_id)
    if facts["awaiting_proposal_correction"]:
        return "proposal_repair_pending"
    if facts["awaiting_external_evidence"]:
        return "external_evidence_waiting"
    if facts["awaiting_capability"]:
        return "capability_waiting"
    if facts["unexamined_candidate_count"]:
        return "candidate_scan_incomplete"
    failure = db.execute(
        """
        SELECT COUNT(*)
        FROM trace.hypothesis_reasoning
        WHERE session_id = ?
          AND body LIKE '[planner-validation]%'
        """,
        (session_id,),
    ).fetchone()
    return (
        "planner_validation_failure"
        if failure and int(failure[0] or 0) > 0
        else "planner_no_executable_action"
    )


@dataclass
class _InvestigateEnv:
    """Session-wide objects and knobs shared by the investigate() phase helpers."""

    case: Case
    db: CaseDB
    base_url: str
    model: str
    state: Any
    ctx: Any
    session_id: str
    report_sections: list[SectionSource]
    case_profile: CaseEvidenceProfile
    progress_callback: Callable[[dict[str, Any]], None] | None
    max_iter: int
    no_progress_limit: int
    max_queries_per_hypothesis: int
    report_every_n_cycles: int
    report_only: bool


def _prepare_case_profile(case: Case, db: CaseDB) -> CaseEvidenceProfile:
    """Build the session projection from current evidence, without global state."""
    case.extract_time_range(db.conn)
    case_profile_dict = build_case_profile(db)
    case_profile = _format_case_profile(case_profile_dict)
    profile_event_ids = {
        e["event_id"]
        for e in case_profile_dict.get("event_ids", [])
        if isinstance(e.get("event_id"), int)
    }
    return CaseEvidenceProfile(
        event_ids=frozenset(profile_event_ids),
        summary=case_profile,
    )


async def _run_investigation_loop(env: _InvestigateEnv) -> tuple[str, int, str]:
    """Run plan cycles until completion, interrupt, or no-progress limit.

    Returns (status, report_refresh_failures, stop_reason_code).
    """
    no_progress_count = 0
    report_refresh_failures = 0
    stop_reason_code = ""
    for plan_cycle in range(1, env.max_iter + 1):
        env.state.iteration = plan_cycle
        if not env.report_only:
            env.state.findings_snapshot = _finding_snapshot(env.db)
        _log(
            "PLAN",
            f"Cycle {plan_cycle}/{env.max_iter} — broad planning (active={len(env.state.active_hypotheses)} resolved={len(env.state.resolved_hypotheses)})",
        )
        if env.ctx.interrupted or is_stopped():
            return "stopped", report_refresh_failures, "interrupted"
        # Snapshot at the cycle's state-commit boundary: this read equals the
        # state the previous cycle committed (Coverage refresh included).
        evaluation_before = evaluation_snapshot(env.db)
        with telemetry_scope(iteration=plan_cycle):
            broad_plan_stop, focus_sections = await _run_cycle_body(
                state=env.state,
                ctx=env.ctx,
                case=env.case,
                db=env.db,
                session_id=env.session_id,
                base_url=env.base_url,
                model=env.model,
                progress_callback=env.progress_callback,
                max_queries_per_hypothesis=env.max_queries_per_hypothesis,
                plan_cycle=plan_cycle,
                max_iter=env.max_iter,
                report_only=env.report_only,
                case_profile=env.case_profile,
            )
        if env.ctx.interrupted or is_stopped():
            return "stopped", report_refresh_failures, "interrupted"
        with telemetry_scope(iteration=plan_cycle):
            report_after, refresh_status = await _run_report_phase(
                case=env.case,
                db=env.db,
                session_id=env.session_id,
                plan_cycle=plan_cycle,
                report_every_n_cycles=env.report_every_n_cycles,
                report_sections=env.report_sections,
                base_url=env.base_url,
                model=env.model,
                progress_callback=env.progress_callback,
                focus_sections=focus_sections,
                state=env.state,
            )
        if env.ctx.interrupted or is_stopped():
            return "stopped", report_refresh_failures, "interrupted"
        if refresh_status.startswith("failed"):
            report_refresh_failures += 1
        env.ctx.report_status = report_after
        # Compare at the commit point so this cycle's Gap/Task admissions are
        # visible to the durable progress calculation (V2-03/R06).
        evaluation_after = evaluation_snapshot(env.db)
        evaluation_changed = report_cycle_progress(evaluation_before, evaluation_after)
        durable_open_gaps, durable_open_tasks = _durable_open_work_counts(env.db)
        terminal_status, no_progress_count, stop_reason_code = _check_termination(
            report_only=env.report_only,
            broad_plan_stop=broad_plan_stop,
            active_hypotheses=env.state.active_hypotheses,
            durable_open_gaps=durable_open_gaps,
            durable_open_tasks=durable_open_tasks,
            no_progress_count=no_progress_count,
            no_progress_limit=env.no_progress_limit,
            evaluation_changed=evaluation_changed,
        )
        if terminal_status is not None:
            if (
                terminal_status == "stopped"
                and stop_reason_code == "no_progress_limit"
                and not env.report_only
            ):
                stop_reason_code = (
                    _planner_only_terminal_reason(env.db, env.session_id)
                    or stop_reason_code
                )
            if stop_reason_code == "no_gaps_no_hypotheses":
                mark_report_sections_ai_exhausted(env.db)
            elif terminal_status == "stopped":
                classify_active_hypotheses_on_stop(
                    env.db,
                    env.state.active_hypotheses,
                    stop_reason_code,
                )
            return terminal_status, report_refresh_failures, stop_reason_code
    planner_only_reason = (
        None
        if env.report_only
        else _planner_only_terminal_reason(env.db, env.session_id)
    )
    classify_active_hypotheses_on_stop(
        env.db, env.state.active_hypotheses, "max_iterations"
    )
    return "stopped", report_refresh_failures, planner_only_reason or "max_iterations"


async def _final_report_refresh(
    env: _InvestigateEnv, *, allow_narration: bool = True
) -> int:
    """Render every section once at the final DB state. Returns 1 on failure, else 0.

    Run after loop termination so stale sections from late-cycle resolutions
    reach the rendered report.
    """
    try:
        with telemetry_scope(iteration=None, action_id="report-finalization"):
            await async_refresh_report_sections(
                case=env.case,
                db=env.db,
                session_id=env.session_id,
                iteration=None,
                base_url=env.base_url,
                model=env.model,
                sections=env.report_sections,
                progress_callback=env.progress_callback,
                focus_sections=[],
                allow_narration=allow_narration,
            )
        render_written_report(env.case, env.db)
        return 0
    except LLMBudgetExceededError:
        raise
    except InvestigationStopped:
        raise
    except Exception as exc:
        _log(
            "FINAL_REFRESH",
            f"failed: {type(exc).__name__}: {exc}",
            level="error",
        )
        print(traceback.format_exc())
        return 1


def _build_investigate_result(
    env: _InvestigateEnv, status: str, report_refresh_failures: int
) -> dict[str, Any]:
    """Assemble the investigate() result payload, warning about refresh failures."""
    if report_refresh_failures:
        _log(
            "REPORT",
            f"{report_refresh_failures} report refresh phase(s) failed during this "
            f"session — see tracebacks above. Stale sections persist and are retried on later "
            f"cycles and the final refresh.",
            level="error",
        )
    return {
        "session_id": env.session_id,
        "status": status,
        "iteration": env.state.iteration,
        "depth": env.state.focus_depth,
        "focus_hypothesis_id": env.state.focus_hypothesis_id,
        "summary": final_summary(env.state),
        "hypotheses": [item.model_dump() for item in _all_hypotheses(env.state)],
        "report_sections": _ctx_get_report_status(env.ctx, env.db, refresh=True),
        "report_refresh_failures": report_refresh_failures,
    }


async def investigate(
    case: Case,
    db: CaseDB,
    base_url: str,
    model: str,
    max_iter: int = 20,
    no_progress_limit: int = 3,
    max_queries_per_hypothesis: int = 5,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    report_every_n_cycles: int = 1,
    report_only: bool = False,
    template_root: Path | None = None,
    report_spec: str | Path | None = None,
    max_llm_calls: int = 0,
    forensia_policy: CasePolicyInput | None = None,
    manual_resume: bool = False,
) -> dict[str, Any]:
    """Run the full investigation loop: broad plan → hypothesis loop → report refresh, with termination checks and LLM budget enforcement."""
    ensure_report_output_paths(
        case,
        (case.reports_dir / "report.md", case.reports_dir / "report.html"),
        report_spec=report_spec,
    )
    # Report inputs are validated and fixed at run start (GOAL 10.7), before
    # the session lease exists: an invalid REPORT.md fails without leaving a
    # dangling running session. The chosen text is parsed once here and reused
    # by every report phase and the final refresh within this session.
    report_decision = decide_report_sources(case, db, template_root, report_spec)
    report_sections = report_decision.sections
    # Coverage is a projection of normalized evidence and must be current
    # before session initialization loads, seeds, or selects hypotheses.
    refresh_evidence_coverage(db)
    case_profile = _prepare_case_profile(case, db)

    def publish_progress(payload: dict[str, Any]) -> None:
        """Persist producer events before notifying an optional observer."""
        record_progress_event(db, payload)
        if progress_callback:
            progress_callback(payload)

    state, ctx, session_id = _init_session(
        case,
        db,
        template_root,
        report_only=report_only,
        forensia_policy=forensia_policy,
        report_input_record=report_decision.record,
        progress_callback=publish_progress,
        manual_resume=manual_resume,
    )
    owner_id = ctx.owner_id
    if not owner_id:
        raise RuntimeError("investigation session has no durable owner lease")
    last_heartbeat = 0.0
    last_stage = ""

    def session_progress(payload: dict[str, Any]) -> None:
        """Publish progress and refresh the session lease at bounded cadence."""
        nonlocal last_heartbeat, last_stage
        payload.setdefault("session_id", session_id)
        now = time.monotonic()
        stage = str(payload.get("stage") or "running")
        reason = str(payload.get("summary") or "") or None
        if (
            now - last_heartbeat >= 10.0
            or stage == "waiting_for_llm"
            or stage != last_stage
        ):
            touch_session_heartbeat(
                db,
                session_id,
                owner_id,
                phase=stage,
                reason=reason,
            )
            last_heartbeat = now
            last_stage = stage
        publish_progress(payload)

    ctx.progress_callback = session_progress
    env = _InvestigateEnv(
        case=case,
        db=db,
        base_url=base_url,
        model=model,
        state=state,
        ctx=ctx,
        session_id=session_id,
        report_sections=report_sections,
        case_profile=case_profile,
        progress_callback=session_progress,
        max_iter=max_iter,
        no_progress_limit=no_progress_limit,
        max_queries_per_hypothesis=max_queries_per_hypothesis,
        report_every_n_cycles=report_every_n_cycles,
        report_only=report_only,
    )
    client_scope_id = session_id
    client_scope_token = set_llm_client_scope(client_scope_id)
    telemetry_token = set_active_telemetry(
        LLMTelemetry(db, session_id, max_logical_calls=max_llm_calls)
    )
    status = "running"
    stop_reason_code = ""
    report_refresh_failures = 0
    finished_at: datetime | None = None
    terminal_receipt: tuple[str, str] | None = None
    stopped_classification_attempted = False

    def persist_terminal_receipt() -> None:
        nonlocal finished_at, terminal_receipt
        if finished_at is None:
            finished_at = datetime.now(UTC).replace(tzinfo=None)
        reason = format_terminal_reason(status, cause=stop_reason_code)
        persist_session_terminal_receipt(
            db,
            session_id,
            status,
            terminal_reason=reason,
            finished_at=finished_at,
            owner_id=owner_id,
        )
        terminal_receipt = (status, reason)

    def classify_stopped_work() -> None:
        nonlocal stopped_classification_attempted
        if (
            stopped_classification_attempted
            or status != "stopped"
            or stop_reason_code not in {"interrupted", "budget_exhausted"}
            or env.report_only
        ):
            return
        stopped_classification_attempted = True
        try:
            classify_active_hypotheses_on_stop(
                db, state.active_hypotheses, stop_reason_code
            )
        except Exception as exc:
            _log(
                "FINALIZE",
                f"stopped work classification failed: {exc}",
                level="error",
            )

    def build_stop_summary() -> dict[str, Any]:
        summary: dict[str, Any] = stop_summary(db)
        if not env.report_only and status == "stopped":
            planner_facts = broad_plan_terminal_facts(db, session_id)
            summary.update(
                {
                    "planner_status": planner_facts["planner_status"],
                    "planner_iteration": planner_facts["planner_iteration"],
                    "planner_step_id": planner_facts["planner_step_id"],
                    "candidate_count": planner_facts["candidate_count"],
                    "drafted_work_count": planner_facts["drafted_work_count"],
                    "drafted_work_scope": planner_facts["drafted_work_scope"],
                    "candidate_unexamined_count": planner_facts[
                        "unexamined_candidate_count"
                    ],
                    "candidate_draft_cap_omitted_count": planner_facts[
                        "draft_cap_omitted_count"
                    ],
                }
            )
        return summary

    try:
        if report_decision.notice:
            _log("REPORT", report_decision.notice)
        notice_event = collect_policy_progress_event(ctx.forensia_policy)
        if notice_event is not None:
            _log("FORENSIA", str(ctx.forensia_policy.notice))
            session_progress(notice_event)
        (
            status,
            report_refresh_failures,
            stop_reason_code,
        ) = await _run_investigation_loop(env)
        persist_terminal_receipt()
        classify_stopped_work()
        # Persist the terminal state before the closing report pass so report
        # validation and narratives observe the same final state as the API.
        # Report-only is a report job (R07): it must not rewrite the Case stop
        # state — an unresolved Case stays resumable after report-only.
        summary = build_stop_summary()
        if not env.report_only:
            save_stop_reason(
                db,
                status=status,
                stop_reason_code=stop_reason_code,
                stop_reason=format_stop_reason(status, stop_reason_code, summary),
                stop_summary=summary,
            )
        if (
            status in {"completed", "stopped"}
            and stop_reason_code not in {"budget_exhausted", "interrupted"}
            and not ctx.interrupted
            and not is_stopped()
        ):
            try:
                report_refresh_failures += await _final_report_refresh(env)
            except LLMBudgetExceededError:
                status = "stopped"
                stop_reason_code = "budget_exhausted"
                _log("FINALIZE", "LLM logical-call budget exhausted", level="warning")
    except InvestigationStopped:
        status = "stopped"
        stop_reason_code = "interrupted"
    except LLMBudgetExceededError:
        status = "stopped"
        stop_reason_code = "budget_exhausted"
        _log("FINALIZE", "LLM logical-call budget exhausted", level="warning")
    except Exception:
        status = "failed"
        stop_reason_code = "exception"
        raise
    finally:
        try:
            terminal_reason = format_terminal_reason(status, cause=stop_reason_code)
            if terminal_receipt != (status, terminal_reason):
                persist_terminal_receipt()
            db.execute(
                "UPDATE trace.investigation_sessions SET iterations = ? "
                "WHERE session_id = ? AND owner_id = ?",
                (state.iteration, session_id, owner_id),
            )
            session_progress(
                progress_event(
                    "investigation.terminal",
                    status,
                    severity=(
                        "success"
                        if status == "completed"
                        else "error"
                        if status == "failed"
                        else "warning"
                    ),
                    reason=stop_reason_code or "work_complete",
                    refs={"session_id": session_id},
                    stage="terminal",
                    iteration=state.iteration,
                    session_id=session_id,
                    summary=terminal_reason,
                )
            )
        except Exception as exc:
            _log("FINALIZE", f"session receipt failed: {exc}", level="error")
        if terminal_receipt == (
            status,
            format_terminal_reason(status, cause=stop_reason_code),
        ):
            classify_stopped_work()
        try:
            summary = build_stop_summary()
            if not env.report_only:
                save_stop_reason(
                    db,
                    status=status,
                    stop_reason_code=stop_reason_code,
                    stop_reason=format_stop_reason(status, stop_reason_code, summary),
                    stop_summary=summary,
                )
        except Exception as exc:
            _log(
                "FINALIZE",
                f"investigation state projection failed: {exc}",
                level="error",
            )
        if status == "stopped" and stop_reason_code in {
            "budget_exhausted",
            "interrupted",
        }:
            try:
                report_refresh_failures += await _final_report_refresh(
                    env, allow_narration=False
                )
            except Exception as exc:
                _log(
                    "FINALIZE",
                    f"deterministic closing report failed: {exc}",
                    level="error",
                )
        try:
            await close_llm_clients(client_scope_id)
        except Exception as exc:
            _log("FINALIZE", f"LLM client cleanup failed: {exc}", level="error")
        reset_llm_client_scope(client_scope_token)
        reset_active_telemetry(telemetry_token)
    return _build_investigate_result(env, status, report_refresh_failures)
