"""Investigation entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.investigation.investigator.
"""

from __future__ import annotations

import signal
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    CaseEvidenceProfile,
    _format_case_profile,
    build_case_profile,
)
from forensia.ai.hypotheses.hypothesis_store import _all_hypotheses
from forensia.ai.investigation.investigation_cycle import (
    _run_cycle_body,
)
from forensia.ai.investigation.investigation_session import (
    _call_with_outage_recovery,
    _ctx_get_report_status,
    _finding_snapshot,
    _init_session,
    persist_session_terminal_receipt,
    sync_keypoint_cards,
    touch_session_heartbeat,
)
from forensia.ai.investigation.work_judgment import open_work_refs
from forensia.ai.investigation.work_state import (
    classify_active_hypotheses_on_stop,
    format_stop_reason,
    stop_summary,
)
from forensia.ai.llm.llm_client import (
    LLMServerUnavailableError,
)
from forensia.ai.llm_telemetry import (
    LLMTelemetry,
    reset_active_telemetry,
    set_active_telemetry,
)
from forensia.ai.report_gap import (
    _build_report_status,
    evaluation_snapshot,
    inject_gap_hypotheses,
    project_investigation_tasks,
    report_cycle_progress,
)
from forensia.ai.sections.section_refresher import async_refresh_report_sections
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.progress_event import progress_event
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import save_stop_reason
from forensia.knowledge.coverage import refresh_evidence_coverage
from forensia.knowledge.resources import profile_path
from forensia.knowledge.rules.loader import resolve_active_packs
from forensia.report.render.writer import render_written_report
from forensia.report.sections.section_store import mark_report_sections_ai_exhausted


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
    template_root: Path,
    base_url: str,
    model: str,
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str],
    report_max_queries_per_section: int,
    state: SessionState,
    memory: MemoryManager,
) -> tuple[dict[str, Any], str]:
    """Run the report refresh phase.

    Returns (report_after, refresh_status) where refresh_status is "skipped"
    (off-cycle), "ok", or "failed: <type>: <msg>".  Cycle progress is not
    decided here: the loop compares evaluation snapshots at its state-commit
    point (after the Coverage refresh), so Coverage changes are visible to the
    comparison in the same cycle they commit.
    """
    if plan_cycle % max(1, report_every_n_cycles) != 0:
        return _build_report_status(db), "skipped"
    report_result: dict[str, Any] | None = None
    try:
        template_paths = sorted(template_root.glob("[0-9]*_*.md"))
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
            template_paths=template_paths,
            llm_logger=llm_logger,
            progress_callback=progress_callback,
            focus_sections=focus_sections,
            max_queries_per_section=report_max_queries_per_section,
        )
    except LLMServerUnavailableError:
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
                    "investigate/report-cycle-done",
                    "running",
                    iteration=plan_cycle,
                    summary=f"[REPORT] refresh failed: {error_label}",
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
        return _build_report_status(db), f"failed: {error_label}"
    if report_result is None:
        return _build_report_status(db), "ok"
    report_after = report_result["report_status"]
    inject_gap_hypotheses(
        db=db,
        state=state,
        gaps=report_result["gaps"],
        session_id=session_id,
        memory=memory,
    )
    # Gap/Task/Hypothesis admission mutates Case State after section refresh;
    # rebuild the status after that mutation, while retaining the section body
    # for the report UI.
    refreshed_status = _build_report_status(db, focus_sections=focus_sections)
    refreshed_status["current_section"] = report_after.get("current_section")
    report_after = refreshed_status
    render_written_report(case, db)
    return report_after, "ok"


def _classify_active_hypotheses_on_stop(
    db: CaseDB,
    active_hypotheses: list,
    stop_reason: str,
    memory: MemoryManager | None = None,
) -> dict[str, int]:
    """Backward-compatible entry point for the authoritative transition."""
    counts = classify_active_hypotheses_on_stop(db, active_hypotheses, stop_reason)
    if memory is not None:
        project_investigation_tasks(db, memory)
    return counts


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
    cycle_progress: bool,
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
    no_progress_count = 0 if cycle_progress else no_progress_count + 1
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
            SUM(CASE WHEN phase = 'plan-hypothesis' THEN 1 ELSE 0 END) AS plan_steps,
            SUM(CASE WHEN phase IN ('do', 'check') THEN 1 ELSE 0 END) AS do_check_steps
        FROM investigation_steps
        WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    if not row or int(row[0] or 0) == 0 or int(row[1] or 0) > 0:
        return None
    failure = db.execute(
        """
        SELECT COUNT(*)
        FROM hypothesis_reasoning
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
    memory: MemoryManager
    llm_logger: LLMCallLogger
    session_id: str
    template_root: Path
    case_profile: CaseEvidenceProfile
    progress_callback: Callable[[dict[str, Any]], None] | None
    max_iter: int
    no_progress_limit: int
    max_queries_per_hypothesis: int
    report_every_n_cycles: int
    report_only: bool
    report_max_queries_per_section: int
    max_llm_calls: int


def _resolve_rulepacks(profile: str, db: CaseDB, auto_rulepacks: bool) -> set[str]:
    """Resolve active rulepack ids for the profile, logging auto-enabled packs."""
    profile_file = profile_path(profile)
    active_pack_ids = resolve_active_packs(
        profile_file if profile_file.exists() else None,
        db,
        auto_rulepacks=auto_rulepacks,
    )
    if auto_rulepacks and active_pack_ids:
        expected = set()
        if profile_file.exists():
            import yaml

            profile_data = (
                yaml.safe_load(profile_file.read_text(encoding="utf-8")) or {}
            )
            expected = set(profile_data.get("rulepacks") or [])
        auto_enabled = active_pack_ids - expected
        if auto_enabled:
            _log(
                "PLAN",
                f"auto-rulepacks enabled: {sorted(auto_enabled)} (detected families trigger pack activation)",
            )
    return active_pack_ids


def _prepare_case_profile(case: Case, db: CaseDB, profile: str) -> CaseEvidenceProfile:
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
        profile_name=profile,
        event_ids=frozenset(profile_event_ids),
        summary=case_profile,
    )


def _enforce_llm_budget(llm_logger: LLMCallLogger, max_llm_calls: int) -> None:
    """Raise RuntimeError when the session's LLM call budget is exhausted."""
    if max_llm_calls > 0 and llm_logger.total_calls >= max_llm_calls:
        raise RuntimeError(
            f"LLM call budget exceeded: {llm_logger.total_calls} calls >= {max_llm_calls} max. "
            f"Per-phase: {llm_logger.count_by_phase()}. "
            "Increase --max-llm-calls (or pass 0 for unlimited) or investigate the cause of excessive calls."
        )


async def _run_investigation_loop(env: _InvestigateEnv) -> tuple[str, int, str]:
    """Run plan cycles until completion, interrupt, or no-progress limit.

    Returns (status, report_refresh_failures, stop_reason_code).
    """
    no_progress_count = 0
    report_refresh_failures = 0
    stop_reason_code = ""
    for plan_cycle in range(1, env.max_iter + 1):
        _enforce_llm_budget(env.llm_logger, env.max_llm_calls)
        env.state.iteration = plan_cycle
        env.state.findings_snapshot = _finding_snapshot(env.db)
        sync_keypoint_cards(env.memory, env.state.findings_snapshot)
        _log(
            "PLAN",
            f"Cycle {plan_cycle}/{env.max_iter} — broad planning (active={len(env.state.active_hypotheses)} resolved={len(env.state.resolved_hypotheses)})",
        )
        if env.ctx.interrupted:
            return "stopped", report_refresh_failures, "interrupted"
        # Snapshot at the cycle's state-commit boundary: this read equals the
        # state the previous cycle committed (Coverage refresh included).
        evaluation_before = evaluation_snapshot(env.db)
        (
            broad_plan_stop,
            cycle_progress,
            focus_sections,
        ) = await _run_cycle_body(
            state=env.state,
            ctx=env.ctx,
            case=env.case,
            db=env.db,
            session_id=env.session_id,
            base_url=env.base_url,
            model=env.model,
            memory=env.memory,
            llm_logger=env.llm_logger,
            progress_callback=env.progress_callback,
            max_queries_per_hypothesis=env.max_queries_per_hypothesis,
            plan_cycle=plan_cycle,
            max_iter=env.max_iter,
            report_only=env.report_only,
            case_profile=env.case_profile,
        )
        if env.ctx.interrupted:
            return "stopped", report_refresh_failures, "interrupted"
        (
            report_after,
            refresh_status,
        ) = await _run_report_phase(
            case=env.case,
            db=env.db,
            session_id=env.session_id,
            plan_cycle=plan_cycle,
            report_every_n_cycles=env.report_every_n_cycles,
            template_root=env.template_root,
            base_url=env.base_url,
            model=env.model,
            llm_logger=env.llm_logger,
            progress_callback=env.progress_callback,
            focus_sections=focus_sections,
            report_max_queries_per_section=env.report_max_queries_per_section,
            state=env.state,
            memory=env.memory,
        )
        if refresh_status.startswith("failed"):
            report_refresh_failures += 1
        env.ctx.report_status = report_after
        env.memory.regenerate_timeline_from_db(env.db)
        refresh_evidence_coverage(env.db)
        # Compare at the commit point: the cycle's own Coverage refresh and
        # Gap/Task admissions are visible to the comparison in the same cycle
        # (V2-03/R06).
        evaluation_after = evaluation_snapshot(env.db)
        cycle_progress = cycle_progress or report_cycle_progress(
            evaluation_before, evaluation_after
        )
        durable_open_gaps, durable_open_tasks = _durable_open_work_counts(env.db)
        terminal_status, no_progress_count, stop_reason_code = _check_termination(
            report_only=env.report_only,
            broad_plan_stop=broad_plan_stop,
            active_hypotheses=env.state.active_hypotheses,
            durable_open_gaps=durable_open_gaps,
            durable_open_tasks=durable_open_tasks,
            no_progress_count=no_progress_count,
            no_progress_limit=env.no_progress_limit,
            cycle_progress=cycle_progress,
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
                _classify_active_hypotheses_on_stop(
                    env.db,
                    env.state.active_hypotheses,
                    stop_reason_code,
                    env.memory,
                )
            return terminal_status, report_refresh_failures, stop_reason_code
    planner_only_reason = (
        None
        if env.report_only
        else _planner_only_terminal_reason(env.db, env.session_id)
    )
    _classify_active_hypotheses_on_stop(
        env.db, env.state.active_hypotheses, "max_iterations", env.memory
    )
    return "stopped", report_refresh_failures, planner_only_reason or "max_iterations"


async def _final_report_refresh(env: _InvestigateEnv) -> int:
    """Render every section once at the final DB state. Returns 1 on failure, else 0.

    R5-03: run after loop termination so stale sections from late-cycle
    resolutions reach the rendered report. R7-04: force_all=True bypasses the
    update_count cap (it guards per-cycle loops, not the closing render).
    """
    try:
        template_paths = sorted(env.template_root.glob("[0-9]*_*.md"))
        await async_refresh_report_sections(
            case=env.case,
            db=env.db,
            session_id=env.session_id,
            iteration=env.max_iter + 1,
            base_url=env.base_url,
            model=env.model,
            template_paths=template_paths,
            llm_logger=env.llm_logger,
            progress_callback=env.progress_callback,
            focus_sections=[],
            max_queries_per_section=env.report_max_queries_per_section,
            force_all=True,
        )
        render_written_report(env.case, env.db)
        env.memory.regenerate_timeline_from_db(env.db)
        return 0
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
    profile: str = "windows-basic",
    max_queries_per_hypothesis: int = 5,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    report_every_n_cycles: int = 1,
    report_only: bool = False,
    template_root: Path | None = None,
    report_max_queries_per_section: int = 3,
    max_llm_calls: int = 200,
    auto_rulepacks: bool = True,
) -> dict[str, Any]:
    """Run the full investigation loop: broad plan → hypothesis loop → report refresh, with termination checks and LLM budget enforcement."""
    active_pack_ids = _resolve_rulepacks(profile, db, auto_rulepacks)
    state, ctx, memory, llm_logger, session_id, started_at, template_root = (
        _init_session(
            case,
            db,
            profile,
            base_url,
            model,
            template_root,
            active_pack_ids=active_pack_ids if auto_rulepacks else None,
            report_only=report_only,
        )
    )
    owner_id = ctx.owner_id
    if not owner_id:
        raise RuntimeError("investigation session has no durable owner lease")
    last_heartbeat = 0.0
    last_stage = ""

    def session_progress(payload: dict[str, Any]) -> None:
        """Publish progress and refresh the session lease at bounded cadence."""
        nonlocal last_heartbeat, last_stage
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
        if progress_callback:
            progress_callback(payload)

    ctx.progress_callback = session_progress
    env = _InvestigateEnv(
        case=case,
        db=db,
        base_url=base_url,
        model=model,
        state=state,
        ctx=ctx,
        memory=memory,
        llm_logger=llm_logger,
        session_id=session_id,
        template_root=template_root,
        case_profile=_prepare_case_profile(case, db, profile),
        progress_callback=session_progress,
        max_iter=max_iter,
        no_progress_limit=no_progress_limit,
        max_queries_per_hypothesis=max_queries_per_hypothesis,
        report_every_n_cycles=report_every_n_cycles,
        report_only=report_only,
        report_max_queries_per_section=report_max_queries_per_section,
        max_llm_calls=max_llm_calls,
    )
    telemetry_token = set_active_telemetry(LLMTelemetry(db, session_id))
    status = "running"
    stop_reason_code = ""
    report_refresh_failures = 0
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(
        signal.SIGINT, lambda signum, frame: setattr(ctx, "interrupted", True)
    )
    try:
        (
            status,
            report_refresh_failures,
            stop_reason_code,
        ) = await _run_investigation_loop(env)
        # Persist the terminal state before the closing report pass so report
        # validation and narratives observe the same final state as the API.
        # Report-only is a report job (R07): it must not rewrite the Case stop
        # state — an unresolved Case stays resumable after report-only.
        summary = stop_summary(db, len(state.active_hypotheses))
        if not env.report_only:
            save_stop_reason(
                db,
                status=status,
                stop_reason_code=stop_reason_code,
                stop_reason=format_stop_reason(status, stop_reason_code, summary),
                stop_summary=summary,
            )
        if status in {"completed", "stopped"} and not ctx.interrupted:
            report_refresh_failures += await _final_report_refresh(env)
    except Exception:
        status = "failed"
        stop_reason_code = "exception"
        raise
    finally:
        finished_at = datetime.now(UTC).replace(tzinfo=None)
        # Persist the terminal session receipt before fallible projections.  A
        # Memory or audit-summary write must not leave a completed DB session
        # looking permanently active.
        try:
            persist_session_terminal_receipt(
                db,
                session_id,
                status,
                terminal_reason=format_stop_reason(
                    status,
                    stop_reason_code,
                    stop_summary(db, len(state.active_hypotheses)),
                ),
                finished_at=finished_at,
                owner_id=owner_id,
            )
            db.execute(
                "UPDATE investigation_sessions SET iterations = ? "
                "WHERE session_id = ? AND owner_id = ?",
                (state.iteration, session_id, owner_id),
            )
        except Exception as exc:
            _log("FINALIZE", f"session receipt failed: {exc}", level="error")
        try:
            summary = stop_summary(db, len(state.active_hypotheses))
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
        try:
            memory.regenerate_timeline_from_db(db)
        except Exception as exc:
            _log("FINALIZE", f"Memory timeline projection failed: {exc}", level="error")
        try:
            llm_logger.write_summary()
        except Exception as exc:
            _log("FINALIZE", f"LLM audit summary failed: {exc}", level="error")
        signal.signal(signal.SIGINT, previous_sigint)
        reset_active_telemetry(telemetry_token)
    return _build_investigate_result(env, status, report_refresh_failures)
