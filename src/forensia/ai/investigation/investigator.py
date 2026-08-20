"""Investigation entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.investigation.investigator.
"""

from __future__ import annotations

import signal
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    _format_case_profile,
    build_case_profile,
    set_case_profile,
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
    sync_keypoint_cards,
)
from forensia.ai.investigation.work_state import (
    classify_active_hypotheses_on_stop,
    format_stop_reason,
    stop_summary,
)
from forensia.ai.llm.llm_client import (
    LLMServerUnavailableError,
)
from forensia.ai.report_gap import (
    _build_report_status,
    inject_gap_hypotheses,
    project_investigation_tasks,
    report_cycle_progress,
)
from forensia.ai.sections.section_refresher import async_refresh_report_sections
from forensia.config import get_llm_settings
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
    output_language = str(get_llm_settings()["output_language"]).lower()
    return {
        "en": "No additional progress was made during this investigation.",
    }.get(output_language, "No additional progress was made during this investigation.")


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
    report_before: dict[str, Any],
    memory: MemoryManager,
) -> tuple[dict[str, Any], bool, str]:
    """Run the report refresh phase.

    Returns (report_after, cycle_progress_from_report, refresh_status) where
    refresh_status is "skipped" (off-cycle), "ok", or "failed: <type>: <msg>".
    """
    cycle_progress = False
    if plan_cycle % max(1, report_every_n_cycles) != 0:
        return report_before, cycle_progress, "skipped"
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
        return report_before, cycle_progress, f"failed: {error_label}"
    if report_result is None:
        return report_before, cycle_progress, "ok"
    report_after = report_result["report_status"]
    gap_new_hypotheses = inject_gap_hypotheses(
        db=db,
        state=state,
        gaps=report_result["gaps"],
        session_id=session_id,
        memory=memory,
    )
    if gap_new_hypotheses:
        cycle_progress = True
    # Gap/Task/Hypothesis admission mutates Case State after section refresh;
    # take the semantic snapshot after that mutation, while retaining the
    # section body for the report UI.
    refreshed_status = _build_report_status(db, focus_sections=focus_sections)
    refreshed_status["current_section"] = report_after.get("current_section")
    report_after = refreshed_status
    if report_cycle_progress(report_before, report_after):
        cycle_progress = True
    render_written_report(case, db)
    return report_after, cycle_progress, "ok"


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


def _check_termination(
    *,
    report_only: bool,
    broad_plan_stop: bool,
    active_hypotheses: list,
    report_after: dict[str, Any],
    no_progress_count: int,
    no_progress_limit: int,
    cycle_progress: bool,
) -> tuple[str | None, int, str]:
    """Check if the investigation loop should stop. Returns (terminal_status or None, updated_no_progress_count, stop_reason_code)."""
    if report_only:
        return "completed", no_progress_count, "report_only_mode"
    unresolved_gap_count = int(report_after.get("total_gaps", 0))
    if broad_plan_stop and not active_hypotheses and unresolved_gap_count == 0:
        return "completed", no_progress_count, "no_gaps_no_hypotheses"
    no_progress_count = 0 if cycle_progress else no_progress_count + 1
    if no_progress_count >= no_progress_limit:
        return "stopped", no_progress_count, "no_progress_limit"
    return None, no_progress_count, ""


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
    case_profile_str: str
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


def _prepare_case_profile(case: Case, db: CaseDB) -> str:
    """Extract the case time range and register the case profile globally."""
    case.extract_time_range(db.conn)
    case_profile_dict = build_case_profile(db)
    case_profile_str = _format_case_profile(case_profile_dict)
    profile_event_ids = {
        e["event_id"]
        for e in case_profile_dict.get("event_ids", [])
        if isinstance(e.get("event_id"), int)
    }
    set_case_profile(case_profile_str, profile_event_ids)
    return case_profile_str


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
        (
            broad_plan_stop,
            cycle_progress,
            focus_sections,
            report_before,
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
            case_profile_str=env.case_profile_str,
        )
        if env.ctx.interrupted:
            return "stopped", report_refresh_failures, "interrupted"
        (
            report_after,
            report_cycle_progress,
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
            report_before=report_before,
            memory=env.memory,
        )
        if refresh_status.startswith("failed"):
            report_refresh_failures += 1
        env.ctx.report_status = report_after
        cycle_progress = cycle_progress or report_cycle_progress
        env.memory.regenerate_timeline_from_db(env.db)
        refresh_evidence_coverage(env.db)
        terminal_status, no_progress_count, stop_reason_code = _check_termination(
            report_only=env.report_only,
            broad_plan_stop=broad_plan_stop,
            active_hypotheses=env.state.active_hypotheses,
            report_after=report_after,
            no_progress_count=no_progress_count,
            no_progress_limit=env.no_progress_limit,
            cycle_progress=cycle_progress,
        )
        if terminal_status is not None:
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
    _classify_active_hypotheses_on_stop(
        env.db, env.state.active_hypotheses, "max_iterations", env.memory
    )
    return "stopped", report_refresh_failures, "max_iterations"


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
        )
    )
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
        case_profile_str=_prepare_case_profile(case, db),
        progress_callback=progress_callback,
        max_iter=max_iter,
        no_progress_limit=no_progress_limit,
        max_queries_per_hypothesis=max_queries_per_hypothesis,
        report_every_n_cycles=report_every_n_cycles,
        report_only=report_only,
        report_max_queries_per_section=report_max_queries_per_section,
        max_llm_calls=max_llm_calls,
    )
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
        summary = stop_summary(db, len(state.active_hypotheses))
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
            db.execute(
                "UPDATE investigation_sessions SET finished_at = ?, iterations = ?, "
                "status = ? WHERE session_id = ?",
                (finished_at, state.iteration, status, session_id),
            )
        except Exception as exc:
            _log("FINALIZE", f"session receipt failed: {exc}", level="error")
        try:
            summary = stop_summary(db, len(state.active_hypotheses))
            save_stop_reason(
                db,
                status=status,
                stop_reason_code=stop_reason_code,
                stop_reason=format_stop_reason(status, stop_reason_code, summary),
                stop_summary=summary,
            )
        except Exception as exc:
            _log("FINALIZE", f"investigation state projection failed: {exc}", level="error")
        try:
            memory.regenerate_timeline_from_db(db)
        except Exception as exc:
            _log("FINALIZE", f"Memory timeline projection failed: {exc}", level="error")
        try:
            llm_logger.write_summary()
        except Exception as exc:
            _log("FINALIZE", f"LLM audit summary failed: {exc}", level="error")
        signal.signal(signal.SIGINT, previous_sigint)
    return _build_investigate_result(env, status, report_refresh_failures)
