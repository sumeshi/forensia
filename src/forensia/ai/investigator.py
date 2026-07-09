"""Investigation entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.investigator.
"""

from __future__ import annotations

import signal
import traceback
from collections.abc import Callable
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
from forensia.ai.hypothesis_manager import (
    _all_hypotheses,
)
from forensia.ai.hypothesis_runner import (  # noqa: F401
    _has_zero_rows_refute_condition,
    _investigate_one_hypothesis,
    _matching_findings,
    _observed_keypoints_from_findings,
    _unavailable_missing_event_ids,
)
from forensia.ai.investigation_cycle import (  # noqa: F401
    _audit_broad_plan_hypotheses,
    _dedup_new_hypotheses,
    _hypothesis_focus_score,
    _normalize_hypothesis_tokens,
    _parse_hypothesis_from_drafter,
    _run_broad_plan_step,
    _run_cycle_body,
    _select_focus_hypotheses,
)
from forensia.ai.investigation_session import (  # noqa: F401
    _MAX_OUTAGE_RETRIES_PER_CALL,
    _append_hypothesis_reasoning,
    _call_with_outage_recovery,
    _Ctx,
    _ctx_get_report_status,
    _ctx_refresh_caches,
    _ensure_profile_objective,
    _finding_snapshot,
    _init_session,
    _initialize_overview,
    _keypoint_card_id,
    _load_profile_config,
    _reasoning_entry_id,
    _save_step,
    _sync_hypothesis_cards,
    _sync_keypoint_cards,
    _to_json,
)
from forensia.ai.llm_client import (
    LLMServerUnavailableError,
)
from forensia.ai.memory_sync import _apply_memory_updates  # noqa: F401
from forensia.ai.progress import (  # noqa: F401
    HypothesisProgressTracker,
    _query_fingerprint,
)
from forensia.ai.report_gap import (
    _inject_gap_hypotheses,
    _report_cycle_progress,
)
from forensia.ai.section_refresher import async_refresh_report_sections
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.progress_event import progress_event
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.report.writer import (
    mark_report_sections_ai_exhausted,
    render_written_report,
)
from forensia.rules.loader import resolve_active_packs


def _final_summary(state: SessionState) -> str:
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
        print(f"[red][report] section refresh failed: {error_label}[/red]")
        print(traceback.format_exc())
        if progress_callback:
            progress_callback(
                progress_event(
                    "investigate/report-cycle-done",
                    "running",
                    iteration=plan_cycle,
                    summary=f"[report] refresh failed: {error_label}",
                )
            )
        try:
            render_written_report(case, db)
        except Exception as render_exc:
            print(f"[yellow][report] fallback render failed: {render_exc}[/yellow]")
        return report_before, cycle_progress, f"failed: {error_label}"
    if report_result is None:
        return report_before, cycle_progress, "ok"
    report_after = report_result["report_status"]
    gap_new_hypotheses = _inject_gap_hypotheses(
        db=db,
        state=state,
        gaps=report_result["gaps"],
        session_id=session_id,
        memory=memory,
    )
    if gap_new_hypotheses:
        cycle_progress = True
    if _report_cycle_progress(report_before, report_after):
        cycle_progress = True
    render_written_report(case, db)
    return report_after, cycle_progress, "ok"


def _check_termination(
    *,
    report_only: bool,
    broad_plan_stop: bool,
    active_hypotheses: list,
    db: CaseDB,
    report_after: dict[str, Any],
    no_progress_count: int,
    no_progress_limit: int,
    cycle_progress: bool,
) -> tuple[str | None, int]:
    """Check if the investigation loop should stop. Returns (terminal_status or None, updated_no_progress_count)."""
    if report_only:
        return "completed", no_progress_count
    unresolved_gap_count = int(report_after.get("total_gaps", 0))
    if broad_plan_stop and not active_hypotheses and unresolved_gap_count == 0:
        mark_report_sections_ai_exhausted(db)
        return "completed", no_progress_count
    no_progress_count = 0 if cycle_progress else no_progress_count + 1
    if no_progress_count >= no_progress_limit:
        return "completed", no_progress_count
    return None, no_progress_count


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
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    active_pack_ids = resolve_active_packs(
        profile_path if profile_path.exists() else None,
        db,
        auto_rulepacks=auto_rulepacks,
    )
    if auto_rulepacks and active_pack_ids:
        expected = set()
        if profile_path.exists():
            import yaml

            profile_data = (
                yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
            )
            expected = set(profile_data.get("rulepacks") or [])
        auto_enabled = active_pack_ids - expected
        if auto_enabled:
            _log(
                "PLAN",
                f"auto-rulepacks enabled: {sorted(auto_enabled)} (detected families trigger pack activation)",
            )
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
    case.extract_time_range(db.conn)
    case_profile_dict = build_case_profile(db)
    case_profile_str = _format_case_profile(case_profile_dict)
    profile_event_ids = {
        e["event_id"]
        for e in case_profile_dict.get("event_ids", [])
        if isinstance(e.get("event_id"), int)
    }
    set_case_profile(case_profile_str, profile_event_ids)
    status = "running"
    no_progress_count = 0
    report_refresh_failures = 0
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(
        signal.SIGINT, lambda signum, frame: setattr(ctx, "interrupted", True)
    )

    def _check_llm_budget() -> None:
        if max_llm_calls > 0 and llm_logger.total_calls >= max_llm_calls:
            raise RuntimeError(
                f"LLM call budget exceeded: {llm_logger.total_calls} calls >= {max_llm_calls} max. "
                f"Per-phase: {llm_logger.count_by_phase()}. "
                "Increase --max-llm-calls (or pass 0 for unlimited) or investigate the cause of excessive calls."
            )

    try:
        for plan_cycle in range(1, max_iter + 1):
            _check_llm_budget()
            state.iteration = plan_cycle
            state.findings_snapshot = _finding_snapshot(db)
            _sync_keypoint_cards(memory, state.findings_snapshot)
            _log(
                "PLAN",
                f"Cycle {plan_cycle}/{max_iter} — broad planning (active={len(state.active_hypotheses)} resolved={len(state.resolved_hypotheses)})",
            )
            if ctx.interrupted:
                status = "stopped"
                break
            (
                broad_plan_stop,
                cycle_progress,
                focus_sections,
                report_before,
            ) = await _run_cycle_body(
                state=state,
                ctx=ctx,
                db=db,
                case=case,
                session_id=session_id,
                base_url=base_url,
                model=model,
                memory=memory,
                llm_logger=llm_logger,
                progress_callback=progress_callback,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                plan_cycle=plan_cycle,
                max_iter=max_iter,
                report_only=report_only,
                case_profile_str=case_profile_str,
            )
            if ctx.interrupted:
                status = "stopped"
                break
            (
                report_after,
                report_cycle_progress,
                refresh_status,
            ) = await _run_report_phase(
                case=case,
                db=db,
                session_id=session_id,
                plan_cycle=plan_cycle,
                report_every_n_cycles=report_every_n_cycles,
                template_root=template_root,
                base_url=base_url,
                model=model,
                llm_logger=llm_logger,
                progress_callback=progress_callback,
                focus_sections=focus_sections,
                report_max_queries_per_section=report_max_queries_per_section,
                state=state,
                report_before=report_before,
                memory=memory,
            )
            if refresh_status.startswith("failed"):
                report_refresh_failures += 1
            ctx.report_status = report_after
            cycle_progress = cycle_progress or report_cycle_progress
            memory.regenerate_timeline_from_db(db)
            terminal_status, no_progress_count = _check_termination(
                report_only=report_only,
                broad_plan_stop=broad_plan_stop,
                active_hypotheses=state.active_hypotheses,
                db=db,
                report_after=report_after,
                no_progress_count=no_progress_count,
                no_progress_limit=no_progress_limit,
                cycle_progress=cycle_progress,
            )
            if terminal_status is not None:
                status = terminal_status
                break
        else:
            status = "completed"

        # R5-03: Final report refresh pass after loop termination, so stale
        # sections from late-cycle resolutions reach the rendered report.
        # R7-04: Use force_all=True so every section renders at one DB state,
        # bypassing the update_count cap (it guards per-cycle loops, not the
        # closing render). Skipped on user interrupt.
        if status == "completed" and not ctx.interrupted:
            try:
                template_paths = sorted(template_root.glob("[0-9]*_*.md"))
                await async_refresh_report_sections(
                    case=case,
                    db=db,
                    session_id=session_id,
                    iteration=max_iter + 1,
                    base_url=base_url,
                    model=model,
                    template_paths=template_paths,
                    llm_logger=llm_logger,
                    progress_callback=progress_callback,
                    focus_sections=[],
                    max_queries_per_section=report_max_queries_per_section,
                    force_all=True,
                )
                render_written_report(case, db)
                memory.regenerate_timeline_from_db(db)
            except Exception as exc:
                report_refresh_failures += 1
                print(
                    f"[yellow][final-refresh] failed: {type(exc).__name__}: {exc}[/yellow]"
                )
                print(traceback.format_exc())
    except Exception:
        status = "failed"
        raise
    finally:
        memory.regenerate_timeline_from_db(db)
        signal.signal(signal.SIGINT, previous_sigint)
        llm_logger.write_summary()
        finished_at = datetime.now(UTC).replace(tzinfo=None)
        db.execute(
            "UPDATE investigation_sessions SET finished_at = ?, iterations = ?, status = ? WHERE session_id = ?",
            (finished_at, state.iteration, status, session_id),
        )
    if report_refresh_failures:
        print(
            f"[red][report] {report_refresh_failures} report refresh phase(s) failed during this "
            f"session — see tracebacks above. Stale sections persist and are retried on later "
            f"cycles and the final refresh.[/red]"
        )
    summary = _final_summary(state)
    return {
        "session_id": session_id,
        "status": status,
        "iteration": state.iteration,
        "depth": state.focus_depth,
        "focus_hypothesis_id": state.focus_hypothesis_id,
        "summary": summary,
        "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
        "report_sections": _ctx_get_report_status(ctx, db, refresh=True),
        "report_refresh_failures": report_refresh_failures,
    }

