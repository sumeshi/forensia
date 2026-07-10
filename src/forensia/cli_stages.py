"""Pipeline stage runners for the investigate command."""

import asyncio
import sys
from pathlib import Path

from forensia.ai.investigator import investigate as investigate_loop
from forensia.ai.llm_client import LLMServerUnavailableError
from forensia.api.cache import (
    write_api_snapshots,
)
from forensia.cli_support import (
    _normalize_counts_summary,
    _prune_orphan_reviews,
    _status,
)
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all
from forensia.normalize import normalize_all
from forensia.report.writer import render_written_report
from forensia.rules.engine import (
    clear_rule_findings,
    generate_findings,
    run_rule,
    save_findings,
)
from forensia.rules.loader import load_rules_from_dir


def _make_initial_progress_state(
    model: str | None,
    llm_base_url: str | None,
    stage: str = "init",
    summary: str = "Case initialized",
) -> dict:
    return progress_event(
        stage,
        "running",
        iteration=0,
        summary=summary,
        current_query=None,
        recent_logs=[],
        llm_model=model,
        llm_base_url=llm_base_url,
        hypotheses=[],
        report_sections={
            "items": [],
            "current_section": None,
            "focus_sections": [],
            "total_gaps": 0,
            "total_body_chars": 0,
        },
    )


def _run_ingest_stage(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    input_dir: str,
    push_progress,
) -> dict:
    """Ingest evidence files (EVTX, MFT, Prefetch) into the case."""

    def stage_status(message: str) -> None:
        _status(message)
        push_progress(message, stage="ingest", status="running", summary=message)

    _status(f"Stage 1/4: ingest from {input_dir}")
    push_progress(f"[ingest] scanning {input_dir}", stage="ingest", status="running")
    counts = ingest_all(case, input_dir, db=db, progress_callback=stage_status)
    note = (
        f"new_files={counts['new_files']}, skipped_files={counts['skipped_files']}, "
        f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}, "
        f"prefetch_files={counts['prefetch_files']}"
    )
    tasks.mark_done("ingest", note)
    _status(f"Ingest complete: {note}")
    push_progress(f"[ingest] {note}", stage="ingest", status="running", summary=note)
    return counts


def _run_normalize_stage(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    init: bool,
    ingest_counts: dict,
    push_progress,
) -> bool:
    """Normalize raw evidence into structured DuckDB tables."""
    existing_rows = int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0])
    normalized_this_run = True
    if (
        not init
        and ingest_counts["new_files"] == 0
        and tasks.is_done("normalize")
        and existing_rows > 0
    ):
        normalized_this_run = False
        _status(f"Stage 2/4: normalize - already done ({existing_rows} rows), skipping")
        push_progress(
            f"[normalize] skipped ({existing_rows} rows already in DB)",
            stage="normalize",
            status="running",
        )
    else:
        _status("Stage 2/4: normalize into DuckDB")
        push_progress("[normalize] starting", stage="normalize", status="running")
        normalized = normalize_all(case, db)
        note = _normalize_counts_summary(normalized)
        tasks.mark_done("normalize", note)
        _status(
            f"Normalize complete: {note}, mft_timeline_rows={normalized['mft_timeline_rows']}"
        )
        push_progress(
            f"[normalize] {note}", stage="normalize", status="running", summary=note
        )
    return normalized_this_run


def _run_analyze_stage(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    profile: str,
    profile_path: Path,
    init: bool,
    normalized_this_run: bool,
    push_progress,
) -> int:
    """Run rule-based analysis to generate findings."""
    if not init and not normalized_this_run and tasks.is_done("analyze"):
        existing_findings = int(
            db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        )
        _status(
            f"Stage 3/4: analyze - already done ({existing_findings} findings), skipping"
        )
        push_progress(
            f"[analyze] skipped ({existing_findings} findings already exist)",
            stage="analyze",
            status="running",
        )
        return existing_findings

    rules_dir = Path(__file__).parent / "rulepacks"
    rules = load_rules_from_dir(rules_dir, profile_path)
    _status(f"Stage 3/4: analyze with profile={profile} ({len(rules)} rules)")
    push_progress(
        f"[analyze] profile={profile}, rules={len(rules)}",
        stage="analyze",
        status="running",
    )
    total_findings = 0
    for rule in rules:
        push_progress(f"[analyze] rule: {rule.id}", stage="analyze", status="running")
        clear_rule_findings(case, db, rule.id)
        findings = generate_findings(rule, run_rule(db, rule))
        save_findings(case, db, findings)
        total_findings += len(findings)
    _prune_orphan_reviews(db)
    tasks.mark_done("analyze", f"profile={profile}, findings={total_findings}")
    _status(f"Analyze complete: findings={total_findings}")
    push_progress(
        f"[analyze] done - findings={total_findings}",
        stage="analyze",
        status="running",
        summary=f"findings={total_findings}",
    )
    return total_findings


def _run_investigate_stage(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    llm_base_url: str | None,
    model: str | None,
    template_root: Path | None,
    profile: str,
    push_progress,
    *,
    max_iter: int,
    max_queries_per_hypothesis: int,
    no_progress_limit: int,
    report_every_n_cycles: int,
    report_max_queries_per_section: int,
    max_llm_calls: int,
    auto_rulepacks: bool = True,
) -> None:
    """Run LLM-driven investigation loop (or skip if LLM not configured)."""
    if not (llm_base_url and model):
        _status(
            "Stage 4/4: LLM not configured - skipping investigate (set LLM_BASE_URL and LLM_MODEL in .env)"
        )
        push_progress(
            "[investigate] skipped - LLM not configured",
            stage="investigate",
            status="running",
        )
        return

    _status(f"Stage 4/4: investigate with model={model}")
    push_progress(
        f"[investigate] starting - model={model}", stage="investigate", status="running"
    )
    write_api_snapshots(case, db)
    try:
        result = asyncio.run(
            investigate_loop(
                case=case,
                db=db,
                base_url=llm_base_url,
                model=model,
                template_root=template_root,
                max_iter=max_iter,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                no_progress_limit=no_progress_limit,
                profile=profile,
                report_every_n_cycles=report_every_n_cycles,
                report_max_queries_per_section=report_max_queries_per_section
                or get_llm_settings()["report_max_queries_per_section"],
                max_llm_calls=max_llm_calls,
                auto_rulepacks=auto_rulepacks,
                progress_callback=lambda payload: push_progress(
                    payload.get("summary"),
                    stage=payload.get("stage", "investigate"),
                    status=payload.get("status", "running"),
                    iteration=payload.get("iteration", 0),
                    current_query=payload.get("current_query"),
                    summary=payload.get("summary"),
                    hypotheses=payload.get("hypotheses", []),
                    report_sections=payload.get("report_sections", {}),
                ),
            )
        )
    except LLMServerUnavailableError as exc:
        _status(f"investigation aborted: LLM server unavailable ({exc})")
        sys.exit(2)
    tasks.mark_done(
        "investigate",
        f"session={result['session_id']}, status={result['status']}, iterations={result['iteration']}",
    )
    _status(
        f"Investigation complete: session={result['session_id']} status={result['status']}"
    )
    push_progress(
        f"[investigate] done - session={result['session_id']} status={result['status']}",
        stage="investigate",
        status=result["status"],
        iteration=result["iteration"],
        summary=result["summary"],
        hypotheses=result.get("hypotheses", []),
        report_sections=result.get("report_sections", {}),
    )


def _run_report_stage(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    push_progress,
) -> Path:
    """Render the final written report."""
    report_md, report_path = render_written_report(case, db)
    write_api_snapshots(case, db)
    tasks.mark_done("report", str(report_path))
    push_progress(
        f"[report] written: {report_path}",
        stage="completed",
        status="completed",
        summary=f"Report: {report_path}",
    )
    return report_path

