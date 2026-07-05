import asyncio
import sys
import time
from collections.abc import Callable
from pathlib import Path

import typer
import uvicorn
from rich import print

from forensia.ai.case_profile import profile_advisor
from forensia.ai.investigator import investigate as investigate_loop
from forensia.ai.llm_client import LLMServerUnavailableError
from forensia.api.cache import (
    VOLATILE_SNAPSHOT_INTERVAL_S,
    clear_api_snapshots,
    write_api_snapshots,
    write_progress_snapshot,
    write_volatile_api_snapshots,
)
from forensia.api.progress import clear_progress_events, record_progress_event
from forensia.config import get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all
from forensia.normalize import normalize_all
from forensia.report.html import render_html_report
from forensia.report.writer import render_written_report
from forensia.report_templates import (
    export_packaged_report_templates,
    has_report_templates,
)
from forensia.rules.engine import (
    clear_rule_findings,
    generate_findings,
    run_rule,
    save_findings,
)
from forensia.rules.loader import load_rules_from_dir
from forensia.web import create_app

app = typer.Typer(help="forensia incident response tool")
PROFILE_ROOT = Path(__file__).parent / "profiles"


def _status(message: str) -> None:
    """Print a colored status message to stdout."""
    print(f"[bold cyan]==>[/bold cyan] {message}")


def _count_records(db: CaseDB) -> dict[str, int]:
    """Query row counts for all major case tables."""
    row = db.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM evtx_events) AS evtx_rows,
            (SELECT COUNT(*) FROM mft_entries) AS mft_entries,
            (SELECT COUNT(*) FROM findings) AS findings,
            (SELECT COUNT(*) FROM investigation_sessions) AS sessions,
            (SELECT COUNT(*) FROM hypotheses) AS hypotheses,
            (SELECT COUNT(*) FROM report_sections) AS report_sections,
            (SELECT COUNT(*) FROM progress_events) AS progress_events
        """
    ).fetchone()
    keys = [
        "evtx_rows",
        "mft_entries",
        "findings",
        "sessions",
        "hypotheses",
        "report_sections",
        "progress_events",
    ]
    return {key: int(row[index] or 0) for index, key in enumerate(keys)}


def _reset_case_tables(db: CaseDB) -> None:
    """Delete all rows from every case table (destructive reset)."""
    for table in (
        "evtx_events",
        "mft_entries",
        "mft_timeline",
        "prefetch_executions",
        "prefetch_timeline",
        "findings",
        "claims",
        "section_facts",
        "section_evidence",
        "query_cache",
        "section_runs",
        "section_questions",
        "ai_reviews",
        "investigation_sessions",
        "investigation_steps",
        "hypothesis_reasoning",
        "hypotheses",
        "report_sections",
        "progress_events",
        "ingested_files",
    ):
        db.execute(f"DELETE FROM {table}")


def _prune_orphan_reviews(db: CaseDB) -> None:
    """Remove AI reviews whose referenced findings no longer exist."""
    db.execute(
        """
        DELETE FROM ai_reviews
        WHERE finding_id NOT IN (SELECT finding_id FROM findings)
          AND finding_id NOT LIKE 'hypothesis:%'
          AND finding_id NOT LIKE 'query:%'
          AND finding_id NOT LIKE 'investigate:%'
        """
    )


def _normalize_counts_summary(counts: dict[str, int]) -> str:
    return (
        f"evtx_rows={counts['evtx_rows']}, "
        f"mft_entries={counts['mft_entries']}, "
        f"prefetch_executions={counts['prefetch_executions']}"
    )


def _resolve_template_dir(case: Case, template_dir: str | None) -> Path:
    """Resolve and validate a report template directory, falling back to the case's bundled templates."""
    if template_dir:
        path = Path(template_dir).resolve()
        if not path.exists():
            raise typer.BadParameter(f"template_dir not found: {path}")
        if not has_report_templates(path):
            raise typer.BadParameter(
                f"template_dir must contain at least one template matching [0-9]*_*.md: {path}"
            )
        return path
    case.ensure_report_templates()
    if case.report_template_dir.exists() and has_report_templates(
        case.report_template_dir
    ):
        return case.report_template_dir
    raise typer.BadParameter("no report templates are available")


def _available_profiles() -> list[str]:
    return sorted(path.stem for path in PROFILE_ROOT.glob("*.yaml"))


def _resolve_profile_path(profile: str) -> Path:
    """Resolve a profile name to a YAML file path, raising an error if not found."""
    profile_name = str(profile).strip()
    path = PROFILE_ROOT / f"{profile_name}.yaml"
    if path.exists():
        return path
    available = ", ".join(_available_profiles()) or "none"
    raise typer.BadParameter(
        f"unknown profile: {profile_name}. Available profiles: {available}"
    )


def _resolve_llm_or_die(base_url: str | None, model: str | None) -> tuple[str, str]:
    """Resolve LLM endpoint and model, raising an error if either is missing."""
    resolved_base_url, resolved_model = resolve_llm_config(base_url, model)
    if not resolved_base_url or not resolved_model:
        raise typer.BadParameter(
            "Set LLM_BASE_URL and LLM_MODEL via .env file or CLI flags."
        )
    return resolved_base_url, resolved_model


def _resolve_timezone(tz, case) -> str:
    """Return the resolved timezone string, preferring CLI flag over manifest value."""
    if isinstance(tz, str):
        return tz if tz else _case_timezone(case)
    return _case_timezone(case)


def _case_timezone(case) -> str:
    val = getattr(case, "source_timezone", "UTC") if case is not None else "UTC"
    return str(val or "UTC")


def _open_case_or_die(case_dir: str, timezone: str | None = None) -> Case:
    """Open a case directory or raise a CLI error if the manifest is missing."""
    try:
        case = Case.open(case_dir)
        case.source_timezone = _resolve_timezone(timezone, case)
        return case
    except FileNotFoundError as exc:
        target = Path(case_dir).resolve()
        raise typer.BadParameter(
            "case_dir must point to an initialized case directory.\n"
            f"missing: {target / 'manifest.yaml'}\n"
            f"initialize with: forensia investigate {target} <input_dir>"
        ) from exc


def _progress_pusher(db: CaseDB, initial_state: dict) -> Callable[..., None]:
    """Return a closure that records progress events and writes snapshots."""
    state = dict(initial_state)

    def push(message: str | None = None, **updates) -> None:
        if message:
            recent = list(state.get("recent_logs", []))
            recent.append(message)
            state["recent_logs"] = recent[-20:]
        state.update(updates)
        payload = {**state, "counts": _count_records(db)}
        record_progress_event(db, payload)
        write_progress_snapshot(db.case, db)
        now = time.monotonic()
        if now - state.get("_last_volatile_at", 0.0) > VOLATILE_SNAPSHOT_INTERVAL_S:
            try:
                write_volatile_api_snapshots(db.case, db)
            except Exception as exc:
                _status(f"volatile snapshot skipped: {exc}")
            state["_last_volatile_at"] = now

    return push


def _seed_api_snapshots_if_possible(case: Case) -> None:
    """Try to write API snapshots; silently skip if the database is unavailable."""
    try:
        with CaseDB(case) as db:
            write_api_snapshots(case, db)
    except Exception as exc:
        _status(f"serve snapshot refresh skipped: {exc}")


@app.command("templates-export", hidden=True)
def templates_export(
    output_dir: str,
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing packaged template files in the target directory",
    ),
) -> None:
    written = export_packaged_report_templates(output_dir, overwrite=force)
    target = Path(output_dir).resolve()
    if written:
        print(f"Exported {len(written)} template files to {target}")
    else:
        print(f"No template files were written to {target} (files already exist)")


@app.command()
def add(case_dir: str, input_dir: str) -> None:
    """Incrementally ingest new evidence into an existing case."""
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    _status(f"Adding evidence from: {input_dir}")
    counts = ingest_all(case, input_dir, progress_callback=_status)
    tasks.mark_done(
        "ingest",
        (
            f"new_files={counts['new_files']}, skipped_files={counts['skipped_files']}, "
            f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}, "
            f"prefetch_files={counts['prefetch_files']}"
        ),
    )
    print(
        "Add complete: "
        f"added={counts['new_files']}, skipped={counts['skipped_files']}, "
        f"evtx={counts['evtx_files']}, mft={counts['mft_files']}, "
        f"prefetch={counts['prefetch_files']}"
    )


@app.command()
def report(
    case_dir: str,
    output: str | None = typer.Option(None, "--output"),
    write: bool = typer.Option(
        False,
        "--write",
        help="Regenerate report sections using LLM-driven agentic writing",
    ),
    template_dir: str | None = typer.Option(None, "--template-dir"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    report_max_queries_per_section: int = typer.Option(
        0,
        "--report-max-queries-per-section",
        help="Max iterative agent queries per report block. 0 = use LLM_REPORT_MAX_QUERIES_PER_SECTION env (default 3)",
    ),
) -> None:
    case = _open_case_or_die(case_dir)
    with CaseDB(case) as db:
        if write:
            llm_base_url, model = _resolve_llm_or_die(llm_base_url, model)
            template_root = _resolve_template_dir(case, template_dir)
            max_queries = (
                report_max_queries_per_section
                or get_llm_settings()["report_max_queries_per_section"]
            )
            _status(
                f"Writing report from templates: {template_root} (max_queries={max_queries})"
            )
            asyncio.run(
                investigate_loop(
                    case=case,
                    db=db,
                    base_url=llm_base_url,
                    model=model,
                    max_iter=1,
                    no_progress_limit=1,
                    profile="windows-basic",
                    max_queries_per_hypothesis=0,
                    report_only=True,
                    template_root=template_root,
                    report_max_queries_per_section=max_queries,
                )
            )
        report_md, report_path = render_written_report(case, db)
        path = (
            render_html_report(case, db, output_path=output) if output else report_path
        )
        write_api_snapshots(case, db)
    print(f"Markdown report written to {report_md}")
    print(f"HTML report written to {path}")


def _make_initial_progress_state(
    model: str | None,
    llm_base_url: str | None,
    stage: str = "init",
    summary: str = "Case initialized",
) -> dict:
    return {
        "stage": stage,
        "status": "running",
        "iteration": 0,
        "current_query": None,
        "summary": summary,
        "recent_logs": [],
        "llm_model": model,
        "llm_base_url": llm_base_url,
        "hypotheses": [],
        "report_sections": {
            "items": [],
            "current_section": None,
            "focus_sections": [],
            "total_gaps": 0,
            "total_body_chars": 0,
        },
    }


def _run_init_stage(
    case: Case,
    db: CaseDB,
    out: str,
    llm_base_url: str | None,
    model: str | None,
    template_dir: str | None,
    init: bool,
) -> tuple[Case, CaseTasks, Path | None]:
    """Initialize case, tasks, resolve template root and profile path."""
    tasks = CaseTasks.for_case(case)
    template_root = (
        _resolve_template_dir(case, template_dir) if (llm_base_url and model) else None
    )

    if init:
        _reset_case_tables(db)
        case.clear_runtime_outputs(
            preserve_memory=True, preserve_ai_logs=True, drop_database=False
        )
        case = Case.init(out)
        tasks = CaseTasks.for_case(case)
        template_root = (
            _resolve_template_dir(case, template_dir)
            if (llm_base_url and model)
            else None
        )

    return case, tasks, template_root


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


@app.command()
def investigate(
    case_dir: str,
    input_dir: str | None = typer.Argument(
        None, help="Evidence input directory (required for new cases)"
    ),
    profile: str = typer.Option("windows-basic", "--profile"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    template_dir: str | None = typer.Option(None, "--template-dir"),
    rerun: bool = typer.Option(False, "--rerun", help="Reset case tables before rerun"),
    report_only: bool = typer.Option(
        False, "--report-only", help="Skip investigation, just write report"
    ),
    max_iter: int = typer.Option(20, "--max-iter"),
    max_queries_per_hypothesis: int = typer.Option(5, "--max-queries-per-hypothesis"),
    no_progress_limit: int = typer.Option(3, "--no-progress-limit"),
    report_every_n_cycles: int = typer.Option(3, "--report-every-n-cycles"),
    report_max_queries_per_section: int = typer.Option(
        0,
        "--report-max-queries-per-section",
        help="Max iterative agent queries per report block. 0 = use LLM_REPORT_MAX_QUERIES_PER_SECTION env (default 3)",
    ),
    max_llm_calls: int = typer.Option(
        0,
        "--max-llm-calls",
        help="Hard cap on total LLM calls per investigation session. 0 = unlimited (default for local LLM).",
    ),
    auto_rulepacks: bool = typer.Option(
        True,
        "--auto-rulepacks/--no-auto-rulepacks",
        help="Automatically enable rulepacks whose applies_when artifact_families are detected in case data",
    ),
    timezone: str = typer.Option(
        "",
        "--timezone",
        help="IANA timezone name (e.g. America/New_York). Overrides manifest value.",
    ),
) -> None:
    """Run full investigation pipeline: ingest, normalize, analyze, investigate, and report."""
    llm_base_url, model = resolve_llm_config(llm_base_url, model)

    case_path = Path(case_dir)
    case_exists = (case_path / "manifest.yaml").exists()

    if not case_exists:
        if input_dir is None:
            raise typer.BadParameter("New case requires an input_dir argument")
        tz_val = _resolve_timezone(timezone, None)
        case = Case.init(case_dir, source_timezone=tz_val)
        clear_api_snapshots(case)
        _status(f"Initialized case at {case.path}")
    else:
        case = _open_case_or_die(case_dir, timezone=timezone)

    if rerun:
        _status("Resetting case tables for rerun (preserving raw/ for re-normalize)")
        with CaseDB(case) as db:
            _reset_case_tables(db)
        case.clear_runtime_outputs(
            preserve_memory=True,
            preserve_ai_logs=True,
            drop_database=False,
            preserve_raw=True,
        )
        # Preserve the manifest timezone across rerun unless --timezone overrides it.
        tz_val = _resolve_timezone(timezone, case)
        case = Case.init(case_dir, source_timezone=tz_val)
        clear_api_snapshots(case)
        _status(f"Re-initialized case at {case.path}")

    with CaseDB(case) as db:
        clear_progress_events(db)
        push_progress = _progress_pusher(
            db,
            _make_initial_progress_state(model, llm_base_url),
        )
        push_progress("Case ready", stage="init", summary=f"Case: {case.path}")

        tasks = CaseTasks.for_case(case)
        template_root = (
            _resolve_template_dir(case, template_dir)
            if (llm_base_url and model)
            else None
        )

        # Determine if we need to (re)build evidence tables.
        # - `input_dir` given: full ingest from input_dir, then normalize + analyze
        # - `rerun` with raw/ already populated: skip ingest, just re-run normalize + analyze
        raw_has_files = any(case.raw_dir.iterdir()) if case.raw_dir.exists() else False
        needs_normalize_from_raw = rerun and input_dir is None and raw_has_files

        if input_dir is not None and not report_only:
            profile_path = _resolve_profile_path(profile)
            ingest_counts = _run_ingest_stage(case, db, tasks, input_dir, push_progress)
            normalized_this_run = _run_normalize_stage(
                case, db, tasks, rerun, ingest_counts, push_progress
            )
            _run_analyze_stage(
                case,
                db,
                tasks,
                profile,
                profile_path,
                rerun,
                normalized_this_run,
                push_progress,
            )
        elif needs_normalize_from_raw and not report_only:
            profile_path = _resolve_profile_path(profile)
            _status("Re-normalizing from existing raw/ (no input_dir provided)")
            normalized_this_run = _run_normalize_stage(
                case, db, tasks, True, {}, push_progress
            )
            _run_analyze_stage(
                case,
                db,
                tasks,
                profile,
                profile_path,
                True,
                normalized_this_run,
                push_progress,
            )

        if not report_only:
            advice = profile_advisor(profile, db)
            if advice:
                # rich's print would swallow [bracketed] pack names as markup tags.
                from rich.markup import escape

                print(escape(advice))
            if case.source_timezone == "UTC":
                # R2-14: surface a conservative timezone hint when no explicit
                # timezone was provided; rendering stays UTC-only until the
                # analyst confirms via --timezone.
                try:
                    from forensia.normalize.timezone import infer_timezone

                    offset_minutes, basis = infer_timezone(db)
                    if offset_minutes is not None:
                        sign = "+" if offset_minutes >= 0 else "-"
                        hours, minutes = divmod(abs(offset_minutes), 60)
                        _status(
                            f"Timezone hint: evidence suggests UTC{sign}{hours}"
                            + (f":{minutes:02d}" if minutes else "")
                            + f" ({basis}). Re-run with --timezone <IANA name> to render local times."
                        )
                except Exception:
                    pass
            _run_investigate_stage(
                case,
                db,
                tasks,
                llm_base_url,
                model,
                template_root,
                profile,
                push_progress,
                max_iter=max_iter,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                no_progress_limit=no_progress_limit,
                report_every_n_cycles=report_every_n_cycles,
                report_max_queries_per_section=report_max_queries_per_section,
                max_llm_calls=max_llm_calls,
                auto_rulepacks=auto_rulepacks,
            )

        report_path = _run_report_stage(case, db, tasks, push_progress)

    print(f"Investigation complete. Report: {report_path}")


@app.command(hidden=True)
def doctor() -> None:
    """Run all health checks: schema coverage, playbook drift, verdict taxonomy."""
    checks: list[tuple[str, bool]] = []

    _status("Schema coverage audit...")
    try:
        import subprocess

        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).parent.parent.parent
                    / "scripts"
                    / "audit_schema_coverage.py"
                ),
                "--strict",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        ok = result.returncode == 0
        checks.append(("Schema coverage", ok))
        if ok:
            print("  ✓ All event IDs and question types covered")
        else:
            print(f"  ✗ Uncovered entries:\n{result.stdout}")
    except Exception as exc:
        checks.append(("Schema coverage", False))
        print(f"  ✗ Error: {exc}")

    _status("Playbook MD/YAML drift check...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).parent.parent.parent
                    / "scripts"
                    / "regenerate_playbook.py"
                ),
                "--check",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = result.returncode == 0
        checks.append(("Playbook drift", ok))
        if ok:
            print("  ✓ All playbook files up to date")
        else:
            print(f"  ✗ Drift detected:\n{result.stdout}")
    except Exception as exc:
        checks.append(("Playbook drift", False))
        print(f"  ✗ Error: {exc}")

    _status("Import layer contract (R4)...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).parent.parent.parent / "scripts" / "check_imports.py"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = result.returncode == 0
        checks.append(("Import layers", ok))
        if ok:
            print("  ✓ No forbidden import edges")
        else:
            print(f"  ✗ Layer violations:\n{result.stdout}")
    except Exception as exc:
        checks.append(("Import layers", False))
        print(f"  ✗ Error: {exc}")

    _status("Verdict taxonomy enforcement...")
    try:
        from forensia.core.verdicts import valid_verdicts

        h_count = len(valid_verdicts("hypothesis_verdict"))
        s_count = len(valid_verdicts("section_verdict"))
        q_count = len(valid_verdicts("structured_status"))
        print(
            f"  ✓ {h_count} hypothesis, {s_count} section, {q_count} structured-question verdicts defined"
        )

        import ast
        import os

        enforcement_files = []
        for root, dirs, files in os.walk(Path(__file__).parent.parent):
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    try:
                        tree = ast.parse(open(path).read())
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                callee = node.func
                                name = (
                                    callee.attr
                                    if isinstance(callee, ast.Attribute)
                                    else (
                                        callee.id
                                        if isinstance(callee, ast.Name)
                                        else ""
                                    )
                                )
                                if name == "assert_valid_verdict":
                                    enforcement_files.append(
                                        os.path.relpath(
                                            path, Path(__file__).parent.parent.parent
                                        )
                                    )
                                    break
                    except Exception:
                        pass
        enforcement_count = len(enforcement_files)
        ok = enforcement_count >= 4
        checks.append(("Verdict enforcement", ok))
        print(
            f"  {'✓' if ok else '✗'} {enforcement_count} files use assert_valid_verdict: {enforcement_files}"
        )
    except Exception as exc:
        checks.append(("Verdict enforcement", False))
        print(f"  ✗ Error: {exc}")

    _status("Report template policy...")
    try:
        from forensia.report.ranking import audit_packaged_report_templates

        problems = audit_packaged_report_templates()
        ok = not problems
        checks.append(("Report template policy", ok))
        if ok:
            print("  ✓ Packaged templates carry no case-specific ranking policy")
        else:
            print(
                "  ✗ Case-specific policy / malformed frontmatter in packaged "
                "templates:\n" + "\n".join(f"      - {p}" for p in problems)
            )
    except Exception as exc:
        checks.append(("Report template policy", False))
        print(f"  ✗ Error: {exc}")

    _status("Report output validation self-check...")
    try:
        from forensia.report.report_validation import validate_report

        # Build a synthetic brief with known-bad patterns to exercise
        # every validator check without depending on pre-generated case output.
        synthetic_brief = {
            "executive_summary": (
                "Analysis revealed signs of lateral movement and network "
                "intrusion via compromised host."
            ),
            "confirmed_hypotheses": [
                {
                    # No source_rule_ids → not a "strong" hypothesis
                    "description": "Attacker used RDP lateral movement to pivot",
                    "source_rule_ids": [],
                    "tags": [],
                },
                {
                    # Tagged benign → should be excluded from strong count
                    "description": "Loopback 4648 logon via explicit credentials",
                    "source_rule_ids": ["SIGMA-001"],
                    "tags": ["benign"],
                },
            ],
            "refuted_hypotheses": [
                {
                    # Duplicate description → verdict_contradiction
                    "description": "Attacker used RDP lateral movement to pivot",
                },
            ],
            "evidence_gaps": [],
        }
        synthetic_body = (
            "Evidence sourced from sample/MFT_C and Prefetch/RDPBLAH.pf. "
            "For Executive Summary, the collected evidence returned 14 related rows."
        )
        findings = validate_report(synthetic_brief, report_body=synthetic_body)
        # The validator should catch: thesis_alignment, verdict_contradiction,
        # local_path_leak (sample/ in body), and fallback_stub.
        ok = len(findings) >= 4
        checks.append(("Report output validation", ok))
        if ok:
            names = [f.check_name for f in findings]
            print(
                f"  ✓ Validator correctly caught {len(findings)} intentional "
                f"issues ({', '.join(names)})"
            )
        else:
            print(
                f"  ✗ Validator only caught {len(findings)} issue(s) "
                "(expected >= 3); possible regression"
            )
            for f_item in findings:
                print(
                    f"      [{f_item.severity}] {f_item.check_name}: "
                    f"{f_item.message}"
                )
    except Exception as exc:
        checks.append(("Report output validation", False))
        print(f"  ✗ Error: {exc}")

    _status("Static lint (undefined names, unused imports)...")
    try:
        # Runtime-only NameErrors (e.g. a constant referenced in a code path
        # tests never execute) crash long investigation runs hours in. Ruff's
        # pyflakes rules catch them statically before any run starts.
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "src/forensia", "tests"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 and "No module named" in (result.stderr or ""):
            checks.append(("Static lint", True))
            print("  ✓ ruff not installed — skipping (dev dependency)")
        else:
            ok = result.returncode == 0
            checks.append(("Static lint", ok))
            if ok:
                print("  ✓ ruff check clean")
            else:
                print(f"  ✗ Lint findings:\n{result.stdout[-500:]}")
    except Exception as exc:
        checks.append(("Static lint", False))
        print(f"  ✗ Error: {exc}")

    _status("Test suite...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                "-q",
                "--no-header",
                "--ignore=tests/test_memory_and_ingest.py",
                "--ignore=tests/test_persistence.py",
                "--ignore=tests/test_web_api.py",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        last_line = (
            result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        )
        ok = result.returncode == 0
        checks.append(("Test suite", ok))
        if ok:
            print(f"  ✓ {last_line}")
        else:
            print(f"  ✗ Failures:\n{result.stdout[-500:]}")
    except Exception as exc:
        checks.append(("Test suite", False))
        print(f"  ✗ Error: {exc}")

    print()
    total = len(checks)
    passed = sum(1 for _, ok in checks if ok)
    failed = total - passed
    if failed == 0:
        print(f"[bold green]✓ All {total} checks passed[/bold green]")
    else:
        print(f"[bold red]✗ {failed}/{total} checks failed[/bold red]")
        for name, ok in checks:
            status_char = "✓" if ok else "✗"
            print(f"  {status_char} {name}")
    sys.exit(0 if failed == 0 else 1)


@app.command()
def serve(
    case_dir: str,
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    case = _open_case_or_die(case_dir)
    _seed_api_snapshots_if_possible(case)
    _status(f"Serving case UI on http://{host}:{port}")
    app_instance = create_app(case)
    uvicorn.run(app_instance, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
