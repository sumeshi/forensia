"""Typer command declarations for the forensia CLI."""

import asyncio
from collections.abc import Callable
from pathlib import Path

import typer
import uvicorn
from rich import print

from forensia.ai.case_profile import profile_advisor
from forensia.ai.investigator import investigate as investigate_loop
from forensia.api.cache import (
    clear_api_snapshots,
    write_api_snapshots,
)
from forensia.api.progress import clear_progress_events
from forensia.cli.doctor import run_doctor
from forensia.cli.stages import (
    _make_initial_progress_state,
    _run_analyze_stage,
    _run_ingest_stage,
    _run_investigate_stage,
    _run_normalize_stage,
    _run_report_stage,
)
from forensia.cli.support import (
    _open_case_or_die,
    _progress_pusher,
    _reset_case_tables,
    _resolve_llm_or_die,
    _resolve_profile_path,
    _resolve_template_dir,
    _resolve_timezone,
    _seed_api_snapshots_if_possible,
    _status,
)
from forensia.config import get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all
from forensia.report.render.html import render_html_report
from forensia.report.render.writer import render_written_report
from forensia.report.template_export import (
    export_packaged_report_templates,
    seed_case_report_templates,
)
from forensia.web.app import create_app

app = typer.Typer(help="forensia incident response tool")


@app.command(hidden=True)
def doctor() -> None:
    """Run repository and installation health checks."""
    run_doctor()


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


def _open_or_init_case(case_dir: str, input_dir: str | None, timezone: str) -> Case:
    """Open an existing case or initialize a new one (requires input_dir)."""
    case_path = Path(case_dir)
    if (case_path / "manifest.yaml").exists():
        return _open_case_or_die(case_dir, timezone=timezone)
    if input_dir is None:
        raise typer.BadParameter("New case requires an input_dir argument")
    tz_val = _resolve_timezone(timezone, None)
    case = Case.init(case_dir, source_timezone=tz_val)
    seed_case_report_templates(case)
    clear_api_snapshots(case)
    _status(f"Initialized case at {case.path}")
    return case


def _rerun_reset(case: Case, case_dir: str, timezone: str) -> Case:
    """Reset case tables and runtime outputs for --rerun, preserving raw/ and memory."""
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
    seed_case_report_templates(case)
    clear_api_snapshots(case)
    _status(f"Re-initialized case at {case.path}")
    return case


def _run_evidence_stages(
    case: Case,
    db: CaseDB,
    tasks: CaseTasks,
    profile: str,
    input_dir: str | None,
    rerun: bool,
    push_progress: Callable[..., None],
) -> None:
    """(Re)build evidence tables: ingest from input_dir, or re-normalize from raw/.

    - `input_dir` given: full ingest from input_dir, then normalize + analyze
    - `rerun` with raw/ already populated: skip ingest, just re-run normalize + analyze
    """
    raw_has_files = any(case.raw_dir.iterdir()) if case.raw_dir.exists() else False
    needs_normalize_from_raw = rerun and input_dir is None and raw_has_files

    if input_dir is not None:
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
    elif needs_normalize_from_raw:
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


def _print_pre_investigation_hints(case: Case, profile: str, db: CaseDB) -> None:
    """Print profile advice and a conservative timezone hint before investigating."""
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
    case = _open_or_init_case(case_dir, input_dir, timezone)
    if rerun:
        case = _rerun_reset(case, case_dir, timezone)

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

        if not report_only:
            _run_evidence_stages(
                case, db, tasks, profile, input_dir, rerun, push_progress
            )
            _print_pre_investigation_hints(case, profile, db)
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
