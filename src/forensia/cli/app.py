"""Typer command declarations for the forensia CLI.

Thin display adapter: commands map CLI options onto the display-agnostic
pipeline entry (``forensia.pipeline.run_investigation``) and render plain text
results. Argument validation lives in the kernel entry as ``UsageError`` and
is translated here into ``typer.BadParameter``.
"""

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path

import typer
from rich import print
from rich.markup import escape

from forensia.ai.case_profile import profile_advisor
from forensia.ai.investigation.investigator import investigate as investigate_loop
from forensia.ai.llm.llm_client import LLMServerUnavailableError
from forensia.cli.doctor import run_doctor
from forensia.cli.support import _open_case_or_die, _resolve_llm_or_die, _status
from forensia.config import get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.db.database import CaseDB
from forensia.evidence.ingest import ingest_all
from forensia.pipeline import (
    UsageError,
    resolve_knowledge_dir,
    resolve_template_dir,
    run_investigation,
)
from forensia.report.render.html import render_html_report
from forensia.report.render.writer import render_written_report
from forensia.report.sections.report_input import (
    ReportSpecError,
    ensure_report_output_paths,
)
from forensia.report.template_export import export_packaged_report_templates

logger = logging.getLogger(__name__)

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
    report_spec: str | None = typer.Option(
        None,
        "--report-spec",
        help=(
            "Explicit REPORT.md path (report input specification). Default: "
            "the case root REPORT.md when present, else the packaged templates"
        ),
    ),
    template_dir: str | None = typer.Option(None, "--template-dir"),
    knowledge: str | None = typer.Option(
        None,
        "--knowledge",
        help="Path to a directory of knowledge files (*.md with YAML frontmatter)",
    ),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    report_max_queries_per_section: int = typer.Option(
        0,
        "--report-max-queries-per-section",
        help="Max iterative agent queries per report block. 0 = use FORENSIA_REPORT_MAX_QUERIES_PER_SECTION env (default 3)",
    ),
) -> None:
    try:
        case = _open_case_or_die(case_dir)
        knowledge_path = resolve_knowledge_dir(knowledge)
        if report_spec and template_dir:
            raise UsageError(
                "--report-spec and --template-dir are alternative report inputs; pass one"
            )
        if not write and (report_spec or template_dir):
            raise UsageError("--report-spec and --template-dir require --write")
    except UsageError as exc:
        raise typer.BadParameter(str(exc)) from None
    from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs

    # CLI commands can be invoked repeatedly in one Python process (embedding,
    # tests). Always replace the process-local index so an omitted option cannot
    # inherit knowledge from a previous invocation.
    set_knowledge_docs([])
    if knowledge_path:
        docs = scan_knowledge_dir(knowledge_path)
        set_knowledge_docs(docs)
        _status(f"knowledge: {len(docs)} files indexed from {knowledge_path}")
        if not docs:
            _status("WARNING: knowledge directory contains no valid knowledge files")
    try:
        with CaseDB(case) as db:
            # Fail before any write when an output target would replace the
            # report input (explicit path, case-insensitive compare included).
            markdown_path = case.reports_dir / "report.md"
            html_path = Path(output) if output else case.reports_dir / "report.html"
            ensure_report_output_paths(
                case, (markdown_path, html_path), report_spec=report_spec
            )
            if write:
                llm_base_url, model = _resolve_llm_or_die(llm_base_url, model)
                template_root = resolve_template_dir(case, template_dir)
                max_queries = (
                    report_max_queries_per_section
                    or get_llm_settings()["report_max_queries_per_section"]
                )
                _status(f"Writing report sections (max_queries={max_queries})")
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
                        report_spec=report_spec,
                        report_max_queries_per_section=max_queries,
                    )
                )
            report_md, report_path = render_written_report(case, db)
            path = (
                render_html_report(case, db, output_path=output)
                if output
                else report_path
            )
    except (UsageError, ReportSpecError) as exc:
        raise typer.BadParameter(str(exc)) from None
    print(f"Markdown report written to {report_md}")
    print(f"HTML report written to {path}")


def _print_pre_investigation_hints(case: Case, profile: str, db: CaseDB) -> None:
    """Print profile advice and a conservative timezone hint before investigating."""
    advice = profile_advisor(profile, db)
    if advice:
        # rich's print would swallow [bracketed] pack names as markup tags.
        print(escape(advice))
    if case.source_timezone == "UTC":
        # R2-14: surface a conservative timezone hint when no explicit
        # timezone was provided; rendering stays UTC-only until the
        # analyst confirms via --timezone.
        try:
            from forensia.evidence.timezone import infer_timezone

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
            logger.debug("Failed to infer timezone hint from evidence", exc_info=True)


def _missing_case_message(case_dir: str) -> str:
    target = Path(case_dir).resolve()
    return (
        "case_dir must point to an initialized case directory.\n"
        f"missing: {target / 'manifest.yaml'}\n"
        f"initialize with: forensia investigate {target} <input_dir>"
    )


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
    report_spec: str | None = typer.Option(
        None,
        "--report-spec",
        help=(
            "Explicit REPORT.md path (report input specification). Default: "
            "the case root REPORT.md when present, else the packaged templates"
        ),
    ),
    knowledge: str | None = typer.Option(
        None,
        "--knowledge",
        help="Path to a directory of knowledge files (*.md with YAML frontmatter)",
    ),
    forensia_md: str | None = typer.Option(
        None,
        "--forensia-md",
        help=(
            "Explicit path to one investigation-policy file. Default: case root "
            "FORENSIA.md. Giving the path explicitly marks it as an explicit "
            "reload, which adopts the current content at this session start."
        ),
    ),
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
        help="Max iterative agent queries per report block. 0 = use FORENSIA_REPORT_MAX_QUERIES_PER_SECTION env (default 3)",
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
    """Run the full investigation pipeline through the kernel entry."""
    llm_base_url, model = resolve_llm_config(llm_base_url, model)
    try:
        report_path = run_investigation(
            case_dir,
            input_dir=input_dir,
            profile=profile,
            llm_base_url=llm_base_url,
            model=model,
            template_dir=template_dir,
            report_spec=report_spec,
            knowledge_dir=knowledge,
            forensia_md=forensia_md,
            rerun=rerun,
            report_only=report_only,
            max_iter=max_iter,
            max_queries_per_hypothesis=max_queries_per_hypothesis,
            no_progress_limit=no_progress_limit,
            report_every_n_cycles=report_every_n_cycles,
            report_max_queries_per_section=report_max_queries_per_section,
            max_llm_calls=max_llm_calls,
            auto_rulepacks=auto_rulepacks,
            timezone=timezone,
            status=_status,
            pre_investigation=_print_pre_investigation_hints_with(profile),
        )
    except (UsageError, ReportSpecError) as exc:
        raise typer.BadParameter(str(exc)) from None
    except FileNotFoundError as exc:
        raise typer.BadParameter(_missing_case_message(case_dir)) from exc
    except LLMServerUnavailableError:
        # The pipeline already emitted the abort line through the status seam;
        # only the process exit policy is the adapter's concern here.
        raise typer.Exit(2) from None
    print(f"Investigation complete. Report: {report_path}")


def _print_pre_investigation_hints_with(
    profile: str,
) -> Callable[[Case, CaseDB], None]:
    def render(case: Case, db: CaseDB) -> None:
        _print_pre_investigation_hints(case, profile, db)

    return render


if __name__ == "__main__":
    app()
