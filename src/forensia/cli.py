"""Typer CLI commands; helpers live in cli_support and cli_stages.

Kept for backward compatibility: existing code and tests import these
names from forensia.cli.
"""

import asyncio
import subprocess
import sys
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
from forensia.cli_stages import (
    _make_initial_progress_state,
    _run_analyze_stage,
    _run_ingest_stage,
    _run_investigate_stage,
    _run_normalize_stage,
    _run_report_stage,
)
from forensia.cli_support import (
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
from forensia.report.html import render_html_report
from forensia.report.writer import render_written_report
from forensia.report_templates import (
    export_packaged_report_templates,
)
from forensia.web import create_app

app = typer.Typer(help="forensia incident response tool")


def _project_root() -> Path:
    return Path(__file__).parent.parent.parent


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


def _doctor_schema_coverage_check() -> tuple[str, bool]:
    _status("Schema coverage audit...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(_project_root() / "scripts" / "audit_schema_coverage.py"),
                "--strict",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        ok = result.returncode == 0
        if ok:
            print("  ✓ All event IDs and question types covered")
        else:
            print(f"  ✗ Uncovered entries:\n{result.stdout}")
        return "Schema coverage", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Schema coverage", False


def _doctor_playbook_drift_check() -> tuple[str, bool]:
    _status("Playbook MD/YAML drift check...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(_project_root() / "scripts" / "regenerate_playbook.py"),
                "--check",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = result.returncode == 0
        if ok:
            print("  ✓ All playbook files up to date")
        else:
            print(f"  ✗ Drift detected:\n{result.stdout}")
        return "Playbook drift", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Playbook drift", False


def _doctor_import_layer_check() -> tuple[str, bool]:
    _status("Import layer contract (R4)...")
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(_project_root() / "scripts" / "check_imports.py"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ok = result.returncode == 0
        if ok:
            print("  ✓ No forbidden import edges")
        else:
            print(f"  ✗ Layer violations:\n{result.stdout}")
        return "Import layers", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Import layers", False


def _doctor_verdict_taxonomy_check() -> tuple[str, bool]:
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
                                            path, _project_root()
                                        )
                                    )
                                    break
                    except Exception:
                        pass
        enforcement_count = len(enforcement_files)
        ok = enforcement_count >= 4
        print(
            f"  {'✓' if ok else '✗'} {enforcement_count} files use assert_valid_verdict: {enforcement_files}"
        )
        return "Verdict enforcement", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Verdict enforcement", False


def _doctor_report_template_policy_check() -> tuple[str, bool]:
    _status("Report template policy...")
    try:
        from forensia.report.ranking import audit_packaged_report_templates

        problems = audit_packaged_report_templates()
        ok = not problems
        if ok:
            print("  ✓ Packaged templates carry no case-specific ranking policy")
        else:
            print(
                "  ✗ Case-specific policy / malformed frontmatter in packaged "
                "templates:\n" + "\n".join(f"      - {p}" for p in problems)
            )
        return "Report template policy", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Report template policy", False


def _doctor_report_validation_self_check() -> tuple[str, bool]:
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
        return "Report output validation", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Report output validation", False


def _doctor_static_lint_check() -> tuple[str, bool]:
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
            print("  ✓ ruff not installed — skipping (dev dependency)")
            return "Static lint", True
        else:
            ok = result.returncode == 0
            if ok:
                print("  ✓ ruff check clean")
            else:
                print(f"  ✗ Lint findings:\n{result.stdout[-500:]}")
            return "Static lint", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Static lint", False


def _doctor_test_suite_check() -> tuple[str, bool]:
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
        if ok:
            print(f"  ✓ {last_line}")
        else:
            print(f"  ✗ Failures:\n{result.stdout[-500:]}")
        return "Test suite", ok
    except Exception as exc:
        print(f"  ✗ Error: {exc}")
        return "Test suite", False


def _finish_doctor_checks(checks: list[tuple[str, bool]]) -> None:
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


@app.command(hidden=True)
def doctor() -> None:
    """Run all health checks: schema coverage, playbook drift, verdict taxonomy."""
    checks = [
        _doctor_schema_coverage_check(),
        _doctor_playbook_drift_check(),
        _doctor_import_layer_check(),
        _doctor_verdict_taxonomy_check(),
        _doctor_report_template_policy_check(),
        _doctor_report_validation_self_check(),
        _doctor_static_lint_check(),
        _doctor_test_suite_check(),
    ]
    _finish_doctor_checks(checks)


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
