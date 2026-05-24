from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import typer
from rich import print
import uvicorn

from forensia.api.cache import clear_api_snapshots, write_api_snapshots, write_progress_snapshot
from forensia.api.progress import clear_progress_events, record_progress_event
from forensia.ai.investigator import investigate as investigate_loop
from forensia.config import get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.ingest import ingest_all
from forensia.normalize import normalize_all
from forensia.report.html import render_html_report
from forensia.report.writer import render_written_report
from forensia.report_templates import export_packaged_report_templates, has_report_templates
from forensia.rules.engine import clear_rule_findings, generate_findings, run_rule, save_findings
from forensia.rules.loader import load_rules_from_dir
from forensia.web import create_app

app = typer.Typer(help="forensia incident response tool")
PROFILE_ROOT = Path(__file__).parent / "profiles"


def _status(message: str) -> None:
    print(f"[bold cyan]==>[/bold cyan] {message}")


def _count_records(db: CaseDB) -> dict[str, int]:
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
    for table in (
        "evtx_events",
        "mft_entries",
        "mft_timeline",
        "findings",
        "claims",
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
    db.execute(
        """
        DELETE FROM ai_reviews
        WHERE finding_id NOT IN (SELECT finding_id FROM findings)
          AND finding_id NOT LIKE 'hypothesis:%'
          AND finding_id NOT LIKE 'query:%'
          AND finding_id NOT LIKE 'investigate:%'
        """
    )


def _resolve_template_dir(case: Case, template_dir: str | None) -> Path:
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
    if case.report_template_dir.exists() and has_report_templates(case.report_template_dir):
        return case.report_template_dir
    raise typer.BadParameter("no report templates are available")


def _available_profiles() -> list[str]:
    return sorted(path.stem for path in PROFILE_ROOT.glob("*.yaml"))


def _resolve_profile_path(profile: str) -> Path:
    profile_name = str(profile).strip()
    path = PROFILE_ROOT / f"{profile_name}.yaml"
    if path.exists():
        return path
    available = ", ".join(_available_profiles()) or "none"
    raise typer.BadParameter(f"unknown profile: {profile_name}. Available profiles: {available}")


def _resolve_llm_or_die(base_url: str | None, model: str | None) -> tuple[str, str]:
    resolved_base_url, resolved_model = resolve_llm_config(base_url, model)
    if not resolved_base_url or not resolved_model:
        raise typer.BadParameter("Set LLM_BASE_URL and LLM_MODEL via .env file or CLI flags.")
    return resolved_base_url, resolved_model


def _open_case_or_die(case_dir: str) -> Case:
    try:
        return Case.open(case_dir)
    except FileNotFoundError as exc:
        target = Path(case_dir).resolve()
        raise typer.BadParameter(
            "case_dir must point to an initialized case directory.\n"
            f"missing: {target / 'manifest.yaml'}\n"
            f"initialize first with: forensia init {target}"
        ) from exc


def _progress_pusher(db: CaseDB, initial_state: dict) -> Callable[..., None]:
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

    return push


def _seed_api_snapshots_if_possible(case: Case) -> None:
    try:
        with CaseDB(case) as db:
            write_api_snapshots(case, db)
    except Exception as exc:
        _status(f"serve snapshot refresh skipped: {exc}")


@app.command()
def init(case_dir: str) -> None:
    case = Case.init(case_dir)
    clear_api_snapshots(case)
    print(f"Initialized case at {case.path}")


@app.command("templates-export")
def templates_export(
    output_dir: str,
    force: bool = typer.Option(False, "--force", help="Overwrite existing packaged template files in the target directory"),
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
            f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}"
        ),
    )
    print(
        "Add complete: "
        f"added={counts['new_files']}, skipped={counts['skipped_files']}, "
        f"evtx={counts['evtx_files']}, mft={counts['mft_files']}"
    )





@app.command()
def report(case_dir: str, output: str | None = typer.Option(None, "--output")) -> None:
    case = _open_case_or_die(case_dir)
    with CaseDB(case) as db:
        report_md, report_html = render_written_report(case, db)
        path = render_html_report(case, db, output_path=output) if output else report_html
        write_api_snapshots(case, db)
    print(f"Markdown report written to {report_md}")
    print(f"HTML report written to {path}")


@app.command("report-write")
def report_write(
    case_dir: str,
    template_dir: str | None = typer.Option(None, "--template-dir"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    report_parallelism: int = typer.Option(
        0,
        "--report-parallelism",
        help="Concurrent LLM workers for section fill. 0 = use LLM_REPORT_PARALLELISM env (default 1)",
    ),
) -> None:
    llm_base_url, model = _resolve_llm_or_die(llm_base_url, model)
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    template_root = _resolve_template_dir(case, template_dir)
    parallelism = report_parallelism or get_llm_settings()["report_parallelism"]
    _status(f"Writing report from templates: {template_root} (parallelism={parallelism})")
    with CaseDB(case) as db:
        clear_api_snapshots(case)
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
            report_parallelism=parallelism,
        )
        report_md, report_html = render_written_report(case, db)
        write_api_snapshots(case, db)
        tasks.mark_done("report", str(report_html))
    print(f"Markdown report written to {report_md}")
    print(f"HTML report written to {report_html}")


@app.command()
def run(
    input_dir: str,
    out: str = typer.Option(..., "--out"),
    profile: str = typer.Option("windows-basic", "--profile"),
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    template_dir: str | None = typer.Option(None, "--template-dir"),
    max_iter: int = typer.Option(20, "--max-iter"),
    max_queries_per_hypothesis: int = typer.Option(5, "--max-queries-per-hypothesis"),
    no_progress_limit: int = typer.Option(3, "--no-progress-limit"),
    report_every_n_cycles: int = typer.Option(1, "--report-every-n-cycles"),
    report_parallelism: int = typer.Option(
        0,
        "--report-parallelism",
        help="Concurrent LLM workers for section fill. 0 = use LLM_REPORT_PARALLELISM env (default 1)",
    ),
    init: bool = typer.Option(False, "--init", help="Clear raw/db/findings/reports before rerun"),
) -> None:
    llm_base_url, model = resolve_llm_config(llm_base_url, model)
    case = Case.init(out)
    tasks = CaseTasks.for_case(case)
    template_root = _resolve_template_dir(case, template_dir) if (llm_base_url and model) else None
    profile_path = _resolve_profile_path(profile)

    if init:
        with CaseDB(case) as existing_db:
            _reset_case_tables(existing_db)
        case.clear_runtime_outputs(preserve_memory=True, preserve_ai_logs=True, drop_database=False)
        case = Case.init(out)
        tasks = CaseTasks.for_case(case)
        template_root = _resolve_template_dir(case, template_dir) if (llm_base_url and model) else None

    with CaseDB(case) as db:
        clear_progress_events(db)
        clear_api_snapshots(case)
        push_progress = _progress_pusher(
            db,
            {
                "stage": "init",
                "status": "running",
                "iteration": 0,
                "current_query": None,
                "summary": "Case initialized",
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
            },
        )

        def stage_status(message: str) -> None:
            _status(message)
            push_progress(message, stage="ingest", status="running", summary=message)

        push_progress("Case ready", stage="init", summary=f"Case: {case.path}")

        _status(f"Stage 1/4: ingest from {input_dir}")
        push_progress(f"[ingest] scanning {input_dir}", stage="ingest", status="running")
        counts = ingest_all(case, input_dir, db=db, progress_callback=stage_status)
        note = (
            f"new_files={counts['new_files']}, skipped_files={counts['skipped_files']}, "
            f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}"
        )
        tasks.mark_done("ingest", note)
        _status(f"Ingest complete: {note}")
        push_progress(f"[ingest] {note}", stage="ingest", status="running", summary=note)

        # Stage 2: Normalize
        existing_rows = int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0])
        normalized_this_run = True
        if not init and counts["new_files"] == 0 and tasks.is_done("normalize") and existing_rows > 0:
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
            evtx_count = normalized["evtx_rows"]
            mft_entries = normalized["mft_entries"]
            mft_timeline = normalized["mft_timeline_rows"]
            note = f"evtx_rows={evtx_count}, mft_entries={mft_entries}"
            tasks.mark_done("normalize", note)
            _status(f"Normalize complete: {note}, mft_timeline_rows={mft_timeline}")
            push_progress(f"[normalize] {note}", stage="normalize", status="running", summary=note)

        # Stage 3: Analyze
        if not init and not normalized_this_run and tasks.is_done("analyze"):
            existing_findings = int(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
            _status(f"Stage 3/4: analyze - already done ({existing_findings} findings), skipping")
            push_progress(
                f"[analyze] skipped ({existing_findings} findings already exist)",
                stage="analyze",
                status="running",
            )
        else:
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

        # Stage 4: Investigate
        if llm_base_url and model:
            _status(f"Stage 4/4: investigate with model={model}")
            push_progress(f"[investigate] starting - model={model}", stage="investigate", status="running")
            result = investigate_loop(
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
                report_parallelism=report_parallelism or get_llm_settings()["report_parallelism"],
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
            tasks.mark_done(
                "investigate",
                f"session={result['session_id']}, status={result['status']}, iterations={result['iteration']}",
            )
            _status(f"Investigation complete: session={result['session_id']} status={result['status']}")
            push_progress(
                f"[investigate] done - session={result['session_id']} status={result['status']}",
                stage="investigate",
                status=result["status"],
                iteration=result["iteration"],
                summary=result["summary"],
                hypotheses=result.get("hypotheses", []),
                report_sections=result.get("report_sections", {}),
            )
        else:
            _status("Stage 4/4: LLM not configured - skipping investigate (set LLM_BASE_URL and LLM_MODEL in .env)")
            push_progress("[investigate] skipped - LLM not configured", stage="investigate", status="running")

        # Report
        report_md, report_path = render_written_report(case, db)
        write_api_snapshots(case, db)
        tasks.mark_done("report", str(report_path))
        push_progress(
            f"[report] written: {report_path}",
            stage="completed",
            status="completed",
            summary=f"Report: {report_path}",
        )

    print(f"Run complete. Report: {report_path}")


@app.command()
def investigate(
    case_dir: str,
    llm_base_url: str | None = typer.Option(None, "--llm-base-url"),
    model: str | None = typer.Option(None, "--model"),
    template_dir: str | None = typer.Option(None, "--template-dir"),
    max_iter: int = typer.Option(20, "--max-iter"),
    max_queries_per_hypothesis: int = typer.Option(5, "--max-queries-per-hypothesis"),
    no_progress_limit: int = typer.Option(3, "--no-progress-limit"),
    report_every_n_cycles: int = typer.Option(1, "--report-every-n-cycles"),
    report_parallelism: int = typer.Option(
        0,
        "--report-parallelism",
        help="Concurrent LLM workers for section fill. 0 = use LLM_REPORT_PARALLELISM env (default 1)",
    ),
    profile: str = typer.Option("windows-basic", "--profile"),
    report_only: bool = typer.Option(False, "--report-only"),
) -> None:
    llm_base_url, model = _resolve_llm_or_die(llm_base_url, model)
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    template_root = _resolve_template_dir(case, template_dir)
    _resolve_profile_path(profile)
    _status(f"Starting investigate for case={case.path.name} model={model}")
    with CaseDB(case) as db:
        clear_progress_events(db)
        clear_api_snapshots(case)
        push_progress = _progress_pusher(
            db,
            {
                "stage": "investigate",
                "status": "running",
                "iteration": 0,
                "current_query": None,
                "summary": f"Starting investigate for case={case.path.name}",
                "recent_logs": [f"[investigate] starting - model={model}"],
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
            },
        )
        push_progress()
        result = investigate_loop(
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
            report_parallelism=report_parallelism or get_llm_settings()["report_parallelism"],
            report_only=report_only,
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
        tasks.mark_done(
            "investigate",
            f"session={result['session_id']}, status={result['status']}, iterations={result['iteration']}",
        )
        push_progress(
            f"[investigate] done - session={result['session_id']} status={result['status']}",
            stage="completed",
            status=result["status"],
            iteration=result["iteration"],
            summary=result["summary"],
            hypotheses=result.get("hypotheses", []),
            report_sections=result.get("report_sections", {}),
        )
        write_api_snapshots(case, db)
    print(
        f"Investigation session {result['session_id']} finished with status={result['status']} at iteration={result['iteration']}"
    )
    print(result["summary"])


@app.command()
def status(case_dir: str) -> None:
    case = _open_case_or_die(case_dir)
    with CaseDB(case) as db:
        counts = _count_records(db)
        latest_session = db.execute(
            """
            SELECT session_id, status, started_at
            FROM investigation_sessions
            ORDER BY started_at DESC, session_id DESC
            LIMIT 1
            """
        ).fetchone()
        section_statuses = fetch_records(
            db,
            """
            SELECT status, COUNT(*) AS count
            FROM report_sections
            GROUP BY status
            ORDER BY status
            """
        )
        total_gaps = int(
            db.execute(
                """
                SELECT COALESCE(SUM(CASE
                    WHEN json_array_length(CAST(gaps AS JSON)) IS NULL THEN 0
                    ELSE json_array_length(CAST(gaps AS JSON))
                END), 0)
                FROM report_sections
                """
            ).fetchone()[0]
            or 0
        )
    print(f"Case: {case.path}")
    print(f"Counts: {counts}")
    if latest_session:
        print(
            "Latest session: "
            f"id={latest_session[0]} status={latest_session[1]} started_at={latest_session[2]}"
        )
    else:
        print("Latest session: none")
    print(f"Report section statuses: {section_statuses or 'none'}")
    print(f"Total gaps: {total_gaps}")


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
