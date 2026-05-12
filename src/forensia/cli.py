from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import typer
from rich import print
import uvicorn

from forensia.api.cache import clear_api_snapshots, write_api_snapshots
from forensia.api.progress import clear_progress_events, record_progress_event
from forensia.ai.investigator import investigate as investigate_loop
from forensia.ai.reviewer import review_finding
from forensia.config import get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all
from forensia.normalize.evtx import normalize_evtx
from forensia.normalize.mft import normalize_mft
from forensia.report.html import render_html_report
from forensia.report.writer import render_written_report
from forensia.rules.engine import clear_rule_findings, generate_findings, run_rule, save_findings
from forensia.rules.loader import load_rules_from_dir
from forensia.web import create_app

app = typer.Typer(help="forensia incident response tool")


def _fetch_records(db: CaseDB, query: str) -> list[dict]:
    result = db.execute(query)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _status(message: str) -> None:
    print(f"[bold cyan]==>[/bold cyan] {message}")


def _count_records(db: CaseDB) -> dict[str, int]:
    return {
        "evtx_rows": int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]),
        "mft_entries": int(db.execute("SELECT COUNT(*) FROM mft_entries").fetchone()[0]),
        "findings": int(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]),
        "sessions": int(db.execute("SELECT COUNT(*) FROM investigation_sessions").fetchone()[0]),
        "hypotheses": int(db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]),
        "report_sections": int(db.execute("SELECT COUNT(*) FROM report_sections").fetchone()[0]),
        "progress_events": int(db.execute("SELECT COUNT(*) FROM progress_events").fetchone()[0]),
    }


def _has_investigation_artifacts(db: CaseDB) -> bool:
    return bool(
        int(db.execute("SELECT COUNT(*) FROM investigation_sessions").fetchone()[0])
        or int(db.execute("SELECT COUNT(*) FROM ai_reviews").fetchone()[0])
        or int(db.execute("SELECT COUNT(*) FROM investigation_steps").fetchone()[0])
    )


def _reset_case_tables(db: CaseDB) -> None:
    for table in (
        "evtx_events",
        "mft_entries",
        "mft_timeline",
        "findings",
        "ai_reviews",
        "investigation_sessions",
        "investigation_steps",
        "hypotheses",
        "report_sections",
        "progress_events",
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
        return Path(template_dir).resolve()
    if case.report_template_dir.exists():
        return case.report_template_dir
    return (Path(__file__).parent / "report_template").resolve()


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
        write_api_snapshots(db.case, db)

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


@app.command()
def ingest(
    case_dir: str,
    input_dir: str,
    force: bool = typer.Option(False, "--force", help="Re-ingest even if already done"),
) -> None:
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    if not force and tasks.is_done("ingest") and any(case.raw_dir.glob("*.jsonl")):
        print(f"[dim]ingest already done — skipping. Use --force to re-run.[/dim]")
        return
    _status(f"Scanning input directory: {input_dir}")
    counts = ingest_all(case, input_dir, progress_callback=_status)
    tasks.mark_done("ingest", f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}")
    print(f"Ingested EVTX files: {counts['evtx_files']}, MFT files: {counts['mft_files']}")


@app.command()
def normalize(
    case_dir: str,
    force: bool = typer.Option(False, "--force", help="Re-normalize even if already done"),
) -> None:
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    with CaseDB(case) as db:
        already = int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0])
        if not force and tasks.is_done("normalize") and already > 0:
            print(f"[dim]normalize already done ({already} rows) — skipping. Use --force to re-run.[/dim]")
            return
        _status(f"Normalizing raw data for case: {case.path}")
        evtx_count = normalize_evtx(case, db)
        mft_entries, mft_timeline = normalize_mft(case, db)
        write_api_snapshots(case, db)
    tasks.mark_done("normalize", f"evtx_rows={evtx_count}, mft_entries={mft_entries}")
    print(
        f"Normalized EVTX rows: {evtx_count}, MFT entries: {mft_entries}, MFT timeline rows: {mft_timeline}"
    )


@app.command()
def analyze(
    case_dir: str,
    profile: str = typer.Option("windows-basic", "--profile"),
    force: bool = typer.Option(False, "--force", help="Re-run rules even if already done"),
) -> None:
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    if not force and tasks.is_done("analyze"):
        with CaseDB(case) as db:
            n = int(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
        print(f"[dim]analyze already done ({n} findings) — skipping. Use --force to re-run.[/dim]")
        return
    profile_path = Path(__file__).parent / "profiles" / f"{profile}.yaml"
    rules_dir = Path(__file__).parent / "rulepacks"
    rules = load_rules_from_dir(rules_dir, profile_path)
    _status(f"Running rules from profile: {profile} ({len(rules)} rules)")
    with CaseDB(case) as db:
        total = 0
        for rule in rules:
            _status(f"Executing rule: {rule.id}")
            clear_rule_findings(case, db, rule.id)
            rows = run_rule(db, rule)
            findings = generate_findings(rule, rows)
            save_findings(case, db, findings)
            total += len(findings)
        _prune_orphan_reviews(db)
        write_api_snapshots(case, db)
    tasks.mark_done("analyze", f"profile={profile}, findings={total}")
    print(f"Generated findings: {total}")


@app.command()
def review(
    case_dir: str,
    lmstudio: str | None = typer.Option(None, "--lmstudio"),
    model: str | None = typer.Option(None, "--model"),
) -> None:
    lmstudio, model = resolve_llm_config(lmstudio, model)
    if not lmstudio or not model:
        raise typer.BadParameter("LLM_BASE_URL と LLM_MODEL を .env または CLI で指定してください")
    case = _open_case_or_die(case_dir)
    _status(f"Reviewing findings with model={model} base_url={lmstudio}")
    with CaseDB(case) as db:
        findings = _fetch_records(db, "SELECT * FROM findings ORDER BY created_at")
        for finding in findings:
            _status(f"Reviewing finding: {finding['finding_id']}")
            review_finding(case, db, finding, base_url=lmstudio, model=model, status_callback=_status)
        write_api_snapshots(case, db)
    print(f"Reviewed findings: {len(findings)}")


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
    lmstudio: str | None = typer.Option(None, "--lmstudio"),
    model: str | None = typer.Option(None, "--model"),
    report_parallelism: int = typer.Option(
        0,
        "--report-parallelism",
        help="Concurrent LLM workers for section fill. 0 = use LLM_REPORT_PARALLELISM env (default 1)",
    ),
) -> None:
    lmstudio, model = resolve_llm_config(lmstudio, model)
    if not lmstudio or not model:
        raise typer.BadParameter("LLM_BASE_URL と LLM_MODEL を .env または CLI で指定してください")
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
    template_root = _resolve_template_dir(case, template_dir)
    if not template_root.exists():
        raise typer.BadParameter(f"template_dir not found: {template_root}")

    parallelism = report_parallelism or get_llm_settings()["report_parallelism"]
    _status(f"Writing report from templates: {template_root} (parallelism={parallelism})")
    with CaseDB(case) as db:
        clear_api_snapshots(case)
        investigate_loop(
            case=case,
            db=db,
            base_url=lmstudio,
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
    lmstudio: str | None = typer.Option(None, "--lmstudio"),
    model: str | None = typer.Option(None, "--model"),
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
    reinvestigate: bool = typer.Option(
        False,
        "--reinvestigate",
        help="Force LLM investigation even when previous investigation artifacts exist",
    ),
) -> None:
    lmstudio, model = resolve_llm_config(lmstudio, model)
    case = Case.init(out)
    tasks = CaseTasks.for_case(case)

    if init:
        with CaseDB(case) as existing_db:
            _reset_case_tables(existing_db)
        case.clear_runtime_outputs(preserve_memory=True, preserve_ai_logs=True, drop_database=False)
        case = Case.init(out)
        tasks = CaseTasks.for_case(case)

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
                "llm_base_url": lmstudio,
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

        if not init and tasks.is_done("ingest") and any(case.raw_dir.glob("*.jsonl")):
            _status("Stage 1/4: ingest — already done, skipping")
            push_progress("[ingest] skipped (already done)", stage="ingest", status="running")
        else:
            _status(f"Stage 1/4: ingest from {input_dir}")
            push_progress(f"[ingest] scanning {input_dir}", stage="ingest", status="running")
            counts = ingest_all(case, input_dir, progress_callback=stage_status)
            note = f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}"
            tasks.mark_done("ingest", note)
            _status(f"Ingest complete: {note}")
            push_progress(f"[ingest] {note}", stage="ingest", status="running", summary=note)

        # ── Stage 2: Normalize ───────────────────────────────────────────────
        existing_rows = int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0])
        if not init and tasks.is_done("normalize") and existing_rows > 0:
            _status(f"Stage 2/4: normalize — already done ({existing_rows} rows), skipping")
            push_progress(
                f"[normalize] skipped ({existing_rows} rows already in DB)",
                stage="normalize",
                status="running",
            )
        else:
            _status("Stage 2/4: normalize into DuckDB")
            push_progress("[normalize] starting", stage="normalize", status="running")
            evtx_count = normalize_evtx(case, db)
            mft_entries, mft_timeline = normalize_mft(case, db)
            note = f"evtx_rows={evtx_count}, mft_entries={mft_entries}"
            tasks.mark_done("normalize", note)
            _status(f"Normalize complete: {note}, mft_timeline_rows={mft_timeline}")
            push_progress(f"[normalize] {note}", stage="normalize", status="running", summary=note)

        # ── Stage 3: Analyze ─────────────────────────────────────────────────
        if not init and tasks.is_done("analyze"):
            existing_findings = int(db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
            _status(f"Stage 3/4: analyze — already done ({existing_findings} findings), skipping")
            push_progress(
                f"[analyze] skipped ({existing_findings} findings already exist)",
                stage="analyze",
                status="running",
            )
        else:
            profile_path = Path(__file__).parent / "profiles" / f"{profile}.yaml"
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
                f"[analyze] done — findings={total_findings}",
                stage="analyze",
                status="running",
                summary=f"findings={total_findings}",
            )

        # ── Stage 4: Investigate ─────────────────────────────────────────────
        if lmstudio and model:
            if reinvestigate or not _has_investigation_artifacts(db):
                _status(f"Stage 4/4: investigate with model={model}")
                push_progress(f"[investigate] starting — model={model}", stage="investigate", status="running")
                result = investigate_loop(
                    case=case,
                    db=db,
                    base_url=lmstudio,
                    model=model,
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
                    f"[investigate] done — session={result['session_id']} status={result['status']}",
                    stage="investigate",
                    status=result["status"],
                    iteration=result["iteration"],
                    summary=result["summary"],
                    hypotheses=result.get("hypotheses", []),
                    report_sections=result.get("report_sections", {}),
                )
            else:
                _status("Stage 4/4: investigate — previous session exists, skipping. Use --reinvestigate to add a new session.")
                push_progress(
                    "[investigate] skipped — previous session exists (use --reinvestigate)",
                    stage="investigate",
                    status="running",
                )
        else:
            _status("Stage 4/4: LLM not configured — skipping investigate (set LLM_BASE_URL and LLM_MODEL in .env)")
            push_progress("[investigate] skipped — LLM not configured", stage="investigate", status="running")

        # ── Report ───────────────────────────────────────────────────────────
        report_path = render_html_report(case, db)
        render_written_report(case, db)
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
    lmstudio: str | None = typer.Option(None, "--lmstudio"),
    model: str | None = typer.Option(None, "--model"),
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
    lmstudio, model = resolve_llm_config(lmstudio, model)
    if not lmstudio or not model:
        raise typer.BadParameter("LLM_BASE_URL と LLM_MODEL を .env または CLI で指定してください")
    case = _open_case_or_die(case_dir)
    tasks = CaseTasks.for_case(case)
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
                "recent_logs": [f"[investigate] starting — model={model}"],
                "llm_model": model,
                "llm_base_url": lmstudio,
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
            base_url=lmstudio,
            model=model,
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
            f"[investigate] done — session={result['session_id']} status={result['status']}",
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
