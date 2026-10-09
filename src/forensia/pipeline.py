"""Display-agnostic investigation pipeline entry.

One run entry shared by display adapters: the headless CLI today, a TUI later
(GOAL §6.3). It owns the assembly of the existing stages — case open/init,
``--rerun`` reset, knowledge indexing, ingest, normalize, rule analysis,
``investigator.investigate`` (the existing ``investigate_loop``),
and the existing report renderer — and owns no planning, stage state, or
service layer of its own.

Display independence contract:

- importing this module pulls no typer/rich (and no HTTP server/frontend);
- user-facing argument problems raise :class:`UsageError` (a ``ValueError``);
  adapters translate it to their own parameter-error rendering (the CLI maps
  it to ``typer.BadParameter``). All other exceptions propagate unchanged, in
  particular ``LLMServerUnavailableError``;
- terminal display is the injected ``status`` callback (plain message text) —
  the kernel never imports a presentation library;
- structured progress is recorded in the trace DB via the existing
  ``db.progress`` owner (one row per emit, capped recent view); progress log
  entries are stored once, in structured tag/level/message form, and any
  string rendering is derived at display time; audit receipts
  remain in the trace tables and are never replaced by the display view;
- SIGINT capture and stop application stay where they are today
  (``investigator.investigate`` owns the converter flag), and the session's
  terminal receipt is still persisted before fallible projections by the same
  lifecycle owner.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

from forensia.ai.investigation.case_policy import CasePolicyInput, load_recorded_policy
from forensia.ai.investigation.investigator import investigate as investigate_loop
from forensia.ai.llm.llm_client import LLMServerUnavailableError
from forensia.config import (
    get_llm_settings,
    get_system_prompt_budget_chars,
    resolve_llm_config,
)
from forensia.core.case import Case, resolve_timezone
from forensia.core.log import structure_progress_log
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import clear_progress_events, record_progress_event
from forensia.db.query import fetch_records
from forensia.evidence.ingest import ingest_all
from forensia.evidence.invalidation import (
    find_replaced_source_ids,
    retire_replaced_sources,
)
from forensia.evidence.normalize import normalize_all
from forensia.knowledge.catalog import validate_declarations
from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs
from forensia.knowledge.resources import rulepacks_dir
from forensia.knowledge.rules.engine import (
    clear_rule_findings,
    generate_findings,
    run_rule,
    save_findings,
)
from forensia.knowledge.rules.loader import load_rules_from_dir
from forensia.report.render.writer import render_written_report
from forensia.report.sections.report_input import ensure_report_output_paths
from forensia.report.template_export import (
    has_report_templates,
    seed_case_report_templates,
)

StatusCallback = Callable[[str], None]


_PARSER_REVISION_FILES = (
    "core/evidence.py",
    "core/textutil.py",
    "db/schema.py",
    "evidence/artifacts.py",
    "evidence/normalize.py",
    "evidence/jsonl.py",
    "evidence/evtx.py",
    "evidence/mft.py",
    "evidence/prefetch.py",
    "evidence/registry.py",
    "evidence/timestamp_policy.py",
    "knowledge/rulepacks/_schema/artifact_capabilities.yaml",
)


class UsageError(ValueError):
    """Invalid pipeline user input that a display adapter should surface as a
    parameter error (missing input_dir, unusable
    template/knowledge directory)."""


def _show(status: StatusCallback | None, message: str) -> None:
    if status is not None:
        status(message)


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


def _content_revision(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    package_root = Path(__file__).resolve().parent
    for path in sorted(paths):
        try:
            label = path.resolve().relative_to(package_root).as_posix()
        except ValueError:
            label = path.name
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _parser_revision() -> str:
    root = Path(__file__).parent
    implementation = _content_revision(
        [root / relative for relative in _PARSER_REVISION_FILES]
    )
    parsers = {
        name: version(name)
        for name in ("duckdb", "evtx2es", "mft2es", "prefetch2es", "reg2es")
    }
    return hashlib.sha256(
        json.dumps([implementation, parsers], sort_keys=True).encode()
    ).hexdigest()


def _analysis_revision(case: Case) -> str:
    rules_root = rulepacks_dir()
    rule_files = list(rules_root.rglob("*.yaml"))
    code_root = Path(__file__).parent / "knowledge" / "rules"
    code_files = list(code_root.rglob("*.py"))
    catalog_file = Path(__file__).parent / "knowledge" / "catalog.py"
    revision = _content_revision([*rule_files, *code_files, catalog_file])
    suppression = (
        case.allowlist_path.read_bytes() if case.allowlist_path.exists() else b""
    )
    return hashlib.sha256(
        revision.encode("ascii") + suppression + version("pysigma").encode("ascii")
    ).hexdigest()


def _stage_receipt(db: CaseDB, phase: str) -> tuple[str, str, str] | None:
    row = db.execute(
        "SELECT output_json FROM trace.investigation_steps "
        "WHERE phase = ? ORDER BY created_at DESC LIMIT 1",
        [phase],
    ).fetchone()
    if not row or not row[0]:
        return None
    payload = json.loads(str(row[0]))
    if payload.get("status") != "completed":
        return None
    return (
        str(payload["revision"]),
        str(payload.get("summary") or ""),
        str(payload.get("parser_revision") or ""),
    )


def _record_stage_receipt(
    db: CaseDB,
    phase: str,
    revision: str,
    summary: str,
    *,
    status: str = "completed",
    details: dict[str, Any] | None = None,
) -> None:
    db.execute(
        """INSERT INTO trace.investigation_steps(
            step_id, session_id, hypothesis_id, iteration, phase,
            input_json, output_json, created_at
        ) VALUES (?, NULL, NULL, 0, ?, ?, ?, current_timestamp)""",
        [
            str(uuid.uuid4()),
            phase,
            json.dumps({"revision": revision}),
            json.dumps(
                {
                    "status": status,
                    "revision": revision,
                    "summary": summary,
                    **(details or {}),
                },
                default=str,
            ),
        ],
    )


def _sources_current_revision(db: CaseDB) -> str:
    source_rows = db.execute(
        "SELECT source_id, artifact_family, ingest_status, parser_name, "
        "parser_version, row_count FROM evidence_sources ORDER BY source_id"
    ).fetchall()
    file_rows = db.execute(
        "SELECT sha256, source_kind, size FROM ingested_files ORDER BY sha256"
    ).fetchall()
    digest = hashlib.sha256(_parser_revision().encode("ascii"))
    digest.update(json.dumps([tuple(row) for row in source_rows], default=str).encode())
    digest.update(json.dumps([tuple(row) for row in file_rows], default=str).encode())
    return digest.hexdigest()


def _sources_normalized(db: CaseDB) -> bool:
    row = db.execute(
        "SELECT COUNT(*) FROM ingested_files AS f "
        "LEFT JOIN evidence_sources AS s ON s.source_id = f.sha256 "
        "AND s.artifact_family = f.source_kind "
        "WHERE s.source_id IS NULL OR s.ingest_status NOT IN ('normalized', 'empty') "
        "OR s.ingest_status IS NULL"
    ).fetchone()
    return int(row[0]) == 0


def reset_case_tables(db: CaseDB) -> None:
    """Clear normalized/derived state, retaining source registrations for rebuild."""
    for table in (
        "evtx_events",
        "mft_entries",
        "mft_timeline",
        "prefetch_executions",
        "prefetch_timeline",
        "registry_artifacts",
        "registry_timeline",
        "case_timeline",
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
        "llm_provider_attempts",
        "llm_logical_calls",
        "llm_deterministic_ops",
        "hypotheses",
        "report_sections",
        "progress_events",
        "retrieval_events",
        "evidence_coverage",
        "investigation_state",
        "report_gaps",
        "investigation_tasks",
        "hypothesis_relations",
        "hypothesis_evidence",
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


def progress_pusher(db: CaseDB, initial_state: dict[str, Any]) -> Callable[..., None]:
    """Return a closure that records progress events in the trace DB.

    Log entries are stored once, in structured ``tag``/``level``/``message``
    form (``recent_log_entries``); the string form is derived from the entry
    at render time. ``level`` is the producer's explicit decision
    (unspecified messages stay neutral ``info``), never word-inferred.
    """
    state = dict(initial_state)

    def push(message: str | None = None, **updates: Any) -> None:
        explicit_log_level = updates.pop("log_level", None)
        if message:
            entry = structure_progress_log(message, level=explicit_log_level)
            entries = [*state.get("recent_log_entries", []), entry]
            state["recent_log_entries"] = entries[-20:]
        state.update(updates)
        payload = {**state, "counts": _count_records(db)}
        record_progress_event(db, payload)

    return push


def resolve_template_dir(case: Case, template_dir: str | Path | None) -> Path:
    """Resolve and validate a report template directory, falling back to the case's bundled templates."""
    if template_dir:
        path = Path(template_dir).resolve()
        if not path.exists():
            raise UsageError(f"template_dir not found: {path}")
        if not has_report_templates(path):
            raise UsageError(
                f"template_dir must contain at least one template matching [0-9]*_*.md: {path}"
            )
        return path
    seed_case_report_templates(case)
    if case.report_template_dir.exists() and has_report_templates(
        case.report_template_dir
    ):
        return case.report_template_dir
    raise UsageError("no report templates are available")


def resolve_knowledge_dir(knowledge_dir: str | Path | None) -> Path | None:
    """Resolve and validate a knowledge directory, returning None if not specified."""
    if not knowledge_dir:
        return None
    path = Path(knowledge_dir).resolve()
    if not path.exists():
        raise UsageError(f"knowledge directory not found: {path}")
    if not path.is_dir():
        raise UsageError(f"knowledge path is not a directory: {path}")
    return path


# Investigation policy must coexist with the playbook inside the fixed system
# budget, so the adopt-time cap is half of it: a valid FORENSIA.md is either
# adopted whole or the run refuses with the reason — constraints are never
# silently truncated.
POLICY_BUDGET_SHARE = 2


def resolve_forensia_policy_input(
    case: Case,
    forensia_md: str | Path | None,
    *,
    recorded_policy_exists: bool = False,
) -> CasePolicyInput | None:
    """Resolve the one designated investigation-policy input (V2-05).

    An explicit ``--forensia-md`` path must exist and is the designated
    reload. Without it, only ``case_root/FORENSIA.md`` is adopted — same-name
    files in parent directories, ``input_dir`` or raw evidence are never
    searched. An oversized file refuses the run with the reason instead of
    silently dropping constraints.
    """
    if forensia_md:
        path = Path(forensia_md).resolve()
        if not path.exists() or not path.is_file():
            raise UsageError(f"forensia_md policy file not found: {path}")
        source = "explicit_path"
    else:
        path = (case.path / "FORENSIA.md").resolve()
        if not path.exists() or not path.is_file():
            return None
        source = "case_root"
    body = path.read_text(encoding="utf-8").strip()
    if not body:
        return None
    budget_chars = get_system_prompt_budget_chars() // POLICY_BUDGET_SHARE
    # An edited case-root file is not adopted on resume without an explicit
    # reload. Its new size cannot prevent the recorded, bounded revision from
    # running; explicit reload and first adoption still fail before any work.
    if len(body) > budget_chars and (
        source == "explicit_path" or not recorded_policy_exists
    ):
        raise UsageError(
            f"FORENSIA.md investigation policy is {len(body)} chars; the "
            f"system-prompt budget allows {budget_chars} chars "
            "(FORENSIA_SYSTEM_PROMPT_BUDGET_CHARS half-weight). Shorten the "
            "policy so the full instruction fits; constraints are not "
            "silently truncated."
        )
    return CasePolicyInput(body=body, source=source, source_path=str(path))


def _make_initial_progress_state(
    model: str | None,
    llm_base_url: str | None,
    stage: str = "init",
    summary: str = "Case initialized",
) -> dict[str, Any]:
    return progress_event(
        stage,
        "running",
        iteration=0,
        summary=summary,
        current_query=None,
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


def _open_or_init_case(
    case_dir: str | Path,
    input_dir: str | None,
    timezone: str,
    status: StatusCallback | None,
) -> Case:
    """Open an existing case or initialize a new one (requires input_dir)."""
    case_path = Path(case_dir)
    if (case_path / "manifest.yaml").exists():
        case = Case.open(case_dir)
        case.source_timezone = resolve_timezone(timezone, case)
        return case
    if input_dir is None:
        raise UsageError("New case requires an input_dir argument")
    tz_val = resolve_timezone(timezone, None)
    case = Case.init(case_dir, source_timezone=tz_val)
    seed_case_report_templates(case)
    _show(status, f"Initialized case at {case.path}")
    return case


def _rerun_reset(
    case: Case,
    case_dir: str | Path,
    timezone: str,
    status: StatusCallback | None,
) -> Case:
    """Reset case tables and runtime outputs for --rerun, preserving raw/ and memory."""
    _show(status, "Resetting case tables for rerun (preserving raw/ for re-normalize)")
    with CaseDB(case) as db:
        reset_case_tables(db)
    case.clear_runtime_outputs(
        preserve_memory=True,
        drop_database=False,
        preserve_raw=True,
    )
    # Preserve the manifest timezone across rerun unless --timezone overrides it.
    tz_val = resolve_timezone(timezone, case)
    case = Case.init(case_dir, source_timezone=tz_val)
    seed_case_report_templates(case)
    _show(status, f"Re-initialized case at {case.path}")
    return case


def _run_ingest_stage(
    case: Case,
    db: CaseDB,
    input_dir: str,
    push_progress: Callable[..., None],
    status: StatusCallback | None,
) -> dict[str, Any]:
    """Ingest evidence files (EVTX, MFT, Prefetch) into the case."""

    def stage_status(message: str) -> None:
        _show(status, message)
        push_progress(message, stage="ingest", status="running", summary=message)

    _show(status, f"Stage 1/4: ingest from {input_dir}")
    push_progress(f"[ingest] scanning {input_dir}", stage="ingest", status="running")
    counts = ingest_all(case, input_dir, db=db, progress_callback=stage_status)
    note = (
        f"new_files={counts['new_files']}, skipped_files={counts['skipped_files']}, "
        f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}, "
        f"prefetch_files={counts['prefetch_files']}"
    )
    _show(status, f"Ingest complete: {note}")
    push_progress(f"[ingest] {note}", stage="ingest", status="running", summary=note)
    return counts


def _run_normalize_stage(
    case: Case,
    db: CaseDB,
    init: bool,
    ingest_counts: dict[str, Any],
    push_progress: Callable[..., None],
    status: StatusCallback | None,
) -> bool:
    """Normalize raw evidence into structured DuckDB tables."""
    revision = _sources_current_revision(db)
    receipt = _stage_receipt(db, "pipeline-normalize")
    parser_revision = _parser_revision()
    normalized_this_run = True
    if (
        not init
        and ingest_counts["new_files"] == 0
        and receipt is not None
        and receipt[0] == revision
        and _sources_normalized(db)
    ):
        normalized_this_run = False
        _show(status, "Stage 2/4: normalize - source state is current, skipping")
        push_progress(
            "[normalize] skipped (source status and parser revision are current)",
            stage="normalize",
            status="running",
        )
    else:
        _show(status, "Stage 2/4: normalize into DuckDB")
        push_progress("[normalize] starting", stage="normalize", status="running")
        source_keys = ingest_counts.get("new_source_keys") or None
        if receipt is None or receipt[2] != parser_revision:
            source_keys = None
        replaced_sources = find_replaced_source_ids(db, source_keys)
        normalized = normalize_all(case, db, source_keys=source_keys)
        if replaced_sources:
            replacement_details: list[dict[str, Any]] = []
            for family, old_to_new in sorted(replaced_sources.items()):
                for old_id, new_id in sorted(old_to_new.items()):
                    source_receipt: dict[str, Any] = {"family": family}
                    for label, source_id in (("old", old_id), ("new", new_id)):
                        source_receipt[f"{label}_source_id"] = source_id
                        for key, query, params in (
                            (
                                "ingested_file",
                                "SELECT * FROM ingested_files WHERE sha256 = ? AND source_kind = ?",
                                [source_id, family],
                            ),
                            (
                                "evidence_source",
                                "SELECT * FROM evidence_sources WHERE source_id = ?",
                                [source_id],
                            ),
                        ):
                            records = fetch_records(db, query, params)
                            source_receipt[f"{label}_{key}"] = (
                                records[0] if records else None
                            )
                    replacement_details.append(source_receipt)
            _record_stage_receipt(
                db,
                "pipeline-normalize",
                _sources_current_revision(db),
                "normalized replacements; retirement pending",
                status="pending_replacement",
                details={
                    "source_replacements": replacement_details,
                    "parser_revision": parser_revision,
                },
            )
        retire_replaced_sources(db, replaced_sources)
        note = _normalize_counts_summary(normalized)
        _record_stage_receipt(
            db,
            "pipeline-normalize",
            _sources_current_revision(db),
            note,
            details={"parser_revision": parser_revision},
        )
        _show(
            status,
            f"Normalize complete: {note}, mft_timeline_rows={normalized['mft_timeline_rows']}",
        )
        push_progress(
            f"[normalize] {note}", stage="normalize", status="running", summary=note
        )
    return normalized_this_run


def _run_analyze_stage(
    case: Case,
    db: CaseDB,
    init: bool,
    normalized_this_run: bool,
    push_progress: Callable[..., None],
    status: StatusCallback | None,
) -> int:
    """Run rule-based analysis to generate findings."""
    rules_dir = rulepacks_dir()
    rules = load_rules_from_dir(rules_dir)
    revision = _analysis_revision(case)
    receipt = _stage_receipt(db, "pipeline-analyze")
    if (
        not init
        and not normalized_this_run
        and receipt is not None
        and receipt[0] == revision
    ):
        existing_findings = int(
            db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        )
        _show(
            status,
            f"Stage 3/4: analyze - already done ({existing_findings} findings), skipping",
        )
        push_progress(
            f"[analyze] skipped ({existing_findings} findings already exist)",
            stage="analyze",
            status="running",
        )
        return existing_findings

    _show(status, f"Stage 3/4: analyze ({len(rules)} common rules)")
    push_progress(
        f"[analyze] common rules={len(rules)}",
        stage="analyze",
        status="running",
    )
    total_findings = 0
    active_rule_ids = {rule.id for rule in rules}
    old_rule_ids = {
        str(row[0])
        for row in db.execute(
            "SELECT DISTINCT rule_id FROM findings WHERE rule_id IS NOT NULL"
        ).fetchall()
    }
    for stale_rule_id in old_rule_ids - active_rule_ids:
        clear_rule_findings(case, db, stale_rule_id)
    for rule in rules:
        push_progress(
            f"[analyze] rule: {rule.id}",
            stage="analyze",
            status="running",
            log_level="info",
        )
        clear_rule_findings(case, db, rule.id)
        findings = generate_findings(rule, run_rule(db, rule))
        save_findings(case, db, findings)
        total_findings += len(findings)
    _prune_orphan_reviews(db)
    _record_stage_receipt(
        db,
        "pipeline-analyze",
        revision,
        f"rules={len(rules)}, findings={total_findings}",
        details={
            "pysigma_version": version("pysigma"),
            "rules": [
                {
                    "id": rule.id,
                    "format": rule.rule_format,
                    "definition_sha256": rule.definition_sha256,
                    "query": rule.query,
                }
                for rule in rules
            ],
        },
    )
    _show(status, f"Analyze complete: findings={total_findings}")
    push_progress(
        f"[analyze] done - findings={total_findings}",
        stage="analyze",
        status="running",
        summary=f"findings={total_findings}",
        log_level="success",
    )
    return total_findings


def _run_investigate_stage(
    case: Case,
    db: CaseDB,
    llm_base_url: str | None,
    model: str | None,
    template_root: Path | None,
    push_progress: Callable[..., None],
    status: StatusCallback | None,
    *,
    max_iter: int,
    max_queries_per_hypothesis: int,
    no_progress_limit: int,
    report_every_n_cycles: int,
    report_max_queries_per_section: int,
    max_llm_calls: int,
    forensia_policy: CasePolicyInput | None = None,
    report_spec: str | Path | None = None,
    report_only: bool = False,
) -> None:
    """Run LLM-driven investigation loop (or skip if LLM not configured)."""
    if not (llm_base_url and model):
        _show(
            status,
            "Stage 4/4: LLM not configured - skipping investigate (set LLM_BASE_URL and LLM_MODEL in .env)",
        )
        push_progress(
            "[investigate] skipped - LLM not configured",
            stage="investigate",
            status="running",
        )
        return

    _show(status, f"Stage 4/4: investigate with model={model}")
    push_progress(
        f"[investigate] starting - model={model}", stage="investigate", status="running"
    )
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
                report_every_n_cycles=report_every_n_cycles,
                report_max_queries_per_section=report_max_queries_per_section
                or get_llm_settings()["report_max_queries_per_section"],
                max_llm_calls=max_llm_calls,
                forensia_policy=forensia_policy,
                report_spec=report_spec,
                report_only=report_only,
                progress_callback=_forward_progress(push_progress),
            )
        )
    except LLMServerUnavailableError as exc:
        # Producer-decided severity: a raised exception here is a processing
        # failure, not evidence content, so it is classified explicitly.
        push_progress(
            f"[investigate] aborted - LLM server unavailable ({exc})",
            stage="investigate",
            status="running",
            log_level="error",
        )
        _show(status, f"investigation aborted: LLM server unavailable ({exc})")
        raise
    _show(
        status,
        f"Investigation complete: session={result['session_id']} status={result['status']}",
    )
    push_progress(
        f"[investigate] done - session={result['session_id']} status={result['status']}",
        stage="investigate",
        status=result["status"],
        iteration=result["iteration"],
        summary=result["summary"],
        hypotheses=result.get("hypotheses", []),
        report_sections=result.get("report_sections", {}),
        log_level="success",
    )


def _forward_progress(
    push_progress: Callable[..., None],
) -> Callable[[dict[str, Any]], None]:
    """Adapt the investigator's payload dict to progress_pusher updates."""

    def forward(payload: dict[str, Any]) -> None:
        push_progress(
            payload.get("summary"),
            stage=payload.get("stage", "investigate"),
            status=payload.get("status", "running"),
            iteration=payload.get("iteration", 0),
            current_query=payload.get("current_query"),
            summary=payload.get("summary"),
            hypotheses=payload.get("hypotheses", []),
            report_sections=payload.get("report_sections", {}),
        )

    return forward


def _run_report_stage(
    case: Case,
    db: CaseDB,
    push_progress: Callable[..., None],
    html_output: str | Path | None = None,
) -> Path:
    """Render the final written report."""
    _report_md, report_path = render_written_report(case, db, html_output=html_output)
    push_progress(
        f"[report] written: {report_path}",
        stage="completed",
        status="completed",
        summary=f"Report: {report_path}",
        log_level="success",
    )
    return report_path


def _run_evidence_stages(
    case: Case,
    db: CaseDB,
    input_dir: str | None,
    rerun: bool,
    push_progress: Callable[..., None],
    status: StatusCallback | None,
) -> None:
    """(Re)build evidence tables: ingest from input_dir, or re-normalize from raw/.

    - `input_dir` given: full ingest from input_dir, then normalize + analyze
    - `rerun` with raw/ already populated: skip ingest, just re-run normalize + analyze
    """
    raw_has_files = any(case.raw_dir.iterdir()) if case.raw_dir.exists() else False
    normalize_receipt = _stage_receipt(db, "pipeline-normalize")
    normalize_is_current = (
        normalize_receipt is not None
        and normalize_receipt[0] == _sources_current_revision(db)
        and _sources_normalized(db)
    )
    needs_normalize_from_raw = (
        input_dir is None and raw_has_files and (rerun or not normalize_is_current)
    )

    if input_dir is not None:
        ingest_counts = _run_ingest_stage(case, db, input_dir, push_progress, status)
        normalized_this_run = _run_normalize_stage(
            case, db, rerun, ingest_counts, push_progress, status
        )
        _run_analyze_stage(
            case,
            db,
            rerun,
            normalized_this_run,
            push_progress,
            status,
        )
    elif needs_normalize_from_raw:
        _show(status, "Re-normalizing from existing raw/ (no input_dir provided)")
        normalized_this_run = _run_normalize_stage(
            case, db, True, {"new_files": 1}, push_progress, status
        )
        _run_analyze_stage(
            case,
            db,
            True,
            normalized_this_run,
            push_progress,
            status,
        )
    elif input_dir is None:
        analyze_receipt = _stage_receipt(db, "pipeline-analyze")
        if analyze_receipt is None or analyze_receipt[0] != _analysis_revision(case):
            _run_analyze_stage(
                case,
                db,
                False,
                False,
                push_progress,
                status,
            )


def run_investigation(
    case_dir: str | Path,
    *,
    input_dir: str | None = None,
    llm_base_url: str | None = None,
    model: str | None = None,
    template_dir: str | Path | None = None,
    report_spec: str | Path | None = None,
    knowledge_dir: str | Path | None = None,
    forensia_md: str | Path | None = None,
    rerun: bool = False,
    report_only: bool = False,
    max_iter: int = 20,
    max_queries_per_hypothesis: int = 5,
    no_progress_limit: int = 3,
    report_every_n_cycles: int = 3,
    report_max_queries_per_section: int = 0,
    max_llm_calls: int = 0,
    timezone: str = "",
    status: StatusCallback | None = None,
    pre_investigation: Callable[[Case, CaseDB], None] | None = None,
) -> Path:
    """Run the investigation pipeline:

    case open/init → optional ``--rerun`` reset → ingest → normalize → analyze
    → ``investigator.investigate`` → report render, with Trace stage receipts
    and DB progress events. ``llm_base_url``/``model`` must already
    be resolved (env + adapter flags).

    Display contract: plain status text goes to the injected ``status``
    callback; ``pre_investigation`` is an adapter hook invoked with
    ``(case, db)`` between the evidence stages and the investigation loop
    (the adapter owns advice/timezone hint rendering). ``forensia_md``
    designates the one investigation-policy input (default:
    ``case_root/FORENSIA.md``) adopted at session start and recorded there
    (V2-05). ``report_spec`` designates the one report input (an explicit
    REPORT.md path); with ``template_dir`` it is normally resolved from the
    case-root REPORT.md or the packaged templates — ``--report-spec`` is the
    designated explicit source and both together are a caller error (V2-06).
    Data reads/writes stay on the existing owners — no separate stage state
    or service layer.

    Returns the rendered report path. Raises :class:`UsageError` for invalid
    user inputs and propagates ``LLMServerUnavailableError`` (adapters decide
    the process exit policy).
    """
    validate_declarations()
    case = _open_or_init_case(case_dir, input_dir, timezone, status)
    if report_spec and template_dir:
        raise UsageError(
            "report_spec and template_dir are alternative report inputs; pass one"
        )
    if report_only and (report_spec or template_dir):
        raise UsageError(
            "report_only renders the adopted sections; use report --write to adopt a report input"
        )
    if (report_spec or template_dir) and not (llm_base_url and model):
        raise UsageError("a report input requires an LLM-backed writing run")
    if rerun:
        case = _rerun_reset(case, case_dir, timezone, status)

    knowledge_path = resolve_knowledge_dir(knowledge_dir)
    # Run entry can be invoked repeatedly in one Python process (adapters,
    # tests). Always replace the process-local index so an omitted option
    # cannot inherit knowledge from a previous invocation.
    set_knowledge_docs([])
    if knowledge_path:
        docs = scan_knowledge_dir(knowledge_path)
        set_knowledge_docs(docs)
        _show(status, f"knowledge: {len(docs)} files indexed from {knowledge_path}")
        if not docs:
            _show(
                status, "WARNING: knowledge directory contains no valid knowledge files"
            )

    with CaseDB(case) as db:
        forensia_policy = resolve_forensia_policy_input(
            case,
            forensia_md,
            recorded_policy_exists=load_recorded_policy(db) is not None,
        )
        clear_progress_events(db)
        push_progress = progress_pusher(
            db,
            _make_initial_progress_state(model, llm_base_url),
        )
        push_progress("Case ready", stage="init", summary=f"Case: {case.path}")

        template_root = (
            resolve_template_dir(case, template_dir)
            if (llm_base_url and model)
            else None
        )

        if not report_only:
            _run_evidence_stages(case, db, input_dir, rerun, push_progress, status)
            if pre_investigation is not None:
                pre_investigation(case, db)
            _run_investigate_stage(
                case,
                db,
                llm_base_url,
                model,
                template_root,
                push_progress,
                status,
                max_iter=max_iter,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                no_progress_limit=no_progress_limit,
                report_every_n_cycles=report_every_n_cycles,
                report_max_queries_per_section=report_max_queries_per_section,
                max_llm_calls=max_llm_calls,
                forensia_policy=forensia_policy,
                report_spec=report_spec,
            )
        return _run_report_stage(case, db, push_progress)


def run_report(
    case_dir: str | Path,
    *,
    output: str | Path | None = None,
    write: bool = False,
    report_spec: str | Path | None = None,
    template_dir: str | Path | None = None,
    knowledge_dir: str | Path | None = None,
    llm_base_url: str | None = None,
    model: str | None = None,
    report_max_queries_per_section: int = 0,
    status: StatusCallback | None = None,
) -> tuple[Path, Path]:
    """Write a case report, optionally refreshing its sections through the
    existing report-only investigator path.

    The report command owns no pipeline state of its own: input validation,
    knowledge selection, output collision checks, report-only writing, and
    rendering all run here without opening an evidence-processing session.
    """
    validate_declarations()
    case = Case.open(case_dir)
    if report_spec and template_dir:
        raise UsageError(
            "--report-spec and --template-dir are alternative report inputs; pass one"
        )
    if not write and (report_spec or template_dir):
        raise UsageError("--report-spec and --template-dir require --write")
    if write:
        llm_base_url, model = resolve_llm_config(llm_base_url, model)
        if not (llm_base_url and model):
            raise UsageError(
                "Set LLM_BASE_URL and LLM_MODEL via .env file or CLI flags."
            )

    knowledge_path = resolve_knowledge_dir(knowledge_dir)
    set_knowledge_docs([])
    if knowledge_path:
        docs = scan_knowledge_dir(knowledge_path)
        set_knowledge_docs(docs)
        _show(status, f"knowledge: {len(docs)} files indexed from {knowledge_path}")
        if not docs:
            _show(
                status, "WARNING: knowledge directory contains no valid knowledge files"
            )

    html_output = Path(output) if output is not None else None
    with CaseDB(case) as db:
        ensure_report_output_paths(
            case,
            (
                case.reports_dir / "report.md",
                html_output or case.reports_dir / "report.html",
            ),
            report_spec=report_spec,
        )
        if write:
            template_root = resolve_template_dir(case, template_dir)
            max_queries = (
                report_max_queries_per_section
                or get_llm_settings()["report_max_queries_per_section"]
            )
            _show(status, f"Writing report sections (max_queries={max_queries})")

            def discard_progress(*_args: Any, **_kwargs: Any) -> None:
                return None

            _run_investigate_stage(
                case,
                db,
                llm_base_url,
                model,
                template_root,
                discard_progress,
                None,
                max_iter=1,
                max_queries_per_hypothesis=0,
                no_progress_limit=1,
                report_every_n_cycles=3,
                report_max_queries_per_section=max_queries,
                max_llm_calls=0,
                report_spec=report_spec,
                report_only=True,
            )
        markdown_path = case.reports_dir / "report.md"
        html_path = _run_report_stage(
            case, db, lambda *_args, **_kwargs: None, html_output=html_output
        )
        return markdown_path, html_path
