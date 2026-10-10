"""Display-agnostic investigation pipeline entry.

One run entry shared by display adapters: the headless CLI today, a TUI later
(GOAL §6.3). It owns the assembly of the existing stages — case open/init,
explicit case reset, knowledge indexing, ingest, normalize, rule analysis,
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
- semantic progress events are appended to the trace DB through the existing
  ``db.progress`` owner; events carry producer-selected kind, status, severity,
  reason, and entity references without copying investigation snapshots;
- SIGINT capture and stop application stay where they are today
  (``investigator.investigate`` owns the converter flag), and the session's
  terminal receipt is still persisted before fallible projections by the same
  lifecycle owner.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import uuid
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

from forensia.config import (
    get_llm_settings,
    get_system_prompt_budget_chars,
    resolve_llm_config,
)
from forensia.core.case import Case, resolve_timezone
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.db.progress import record_progress_event
from forensia.db.query import fetch_records
from forensia.db.schema import TRACE_TABLES
from forensia.evidence.ingest import ingest_all
from forensia.evidence.invalidation import (
    find_replaced_source_ids,
    retire_replaced_sources,
)
from forensia.evidence.normalize import normalize_all
from forensia.investigation.case_policy import CasePolicyInput, load_recorded_policy
from forensia.investigation.investigator import investigate as investigate_loop
from forensia.knowledge.catalog import validate_declarations
from forensia.knowledge.external import scan_knowledge_dir, set_knowledge_docs
from forensia.knowledge.resources import rules_dir, schema_dir, sigma_bundle_path
from forensia.knowledge.rules.engine import (
    clear_rule_findings_batch,
    feed_findings_to_timeline,
    generate_findings,
    iter_rule_row_batches,
    prepare_finding_run,
    save_findings,
)
from forensia.knowledge.rules.loader import load_rules
from forensia.knowledge.sigma_bundle import binding_admitted, load_sigma_bundle
from forensia.llm.llm_client import LLMServerUnavailableError
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
    "data/schema/artifact_capabilities.yaml",
)


class UsageError(ValueError):
    """Invalid pipeline user input that a display adapter should surface as a
    parameter error (missing input_dir, unusable
    template/knowledge directory)."""


def _show(status: StatusCallback | None, message: str) -> None:
    if status is not None:
        status(message)


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
    rules_root = rules_dir()
    rule_files = list(rules_root.rglob("*.yaml"))
    code_root = Path(__file__).parent / "knowledge" / "rules"
    code_files = list(code_root.rglob("*.py"))
    catalog_file = Path(__file__).parent / "knowledge" / "catalog.py"
    sigma_contract_file = Path(__file__).parent / "knowledge" / "sigma_bundle.py"
    pipeline_file = Path(__file__).resolve()
    runtime_catalog_files = [
        schema_dir() / "false_positive_rules.yaml",
        schema_dir() / "dfir_ioc_catalog.yaml",
    ]
    revision = _content_revision(
        [
            *rule_files,
            *code_files,
            catalog_file,
            sigma_contract_file,
            pipeline_file,
            *runtime_catalog_files,
            sigma_bundle_path(),
        ]
    )
    suppression = (
        case.allowlist_path.read_bytes() if case.allowlist_path.exists() else b""
    )
    return hashlib.sha256(revision.encode("ascii") + suppression).hexdigest()


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
    """Clear derived state and its trace references, retaining source registrations."""
    with db.transaction():
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
            # An explicit rerun resets events with the entities they reference.
            schema = "trace." if table in TRACE_TABLES else ""
            db.execute(f"DELETE FROM {schema}{table}")


def _prune_orphan_reviews(db: CaseDB) -> None:
    """Remove AI reviews whose referenced findings no longer exist."""
    db.execute(
        """
        DELETE FROM trace.ai_reviews
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


def progress_pusher(db: CaseDB) -> Callable[[dict[str, Any]], int]:
    """Persist one compact, producer-structured event without UI snapshots."""

    def push(event: dict[str, Any]) -> int:
        return record_progress_event(db, event)

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
    existing_case_databases = [
        path
        for path in (
            case_path / "db" / "case.duckdb",
            case_path / "db" / "trace.duckdb",
        )
        if path.exists()
    ]
    if existing_case_databases:
        paths = ", ".join(str(path) for path in existing_case_databases)
        raise UsageError(
            "Case manifest is missing but database files already exist; "
            f"preserving them without initialization: {paths}"
        )
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
    """Reset case tables and runtime outputs for --rerun, preserving raw/."""
    _show(status, "Resetting case tables for rerun (preserving raw/ for re-normalize)")
    with CaseDB(case) as db:
        reset_case_tables(db)
    case.clear_runtime_outputs(
        drop_database=False,
        preserve_raw=True,
    )
    # Preserve the manifest timezone across rerun unless --timezone overrides it.
    tz_val = resolve_timezone(timezone, case)
    case = Case.init(case_dir, source_timezone=tz_val)
    seed_case_report_templates(case)
    _show(status, f"Re-initialized case at {case.path}")
    return case


def _overwrite_case(
    case_dir: str | Path,
    input_dir: str | None,
    inputs: dict[str, str | Path | None],
    status: StatusCallback | None,
) -> None:
    """Delete an explicitly selected case after protecting all run inputs."""
    if input_dir is None or not Path(input_dir).is_dir():
        raise UsageError("--overwrite requires an existing input_dir directory")
    target = Path(case_dir)
    if target.is_symlink():
        raise UsageError("--overwrite cannot delete a symlinked case directory")
    target = target.resolve()
    if Path.cwd().resolve().is_relative_to(target):
        raise UsageError(
            "--overwrite cannot delete the current working directory or its parents"
        )
    source = Path(input_dir).resolve()
    if source.is_relative_to(target) or target.is_relative_to(source):
        raise UsageError("--overwrite requires non-overlapping input_dir and case_dir")
    for name, path in inputs.items():
        if path:
            resolved = Path(path).resolve()
            if resolved.is_relative_to(target) or (
                resolved.is_dir() and target.is_relative_to(resolved)
            ):
                raise UsageError(f"--overwrite requires {name} outside case_dir")
            if not resolved.exists():
                raise UsageError(f"{name} not found: {resolved}")
    if target.exists():
        if not (target / "manifest.yaml").is_file():
            raise UsageError("--overwrite refuses a directory without a case manifest")
        _show(status, f"Deleting entire case directory: {target}")
        # shortcut: caller must stop the case; add ownership locking with the Runtime.
        shutil.rmtree(target)


def _run_ingest_stage(
    case: Case,
    db: CaseDB,
    input_dir: str,
    push_progress: Callable[[dict[str, Any]], int],
    status: StatusCallback | None,
) -> dict[str, Any]:
    """Ingest evidence files (EVTX, MFT, Prefetch) into the case."""

    def stage_status(message: str) -> None:
        _show(status, message)

    _show(status, f"Stage 1/4: ingest from {input_dir}")
    push_progress(
        progress_event(
            "pipeline.ingest", "running", stage="ingest", summary="Scanning input files"
        )
    )
    counts = ingest_all(case, input_dir, db=db, progress_callback=stage_status)
    note = (
        f"new_files={counts['new_files']}, skipped_files={counts['skipped_files']}, "
        f"evtx_files={counts['evtx_files']}, mft_files={counts['mft_files']}, "
        f"prefetch_files={counts['prefetch_files']}"
    )
    _show(status, f"Ingest complete: {note}")
    push_progress(
        progress_event(
            "pipeline.ingest",
            "completed",
            stage="ingest",
            summary="Evidence ingest completed",
            new_files=counts["new_files"],
            skipped_files=counts["skipped_files"],
        )
    )
    return counts


def _run_normalize_stage(
    case: Case,
    db: CaseDB,
    init: bool,
    ingest_counts: dict[str, Any],
    push_progress: Callable[[dict[str, Any]], int],
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
            progress_event(
                "pipeline.normalize",
                "skipped",
                stage="normalize",
                reason="source_state_current",
                summary="Normalization skipped; sources and parser revision are current",
            )
        )
    else:
        _show(status, "Stage 2/4: normalize into DuckDB")
        push_progress(
            progress_event(
                "pipeline.normalize", "running", stage="normalize", summary="Started"
            )
        )
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
            progress_event(
                "pipeline.normalize",
                "completed",
                stage="normalize",
                summary="Evidence normalization completed",
                normalized_sources=normalized.get("sources", 0),
            )
        )
    return normalized_this_run


def _run_analyze_stage(
    case: Case,
    db: CaseDB,
    init: bool,
    normalized_this_run: bool,
    push_progress: Callable[[dict[str, Any]], int],
    status: StatusCallback | None,
) -> int:
    """Run rule-based analysis to generate findings."""
    bundle = load_sigma_bundle()
    rules = load_rules()
    sigma_bindings = {
        item["rule"]["id"]: item
        for item in bundle["bindings"]
        if binding_admitted(item)
    }
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
            progress_event(
                "pipeline.analyze",
                "skipped",
                stage="analyze",
                reason="analysis_receipt_current",
                summary="Rule analysis skipped; current findings are retained",
                finding_count=existing_findings,
            )
        )
        return existing_findings

    _record_stage_receipt(
        db,
        "pipeline-analyze",
        revision,
        f"rules={len(rules)}, analysis started",
        status="running",
        details={"rule_count": len(rules)},
    )
    total_findings = 0
    active_rule_ids = {rule.id for rule in rules}
    current_rule_id: str | None = None
    rule_runs: list[dict[str, object]] = []
    try:
        _show(status, f"Stage 3/4: analyze ({len(rules)} common rules)")
        push_progress(
            progress_event(
                "pipeline.analyze",
                "running",
                stage="analyze",
                summary="Rule analysis started",
                rule_count=len(rules),
            )
        )
        old_rule_ids = {
            str(row[0])
            for row in db.execute(
                "SELECT DISTINCT rule_id FROM findings WHERE rule_id IS NOT NULL"
            ).fetchall()
        }
        clear_rule_findings_batch(db, old_rule_ids | active_rule_ids)
        run_context = prepare_finding_run(case, db)
        observed_logs = db.execute(
            "SELECT DISTINCT channel, event_id, "
            "json_extract_string(raw_json, '$.winlog.provider.name') "
            "FROM evtx_events"
        ).fetchall()
        for rule in rules:
            current_rule_id = rule.id
            binding = sigma_bindings.get(rule.id)
            result: dict[str, object] = {
                "id": rule.id,
                "format": rule.rule_format,
                "definition_sha256": rule.definition_sha256,
                "execution": {"status": "running", "matches": None},
            }
            rule_runs.append(result)
            if binding is not None:
                target = binding["target_binding"]
                result.update(
                    source_rule_id=binding["rule_id"],
                    target=target,
                    fixture=binding["validation"]["fixture"]["status"],
                )
                if not any(
                    channel in target["channels"]
                    and (not target.get("event_ids") or event_id in target["event_ids"])
                    and (not target.get("providers") or provider in target["providers"])
                    and (
                        not target.get("provider_scopes")
                        or any(
                            channel == scope["channel"]
                            and provider == scope["provider"]
                            for scope in target["provider_scopes"]
                        )
                    )
                    and (
                        not target.get("provider_event_ids")
                        or (
                            event_id in target["provider_event_ids"][provider]
                            if provider in target["provider_event_ids"]
                            else all(
                                event_id not in ids
                                for ids in target["provider_event_ids"].values()
                            )
                        )
                    )
                    for channel, event_id, provider in observed_logs
                ):
                    result["execution"] = {"status": "not_observed", "matches": None}
                    continue
            result["query"] = rule.query
            match_count = 0
            for batch in iter_rule_row_batches(db, rule):
                findings = generate_findings(rule, batch, first_ordinal=match_count + 1)
                save_findings(
                    case,
                    db,
                    findings,
                    run_context=run_context,
                    feed_timeline=False,
                )
                if findings:
                    finding_ids = [item.finding_id for item in findings]
                    evidence_ids = list(
                        dict.fromkeys(
                            str(row["evidence_id"])
                            for finding in findings
                            for row in finding.evidence
                            if row.get("evidence_id")
                        )
                    )
                    push_progress(
                        progress_event(
                            "finding.created",
                            "completed",
                            stage="analyze",
                            summary=f"Detection rule produced {len(findings)} findings",
                            refs={
                                "finding_ids": finding_ids[:20],
                                "evidence_ids": evidence_ids[:20],
                            },
                            rule_id=rule.id,
                            finding_count=len(findings),
                        )
                    )
                match_count += len(findings)
            if match_count:
                push_progress(
                    progress_event(
                        "rule.completed",
                        "completed",
                        stage="analyze",
                        summary="Detection rule completed",
                        rule_id=rule.id,
                        finding_count=match_count,
                    )
                )
            total_findings += match_count
            result["execution"] = {"status": "completed", "matches": match_count}
        current_rule_id = None
        feed_findings_to_timeline(db)
        _prune_orphan_reviews(db)
    except BaseException as exc:
        failure_status = "failed" if isinstance(exc, Exception) else "interrupted"
        if rule_runs and rule_runs[-1]["execution"]["status"] == "running":
            rule_runs[-1]["execution"] = {"status": failure_status, "matches": None}
        _record_stage_receipt(
            db,
            "pipeline-analyze",
            revision,
            f"rules={len(rules)}, analysis {failure_status}",
            status=failure_status,
            details={
                "rule_count": len(rules),
                "failed_rule_id": current_rule_id,
                "failure": {"type": type(exc).__name__, "message": str(exc)},
                "rules": rule_runs,
            },
        )
        push_progress(
            progress_event(
                "pipeline.analyze",
                failure_status,
                severity="error",
                reason="rule_analysis_exception",
                stage="analyze",
                summary="Rule analysis did not complete",
                rule_id=current_rule_id,
                error_type=type(exc).__name__,
            )
        )
        raise
    _record_stage_receipt(
        db,
        "pipeline-analyze",
        revision,
        f"rules={len(rules)}, findings={total_findings}",
        details={
            "sigma_bundle": {
                "build_id": bundle["build_id"],
                "artifact_sha256": hashlib.sha256(
                    sigma_bundle_path().read_bytes()
                ).hexdigest(),
                "source": {
                    "repository": bundle["source"]["repository"],
                    "commit": bundle["source"]["commit"],
                    "tree_sha256": bundle["source"]["tree_sha256"],
                },
                "environment_hashes": bundle["environment"]["hashes"],
                "summary": bundle["summary"],
            },
            "rules": rule_runs,
        },
    )
    _show(status, f"Analyze complete: findings={total_findings}")
    push_progress(
        progress_event(
            "pipeline.analyze",
            "completed",
            severity="success",
            stage="analyze",
            summary="Rule analysis completed",
            finding_count=total_findings,
        )
    )
    return total_findings


def _run_investigate_stage(
    case: Case,
    db: CaseDB,
    llm_base_url: str | None,
    model: str | None,
    template_root: Path | None,
    push_progress: Callable[[dict[str, Any]], int],
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
            progress_event(
                "investigation.skipped",
                "skipped",
                stage="investigate",
                reason="llm_not_configured",
                summary="Investigation skipped because no LLM is configured",
            )
        )
        return

    _show(status, f"Stage 4/4: investigate with model={model}")
    push_progress(
        progress_event(
            "investigation.started",
            "running",
            stage="investigate",
            summary="Investigation started",
        )
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
            )
        )
    except LLMServerUnavailableError as exc:
        # Producer-decided severity: a raised exception here is a processing
        # failure, not evidence content, so it is classified explicitly.
        push_progress(
            progress_event(
                "investigation.failed",
                "failed",
                severity="error",
                reason="llm_server_unavailable",
                stage="investigate",
                summary="Investigation could not reach the configured LLM",
                error_type=type(exc).__name__,
            )
        )
        _show(status, f"investigation aborted: LLM server unavailable ({exc})")
        raise
    _show(
        status,
        f"Investigation complete: session={result['session_id']} status={result['status']}",
    )
    push_progress(
        progress_event(
            f"investigation.{result['status']}",
            result["status"],
            severity="success" if result["status"] == "completed" else "info",
            stage="investigate",
            iteration=result["iteration"],
            summary=result["summary"],
            session_id=result["session_id"],
        )
    )


def _run_report_stage(
    case: Case,
    db: CaseDB,
    push_progress: Callable[[dict[str, Any]], int],
    html_output: str | Path | None = None,
) -> Path:
    """Render the final written report."""
    _report_md, report_path = render_written_report(case, db, html_output=html_output)
    push_progress(
        progress_event(
            "report.rendered",
            "completed",
            severity="success",
            stage="report",
            summary="Report rendered",
            output_path=str(report_path),
        )
    )
    return report_path


def _run_evidence_stages(
    case: Case,
    db: CaseDB,
    input_dir: str | None,
    rerun: bool,
    push_progress: Callable[[dict[str, Any]], int],
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
    overwrite: bool = False,
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
    the process exit policy). ``overwrite=True`` deletes the entire existing
    case, including its policy and templates, before fresh initialization;
    every explicit input must be outside it. Use only on a stopped case.
    """
    validate_declarations()
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
    if overwrite:
        if rerun or report_only:
            raise UsageError(
                "--overwrite cannot be combined with --rerun or --report-only"
            )
        _overwrite_case(
            case_dir,
            input_dir,
            {
                "template_dir": template_dir,
                "report_spec": report_spec,
                "knowledge_dir": knowledge_dir,
                "forensia_md": forensia_md,
            },
            status,
        )
    case = _open_or_init_case(case_dir, input_dir, timezone, status)
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
        push_progress = progress_pusher(db)
        push_progress(
            progress_event(
                "case.ready",
                "completed",
                stage="init",
                summary="Case ready for investigation",
            )
        )

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
        push_progress = progress_pusher(db)
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
        html_path = _run_report_stage(case, db, push_progress, html_output=html_output)
        return markdown_path, html_path
