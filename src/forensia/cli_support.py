"""Shared helpers for CLI commands: case/LLM resolution, progress, counts."""

import time
from collections.abc import Callable
from pathlib import Path

import typer
from rich import print

from forensia.api.cache import (
    VOLATILE_SNAPSHOT_INTERVAL_S,
    write_api_snapshots,
    write_progress_snapshot,
    write_volatile_api_snapshots,
)
from forensia.api.progress import record_progress_event
from forensia.config import resolve_llm_config
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report_templates import (
    has_report_templates,
)

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

