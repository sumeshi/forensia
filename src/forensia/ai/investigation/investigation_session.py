"""Investigation session context: setup, caches, step logging, card sync."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import propose_scope_candidates
from forensia.ai.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.ai.hypotheses.seeding import (
    _seed_rule_hypotheses,
    seed_findings,
)
from forensia.ai.investigation.work_state import (
    ensure_objective_gap,
    format_terminal_reason,
    reopen_retryable_work,
)
from forensia.ai.llm.llm_client import (
    LLMRequestTimeoutError,
    LLMServerUnavailableError,
    chat_completion,
    outage_wait_until_recovered,
)
from forensia.ai.report_gap import (
    _build_report_status,
    _overlay_report_status,
)
from forensia.ai.sections.section_run_store import _findings_snapshot
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import (
    ensure_investigation_state,
    load_investigation_state,
    mark_investigation_started,
)
from forensia.knowledge.coverage import refresh_evidence_coverage
from forensia.knowledge.resources import profile_path
from forensia.report.finding_themes import classify_finding_theme
from forensia.report.template_export import seed_case_report_templates


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


# Terminal status vocabulary written by the investigation harness
# (investigator.py `finally` block) and reconciled here for stale runs.
_TERMINAL_STATUS_CODES = ("completed", "stopped", "failed", "cancelled", "abandoned")


def persist_session_terminal_receipt(
    db: CaseDB,
    session_id: str,
    status: str,
    *,
    terminal_reason: str | None = None,
    finished_at: datetime | None = None,
) -> None:
    """Persist the durable session terminal receipt before fallible projections.

    Always records ``finished_at`` (timezone-aware UTC) and a structured
    ``terminal_reason`` so a session never remains permanently ``running`` even
    if a later Memory/report/API projection fails (T-12.1).
    """
    finished = finished_at or datetime.now(UTC)
    reason = terminal_reason or format_terminal_reason(status)
    db.execute(
        "UPDATE investigation_sessions SET finished_at = ?, status = ?, "
        "terminal_reason = ? WHERE session_id = ?",
        (finished.replace(tzinfo=None), status, reason, session_id),
    )


def _conservative_finish_time(db: CaseDB, session_id: str, started_at: Any) -> Any:
    """Conservative finish-time fallback: last observed step/event time.

    Never collapses wall time to ``started_at`` (T-12.2). Falls back to
    ``started_at`` only when no later activity exists.
    """
    step_row = db.execute(
        "SELECT MAX(created_at) FROM investigation_steps WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    last_step = step_row[0] if step_row else None
    # progress_events are not session-scoped; the last step time is the
    # conservative finish fallback. Falls back to started_at only when no
    # later activity exists (T-12.2).
    candidate = started_at
    if last_step is not None:
        candidate = last_step
    return candidate


def reconcile_stale_sessions(db: CaseDB) -> int:
    """Reconcile stale ``running`` sessions into a structured terminal state.

    Runs on startup (in ``_init_session``) and on every read of the sessions
    list. A ``running`` session left by SIGKILL/host loss is marked
    ``abandoned`` with a conservative finish-time fallback and a structured
    abandonment reason. Terminal sessions missing a ``terminal_reason`` (e.g.
    finalized by the harness before this column existed) are backfilled from
    their status (T-12.2). Returns the number of sessions reconciled.
    """
    reconciled = 0
    running_rows = db.execute(
        "SELECT session_id, started_at FROM investigation_sessions "
        "WHERE status = 'running'"
    ).fetchall()
    for session_id, started_at in running_rows:
        finish = _conservative_finish_time(db, session_id, started_at)
        db.execute(
            "UPDATE investigation_sessions SET status = 'abandoned', "
            "finished_at = ?, terminal_reason = ? WHERE session_id = ?",
            (
                finish,
                format_terminal_reason("abandoned"),
                session_id,
            ),
        )
        reconciled += 1
    # Backfill structured terminal reasons for any terminal session missing one.
    for status in _TERMINAL_STATUS_CODES:
        db.execute(
            "UPDATE investigation_sessions SET terminal_reason = ? "
            "WHERE status = ? AND terminal_reason IS NULL",
            (format_terminal_reason(status), status),
        )
        reconciled += 0  # backfill is non-destructive; not counted as a reopen
    return reconciled


@dataclass
class Ctx:
    """Mutable per-session state shared across investigate() helpers."""

    interrupted: bool = False
    report_status: dict = field(default_factory=dict)
    memory_overview: str = ""
    memory_plan: str = ""
    memory_check: str = ""
    current_hypothesis_id: str | None = None


_MAX_OUTAGE_RETRIES_PER_CALL = 3


async def _call_with_outage_recovery(
    call_fn,
    base_url: str,
    model: str,
    **kwargs,
):
    for attempt in range(1, _MAX_OUTAGE_RETRIES_PER_CALL + 1):
        try:
            if inspect.iscoroutinefunction(call_fn):
                return await call_fn(base_url=base_url, model=model, **kwargs)
            else:
                return await asyncio.to_thread(
                    call_fn, base_url=base_url, model=model, **kwargs
                )
        except LLMRequestTimeoutError:
            raise
        except LLMServerUnavailableError:
            if attempt >= _MAX_OUTAGE_RETRIES_PER_CALL:
                raise
            await outage_wait_until_recovered(base_url, model)
    raise LLMServerUnavailableError("Outage recovery failed")


def _ctx_get_report_status(
    ctx: Ctx,
    db: CaseDB,
    *,
    current_section: str | None = None,
    focus_sections: list[str] | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    """Return the current or refreshed report status, optionally filtered to specific sections."""
    if refresh:
        ctx.report_status = _build_report_status(db)
    return _overlay_report_status(
        ctx.report_status,
        current_section=current_section,
        focus_sections=focus_sections,
    )


def ctx_refresh_caches(
    ctx: Ctx,
    memory: MemoryManager,
    base_url: str,
    model: str,
    current_hypothesis_id: str | None = None,
    hypothesis: Hypothesis | None = None,
    db: CaseDB | None = None,
    session_id: str | None = None,
) -> None:
    """Reload memory context caches and compact overview if needed.

    When *hypothesis* is provided, entity/keypoint files are filtered by
    relevance to it (G-3) — these caches are handed to the planner and
    checker as their default context, so the filtering must happen here,
    not only in the lazy-load fallbacks inside planner/checker.
    """
    memory.compact_overview_if_needed(base_url=base_url, model=model)
    ctx.memory_overview = memory.load_compact_context(
        ["overview.md"], max_bytes=memory.max_bytes
    )
    if hypothesis is not None and current_hypothesis_id is None:
        current_hypothesis_id = hypothesis.id
    relevance_terms = (
        memory.build_relevance_terms_from_hypothesis(hypothesis)
        if hypothesis is not None
        else None
    )
    ctx.current_hypothesis_id = current_hypothesis_id
    plan_budget = max(1024, memory.max_bytes // 3)
    index_budget = min(2048, max(256, plan_budget // 4))
    memory_index = memory.build_memory_index(
        current_hypothesis_id,
        relevance_terms=relevance_terms or None,
        max_bytes=index_budget,
    )
    ctx.memory_plan = memory.load_investigation_context(
        current_hypothesis_id,
        relevance_terms=relevance_terms or None,
        max_bytes=max(768, plan_budget - len(memory_index.encode("utf-8"))),
        include_overview=False,
        include_archive=current_hypothesis_id is None,
    )
    if memory_index:
        ctx.memory_plan = f"{ctx.memory_plan.rstrip()}\n\n{memory_index}".strip()
    ctx.memory_check = memory.load_investigation_context(
        current_hypothesis_id,
        relevance_terms=relevance_terms or None,
        max_bytes=max(1024, memory.max_bytes // 2),
        include_overview=False,
        include_archive=current_hypothesis_id is None,
    )
    if db is not None:
        from forensia.ai.retrieval_telemetry import record_retrieval_event

        selected_refs = re.findall(r"^- ([^:][^\n]*\.md)$", memory_index, re.MULTILINE)
        record_retrieval_event(
            db,
            session_id=session_id,
            scope_kind="hypothesis" if current_hypothesis_id else "global",
            scope_id=current_hypothesis_id,
            phase="index",
            source_kind="memory",
            query_terms=sorted(relevance_terms or []),
            candidate_count=sum(
                int(value)
                for value in re.findall(r"^- [^:]+: (\d+)", memory_index, re.MULTILINE)
            ),
            selected_refs=selected_refs,
            selected_chars=len(memory_index),
            budget=index_budget,
        )


def _save_step(
    db: CaseDB,
    session_id: str,
    iteration: int,
    phase: str,
    hypothesis_id: str | None,
    input_json: Any,
    output_json: Any,
    suffix: str | None = None,
) -> None:
    """Persist an investigation step (input/output JSON) to the database."""
    step_id = f"{session_id}-{iteration:02d}-{phase}"
    if suffix:
        step_id = f"{step_id}-{suffix}"
    db.execute(
        """
        INSERT INTO investigation_steps (
            step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (step_id) DO UPDATE SET
            output_json = excluded.output_json,
            created_at = excluded.created_at
        """,
        (
            step_id,
            session_id,
            hypothesis_id,
            iteration,
            phase,
            _to_json(input_json),
            _to_json(output_json),
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )


def _reasoning_entry_id(
    hypothesis_id: str,
    iteration: int,
    phase: str,
    query_id: str | None,
) -> str:
    """Generate a deterministic SHA1-based ID for a reasoning entry."""
    body = f"{hypothesis_id}-{iteration}-{phase}-{query_id or '-'}"
    return hashlib.sha1(body.encode("utf-8")).hexdigest()[:16]


def append_hypothesis_reasoning(
    db: CaseDB,
    hypothesis_id: str,
    session_id: str,
    iteration: int,
    phase: str,
    body: str,
    verdict: str | None = None,
    query_id: str | None = None,
) -> str | None:
    """Persist a free-text reasoning entry linked to a hypothesis and phase."""
    text = str(body).strip()
    if not hypothesis_id or not text:
        return None
    entry_id = _reasoning_entry_id(hypothesis_id, iteration, phase, query_id)
    db.execute(
        """
        INSERT INTO hypothesis_reasoning (
            entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (entry_id) DO NOTHING
        """,
        (
            entry_id,
            hypothesis_id,
            session_id,
            iteration,
            phase,
            verdict,
            query_id,
            text,
            datetime.now(UTC).replace(tzinfo=None),
        ),
    )
    return entry_id


def append_settlement_feedback(
    db: CaseDB,
    hypothesis_id: str,
    session_id: str,
    iteration: int,
    query_id: str | None,
    previous_verdict: str,
    decision: Any,
) -> str | None:
    """Persist a host settlement override so the next plan can observe it."""
    final_verdict = str(decision.verdict)
    if decision.allowed and final_verdict == previous_verdict:
        return None
    body = (
        f"Host settlement changed verdict {previous_verdict} -> {final_verdict}: "
        f"{decision.reason}"
    )
    failed_gates = "; ".join(decision.gates_failed)
    if failed_gates:
        body += f"; failed_gates={failed_gates}"
    return append_hypothesis_reasoning(
        db, hypothesis_id, session_id, iteration, "settlement", body[:1000],
        verdict=final_verdict, query_id=query_id,
    )


def _load_profile_config(profile: str) -> dict[str, Any]:
    """Load the YAML configuration for a given profile name."""
    profile_file = profile_path(profile)
    if not profile_file.exists():
        return {}
    return yaml.safe_load(profile_file.read_text(encoding="utf-8")) or {}


def _initialize_overview(
    memory: MemoryManager, case: Case, profile_config: dict[str, Any] | None = None
) -> None:
    """Create the initial investigation overview memory file if it doesn't exist yet."""
    objective = str((profile_config or {}).get("objective") or "").strip()
    if memory.has_overview():
        return
    output_language = str(get_llm_settings()["output_language"]).lower()
    open_question_seed = {
        "en": "Awaiting initial investigation",
    }.get(output_language, "Awaiting initial investigation")
    objective_line = objective or {
        "en": "Establish the evidence-backed incident narrative.",
    }.get(output_language, "Establish the evidence-backed incident narrative.")
    memory.update_overview(
        f"# Investigation Overview\n\n"
        f"Case: {case.path.name}\n\n"
        f"## Investigation Objective\n- {objective_line}\n\n"
        "## Memory Details\n"
        "- Detailed fact records can be stored under memory/details/fact-NNN.md and loaded on demand.\n\n"
        "## Case Scope\n- none\n\n"
        "## Key Findings\n- none\n\n"
        "## Investigation Policy\n- preserve evidence fidelity\n\n"
        f"## Active Tasks\n- {open_question_seed}\n"
    )


def _ensure_profile_objective(
    memory: MemoryManager, profile_config: dict[str, Any] | None = None
) -> None:
    """Patch the investigation objective from profile config into overview and tasks."""
    objective = str((profile_config or {}).get("objective") or "").strip()
    if not objective:
        return
    overview = memory.load_overview()
    if "## Investigation Objective" not in overview:
        memory.update_overview(
            overview.rstrip() + f"\n\n## Investigation Objective\n- {objective}\n"
        )
    elif objective not in overview:
        memory.update_overview(
            overview.replace(
                "## Investigation Objective\n",
                f"## Investigation Objective\n- {objective}\n",
                1,
            )
            if "## Investigation Objective\n- " not in overview
            else overview
        )
    if memory.tasks_memory_path.exists():
        tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
    else:
        tasks_text = ""
    objective_task = f"Investigation objective: {objective}"
    if objective_task not in tasks_text:
        memory.append_task(objective_task, "human_decision")


def _finding_snapshot(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    """Fetch a bounded, theme-diverse finding projection for LLM working Memory."""
    candidates = _findings_snapshot(db, max(limit * 8, limit), include_evidence=True)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in candidates:
        grouped.setdefault(classify_finding_theme(finding), []).append(finding)
    projected: list[dict[str, Any]] = []
    depth = 0
    while len(projected) < limit:
        added = False
        for theme, items in grouped.items():
            if depth >= len(items):
                continue
            item = dict(items[depth])
            item["projection_theme"] = theme
            item["theme_count"] = len(items)
            item["theme_finding_ids"] = [
                str(candidate.get("finding_id") or "") for candidate in items
            ]
            projected.append(item)
            added = True
            if len(projected) >= limit:
                break
        if not added:
            break
        depth += 1
    revision = hashlib.sha256(
        json.dumps(
            [
                {
                    key: item.get(key)
                    for key in (
                        "finding_id",
                        "title",
                        "status",
                        "confidence",
                        "summary",
                    )
                }
                for item in projected
            ],
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:16]
    generated_at = datetime.now(UTC).isoformat()
    for item in projected:
        item["projection_revision"] = revision
        item["projection_generated_at"] = generated_at
        item["projection_state"] = "in-progress"
    return projected


def _keypoint_card_id(index: int) -> str:
    return f"KP-{index:04d}"


def sync_keypoint_cards(
    memory: MemoryManager, findings_snapshot: list[dict[str, Any]]
) -> None:
    """Reconcile findings → keypoint-memory cards, removing stale entries."""
    for index, finding in enumerate(findings_snapshot, start=1):
        evidence_ids: list[str] = []
        evidence = finding.get("evidence")
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except json.JSONDecodeError:
                evidence = []
        if isinstance(evidence, list):
            for row in evidence:
                if not isinstance(row, dict):
                    continue
                evidence_id = str(row.get("evidence_id") or "").strip()
                if evidence_id:
                    evidence_ids.append(evidence_id)
        lines = [
            f"# {_keypoint_card_id(index)}",
            "",
            f"- finding_id: {finding.get('finding_id')}",
            f"- title: {finding.get('title')}",
            f"- severity: {finding.get('severity')}",
            f"- confidence: {finding.get('confidence')}",
            f"- theme: {finding.get('projection_theme') or 'other'}",
            f"- theme_finding_count: {finding.get('theme_count') or 1}",
            f"- projection_revision: {finding.get('projection_revision') or 'unknown'}",
            f"- projection_generated_at: {finding.get('projection_generated_at') or 'unknown'}",
            f"- projection_state: {finding.get('projection_state') or 'unknown'}",
            "",
            "## Summary",
            str(finding.get("summary") or "").strip() or "-",
        ]
        theme_finding_ids = [
            str(item)
            for item in (finding.get("theme_finding_ids") or [])
            if str(item).strip()
        ]
        if theme_finding_ids:
            lines.extend(
                [
                    "",
                    "## Theme Finding IDs",
                    *[f"- {item}" for item in theme_finding_ids],
                ]
            )
        lines.extend(["", "## Evidence IDs"])
        lines.extend([f"- {evidence_id}" for evidence_id in evidence_ids] or ["- none"])
        memory.upsert_keypoint(
            _keypoint_card_id(index), "\n".join(lines).rstrip() + "\n"
        )
    active_ids = {
        _keypoint_card_id(index) for index in range(1, len(findings_snapshot) + 1)
    }
    for path in memory.keypoints_dir.glob("KP-*.md"):
        if path.stem not in active_ids:
            path.unlink(missing_ok=True)


def sync_scope_candidates(memory: MemoryManager, db: CaseDB, objective: str) -> None:
    """Project ranked host/time candidates into Memory without excluding evidence."""
    scope = propose_scope_candidates(db, objective)
    lines = [
        "# Scope Candidates",
        "",
        f"- policy: {scope['policy']}",
        f"- objective: {scope['objective'] or '-'}",
        "",
        "## Hosts",
    ]
    for item in scope["hosts"]:
        lines.append(
            f"- {item['host']} | {item['relationship']} | events={item['event_count']} "
            f"| {item['first_seen'] or '?'}..{item['last_seen'] or '?'}"
        )
    if not scope["hosts"]:
        lines.append("- none observed")
    lines.extend(["", "## Time Candidates"])
    for item in scope["time_ranges"]:
        lines.append(
            f"- {item['start'] or '?'}..{item['end'] or '?'} | {item['relationship']}"
        )
    if not scope["time_ranges"]:
        lines.append("- none observed")
    memory.upsert_keypoint("SCOPE-CANDIDATES", "\n".join(lines).rstrip() + "\n")


def _sync_hypothesis_cards(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
) -> None:
    """Remove hypothesis memory files that no longer correspond to active or resolved hypotheses."""
    valid_ids = {
        re.sub(r"[^a-zA-Z0-9._-]+", "-", str(item.id).strip()).strip("-") or "unknown"
        for item in [*active_hypotheses, *resolved_hypotheses]
    }
    for path in memory.hypotheses_dir.glob("*.md"):
        if path.stem not in valid_ids:
            path.unlink(missing_ok=True)


def _init_session(
    case: Case,
    db: CaseDB,
    profile: str,
    base_url: str,
    model: str,
    template_root: Path | None,
    active_pack_ids: set[str] | None = None,
) -> tuple[SessionState, Ctx, MemoryManager, LLMCallLogger, str, datetime, Path]:
    """Initialize a new investigation session. Returns (state, ctx, memory, llm_logger, session_id, started_at, template_root)."""
    session_id = f"session-{uuid4().hex[:12]}"
    started_at = datetime.now(UTC).replace(tzinfo=None)
    memory = MemoryManager(
        case,
        summarize=lambda messages, m: chat_completion(
            messages=messages, model=m, base_url=base_url
        ),
    )
    profile_config = _load_profile_config(profile)
    if template_root is None:
        seed_case_report_templates(case)
        template_root = case.report_template_dir
    seed_findings(case, db, profile, active_pack_ids=active_pack_ids)
    refresh_evidence_coverage(db)
    _initialize_overview(memory, case, profile_config)
    _ensure_profile_objective(memory, profile_config)
    objective = ""
    if profile_config:
        objective = profile_config.get("objective", "")
    ensure_investigation_state(db, objective=objective)
    persisted_investigation = load_investigation_state(db) or {}
    ensure_objective_gap(db, str(persisted_investigation.get("objective") or ""))
    reopen_retryable_work(db)
    mark_investigation_started(db)
    sync_scope_candidates(
        memory, db, str(persisted_investigation.get("objective") or objective)
    )
    llm_logger = LLMCallLogger(case, session_id)
    active_hypotheses, resolved_hypotheses = load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id,
        iteration=0,
        findings_snapshot=_finding_snapshot(db),
        active_hypotheses=active_hypotheses,
        resolved_hypotheses=resolved_hypotheses,
    )
    _seed_rule_hypotheses(db, state, session_id, active_pack_ids=active_pack_ids)
    sync_keypoint_cards(memory, state.findings_snapshot)
    _sync_hypothesis_cards(memory, state.active_hypotheses, state.resolved_hypotheses)
    ctx = Ctx(report_status=_build_report_status(db))
    ctx_refresh_caches(ctx, memory, base_url, model, db=db, session_id=session_id)
    # Opening this writer means no older investigation process can still own
    # the same case DB. Reconcile receipts left running by SIGKILL, host loss,
    # or process termination before recording the new session. The reconcile
    # uses a conservative finish-time fallback (last observed step/event) and a
    # structured abandonment reason rather than collapsing wall time to
    # started_at (T-12.2).
    reconcile_stale_sessions(db)
    db.execute(
        "INSERT INTO investigation_sessions (session_id, started_at, finished_at, iterations, status) VALUES (?, ?, ?, ?, ?)",
        (session_id, started_at, None, 0, "running"),
    )
    return state, ctx, memory, llm_logger, session_id, started_at, template_root
