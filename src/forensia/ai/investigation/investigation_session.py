"""Investigation session context: setup, caches, step logging, card sync."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from forensia.ai.case_profile import propose_scope_candidates
from forensia.ai.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.ai.hypotheses.seeding import (
    _seed_rule_hypotheses,
)
from forensia.ai.investigation.case_policy import (
    CASE_POLICY_STEP_PHASE,
    CasePolicyInput,
    decide_policy,
    load_recorded_policy,
    policy_objective,
    sha256_hex,
)
from forensia.ai.investigation.work_state import (
    ensure_objective_gap,
    format_terminal_reason,
    reopen_retryable_work,
)
from forensia.ai.llm.llm_client import (
    LLMRequestTimeoutError,
    LLMServerUnavailableError,
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
from forensia.report.finding_themes import classify_finding_theme
from forensia.report.sections.report_input import REPORT_INPUT_PHASE
from forensia.report.template_export import seed_case_report_templates


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


# Session lease timeout used by startup crash recovery: only an expired lease
# may be abandoned (R07 keeps the writer-always-reasons contract; past terminal
# rows keep their original ``terminal_reason``).
_SESSION_LEASE_TIMEOUT_S = 600
_DEFAULT_INVESTIGATION_OBJECTIVE = (
    "Reconstruct evidence-backed activity and identify unresolved questions."
)


def persist_session_terminal_receipt(
    db: CaseDB,
    session_id: str,
    status: str,
    *,
    terminal_reason: str | None = None,
    finished_at: datetime | None = None,
    owner_id: str | None = None,
) -> None:
    """Persist the durable session terminal receipt before fallible projections.

    Always records ``finished_at`` (timezone-aware UTC) and a structured
    ``terminal_reason`` so a session never remains permanently ``running`` even
    if a later Memory/report/API projection fails (T-12.1).
    """
    finished = finished_at or datetime.now(UTC)
    reason = terminal_reason or format_terminal_reason(status)
    if owner_id:
        db.execute(
            "UPDATE investigation_sessions SET finished_at = ?, status = ?, "
            "terminal_reason = ?, phase = 'terminal', status_reason = ? "
            "WHERE session_id = ? AND owner_id = ?",
            (
                finished.replace(tzinfo=None),
                status,
                reason,
                reason,
                session_id,
                owner_id,
            ),
        )
    else:
        db.execute(
            "UPDATE investigation_sessions SET finished_at = ?, status = ?, "
            "terminal_reason = ?, phase = 'terminal', status_reason = ? "
            "WHERE session_id = ?",
            (finished.replace(tzinfo=None), status, reason, reason, session_id),
        )


def touch_session_heartbeat(
    db: CaseDB,
    session_id: str,
    owner_id: str,
    *,
    phase: str | None = None,
    reason: str | None = None,
) -> None:
    """Refresh the owning worker's lease without changing terminal state."""
    db.execute(
        "UPDATE investigation_sessions SET heartbeat_at = now(), "
        "phase = COALESCE(?, phase), status_reason = COALESCE(?, status_reason) "
        "WHERE session_id = ? AND owner_id = ? AND status = 'running'",
        (phase, reason, session_id, owner_id),
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

    Runs on startup (in ``_init_session``). Only an expired or legacy
    heartbeat may be abandoned; a live owner's lease is never changed by a
    different process. Past terminal rows keep whatever reason they were
    written with: the current writer always persists a ``terminal_reason``
    (T-12.1), so a missing reason stays as historical evidence instead of
    being fabricated from today's status (R07). Returns the number of
    sessions reconciled.
    """
    reconciled = 0
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(
        seconds=_SESSION_LEASE_TIMEOUT_S
    )
    running_rows = db.execute(
        "SELECT session_id, started_at, heartbeat_at FROM investigation_sessions "
        "WHERE status = 'running'"
    ).fetchall()
    active: list[str] = []
    for session_id, started_at, heartbeat_at in running_rows:
        if heartbeat_at is not None and heartbeat_at >= cutoff:
            active.append(str(session_id))
            continue
        finish = _conservative_finish_time(db, session_id, started_at)
        persist_session_terminal_receipt(
            db,
            str(session_id),
            "abandoned",
            terminal_reason=format_terminal_reason("abandoned"),
            finished_at=finish,
        )
        reconciled += 1
    if active:
        raise RuntimeError(
            "an investigation session already owns this case: " + ", ".join(active)
        )
    return reconciled


@dataclass
class Ctx:
    """Mutable per-session state shared across investigate() helpers."""

    interrupted: bool = False
    report_status: dict = field(default_factory=dict)
    memory_plan: str = ""
    current_hypothesis_id: str | None = None
    owner_id: str | None = None
    progress_callback: Callable[[dict[str, Any]], None] | None = None
    # Adopted FORENSIA.md investigation policy for this session (V2-05),
    # fixed at session start; None when no policy is in force.
    forensia_policy: Any = None


_MAX_OUTAGE_RETRIES_PER_CALL = 3


async def _call_with_outage_recovery(
    call_fn,
    base_url: str,
    model: str,
    _outage_progress_callback: Callable[[dict[str, Any]], None] | None = None,
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
            if _outage_progress_callback is None:
                await outage_wait_until_recovered(base_url, model)
            else:
                await outage_wait_until_recovered(
                    base_url,
                    model,
                    progress_callback=_outage_progress_callback,
                )
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
    current_hypothesis_id: str | None = None,
    hypothesis: Hypothesis | None = None,
    db: CaseDB | None = None,
    session_id: str | None = None,
) -> None:
    """Rebuild the scoped model-visible memory context.

    When *hypothesis* is provided, entity/keypoint files are filtered by
    relevance to it (G-3) — this cache is handed to the planner as its
    default context, so the filtering must happen here, not only in the
    lazy-load fallbacks inside the planner.
    """
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
        db,
        hypothesis_id,
        session_id,
        iteration,
        "settlement",
        body[:1000],
        verdict=final_verdict,
        query_id=query_id,
    )


def _initialize_overview(
    memory: MemoryManager, case: Case, objective: str = ""
) -> None:
    """Create the initial investigation overview memory file if it doesn't exist yet."""
    if memory.has_overview():
        return
    output_language = str(get_llm_settings()["output_language"]).lower()
    open_question_seed = {
        "en": "Awaiting initial investigation",
    }.get(output_language, "Awaiting initial investigation")
    objective_line = objective or _DEFAULT_INVESTIGATION_OBJECTIVE
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
    template_root: Path | None,
    *,
    report_only: bool = False,
    forensia_policy: CasePolicyInput | None = None,
    report_input_record: dict[str, Any],
) -> tuple[SessionState, Ctx, MemoryManager, str]:
    """Initialize a new investigation session and its durable state.

    With ``report_only=True`` the resume writes are skipped (R07): a report
    job does not reopen retryable work and does not mark the investigation
    started, so the Case stop state keeps the value of the last real stop.
    The FORENSIA.md policy (``forensia_policy``) is adopted here — the one
    safe run-start boundary — decided against the recorded receipt (resume
    re-applies the recorded revision; a differing file is surfaced
    explicitly), and the applied body/hash/source/roles are persisted as the
    session's ``forensia-md`` step (V2-05)."""
    session_id = f"session-{uuid4().hex[:12]}"
    started_at = datetime.now(UTC).replace(tzinfo=None)
    owner_id = f"worker-{uuid4().hex[:12]}"
    # Acquire the case's single-writer lease before any ingest, memory, or
    # investigation-state projection can mutate the case.  A live lease
    # aborts startup; only expired leases are reconciled.
    with db.transaction():
        reconcile_stale_sessions(db)
        db.execute(
            "INSERT INTO investigation_sessions (session_id, started_at, "
            "finished_at, iterations, status, owner_id, heartbeat_at, phase, "
            "status_reason) VALUES (?, ?, ?, ?, ?, ?, now(), ?, ?)",
            (
                session_id,
                started_at,
                None,
                0,
                "running",
                owner_id,
                "initializing",
                "session lease acquired",
            ),
        )
    try:
        memory = MemoryManager(case)
        if template_root is None:
            seed_case_report_templates(case)
            template_root = case.report_template_dir
        policy = decide_policy(forensia_policy, load_recorded_policy(db))
        ctx = Ctx(owner_id=owner_id)
        if policy.record is not None:
            _save_step(
                db=db,
                session_id=session_id,
                iteration=0,
                phase=CASE_POLICY_STEP_PHASE,
                hypothesis_id=None,
                input_json={
                    "designated": bool(forensia_policy),
                    "source": forensia_policy.source if forensia_policy else None,
                    "source_path": (
                        forensia_policy.source_path if forensia_policy else None
                    ),
                    "current_file_sha256": (
                        sha256_hex(forensia_policy.body) if forensia_policy else None
                    ),
                },
                output_json=policy.record,
            )
        _save_step(
            db=db,
            session_id=session_id,
            iteration=0,
            phase=REPORT_INPUT_PHASE,
            hypothesis_id=None,
            input_json={"source_path": report_input_record.get("source_path")},
            output_json=report_input_record,
        )
        ctx.forensia_policy = policy.applied
        policy_objective_line = (
            policy_objective(policy.applied) if policy.applied else ""
        )
        if not report_only:
            ensure_investigation_state(
                db,
                objective=policy_objective_line or _DEFAULT_INVESTIGATION_OBJECTIVE,
            )
            persisted_investigation = load_investigation_state(db) or {}
            ensure_objective_gap(
                db, str(persisted_investigation.get("objective") or "")
            )
        else:
            persisted_investigation = load_investigation_state(db) or {}
        effective_objective = str(
            persisted_investigation.get("objective")
            or policy_objective_line
            or _DEFAULT_INVESTIGATION_OBJECTIVE
        )
        _initialize_overview(memory, case, effective_objective)
        if not report_only:
            reopen_retryable_work(db)
            mark_investigation_started(db)
        sync_scope_candidates(
            memory,
            db,
            str(persisted_investigation.get("objective") or effective_objective),
        )
        active_hypotheses, resolved_hypotheses = load_persisted_hypotheses(db)
        state = SessionState(
            session_id=session_id,
            iteration=0,
            findings_snapshot=_finding_snapshot(db),
            active_hypotheses=active_hypotheses,
            resolved_hypotheses=resolved_hypotheses,
        )
        if not report_only:
            _seed_rule_hypotheses(db, state, session_id)
        sync_keypoint_cards(memory, state.findings_snapshot)
        _sync_hypothesis_cards(
            memory, state.active_hypotheses, state.resolved_hypotheses
        )
        ctx.report_status = _build_report_status(db)
        ctx_refresh_caches(ctx, memory, db=db, session_id=session_id)
        return state, ctx, memory, session_id
    except Exception:
        persist_session_terminal_receipt(
            db,
            session_id,
            "failed",
            terminal_reason="exception: session initialization failed",
            finished_at=datetime.now(UTC).replace(tzinfo=None),
            owner_id=owner_id,
        )
        raise
