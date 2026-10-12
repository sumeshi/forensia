"""Investigation session setup, leases, and durable step logging."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from forensia.config import get_settings
from forensia.context.investigation_candidates import build_investigation_candidates
from forensia.core.case import Case
from forensia.core.progress_event import progress_event
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.db.investigation_state import (
    ensure_investigation_state,
    load_investigation_state,
    mark_investigation_started,
)
from forensia.investigation.case_policy import (
    CASE_POLICY_STEP_PHASE,
    CasePolicyInput,
    decide_policy,
    load_recorded_policy,
    policy_objective,
    sha256_hex,
)
from forensia.investigation.hypotheses.hypothesis_store import load_persisted_hypotheses
from forensia.investigation.hypotheses.seeding import (
    _seed_rule_hypotheses,
)
from forensia.investigation.work_state import (
    ensure_objective_gap,
    format_terminal_reason,
    reopen_retryable_work,
)
from forensia.llm.llm_client import (
    LLMRequestTimeoutError,
    LLMServerUnavailableError,
    outage_wait_until_recovered,
)
from forensia.llm.telemetry import interrupt_open_calls
from forensia.report.sections.report_input import REPORT_INPUT_PHASE
from forensia.report.sections.status import build_report_status, overlay_report_status
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
    if a later report/API projection fails (T-12.1).
    """
    finished = finished_at or datetime.now(UTC)
    reason = terminal_reason or format_terminal_reason(status)
    if owner_id:
        db.execute(
            "UPDATE trace.investigation_sessions SET finished_at = ?, status = ?, "
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
            "UPDATE trace.investigation_sessions SET finished_at = ?, status = ?, "
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
        "UPDATE trace.investigation_sessions SET heartbeat_at = now(), "
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
        "SELECT MAX(created_at) FROM trace.investigation_steps WHERE session_id = ?",
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


def reconcile_stale_sessions(db: CaseDB, *, recovered_owner: bool = False) -> int:
    """Reconcile stale ``running`` sessions into a structured terminal state.

    A caller holding the external writer lock may recover any unfinished
    session. Other callers can recover only expired heartbeats and refuse a
    live lease. Past terminal rows keep whatever reason they were
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
        "SELECT session_id, started_at, heartbeat_at FROM trace.investigation_sessions "
        "WHERE status = 'running'"
    ).fetchall()
    active: list[str] = []
    for session_id, started_at, heartbeat_at in running_rows:
        if not recovered_owner and heartbeat_at is not None and heartbeat_at >= cutoff:
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
        interrupt_open_calls(db, str(session_id))
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
                await outage_wait_until_recovered(base_url)
            else:
                await outage_wait_until_recovered(
                    base_url,
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
        ctx.report_status = build_report_status(db)
        return overlay_report_status(
            ctx.report_status,
            current_section=current_section,
            focus_sections=focus_sections,
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
    if hypothesis_id and not (suffix or "").startswith(f"{hypothesis_id}-"):
        step_id = f"{step_id}-{hypothesis_id}"
    if suffix:
        step_id = f"{step_id}-{suffix}"
    attempt_ref = (
        input_json.get("attempt_ref") if isinstance(input_json, dict) else None
    )
    if isinstance(output_json, dict):
        attempt_ref = attempt_ref or output_json.get("attempt_ref")
        attempt = output_json.get("attempt")
        if isinstance(attempt, dict):
            attempt_ref = attempt_ref or attempt.get("attempt_ref")
    if attempt_ref:
        step_id = f"{step_id}-{attempt_ref}"
    db.execute(
        """
        INSERT INTO trace.investigation_steps (
            step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (step_id) DO UPDATE SET
            input_json = excluded.input_json,
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
    session_id: str,
    iteration: int,
    phase: str,
    query_id: str | None,
) -> str:
    """Generate a deterministic SHA1-based ID for a reasoning entry."""
    body = f"{session_id}-{hypothesis_id}-{iteration}-{phase}-{query_id or '-'}"
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
    entry_id = _reasoning_entry_id(
        hypothesis_id, session_id, iteration, phase, query_id
    )
    db.execute(
        """
        INSERT INTO trace.hypothesis_reasoning (
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


def _finding_snapshot(db: CaseDB, limit: int = 20) -> list[dict[str, Any]]:
    """Fetch the shared bounded candidate projection from the complete current match set."""
    projection = build_investigation_candidates(db, limit)
    projected = projection["candidates"]
    generated_at = datetime.now(UTC).isoformat()
    for index, item in enumerate(projected):
        item["projection_revision"] = item["candidate_fingerprint"]
        item["projection_generated_at"] = generated_at
        item["projection_state"] = "in-progress"
        if index == 0:
            item["projection_counts"] = projection["counts"]
    return projected


def _init_session(
    case: Case,
    db: CaseDB,
    template_root: Path | None,
    *,
    report_only: bool = False,
    forensia_policy: CasePolicyInput | None = None,
    report_input_record: dict[str, Any],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    manual_resume: bool = False,
) -> tuple[SessionState, Ctx, str]:
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
    # Runtime holds the external writer lock before ingestion. The session
    # lease tracks investigation lifecycle separately from process ownership.
    with db.transaction():
        reconcile_stale_sessions(
            db, recovered_owner=getattr(db, "runtime_owned", False)
        )
        db.execute(
            "INSERT INTO trace.investigation_sessions (session_id, started_at, "
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
        if template_root is None:
            seed_case_report_templates(case)
            template_root = case.report_template_dir
        policy = decide_policy(forensia_policy, load_recorded_policy(db))
        ctx = Ctx(owner_id=owner_id)
        adopted_settings = asdict(get_settings())
        adopted_settings.pop("llm_api_key", None)
        _save_step(
            db=db,
            session_id=session_id,
            iteration=0,
            phase="session-settings",
            hypothesis_id=None,
            input_json={},
            output_json=adopted_settings,
        )
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
        if not report_only:
            reopen_retryable_work(db, manual_resume=manual_resume)
            mark_investigation_started(db)
        active_hypotheses, resolved_hypotheses = load_persisted_hypotheses(db)
        state = SessionState(
            session_id=session_id,
            iteration=0,
            active_hypotheses=active_hypotheses,
            resolved_hypotheses=resolved_hypotheses,
        )
        if not report_only:
            seeded_hypothesis_ids = _seed_rule_hypotheses(db, state, session_id)
            if seeded_hypothesis_ids and progress_callback:
                progress_callback(
                    progress_event(
                        "hypothesis.seeded",
                        "completed",
                        severity="success",
                        reason="rule_declared_hypothesis_admitted",
                        refs={"hypothesis_ids": seeded_hypothesis_ids[:20]},
                        stage="seed",
                        session_id=session_id,
                        summary=f"seeded {len(seeded_hypothesis_ids)} rule-declared hypotheses",
                    )
                )
        ctx.report_status = build_report_status(db)
        return state, ctx, session_id
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
