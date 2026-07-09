"""Investigation session context: setup, caches, step logging, card sync."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from re import sub
from typing import Any
from uuid import uuid4

import yaml

from forensia.ai.audit import LLMCallLogger
from forensia.ai.hypothesis_manager import (
    _load_persisted_hypotheses,
)
from forensia.ai.llm_client import (
    LLMServerUnavailableError,
    chat_completion,
    outage_wait_until_recovered,
)
from forensia.ai.report_gap import (
    _build_report_status,
    _overlay_report_status,
)
from forensia.ai.seeding import (
    _seed_findings,
    _seed_rule_hypotheses,
)
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


def _to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


@dataclass
class _Ctx:
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
        except LLMServerUnavailableError:
            if attempt >= _MAX_OUTAGE_RETRIES_PER_CALL:
                raise
            await outage_wait_until_recovered(base_url, model)
    raise LLMServerUnavailableError("Outage recovery failed")


def _ctx_get_report_status(
    ctx: _Ctx,
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


def _ctx_refresh_caches(
    ctx: _Ctx,
    memory: MemoryManager,
    base_url: str,
    model: str,
    current_hypothesis_id: str | None = None,
    hypothesis: Hypothesis | None = None,
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
    ctx.memory_plan = memory.load_investigation_context(
        current_hypothesis_id,
        relevance_terms=relevance_terms or None,
        max_bytes=max(1024, memory.max_bytes // 3),
        include_overview=False,
    )
    ctx.memory_check = memory.load_investigation_context(
        current_hypothesis_id,
        relevance_terms=relevance_terms or None,
        max_bytes=max(1024, memory.max_bytes // 2),
        include_overview=False,
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


def _append_hypothesis_reasoning(
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


def _load_profile_config(profile: str) -> dict[str, Any]:
    """Load the YAML configuration for a given profile name."""
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    if not profile_path.exists():
        return {}
    return yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}


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
    """Fetch the top findings ordered by confidence and recency."""
    return fetch_records(
        db,
        """
        SELECT finding_id, title, summary, severity, confidence, status, evidence
        FROM findings
        ORDER BY confidence DESC, created_at DESC
        LIMIT ?
        """,
        (limit,),
    )


def _keypoint_card_id(index: int) -> str:
    return f"KP-{index:04d}"


def _sync_keypoint_cards(
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
            "",
            "## Summary",
            str(finding.get("summary") or "").strip() or "-",
            "",
            "## Evidence IDs",
        ]
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


def _sync_hypothesis_cards(
    memory: MemoryManager,
    active_hypotheses: list[Hypothesis],
    resolved_hypotheses: list[Hypothesis],
) -> None:
    """Remove hypothesis memory files that no longer correspond to active or resolved hypotheses."""
    valid_ids = {
        sub(r"[^a-zA-Z0-9._-]+", "-", str(item.id).strip()).strip("-") or "unknown"
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
) -> tuple[SessionState, _Ctx, MemoryManager, LLMCallLogger, str, datetime, Path]:
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
        case.ensure_report_templates()
        template_root = case.report_template_dir
    _seed_findings(case, db, profile, active_pack_ids=active_pack_ids)
    _initialize_overview(memory, case, profile_config)
    _ensure_profile_objective(memory, profile_config)
    llm_logger = LLMCallLogger(case, session_id)
    active_hypotheses, resolved_hypotheses = _load_persisted_hypotheses(db)
    state = SessionState(
        session_id=session_id,
        iteration=0,
        findings_snapshot=_finding_snapshot(db),
        active_hypotheses=active_hypotheses,
        resolved_hypotheses=resolved_hypotheses,
    )
    _seed_rule_hypotheses(db, state, session_id, active_pack_ids=active_pack_ids)
    _sync_keypoint_cards(memory, state.findings_snapshot)
    _sync_hypothesis_cards(memory, state.active_hypotheses, state.resolved_hypotheses)
    ctx = _Ctx(report_status=_build_report_status(db))
    _ctx_refresh_caches(ctx, memory, base_url, model)
    db.execute(
        "INSERT INTO investigation_sessions (session_id, started_at, finished_at, iterations, status) VALUES (?, ?, ?, ?, ?)",
        (session_id, started_at, None, 0, "running"),
    )
    return state, ctx, memory, llm_logger, session_id, started_at, template_root

