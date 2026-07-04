from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
import re
import signal
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from re import sub
from typing import Any
from uuid import uuid4

import httpx
import yaml
from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    _format_case_profile,
    build_case_profile,
    get_profile_event_ids,
    set_case_profile,
)
from forensia.ai.checker import check_query_result, summarize_query_result
from forensia.ai.hypothesis_manager import (
    _filter_valid_entities,
    _all_hypotheses,
    _guess_related_sections,
    _hypothesis_similarity,
    _load_persisted_hypotheses,
    _merge_active_hypotheses,
    _resolve_hypothesis,
    _upsert_hypothesis,
    admit_new_hypothesis,
)
from forensia.ai.json_response import request_llm_json
from forensia.ai.llm_client import (
    LLMServerUnavailableError,
    chat_completion,
    outage_wait_until_recovered,
)
from forensia.ai.memory_sync import _apply_memory_updates
from forensia.ai.planner import _compute_uncovered_keypoints, plan_hypothesis_query
from forensia.ai.progress import HypothesisProgressTracker, _query_fingerprint
from forensia.ai.prompts import (
    build_gap_identifier_messages,
    build_hypothesis_drafter_messages,
    resolve_rule_context,
)
from forensia.ai.report_gap import (
    _build_report_status,
    _inject_gap_hypotheses,
    _overlay_report_status,
    _report_cycle_progress,
)
from forensia.ai.section_refresher import async_refresh_report_sections
from forensia.ai.seeding import (
    _scan_report_keypoints,
    _seed_findings,
    _seed_rule_hypotheses,
)
from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.session import HistoryEntry, Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.report.writer import (
    REPORT_KEYPOINTS,
    mark_report_sections_ai_exhausted,
    render_written_report,
)
from forensia.rules.engine import (
    execute_event_keyword_fallback_search,
    execute_fallback_search,
)
from forensia.rules.loader import _get_rule_cache, load_rule_by_id, resolve_active_packs


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


def _has_zero_rows_refute_condition(hypothesis: Hypothesis) -> bool:
    """Check whether a hypothesis has a rule-declared refute_when with zero_rows condition."""
    refute_when = hypothesis.refute_when or {}
    if refute_when.get("zero_rows"):
        return True
    for source_rule_id in hypothesis.source_rule_ids:
        rule = load_rule_by_id(source_rule_id)
        if rule and rule.hypotheses:
            for decl in rule.hypotheses:
                if (
                    decl.id == hypothesis.id
                    and decl.refute_when
                    and decl.refute_when.get("zero_rows")
                ):
                    return True
    return False


def _unavailable_missing_event_ids(
    missing_questions: list[Any],
    available_event_ids: set[int] | None,
) -> list[int]:
    """Return event IDs referenced by the check's missing_questions that the case
    telemetry cannot contain.

    Returns an empty list (i.e. "keep investigating") when:
    - no availability profile is set,
    - the missing questions reference no known event IDs,
    - at least one referenced event ID exists in the case, or
    - the missing questions also point at an artifact-table alternative
      (mft_*/prefetch_*), which remains testable without those event IDs.
    """
    if not available_event_ids or not missing_questions:
        return []
    from forensia.ai.prompts import _load_event_id_hints

    vocabulary = set(_load_event_id_hints().keys())
    if not vocabulary:
        return []
    missing_text = " ".join(str(q).lower() for q in missing_questions if q)
    referenced = {
        int(m) for m in re.findall(r"\b(\d{3,5})\b", missing_text)
    } & vocabulary
    if not referenced:
        return []
    if referenced & available_event_ids:
        return []
    if any(
        t in missing_text for t in ("mft_entries", "mft_timeline", "prefetch", "mft ")
    ):
        return []
    return sorted(referenced)


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


def _matching_findings(
    snapshot: list[dict[str, Any]], hypothesis: Hypothesis | None
) -> list[dict[str, Any]]:
    """Return findings whose title/summary/severity share tokens with the hypothesis description."""
    if hypothesis is None:
        return snapshot[:10]
    words = {
        token.lower() for token in hypothesis.description.split() if len(token) >= 3
    }
    if not words:
        return snapshot[:10]
    matched = []
    for finding in snapshot:
        haystack = " ".join(
            str(finding.get(key, "") or "")
            for key in ("title", "summary", "severity", "status")
        ).lower()
        if any(word in haystack for word in words):
            matched.append(finding)
    return matched[:10] if matched else snapshot[:10]


def _observed_keypoints_from_findings(
    snapshot: list[dict[str, Any]], limit: int = 20
) -> list[str]:
    """Format findings as human-readable keypoint labels for LLM context."""
    keypoints: list[str] = []
    for item in snapshot[:limit]:
        title = str(item.get("title") or "").strip()
        finding_id = str(item.get("finding_id") or "").strip()
        if not title:
            continue
        if finding_id:
            keypoints.append(f"{finding_id}: {title}")
        else:
            keypoints.append(title)
    return keypoints


def _normalize_hypothesis_tokens(text: str) -> set[str]:
    import re

    return {
        token
        for token in re.findall(r"[a-z0-9]+", str(text).lower())
        if len(token) >= 3
    }


def _audit_broad_plan_hypotheses(
    state: SessionState,
    hypotheses: list[Hypothesis],
) -> list[dict[str, Any]]:
    """Classify each new hypothesis as new/duplicate/follow_up/related against existing ones."""
    audits: list[dict[str, Any]] = []
    existing = [*state.active_hypotheses, *state.resolved_hypotheses]
    for hyp in hypotheses:
        best_match: Hypothesis | None = None
        best_score = 0.0
        hyp_tokens = _normalize_hypothesis_tokens(hyp.description)
        for candidate in existing:
            candidate_tokens = _normalize_hypothesis_tokens(candidate.description)
            if not hyp_tokens or not candidate_tokens:
                continue
            union = hyp_tokens | candidate_tokens
            score = len(hyp_tokens & candidate_tokens) / len(union)
            if score > best_score:
                best_score = score
                best_match = candidate
        if best_match is None:
            relation = "new"
        elif best_score >= 0.75:
            relation = "duplicate"
        elif set(hyp.source_rule_ids) & set(best_match.source_rule_ids):
            relation = "follow_up"
        else:
            relation = "related"
        audits.append(
            {
                "hypothesis_id": hyp.id,
                "description": hyp.description,
                "relation": relation,
                "matched_hypothesis_id": best_match.id if best_match else None,
                "similarity": round(best_score, 3),
            }
        )
    return audits


def _hypothesis_focus_score(
    state: SessionState, hypothesis: Hypothesis
) -> tuple[int, int, int, int]:
    """Rank hypotheses by fairness first, then rough confidence.

    Newly drafted hypotheses must get at least one investigation pass. Otherwise
    high-confidence but repeatedly inconclusive hypotheses monopolize every
    cycle and later hypotheses remain visibly half-started in the report/API.
    """
    recent_iteration = -1
    for entry in reversed(state.history):
        if entry.hypothesis_id == hypothesis.id:
            recent_iteration = int(entry.iteration)
            break
    confidence_proxy = len(hypothesis.source_rule_ids) + (
        1 if hypothesis.required_entities else 0
    )
    never_investigated = 1 if recent_iteration < 0 else 0
    least_recent_first = -recent_iteration if recent_iteration >= 0 else 0
    return (
        never_investigated,
        least_recent_first,
        confidence_proxy,
        -len(hypothesis.description),
    )


def _select_focus_hypotheses(
    state: SessionState, max_items: int = 2
) -> list[Hypothesis]:
    ranked = sorted(
        state.active_hypotheses,
        key=lambda item: _hypothesis_focus_score(state, item),
        reverse=True,
    )
    return ranked[: max(1, max_items)] if ranked else []


def _final_summary(state: SessionState) -> str:
    """Build a human-readable summary of the investigation outcome."""
    if state.resolved_hypotheses:
        lines = []
        for item in state.resolved_hypotheses[-5:]:
            verdict = item.verdict or item.status
            lines.append(
                f"[{verdict}] {item.description}: {item.summary or 'summary unavailable'}"
            )
        return "\n".join(lines)
    if state.history:
        return "\n".join(entry.summary for entry in state.history[-5:] if entry.summary)
    output_language = str(get_llm_settings()["output_language"]).lower()
    return {
        "en": "No additional progress was made during this investigation.",
    }.get(output_language, "No additional progress was made during this investigation.")


async def _investigate_one_hypothesis(
    hypothesis: Hypothesis,
    state: SessionState,
    ctx: _Ctx,
    memory: MemoryManager,
    db: CaseDB,
    base_url: str,
    model: str,
    plan_cycle: int,
    llm_logger: LLMCallLogger,
    session_id: str,
    max_queries_per_hypothesis: int,
    case: Case,
    query_limit: int | None = None,
    emit_fn: Callable[..., None] | None = None,
    llm_status_fn: Callable[[str], None] | None = None,
    case_profile_str: str | None = None,
) -> tuple[bool, SessionState, dict[str, str]]:
    """Investigate a single hypothesis with full emit/save/memory lifecycle.
    Returns (cycle_progress, updated_state, focus_sections).
    """
    candidates = _matching_findings(state.findings_snapshot, hypothesis)
    tracker = HypothesisProgressTracker()
    cycle_progress = False
    focus_sections = _guess_related_sections(hypothesis.description)
    limit = query_limit if query_limit is not None else max_queries_per_hypothesis
    for query_index in range(1, limit + 1):
        state.focus_depth = query_index
        try:
            hypothesis_plan = await _call_with_outage_recovery(
                plan_hypothesis_query,
                base_url=base_url,
                model=model,
                state=state,
                hypothesis=hypothesis,
                memory=memory,
                db=db,
                overview_md=ctx.memory_overview,
                default_context_md=ctx.memory_plan,
                status_callback=llm_status_fn
                or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
                audit_callback=lambda msgs, out, parsed, hid=hypothesis.id, qi=query_index: (
                    llm_logger.write(
                        iteration=plan_cycle,
                        phase="plan-hypothesis",
                        input_messages=msgs,
                        output=parsed,
                        model=model,
                        base_url=base_url,
                        suffix=f"{hid}-{qi:02d}",
                    )
                ),
                query_index=query_index,
                time_range=case.time_range,
                case_profile=case_profile_str,
            )
        except Exception as exc:
            err_msg = f"[plan-hypothesis] LLM failed for {hypothesis.id}: {exc}"
            print(f"[red]{err_msg}[/red]")
            _append_hypothesis_reasoning(
                db=db,
                hypothesis_id=hypothesis.id,
                session_id=session_id,
                iteration=plan_cycle,
                phase="error",
                body=f"[internal-error] {err_msg}",
            )
            break
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="plan-hypothesis",
            hypothesis_id=hypothesis.id,
            input_json={
                "hypothesis": hypothesis.model_dump(),
                "query_index": query_index,
            },
            output_json=hypothesis_plan.raw_response,
            suffix=f"{hypothesis.id}-{query_index:02d}",
        )
        if hypothesis_plan.hypothesis is not None:
            hypothesis = hypothesis_plan.hypothesis
            _upsert_hypothesis(
                db, hypothesis, origin="broad_plan", session_id=session_id
            )
        if not hypothesis_plan.query:
            if not hypothesis_plan.needs_more:
                break
            continue
        planned_query = hypothesis_plan.query
        reasoning_entry_id = _append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="plan",
            body=planned_query.purpose,
            query_id=planned_query.query_id,
        )
        _log(
            "QUERY",
            f"{hypothesis.id} {planned_query.query_id} — {planned_query.purpose}",
        )
        if emit_fn:
            emit_fn(
                "investigate/do",
                f"[do] {planned_query.query_id}: {planned_query.purpose}",
                iteration=plan_cycle,
                report_kw={"focus_sections": focus_sections},
                current_query=planned_query.query_id,
                hypothesis_id=hypothesis.id,
                reasoning_entry_id=reasoning_entry_id,
            )
        query_fp = _query_fingerprint(planned_query.sql)
        try:
            rows = fetch_records(db, planned_query.sql)
            _log("EXEC", f"{hypothesis.id} {planned_query.query_id} — {len(rows)} rows")
            fallback_info = None
            if len(rows) == 0 and hypothesis.source_rule_ids:
                for source_rule_id in hypothesis.source_rule_ids:
                    rule = load_rule_by_id(source_rule_id)
                    if rule and rule.fallback_search:
                        for fallback in rule.fallback_search:
                            if isinstance(fallback, dict):
                                ph = fallback.get("phase")
                                if ph not in {
                                    "keyword_in_raw_json",
                                    "related_event_ids",
                                    "artifact_table",
                                }:
                                    continue
                                fb_rows = execute_fallback_search(db, fallback)
                                if fb_rows:
                                    _log(
                                        "FALLBACK",
                                        f"{hypothesis.id} — found {len(fb_rows)} rows via {ph}",
                                    )
                                    for r in fb_rows[:20]:
                                        if isinstance(r, dict):
                                            r["_fallback_phase"] = ph
                                            r["_fallback_source_rule_id"] = (
                                                source_rule_id
                                            )
                                    rows = fb_rows[:20]
                                    fallback_info = {
                                        "phase": ph,
                                        "source_rule_id": source_rule_id,
                                    }
                                    break
                        if fallback_info:
                            break
            if len(rows) == 0 and fallback_info is None:
                fb_rows, fb_info = execute_event_keyword_fallback_search(
                    db, planned_query.sql
                )
                if fb_rows:
                    _log(
                        "FALLBACK",
                        f"{hypothesis.id} — found {len(fb_rows)} rows via keyword_in_raw_json"
                        + (
                            f" event_ids={fb_info.get('event_ids', [])} keywords={fb_info.get('keywords', [])}"
                            if fb_info
                            else ""
                        ),
                    )
                    for r in fb_rows[:20]:
                        if isinstance(r, dict):
                            r["_fallback_phase"] = "keyword_in_raw_json"
                            r["_fallback_source_rule_id"] = "event_id_schema"
                    rows = fb_rows[:20]
                    fallback_info = fb_info or {
                        "phase": "keyword_in_raw_json",
                        "source_rule_id": "event_id_schema",
                    }
                    fallback_info["query_sql"] = planned_query.sql
        except Exception as exc:
            err_msg = str(exc)
            tracker.record(query_fp, verdict="exec_error", row_count=0)
            print(
                f"[red]SQL execution error — {planned_query.query_id}: {err_msg}[/red]"
            )
            if emit_fn:
                emit_fn(
                    "investigate/do",
                    f"[do] SQL execution error — {planned_query.query_id}: {err_msg}",
                    iteration=plan_cycle,
                    hypothesis_id=hypothesis.id,
                )
            _append_hypothesis_reasoning(
                db=db,
                hypothesis_id=hypothesis.id,
                session_id=session_id,
                iteration=plan_cycle,
                phase="error",
                body=f"[internal-error] SQL execution error: {err_msg}",
                query_id=planned_query.query_id,
            )
            state.last_execution_error = {
                "query_id": planned_query.query_id,
                "sql": planned_query.sql,
                "error": err_msg[:500],
            }
            continue
        result_summary = summarize_query_result(rows)
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="do",
            hypothesis_id=hypothesis.id,
            input_json={
                "planned_query": planned_query.model_dump(),
                "query_index": query_index,
            },
            output_json=result_summary,
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        try:
            check_result = check_query_result(
                case=case,
                db=db,
                session_id=session_id,
                planned_query=planned_query,
                hypothesis=hypothesis,
                finding_candidates=candidates,
                result_summary=result_summary,
                memory=memory,
                base_url=base_url,
                model=model,
                overview_md=ctx.memory_overview,
                memory_context_md=ctx.memory_check,
                status_callback=llm_status_fn
                or (lambda msg: print(f"[yellow]{msg}[/yellow]")),
                fallback_info=fallback_info,
                audit_callback=lambda phase, msgs, out, parsed: llm_logger.write(
                    iteration=plan_cycle,
                    phase=phase,
                    input_messages=msgs,
                    output=parsed,
                    model=model,
                    base_url=base_url,
                ),
            )
        except Exception as exc:
            err_msg = f"[check] LLM failed for {hypothesis.id}/{planned_query.query_id}: {exc}"
            print(f"[red]{err_msg}[/red]")
            _append_hypothesis_reasoning(
                db=db,
                hypothesis_id=hypothesis.id,
                session_id=session_id,
                iteration=plan_cycle,
                phase="error",
                body=f"[internal-error] {err_msg}",
                query_id=planned_query.query_id,
            )
            continue
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="check",
            hypothesis_id=hypothesis.id,
            input_json={
                "planned_query": planned_query.model_dump(),
                "hypothesis": hypothesis.model_dump(),
                "result_summary": result_summary,
            },
            output_json=check_result.raw_response,
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        reasoning_entry_id = _append_hypothesis_reasoning(
            db=db,
            hypothesis_id=hypothesis.id,
            session_id=session_id,
            iteration=plan_cycle,
            phase="check",
            body=check_result.report_text,
            verdict=check_result.verdict,
            query_id=planned_query.query_id,
        )
        chk_txt = (check_result.report_text or "").strip().replace("\n", " ")
        if len(chk_txt) > 120:
            chk_txt = chk_txt[:117] + "..."
        _log(
            "CHECK",
            f"{hypothesis.id} {planned_query.query_id} — verdict={check_result.verdict}"
            + (f": {chk_txt}" if chk_txt else ""),
        )
        if emit_fn:
            emit_fn(
                "investigate/check",
                f"[check] {hypothesis.id}: verdict={check_result.verdict} query={planned_query.query_id}",
                iteration=plan_cycle,
                report_kw={"focus_sections": focus_sections},
                current_query=planned_query.query_id,
                hypothesis_id=hypothesis.id,
                reasoning_entry_id=reasoning_entry_id,
            )
        state.history.append(
            HistoryEntry(
                iteration=plan_cycle,
                query_id=planned_query.query_id,
                hypothesis_id=hypothesis.id,
                verdict=check_result.verdict,
                summary=check_result.report_text,
                evidence_ids=result_summary.get("evidence_ids", []),
                template_id=planned_query.template_id,
                params=planned_query.params,
                purpose=planned_query.purpose,
            )
        )
        state.history = state.history[-50:]
        if check_result.new_hypotheses:
            # --- Unified admission gate (G-5) ---
            admitted = []
            for hyp in check_result.new_hypotheses:
                ok, reason = admit_new_hypothesis(hyp, state)
                if ok:
                    admitted.append(hyp)
                else:
                    _log(
                        "HYPOTHESIS",
                        f"check_new rejected: '{hyp.description[:80]}' reason={reason}",
                    )
            if admitted:
                state.active_hypotheses = _merge_active_hypotheses(
                    db=db,
                    current=state.active_hypotheses,
                    updates=admitted,
                    resolved=state.resolved_hypotheses,
                    session_id=session_id,
                    origin="check_new",
                )
        if check_result.verdict in {"confirmed", "refuted", "untestable"}:
            _resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hypothesis.id,
                verdict=check_result.verdict,
                summary=check_result.report_text,
                session_id=session_id,
                sample_rows=rows,
            )
            _log(
                "RESOLVE",
                f"{hypothesis.id} — {check_result.verdict} (resolved={len(state.resolved_hypotheses)})",
            )
            cycle_progress = True
        elif check_result.verdict == "newlead" or check_result.progress:
            cycle_progress = True
            _upsert_hypothesis(
                db=db,
                hypothesis=Hypothesis(
                    id=hypothesis.id,
                    description=hypothesis.description,
                    status="active",
                    verdict=None,
                    summary=check_result.report_text,
                ),
                origin="check_new",
                session_id=session_id,
            )
        _apply_memory_updates(
            memory=memory,
            active_hypotheses=state.active_hypotheses,
            resolved_hypotheses=state.resolved_hypotheses,
            check_output={
                **check_result.raw_response,
                "memory_updates": check_result.memory_updates,
                "suspicious_evidence": check_result.suspicious_evidence,
            },
            current_hypothesis_id=hypothesis.id,
            db=db,
            query_id=planned_query.query_id,
            hypothesis_description=hypothesis.description,
        )
        # R3-09: Collapse refuted-template overview lines into counter
        memory.collapse_refuted_overview_lines()
        try:
            memory.compact_overview_if_needed(base_url=base_url, model=model)
            memory.compact_oversized_with_llm(base_url=base_url, model=model)
        except Exception as exc:
            print(f"[yellow][memory] compaction failed: {exc}[/yellow]")
        if check_result.verdict == "confirmed":
            memory.promote_hypothesis_scratch(hypothesis.id)
        elif check_result.verdict == "refuted":
            memory.archive_hypothesis_scratch(hypothesis.id)
        elif check_result.verdict == "untestable":
            memory.archive_untestable_hypothesis_scratch(hypothesis.id)
        _ctx_refresh_caches(ctx, memory, base_url, model, hypothesis=hypothesis)
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="act",
            hypothesis_id=hypothesis.id,
            input_json={
                "hypothesis_id": hypothesis.id,
                "query_id": planned_query.query_id,
            },
            output_json={
                "verdict": check_result.verdict,
                "active_hypotheses": [h.model_dump() for h in state.active_hypotheses],
                "resolved_hypotheses": [
                    h.model_dump() for h in state.resolved_hypotheses
                ],
            },
            suffix=f"{planned_query.query_id}-{query_index:02d}",
        )
        if emit_fn:
            emit_fn(
                "investigate/act",
                f"[act] {hypothesis.id}: verdict={check_result.verdict} resolved={len(state.resolved_hypotheses)}",
                iteration=plan_cycle,
                report_kw={"focus_sections": focus_sections},
            )
        if check_result.verdict in {"confirmed", "refuted", "untestable"}:
            break
        row_count = int(result_summary.get("row_count") or 0)
        query_fp = _query_fingerprint(planned_query.sql)
        tracker.record(query_fp, check_result.verdict, row_count)

        def _rationale_signature(rationale: str) -> str:
            eids = sorted(
                set(re.findall(r"\b(?:event\s*id\s*)?(\d{3,5})\b", rationale.lower()))
            )
            keywords = sorted(
                set(
                    re.findall(
                        r"\b(missing|requires|correlation|not\s+present|absent)\b",
                        rationale.lower(),
                    )
                )
            )
            return "eid:" + ",".join(eids) + "|kw:" + ",".join(keywords)

        missing_checks_raw = (
            check_result.raw_response.get("missing_questions")
            or check_result.raw_response.get("missing_checks")
            or []
        )
        missing_signature = "|".join(
            sorted(str(q).lower().strip() for q in missing_checks_raw if q)
        ) or _rationale_signature(
            str(
                check_result.report_text
                or check_result.raw_response.get("rationale", "")
            )
        )
        tracker.register_check(check_result.verdict, row_count, missing_signature)
        # T-05b: when the only missing evidence is event IDs the case telemetry
        # cannot contain, resolve untestable now instead of looping 3 cycles.
        if check_result.verdict == "inconclusive":
            unavailable_ids = _unavailable_missing_event_ids(
                missing_checks_raw, get_profile_event_ids()
            )
            if unavailable_ids:
                id_list = ", ".join(str(eid) for eid in unavailable_ids)
                _log(
                    "RESOLVE",
                    f"{hypothesis.id} — untestable: missing event IDs [{id_list}] are not in case telemetry",
                )
                _resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id=hypothesis.id,
                    verdict="untestable",
                    summary=f"Untestable: verification requires event IDs [{id_list}] which are not present in the available telemetry — absence of telemetry is not a disproof.",
                    session_id=session_id,
                )
                cycle_progress = True
                break
        if tracker.should_pivot():
            _log(
                "PIVOT",
                f"{hypothesis.id} — duplicate query fingerprint detected, auto-exhausted",
            )
            break
        rule_context = resolve_rule_context(hypothesis)
        partial_confirm_signal = tracker.has_partial_confirm_signal(
            rule_context, rows, hypothesis
        )
        if (
            tracker.should_auto_refute(consecutive_threshold=3)
            and not partial_confirm_signal
        ):
            has_rule_refute = _has_zero_rows_refute_condition(hypothesis)
            if has_rule_refute:
                verdict = "refuted"
                summary = "Auto-refuted: repeated 0-row inconclusive results, consistent with rule-declared refute_when.zero_rows condition."
            else:
                verdict = "untestable"
                missing_eids = sorted(
                    set(
                        re.findall(
                            r"event(?:\s+)?[iI][dD]\s*(\d{3,5})", hypothesis.description
                        )
                    )
                )
                telemetry_hint = (
                    f" (event IDs: {', '.join(missing_eids)})" if missing_eids else ""
                )
                summary = f"Untestable: repeated 0-row inconclusive results — available telemetry does not contain the event types required to verify this hypothesis{telemetry_hint}."
            _log(
                "RESOLVE",
                f"{hypothesis.id} — auto-{verdict} after 3+ consecutive 0-row inconclusive",
            )
            _resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hypothesis.id,
                verdict=verdict,
                summary=summary,
                session_id=session_id,
            )
            cycle_progress = True
            break
        if tracker.should_auto_refute_due_to_unobserved_events():
            has_rule_refute = _has_zero_rows_refute_condition(hypothesis)
            if has_rule_refute:
                verdict = "refuted"
                summary = "hypothesis requires evidence not present in current dataset (3+ consecutive same-missing check)"
            else:
                verdict = "untestable"
                summary = "Untestable: hypothesis requires evidence not present in current dataset (3+ consecutive same-missing check) — absence of telemetry is not a disproof."
            _log(
                "RESOLVE",
                f"{hypothesis.id} — auto-{verdict} after {tracker.consecutive_same_missing}+ consecutive same-missing checks",
            )
            _resolve_hypothesis(
                db=db,
                state=state,
                hypothesis_id=hypothesis.id,
                verdict=verdict,
                summary=summary,
                session_id=session_id,
            )
            cycle_progress = True
            break
        if check_result.verdict == "inconclusive":
            if tracker.should_auto_confirm(rule_context, rows, hypothesis):
                _log(
                    "RESOLVE",
                    f"{hypothesis.id} — auto-confirmed via co_observed_event_ids",
                )
                _resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id=hypothesis.id,
                    verdict="confirmed",
                    summary="Auto-confirmed: all co_observed_event_ids from rule context were found in query results.",
                    session_id=session_id,
                )
                cycle_progress = True
                break
        if query_index >= limit:
            break

    return cycle_progress, state, focus_sections


def _dedup_new_hypotheses(
    new_hypotheses: list[Hypothesis],
    active_hypotheses: list[Hypothesis],
    threshold: float = 0.85,
) -> list[Hypothesis]:
    """Filter out hypotheses that are too similar to existing active ones."""
    accepted = []
    for new_h in new_hypotheses:
        is_duplicate = False
        for existing in active_hypotheses:
            if (
                _hypothesis_similarity(new_h.description, existing.description)
                > threshold
            ):
                is_duplicate = True
                break
        if not is_duplicate:
            accepted.append(new_h)

    # _known_db_columns and _filter_valid_entities moved to hypothesis_manager.py
    # (shared with the unified admission gate).  Import kept above.


def _parse_hypothesis_from_drafter(parsed: dict[str, Any]) -> Hypothesis | None:
    """Parse drafter LLM output into a Hypothesis object.

    The drafter returns ``{"hypothesis": {"description": "...", "required_entities": [...], "source_rule_ids": [...], "confirm_when": {...}, "refute_when": {...}}}``.
    Tolerates LLMs that return ``confirm_when`` / ``refute_when`` as strings by
    coercing to the schema's dict shape. Assigns a placeholder id that
    ``_merge_active_hypotheses`` will replace.
    """
    hyp_raw = parsed.get("hypothesis")
    if not isinstance(hyp_raw, dict):
        return None
    hyp_raw = dict(hyp_raw)
    hyp_raw.setdefault("id", "draft")
    hyp_raw.setdefault("source_rule_ids", [])
    # Coerce string confirm_when/refute_when (LLM drift) into the dict shape Pydantic expects.
    for key in ("confirm_when", "refute_when"):
        val = hyp_raw.get(key)
        if isinstance(val, str):
            hyp_raw[key] = {"_llm_note": val} if val.strip() else None
    entities = _filter_valid_entities(hyp_raw.get("required_entities") or [])
    if not entities:
        _log(
            "PLAN",
            f"drafter output dropped: invalid required_entities {hyp_raw.get('required_entities')}",
        )
        return None
    hyp_raw["required_entities"] = entities
    # Filter co_observed_event_ids to only include event IDs available in the case profile
    cw = hyp_raw.get("confirm_when")
    if isinstance(cw, dict):
        co_ids = cw.get("co_observed_event_ids")
        if co_ids and isinstance(co_ids, list):
            available_ids = get_profile_event_ids()
            if available_ids is not None:
                numeric_ids: list[int] = []
                for eid in co_ids:
                    try:
                        numeric_ids.append(int(str(eid).strip()))
                    except (TypeError, ValueError):
                        continue
                filtered = [eid for eid in numeric_ids if eid in available_ids]
                if len(filtered) < len(numeric_ids) or len(numeric_ids) < len(co_ids):
                    dropped = sorted(set(numeric_ids) - available_ids)
                    _log(
                        "PLAN",
                        f"drafter co_observed_event_ids filtered: dropped {dropped} (not in case evidence profile)",
                    )
                    cw["co_observed_event_ids"] = filtered
                    if not filtered:
                        cw["_llm_note"] = (
                            "All co_observed_event_ids were removed (not in case evidence). This hypothesis may be untestable via event IDs."
                        )
    try:
        return Hypothesis.model_validate(hyp_raw)
    except Exception as exc:
        _log(
            "PLAN",
            f"drafter output dropped (validation failed): {str(exc).splitlines()[0][:160]}",
        )
        return None


async def _run_broad_plan_step(
    state: SessionState,
    db: CaseDB,
    session_id: str,
    base_url: str,
    model: str,
    llm_logger: LLMCallLogger,
    plan_cycle: int,
    observed_keypoints: list[dict[str, Any]],
    emit_fn: Callable[..., None] | None,
    llm_status_fn: Callable[[str], None],
    case_profile_str: str | None = None,
) -> bool:
    """Execute broad planning step (2-stage: gap_identifier → hypothesis_drafter). Returns stop flag."""
    observed_keypoint_labels = [
        f"{item['keypoint']} (rows={item['row_count']})" for item in observed_keypoints
    ]
    plan_input = state.model_dump()
    try:
        # 1) gap_identifier — identify which keypoints lack hypothesis coverage
        observed_kp_strs = (
            observed_keypoint_labels
            or _observed_keypoints_from_findings(state.findings_snapshot)
        )
        uncovered_keypoints = _compute_uncovered_keypoints(
            observed_kp_strs,
            state.active_hypotheses,
            state.resolved_hypotheses,
            proposed_counts=state.proposed_keypoints,
        )
        active_hypotheses_slim = [
            {"id": h.id, "description": h.description, "verdict": h.verdict}
            for h in state.active_hypotheses[:10]
        ]
        gap_msgs, gap_schema = build_gap_identifier_messages(
            observed_keypoints=observed_keypoints,
            uncovered_keypoints=uncovered_keypoints,
            active_hypotheses_slim=active_hypotheses_slim,
            case_profile=case_profile_str,
        )
        gap_parsed = await _call_with_outage_recovery(
            request_llm_json,
            base_url=base_url,
            model=model,
            messages=gap_msgs,
            json_schema=gap_schema,
            status_callback=llm_status_fn,
            audit_callback=lambda msgs, out, parsed: llm_logger.write(
                iteration=plan_cycle,
                phase="plan-broad-gap",
                input_messages=msgs,
                output=parsed,
                model=model,
                base_url=base_url,
            ),
        )
        gap_areas = gap_parsed.get("gap_areas", [])
        # Track per-keypoint proposal history for round-robin coverage
        for gap in gap_areas:
            kpid = gap.get("keypoint_id", "")
            if kpid:
                state.proposed_keypoints[kpid] = (
                    state.proposed_keypoints.get(kpid, 0) + 1
                )
        valid_gap_areas = [
            g for g in gap_areas if g.get("keypoint_id") in REPORT_KEYPOINTS
        ]
        if len(valid_gap_areas) < len(gap_areas):
            _log(
                "PLAN",
                f"gap_identifier invented {len(gap_areas) - len(valid_gap_areas)} non-existent keypoint names, dropped",
            )
        gap_areas = valid_gap_areas

        # R3-08: Cap gap_areas to match investigation throughput. Drafting more
        # hypotheses than the loop can investigate only pads the Gaps table with
        # "not started" rows, so draft at most what fits into the active cap
        # (always >=2 so replacements keep flowing when the set is full).
        available_slots = max(0, MAX_ACTIVE_HYPOTHESES - len(state.active_hypotheses))
        max_gap_areas = max(2, min(4, available_slots))
        if len(gap_areas) > max_gap_areas:
            gap_areas = gap_areas[:max_gap_areas]

        # 2) hypothesis_drafter — draft one hypothesis per gap area
        rule_cache = _get_rule_cache()
        all_rule_models = list(rule_cache.values())
        # T-09: Deterministic relevance ranking — score rules by token overlap with
        # all gap keypoint names and event ID intersection with case profile
        _all_gap_kp_text = " ".join(str(g.get("keypoint_id", "")) for g in gap_areas)
        _all_gap_tokens: set[str] = (
            set(re.findall(r"[a-z0-9]+", _all_gap_kp_text.lower()))
            if _all_gap_kp_text
            else set()
        )
        _profile_eids = get_profile_event_ids() or set()

        def _rule_relevance_score(rule: Any) -> float:
            score = 0.0
            rule_text = f"{rule.id} {rule.title} {' '.join(rule.tags)}".lower()
            rule_tokens = set(re.findall(r"[a-z0-9]+", rule_text))
            if _all_gap_tokens and rule_tokens:
                overlap = len(_all_gap_tokens & rule_tokens)
                score += overlap / max(len(_all_gap_tokens), 1)
            rule_event_ids: set[int] = set()
            for corr in getattr(rule, "correlate_with", []) or []:
                rule_event_ids.update(getattr(corr, "event_ids", []) or [])
            if _profile_eids and rule_event_ids:
                intersection = len(rule_event_ids & _profile_eids)
                score += intersection / max(len(rule_event_ids), 1) * 0.5
            return score

        scored = sorted(all_rule_models, key=_rule_relevance_score, reverse=True)
        available_rules = [r.model_dump() for r in scored[:5]]
        drafted_hypotheses: list[Hypothesis] = []
        for gap in gap_areas:
            h_msgs, h_schema = build_hypothesis_drafter_messages(
                gap, available_rules, case_profile=case_profile_str
            )
            h_parsed = await _call_with_outage_recovery(
                request_llm_json,
                base_url=base_url,
                model=model,
                messages=h_msgs,
                json_schema=h_schema,
                status_callback=llm_status_fn,
                audit_callback=lambda msgs, out, parsed: llm_logger.write(
                    iteration=plan_cycle,
                    phase="plan-broad-draft",
                    input_messages=msgs,
                    output=parsed,
                    model=model,
                    base_url=base_url,
                ),
            )
            hyp = _parse_hypothesis_from_drafter(h_parsed)
            if hyp:
                kpid = gap.get("keypoint_id", "")
                if kpid:
                    hyp.target_keypoint_id = kpid
                # Unique placeholder id per draft: _merge_active_hypotheses aliases
                # by incoming id, so a shared "draft" id collapses all but the
                # first drafted hypothesis of the cycle into one record.
                hyp.id = f"draft-{plan_cycle}-{len(drafted_hypotheses) + 1}"
                drafted_hypotheses.append(hyp)

        # 3) admission gate + merge  (G-5: unified gate replaces _dedup_new_hypotheses)
        admitted = []
        for hyp in drafted_hypotheses:
            ok, reason = admit_new_hypothesis(hyp, state)
            if ok:
                admitted.append(hyp)
            else:
                _log(
                    "HYPOTHESIS",
                    f"broad_plan rejected: '{hyp.description[:80]}' reason={reason}",
                )
        state.active_hypotheses = _merge_active_hypotheses(
            db=db,
            current=state.active_hypotheses,
            updates=admitted,
            resolved=state.resolved_hypotheses,
            session_id=session_id,
            origin="broad_plan",
        )
        stop_flag = not bool(gap_areas)
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="plan-broad",
            hypothesis_id=None,
            input_json=plan_input,
            output_json={
                "gap_areas": gap_areas,
                "hypotheses": [h.model_dump() for h in drafted_hypotheses],
            },
        )
        _save_step(
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            phase="plan-broad-audit",
            hypothesis_id=None,
            input_json={
                "hypotheses": [item.model_dump() for item in drafted_hypotheses]
            },
            output_json={
                "audits": _audit_broad_plan_hypotheses(state, drafted_hypotheses)
            },
        )
        _log(
            "PLAN",
            f"+{len(drafted_hypotheses)} new hypotheses (active={len(state.active_hypotheses)}, stop={stop_flag})",
        )
        if emit_fn:
            emit_fn(
                "investigate/plan",
                f"[plan] new_hypotheses={len(drafted_hypotheses)} active={len(state.active_hypotheses)}",
                iteration=plan_cycle,
            )
        return stop_flag
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code >= 500:
            raise
        err_msg = f"[plan-broad] LLM failed: {exc}"
        print(f"[red]{err_msg}[/red]")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        err_msg = f"[plan-broad] LLM server error: {exc}"
        print(f"[red]{err_msg}[/red]")
        raise
    except LLMServerUnavailableError:
        raise
    except Exception as exc:
        err_msg = f"[plan-broad] LLM failed: {exc}"
        print(f"[red]{err_msg}[/red]")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False


async def _run_cycle_body(
    *,
    state: SessionState,
    ctx: _Ctx,
    db: CaseDB,
    case: Case,
    session_id: str,
    base_url: str,
    model: str,
    memory: MemoryManager,
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    max_queries_per_hypothesis: int,
    plan_cycle: int,
    max_iter: int,
    report_only: bool,
    case_profile_str: str | None = None,
) -> tuple[bool, bool, list[str], dict[str, Any]]:
    """Run one plan cycle: broad plan + hypothesis loop.

    Returns (broad_plan_stop, cycle_progress, focus_sections, report_before).
    """

    def _emit(
        stage: str,
        summary: str,
        *,
        report_kw: dict | None = None,
        iteration: int | None = None,
        **extras: Any,
    ) -> None:
        if not progress_callback:
            return
        payload = {
            "stage": stage,
            "status": "running",
            "iteration": state.iteration if iteration is None else iteration,
            "summary": summary,
            "focus_hypothesis_id": state.focus_hypothesis_id,
            "hypotheses": [h.model_dump() for h in _all_hypotheses(state)],
            "report_sections": _ctx_get_report_status(ctx, db, **(report_kw or {})),
        }
        payload.update(extras)
        progress_callback(payload)

    def llm_status(message: str) -> None:
        print(f"[yellow]{message}[/yellow]")
        _emit("investigate/llm", message, iteration=state.iteration)

    broad_plan_stop = False
    cycle_progress = False
    focus_sections: list[str] = []
    report_before = _ctx_get_report_status(ctx, db)
    observed_keypoints = _scan_report_keypoints(case, db)
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="plan-keypoint-scan",
        hypothesis_id=None,
        input_json={"keypoints": sorted(REPORT_KEYPOINTS.keys())},
        output_json={"observed_keypoints": observed_keypoints},
    )

    if not report_only:
        if len(state.active_hypotheses) >= MAX_ACTIVE_HYPOTHESES:
            _log(
                "PLAN",
                f"active cap reached ({len(state.active_hypotheses)} >= {MAX_ACTIVE_HYPOTHESES}); skipping broad_plan this cycle",
            )
        else:
            broad_plan_stop = await _call_with_outage_recovery(
                _run_broad_plan_step,
                base_url=base_url,
                model=model,
                state=state,
                db=db,
                session_id=session_id,
                llm_logger=llm_logger,
                plan_cycle=plan_cycle,
                observed_keypoints=observed_keypoints,
                emit_fn=_emit,
                llm_status_fn=llm_status,
                case_profile_str=case_profile_str,
            )
        remaining_cycles = max(1, max_iter - plan_cycle + 1)
        focus_max = max(
            2, (len(state.active_hypotheses) + remaining_cycles - 1) // remaining_cycles
        )
        focus_hypotheses = _select_focus_hypotheses(state, max_items=focus_max)
        for hypothesis in focus_hypotheses:
            if ctx.interrupted:
                break
            state.focus_hypothesis_id = hypothesis.id
            state.focus_depth = 0
            _ctx_refresh_caches(ctx, memory, base_url, model, hypothesis=hypothesis)
            focus_sections = _guess_related_sections(hypothesis.description)
            _log("HYPOTHESIS", f"{hypothesis.id} — {hypothesis.description}")
            _emit(
                "investigate/hypothesis",
                f"[hypothesis] {hypothesis.id}: {hypothesis.description}",
                iteration=plan_cycle,
                report_kw={"focus_sections": focus_sections},
            )
            progress, state, sections = await _investigate_one_hypothesis(
                hypothesis=hypothesis,
                state=state,
                ctx=ctx,
                memory=memory,
                db=db,
                base_url=base_url,
                model=model,
                plan_cycle=plan_cycle,
                llm_logger=llm_logger,
                session_id=session_id,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                case=case,
                query_limit=max_queries_per_hypothesis,
                emit_fn=_emit,
                llm_status_fn=llm_status,
                case_profile_str=case_profile_str,
            )
            if progress:
                cycle_progress = True

    return broad_plan_stop, cycle_progress, focus_sections, report_before


async def _run_report_phase(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    plan_cycle: int,
    report_every_n_cycles: int,
    template_root: Path,
    base_url: str,
    model: str,
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str],
    report_max_queries_per_section: int,
    state: SessionState,
    report_before: dict[str, Any],
    memory: MemoryManager,
) -> tuple[dict[str, Any], bool, str]:
    """Run the report refresh phase.

    Returns (report_after, cycle_progress_from_report, refresh_status) where
    refresh_status is "skipped" (off-cycle), "ok", or "failed: <type>: <msg>".
    """
    cycle_progress = False
    if plan_cycle % max(1, report_every_n_cycles) != 0:
        return report_before, cycle_progress, "skipped"
    report_result: dict[str, Any] | None = None
    try:
        template_paths = sorted(template_root.glob("[0-9]*_*.md"))
        # LLM-server outages get the same wait-for-recovery treatment as the
        # investigation loop (unattended multi-day runs must survive them);
        # only an exhausted outage budget propagates and stops the session.
        report_result = await _call_with_outage_recovery(
            async_refresh_report_sections,
            base_url=base_url,
            model=model,
            case=case,
            db=db,
            session_id=session_id,
            iteration=plan_cycle,
            template_paths=template_paths,
            llm_logger=llm_logger,
            progress_callback=progress_callback,
            focus_sections=focus_sections,
            max_queries_per_section=report_max_queries_per_section,
        )
    except LLMServerUnavailableError:
        raise
    except Exception as exc:
        # Rule 12: loud, not dead. Log the full traceback and a typed progress
        # event, publish any sections that were persisted before the crash,
        # and let the investigation continue — stale flags stay in the DB, so
        # the next successful refresh catches up on everything missed.
        error_label = f"{type(exc).__name__}: {exc}"
        print(f"[red][report] section refresh failed: {error_label}[/red]")
        print(traceback.format_exc())
        if progress_callback:
            progress_callback(
                {
                    "stage": "investigate/report-cycle-done",
                    "status": "running",
                    "iteration": plan_cycle,
                    "summary": f"[report] refresh failed: {error_label}",
                }
            )
        try:
            render_written_report(case, db)
        except Exception as render_exc:
            print(f"[yellow][report] fallback render failed: {render_exc}[/yellow]")
        return report_before, cycle_progress, f"failed: {error_label}"
    if report_result is None:
        return report_before, cycle_progress, "ok"
    report_after = report_result["report_status"]
    gap_new_hypotheses = _inject_gap_hypotheses(
        db=db,
        state=state,
        gaps=report_result["gaps"],
        session_id=session_id,
        memory=memory,
    )
    if gap_new_hypotheses:
        cycle_progress = True
    if _report_cycle_progress(report_before, report_after):
        cycle_progress = True
    render_written_report(case, db)
    return report_after, cycle_progress, "ok"


def _check_termination(
    *,
    report_only: bool,
    broad_plan_stop: bool,
    active_hypotheses: list,
    db: CaseDB,
    report_after: dict[str, Any],
    no_progress_count: int,
    no_progress_limit: int,
    cycle_progress: bool,
) -> tuple[str | None, int]:
    """Check if the investigation loop should stop. Returns (terminal_status or None, updated_no_progress_count)."""
    if report_only:
        return "completed", no_progress_count
    unresolved_gap_count = int(report_after.get("total_gaps", 0))
    if broad_plan_stop and not active_hypotheses and unresolved_gap_count == 0:
        mark_report_sections_ai_exhausted(db)
        return "completed", no_progress_count
    no_progress_count = 0 if cycle_progress else no_progress_count + 1
    if no_progress_count >= no_progress_limit:
        return "completed", no_progress_count
    return None, no_progress_count


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


async def investigate(
    case: Case,
    db: CaseDB,
    base_url: str,
    model: str,
    max_iter: int = 20,
    no_progress_limit: int = 3,
    profile: str = "windows-basic",
    max_queries_per_hypothesis: int = 5,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    report_every_n_cycles: int = 1,
    report_only: bool = False,
    template_root: Path | None = None,
    report_max_queries_per_section: int = 3,
    max_llm_calls: int = 200,
    auto_rulepacks: bool = True,
) -> dict[str, Any]:
    """Run the full investigation loop: broad plan → hypothesis loop → report refresh, with termination checks and LLM budget enforcement."""
    profile_path = Path(__file__).parent.parent / "profiles" / f"{profile}.yaml"
    active_pack_ids = resolve_active_packs(
        profile_path if profile_path.exists() else None,
        db,
        auto_rulepacks=auto_rulepacks,
    )
    if auto_rulepacks and active_pack_ids:
        expected = set()
        if profile_path.exists():
            import yaml

            profile_data = (
                yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
            )
            expected = set(profile_data.get("rulepacks") or [])
        auto_enabled = active_pack_ids - expected
        if auto_enabled:
            _log(
                "PLAN",
                f"auto-rulepacks enabled: {sorted(auto_enabled)} (detected families trigger pack activation)",
            )
    state, ctx, memory, llm_logger, session_id, started_at, template_root = (
        _init_session(
            case,
            db,
            profile,
            base_url,
            model,
            template_root,
            active_pack_ids=active_pack_ids if auto_rulepacks else None,
        )
    )
    case.extract_time_range(db.conn)
    case_profile_dict = build_case_profile(db)
    case_profile_str = _format_case_profile(case_profile_dict)
    profile_event_ids = {
        e["event_id"]
        for e in case_profile_dict.get("event_ids", [])
        if isinstance(e.get("event_id"), int)
    }
    set_case_profile(case_profile_str, profile_event_ids)
    status = "running"
    no_progress_count = 0
    report_refresh_failures = 0
    previous_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(
        signal.SIGINT, lambda signum, frame: setattr(ctx, "interrupted", True)
    )

    def _check_llm_budget() -> None:
        if max_llm_calls > 0 and llm_logger.total_calls >= max_llm_calls:
            raise RuntimeError(
                f"LLM call budget exceeded: {llm_logger.total_calls} calls >= {max_llm_calls} max. "
                f"Per-phase: {llm_logger.count_by_phase()}. "
                "Increase --max-llm-calls (or pass 0 for unlimited) or investigate the cause of excessive calls."
            )

    try:
        for plan_cycle in range(1, max_iter + 1):
            _check_llm_budget()
            state.iteration = plan_cycle
            state.findings_snapshot = _finding_snapshot(db)
            _sync_keypoint_cards(memory, state.findings_snapshot)
            _log(
                "PLAN",
                f"Cycle {plan_cycle}/{max_iter} — broad planning (active={len(state.active_hypotheses)} resolved={len(state.resolved_hypotheses)})",
            )
            if ctx.interrupted:
                status = "stopped"
                break
            (
                broad_plan_stop,
                cycle_progress,
                focus_sections,
                report_before,
            ) = await _run_cycle_body(
                state=state,
                ctx=ctx,
                db=db,
                case=case,
                session_id=session_id,
                base_url=base_url,
                model=model,
                memory=memory,
                llm_logger=llm_logger,
                progress_callback=progress_callback,
                max_queries_per_hypothesis=max_queries_per_hypothesis,
                plan_cycle=plan_cycle,
                max_iter=max_iter,
                report_only=report_only,
                case_profile_str=case_profile_str,
            )
            if ctx.interrupted:
                status = "stopped"
                break
            (
                report_after,
                report_cycle_progress,
                refresh_status,
            ) = await _run_report_phase(
                case=case,
                db=db,
                session_id=session_id,
                plan_cycle=plan_cycle,
                report_every_n_cycles=report_every_n_cycles,
                template_root=template_root,
                base_url=base_url,
                model=model,
                llm_logger=llm_logger,
                progress_callback=progress_callback,
                focus_sections=focus_sections,
                report_max_queries_per_section=report_max_queries_per_section,
                state=state,
                report_before=report_before,
                memory=memory,
            )
            if refresh_status.startswith("failed"):
                report_refresh_failures += 1
            ctx.report_status = report_after
            cycle_progress = cycle_progress or report_cycle_progress
            memory.regenerate_timeline_from_db(db)
            terminal_status, no_progress_count = _check_termination(
                report_only=report_only,
                broad_plan_stop=broad_plan_stop,
                active_hypotheses=state.active_hypotheses,
                db=db,
                report_after=report_after,
                no_progress_count=no_progress_count,
                no_progress_limit=no_progress_limit,
                cycle_progress=cycle_progress,
            )
            if terminal_status is not None:
                status = terminal_status
                break
        else:
            status = "completed"

        # R5-03: Final report refresh pass after loop termination, so stale
        # sections from late-cycle resolutions reach the rendered report.
        # R7-04: Use force_all=True so every section renders at one DB state,
        # bypassing the update_count cap (it guards per-cycle loops, not the
        # closing render). Skipped on user interrupt.
        if status == "completed" and not ctx.interrupted:
            try:
                template_paths = sorted(template_root.glob("[0-9]*_*.md"))
                await async_refresh_report_sections(
                    case=case,
                    db=db,
                    session_id=session_id,
                    iteration=max_iter + 1,
                    base_url=base_url,
                    model=model,
                    template_paths=template_paths,
                    llm_logger=llm_logger,
                    progress_callback=progress_callback,
                    focus_sections=[],
                    max_queries_per_section=report_max_queries_per_section,
                    force_all=True,
                )
                render_written_report(case, db)
                memory.regenerate_timeline_from_db(db)
            except Exception as exc:
                report_refresh_failures += 1
                print(
                    f"[yellow][final-refresh] failed: {type(exc).__name__}: {exc}[/yellow]"
                )
                print(traceback.format_exc())
    except Exception:
        status = "failed"
        raise
    finally:
        memory.regenerate_timeline_from_db(db)
        signal.signal(signal.SIGINT, previous_sigint)
        llm_logger.write_summary()
        finished_at = datetime.now(UTC).replace(tzinfo=None)
        db.execute(
            "UPDATE investigation_sessions SET finished_at = ?, iterations = ?, status = ? WHERE session_id = ?",
            (finished_at, state.iteration, status, session_id),
        )
    if report_refresh_failures:
        print(
            f"[red][report] {report_refresh_failures} report refresh phase(s) failed during this "
            f"session — see tracebacks above. Stale sections persist and are retried on later "
            f"cycles and the final refresh.[/red]"
        )
    summary = _final_summary(state)
    return {
        "session_id": session_id,
        "status": status,
        "iteration": state.iteration,
        "depth": state.focus_depth,
        "focus_hypothesis_id": state.focus_hypothesis_id,
        "summary": summary,
        "hypotheses": [item.model_dump() for item in _all_hypotheses(state)],
        "report_sections": _ctx_get_report_status(ctx, db, refresh=True),
        "report_refresh_failures": report_refresh_failures,
    }
