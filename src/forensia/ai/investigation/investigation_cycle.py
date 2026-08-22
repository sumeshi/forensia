"""Investigation cycle: broad planning, hypothesis selection, cycle body."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from forensia.ai.audit import LLMCallLogger
from forensia.ai.case_profile import (
    get_profile_event_ids,
)
from forensia.ai.hypotheses.hypothesis_manager import (
    MAX_ACTIVE_HYPOTHESES,
    _guess_related_sections,
    admit_new_hypothesis,
    merge_active_hypotheses,
)
from forensia.ai.hypotheses.hypothesis_model import (
    _filter_valid_entities,
    hypothesis_similarity,
)
from forensia.ai.hypotheses.hypothesis_runner import (
    _investigate_one_hypothesis,
    _observed_keypoints_from_findings,
)
from forensia.ai.hypotheses.hypothesis_store import _all_hypotheses
from forensia.ai.hypotheses.seeding import (
    _scan_report_keypoints,
)
from forensia.ai.investigation.investigation_session import (
    Ctx,
    _call_with_outage_recovery,
    _ctx_get_report_status,
    _save_step,
    ctx_refresh_caches,
)
from forensia.ai.investigation.planner import _compute_uncovered_keypoints
from forensia.ai.investigation.selection import (
    select_focus_hypotheses as select_focus_hypotheses_v2,
)
from forensia.ai.llm import llm_gateway
from forensia.ai.llm.llm_client import (
    LLMRequestTimeoutError,
    LLMServerUnavailableError,
)
from forensia.ai.prompts.prompt_investigation import (
    build_gap_identifier_messages,
    build_hypothesis_drafter_messages,
)
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.progress_event import progress_event
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.knowledge.rules.loader import _get_rule_cache
from forensia.report.answers.keypoint_catalog import (
    REPORT_KEYPOINTS,
    investigation_keypoint_names,
)

_BROAD_DRAFT_MAX_TOKENS = 4096


@dataclass(slots=True)
class _BroadPlanContext:
    state: SessionState
    db: CaseDB
    session_id: str
    base_url: str
    model: str
    llm_logger: LLMCallLogger
    plan_cycle: int
    observed_keypoints: list[dict[str, Any]]
    observed_keypoint_labels: list[str]
    emit_fn: Callable[..., None] | None
    llm_status_fn: Callable[[str], None]
    progress_callback: Callable[[dict[str, Any]], None] | None
    case_profile_str: str | None


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


def select_focus_hypotheses(
    state: SessionState, max_items: int = 2
) -> list[Hypothesis]:
    ranked = sorted(
        state.active_hypotheses,
        key=lambda item: _hypothesis_focus_score(state, item),
        reverse=True,
    )
    return ranked[: max(1, max_items)] if ranked else []


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
                hypothesis_similarity(new_h.description, existing.description)
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
    ``merge_active_hypotheses`` will replace.
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
                    except TypeError, ValueError:
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


def _broad_plan_observed_labels(observed_keypoints: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item['keypoint']} (rows={item['row_count']})" for item in observed_keypoints
    ]


async def _identify_broad_plan_gaps(ctx: _BroadPlanContext) -> list[dict[str, Any]]:
    observed_kp_strs = (
        ctx.observed_keypoint_labels
        or _observed_keypoints_from_findings(ctx.state.findings_snapshot)
    )
    uncovered_keypoints = _compute_uncovered_keypoints(
        observed_kp_strs,
        ctx.state.active_hypotheses,
        ctx.state.resolved_hypotheses,
        proposed_counts=ctx.state.proposed_keypoints,
    )
    active_hypotheses_slim = [
        {"id": h.id, "description": h.description, "verdict": h.verdict}
        for h in ctx.state.active_hypotheses[:10]
    ]
    gap_msgs, gap_schema = build_gap_identifier_messages(
        observed_keypoints=ctx.observed_keypoints,
        uncovered_keypoints=uncovered_keypoints,
        active_hypotheses_slim=active_hypotheses_slim,
        case_profile=ctx.case_profile_str,
    )
    gap_parsed = await _call_with_outage_recovery(
        llm_gateway.request_llm_json,
        base_url=ctx.base_url,
        model=ctx.model,
        _outage_progress_callback=ctx.progress_callback,
        messages=gap_msgs,
        json_schema=gap_schema,
        telemetry_phase="plan-broad-gap",
        status_callback=ctx.llm_status_fn,
        audit_callback=lambda msgs, out, parsed: ctx.llm_logger.write(
            iteration=ctx.plan_cycle,
            phase="plan-broad-gap",
            input_messages=msgs,
            output=parsed,
            model=ctx.model,
            base_url=ctx.base_url,
        ),
    )
    gap_areas = gap_parsed.get("gap_areas", [])
    for gap in gap_areas:
        kpid = gap.get("keypoint_id", "")
        if kpid:
            ctx.state.proposed_keypoints[kpid] = (
                ctx.state.proposed_keypoints.get(kpid, 0) + 1
            )

    valid_gap_areas = [g for g in gap_areas if g.get("keypoint_id") in REPORT_KEYPOINTS]
    if len(valid_gap_areas) < len(gap_areas):
        _log(
            "PLAN",
            f"gap_identifier invented {len(gap_areas) - len(valid_gap_areas)} non-existent keypoint names, dropped",
        )
    gap_areas = valid_gap_areas

    available_slots = max(0, MAX_ACTIVE_HYPOTHESES - len(ctx.state.active_hypotheses))
    max_gap_areas = max(2, min(4, available_slots))
    if len(gap_areas) > max_gap_areas:
        gap_areas = gap_areas[:max_gap_areas]
    return gap_areas


def _rank_broad_plan_rules(gap_areas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rule_cache = _get_rule_cache()
    all_rule_models = list(rule_cache.values())
    all_gap_kp_text = " ".join(str(g.get("keypoint_id", "")) for g in gap_areas)
    all_gap_tokens: set[str] = (
        set(re.findall(r"[a-z0-9]+", all_gap_kp_text.lower()))
        if all_gap_kp_text
        else set()
    )
    profile_eids = get_profile_event_ids() or set()

    def _rule_relevance_score(rule: Any) -> float:
        score = 0.0
        rule_text = f"{rule.id} {rule.title} {' '.join(rule.tags)}".lower()
        rule_tokens = set(re.findall(r"[a-z0-9]+", rule_text))
        if all_gap_tokens and rule_tokens:
            overlap = len(all_gap_tokens & rule_tokens)
            score += overlap / max(len(all_gap_tokens), 1)
        rule_event_ids: set[int] = set()
        for corr in getattr(rule, "correlate_with", []) or []:
            rule_event_ids.update(getattr(corr, "event_ids", []) or [])
        if profile_eids and rule_event_ids:
            intersection = len(rule_event_ids & profile_eids)
            score += intersection / max(len(rule_event_ids), 1) * 0.5
        return score

    scored = sorted(all_rule_models, key=_rule_relevance_score, reverse=True)
    return [rule.model_dump() for rule in scored[:5]]


async def _draft_broad_plan_hypotheses(
    ctx: _BroadPlanContext,
    gap_areas: list[dict[str, Any]],
    available_rules: list[dict[str, Any]],
) -> list[Hypothesis]:
    drafted_hypotheses: list[Hypothesis] = []
    for gap in gap_areas:
        h_msgs, h_schema = build_hypothesis_drafter_messages(
            gap, available_rules, case_profile=ctx.case_profile_str
        )
        h_parsed = await _call_with_outage_recovery(
            llm_gateway.request_llm_json,
            base_url=ctx.base_url,
            model=ctx.model,
            _outage_progress_callback=ctx.progress_callback,
            messages=h_msgs,
            json_schema=h_schema,
            telemetry_phase="plan-broad-draft",
            max_tokens=_BROAD_DRAFT_MAX_TOKENS,
            status_callback=ctx.llm_status_fn,
            audit_callback=lambda msgs, out, parsed: ctx.llm_logger.write(
                iteration=ctx.plan_cycle,
                phase="plan-broad-draft",
                input_messages=msgs,
                output=parsed,
                model=ctx.model,
                base_url=ctx.base_url,
            ),
        )
        hyp = _parse_hypothesis_from_drafter(h_parsed)
        if hyp:
            kpid = gap.get("keypoint_id", "")
            if kpid:
                hyp.target_keypoint_id = kpid
            hyp.id = f"draft-{ctx.plan_cycle}-{len(drafted_hypotheses) + 1}"
            drafted_hypotheses.append(hyp)
    return drafted_hypotheses


def _admit_broad_plan_hypotheses(
    ctx: _BroadPlanContext, drafted_hypotheses: list[Hypothesis]
) -> None:
    admitted = []
    for hyp in drafted_hypotheses:
        ok, reason = admit_new_hypothesis(hyp, ctx.state)
        if ok:
            admitted.append(hyp)
        else:
            _log(
                "HYPOTHESIS",
                f"broad_plan rejected: '{hyp.description[:80]}' reason={reason}",
            )
    ctx.state.active_hypotheses = merge_active_hypotheses(
        db=ctx.db,
        current=ctx.state.active_hypotheses,
        updates=admitted,
        resolved=ctx.state.resolved_hypotheses,
        session_id=ctx.session_id,
        origin="broad_plan",
    )


def _save_broad_plan_results(
    ctx: _BroadPlanContext,
    plan_input: dict[str, Any],
    gap_areas: list[dict[str, Any]],
    drafted_hypotheses: list[Hypothesis],
) -> None:
    _save_step(
        db=ctx.db,
        session_id=ctx.session_id,
        iteration=ctx.plan_cycle,
        phase="plan-broad",
        hypothesis_id=None,
        input_json=plan_input,
        output_json={
            "gap_areas": gap_areas,
            "hypotheses": [h.model_dump() for h in drafted_hypotheses],
        },
    )
    _save_step(
        db=ctx.db,
        session_id=ctx.session_id,
        iteration=ctx.plan_cycle,
        phase="plan-broad-audit",
        hypothesis_id=None,
        input_json={"hypotheses": [item.model_dump() for item in drafted_hypotheses]},
        output_json={
            "audits": _audit_broad_plan_hypotheses(ctx.state, drafted_hypotheses)
        },
    )


def _emit_broad_plan_result(
    ctx: _BroadPlanContext, drafted_hypotheses: list[Hypothesis], stop_flag: bool
) -> None:
    _log(
        "PLAN",
        f"+{len(drafted_hypotheses)} new hypotheses (active={len(ctx.state.active_hypotheses)}, stop={stop_flag})",
    )
    if ctx.emit_fn:
        ctx.emit_fn(
            "investigate/plan",
            f"[plan] new_hypotheses={len(drafted_hypotheses)} active={len(ctx.state.active_hypotheses)}",
            iteration=ctx.plan_cycle,
        )


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
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    case_profile_str: str | None = None,
) -> bool:
    """Execute broad planning step (2-stage: gap_identifier → hypothesis_drafter). Returns stop flag."""
    observed_keypoint_labels = _broad_plan_observed_labels(observed_keypoints)
    plan_input = state.model_dump()
    ctx = _BroadPlanContext(
        state=state,
        db=db,
        session_id=session_id,
        base_url=base_url,
        model=model,
        llm_logger=llm_logger,
        plan_cycle=plan_cycle,
        observed_keypoints=observed_keypoints,
        observed_keypoint_labels=observed_keypoint_labels,
        emit_fn=emit_fn,
        llm_status_fn=llm_status_fn,
        progress_callback=progress_callback,
        case_profile_str=case_profile_str,
    )
    try:
        gap_areas = await _identify_broad_plan_gaps(ctx)
        available_rules = _rank_broad_plan_rules(gap_areas)
        drafted_hypotheses = await _draft_broad_plan_hypotheses(
            ctx, gap_areas, available_rules
        )
        _admit_broad_plan_hypotheses(ctx, drafted_hypotheses)
        stop_flag = not bool(gap_areas)
        _save_broad_plan_results(ctx, plan_input, gap_areas, drafted_hypotheses)
        _emit_broad_plan_result(ctx, drafted_hypotheses, stop_flag)
        return stop_flag
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code >= 500:
            raise
        err_msg = f"LLM failed: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        err_msg = f"LLM server error: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        raise
    except LLMRequestTimeoutError as exc:
        err_msg = f"LLM request timed out; broad planning skipped: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False
    except LLMServerUnavailableError:
        raise
    except Exception as exc:
        err_msg = f"LLM failed: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn("investigate/plan", err_msg, iteration=plan_cycle)
        return False


async def _run_cycle_body(
    *,
    state: SessionState,
    ctx: Ctx,
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
        progress_callback(
            progress_event(
                stage,
                "running",
                iteration=state.iteration if iteration is None else iteration,
                summary=summary,
                focus_hypothesis_id=state.focus_hypothesis_id,
                hypotheses=[h.model_dump() for h in _all_hypotheses(state)],
                report_sections=_ctx_get_report_status(ctx, db, **(report_kw or {})),
                **extras,
            )
        )

    def llm_status(message: str) -> None:
        _log("LLM", message)
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
        input_json={
            "keypoints": sorted(REPORT_KEYPOINTS.keys()),
            "investigation_eligible_keypoints": list(investigation_keypoint_names()),
        },
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
                _outage_progress_callback=progress_callback,
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
        # Use M4 selector if investigation_state table exists (M1 migration ran)
        try:
            selection_results = select_focus_hypotheses_v2(
                db,
                limit=focus_max,
                findings_snapshot=state.findings_snapshot,
                session_id=session_id,
                iteration=plan_cycle,
            )
            focus_hypotheses = []
            for sr in selection_results:
                if sr.eligible:
                    hyp = next(
                        (
                            h
                            for h in state.active_hypotheses
                            if h.id == sr.hypothesis_id
                        ),
                        None,
                    )
                    if hyp:
                        focus_hypotheses.append(hyp)
        except Exception:
            # Fallback to legacy selector if M4 tables not available
            focus_hypotheses = select_focus_hypotheses(state, max_items=focus_max)
        for hypothesis in focus_hypotheses:
            if ctx.interrupted:
                break
            state.focus_hypothesis_id = hypothesis.id
            state.focus_depth = 0
            ctx_refresh_caches(
                ctx,
                memory,
                base_url,
                model,
                hypothesis=hypothesis,
                db=db,
                session_id=session_id,
            )
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
                progress_callback=progress_callback,
                case_profile_str=case_profile_str,
            )
            if progress:
                cycle_progress = True

    return broad_plan_stop, cycle_progress, focus_sections, report_before
