"""Section block agent entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.sections.section_agent.
"""

from __future__ import annotations

import asyncio
from typing import Any

from forensia.ai.sections.section_block_context import (
    _BlockContext,
    prepare_block_context,
)
from forensia.ai.sections.section_block_narrative import (
    _postprocess_block_body,
    _write_block_body,
)
from forensia.ai.sections.section_block_plan import (
    _execute_block_plan,
    _run_block_check,
    _run_block_plan,
    _try_evidence_chain_fallback,
)
from forensia.ai.sections.section_exec import (
    SectionBlockResult,
    _execute_keypoint,
    _filter_template_catalog_by_section,
    _known_keypoints,
    _split_keypoint_names,
)
from forensia.ai.sections.section_run_store import (
    _evidence_as_result,
    _facts_as_result,
    _load_prior_runs,
    _store_section_evidence,
    _store_section_run,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.db.database import CaseDB

# ====================================================================
# BLOCK WALKTHROUGH PHASES — private helpers for run_section_block_agent
# ====================================================================


def _prepare_block_seed_data(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    actual_query_row_counts: list[int],
) -> tuple[int, set[str]]:
    """Execute seed keypoints and collect reusable facts/evidence.

    Populates *collected_results* and *actual_query_row_counts* in-place.
    Returns (actual_query_count, executed_seed_keypoints).
    """
    if ctx.reusable_facts:
        collected_results.append(_facts_as_result(ctx.reusable_facts))
    if ctx.reusable_evidence:
        collected_results.append(_evidence_as_result(ctx.reusable_evidence))
    actual_query_count = 0
    seed_keypoints = (
        _default_keypoints_for_section(
            ctx.section_key, block_heading=ctx.block_heading
        )[:2]
        if not ctx.question_mode
        else list(ctx.evidence_keypoints or [])[:3]
    )
    executed_seed_keypoints: set[str] = set()
    for seed_index, kp in enumerate(seed_keypoints, start=0):
        if kp in _known_keypoints(ctx.keypoint_catalog):
            try:
                source_query, result = _execute_keypoint(ctx.case, ctx.db, kp)
                collected_results.append(result)
                executed_seed_keypoints.add(kp)
                _store_section_run(
                    ctx.db,
                    section_key=ctx.section_key,
                    block_heading=ctx.block_heading,
                    iteration=seed_index,
                    phase="query",
                    payload={
                        "seed": True,
                        "source_kind": str(result.get("source_kind") or "unknown"),
                        "source_ref": str(result.get("source_ref") or source_query),
                        "result": result,
                    },
                )
                if str(result.get("kind") or "rows") == "rows":
                    actual_query_count += 1
                    actual_query_row_counts.append(int(result.get("row_count") or 0))
                    _store_section_evidence(
                        ctx.db,
                        section_key=ctx.section_key,
                        block_heading=ctx.block_heading,
                        result=result,
                        source_query=source_query,
                    )
            except Exception:
                _store_section_run(
                    ctx.db,
                    section_key=ctx.section_key,
                    block_heading=ctx.block_heading,
                    iteration=seed_index,
                    phase="query_error",
                    payload={"seed": True, "keypoint": kp},
                )
    return actual_query_count, executed_seed_keypoints


def _run_plan_execute_check_loop(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    actual_query_row_counts: list[int],
    actual_query_count: int,
    executed_seed_keypoints: set[str],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    template_catalog: list[dict],
) -> tuple[str, str, list[Any], str, int]:
    """Run the plan→execute→check iteration loop.

    Returns (verdict, rationale, missing_questions, status, actual_query_count).
    """
    verdict = "block_needs_more"
    rationale = ""
    missing_questions: list[Any] = []
    status = "insufficient_evidence"
    for iteration in range(1, ctx.max_queries + 1):
        prior_runs = _load_prior_runs(ctx.db, ctx.section_key, ctx.block_heading)
        template_catalog = _filter_template_catalog_by_section(
            template_catalog, ctx.section_key, collected_results
        )
        plan_action = _run_block_plan(
            ctx,
            iteration,
            prior_runs,
            template_catalog,
            context_sections,
            current_section_outline,
        )
        if plan_action is None or plan_action.action == "write":
            break
        if plan_action.action == "keypoint":
            planned_keypoints = set(_split_keypoint_names(plan_action.keypoint))
            if planned_keypoints and planned_keypoints.issubset(
                executed_seed_keypoints
            ):
                continue
        outcome = _execute_block_plan(ctx, plan_action, iteration)
        if outcome is None:
            continue
        source_query, result = outcome
        collected_results.append(result)
        if str(result.get("kind") or "rows") == "rows":
            actual_query_count += 1
            actual_query_row_counts.append(int(result.get("row_count") or 0))
        check_result = _run_block_check(
            ctx,
            iteration,
            result,
            collected_results,
            prior_runs,
            actual_query_count,
            actual_query_row_counts,
            source_query,
        )
        if check_result is None:
            break
        verdict, rationale, missing_questions, status = check_result
        if verdict in {"block_supported", "block_contradicted"}:
            break
    return verdict, rationale, missing_questions, status, actual_query_count


from forensia.report.answers.answer_registry import (
    _feed_structured_to_timeline,
    build_structured_answer,
)
from forensia.report.answers.answer_store import (
    _render_structured_answer_markdown,
)
from forensia.report.answers.keypoint_catalog import (
    _default_keypoints_for_section,
)


def _try_question_structured_answer(
    ctx: _BlockContext,
    audit_callback=None,
) -> SectionBlockResult | None:
    """Return a SectionBlockResult when a structured answer already covers this block.

    Returns *None* when there is no structured answer (caller should continue
    with the normal plan loop).
    """
    if not (ctx.question_mode and ctx.answer_spec):
        return None
    structured_answer = build_structured_answer(
        ctx.case,
        ctx.db,
        answer_spec=ctx.answer_spec,
        answer_id=ctx.answer_id or ctx.question_id or ctx.answer_spec,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
    )
    if structured_answer is None:
        return None
    body = _render_structured_answer_markdown(
        structured_answer,
        ctx.block_heading,
        template_dir=ctx.case.report_template_dir,
    )
    body = _postprocess_block_body(
        body,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
    )
    if audit_callback:
        audit_callback([], body)
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=1,
        phase="write",
        payload={
            "structured": True,
            "answer_id": structured_answer.get("id"),
            "answer_spec": ctx.answer_spec,
            "status": structured_answer.get("status"),
        },
    )
    if (
        structured_answer.get("status") in {"answered", "partial"}
        and ctx.question_spec is not None
        and ctx.question_spec.timeline
    ):
        _feed_structured_to_timeline(ctx.db, ctx.answer_spec, structured_answer)
    return SectionBlockResult(
        body=body,
        evidence_results=[],
        iterations=1,
        status=str(structured_answer.get("status") or "insufficient_evidence"),
    )


def _try_fast_path_write(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    audit_callback=None,
) -> SectionBlockResult | None:
    """R3-07: fast-path return when seed evidence rows already suffice.

    Returns *None* when the fast path does not apply.
    """
    if not collected_results or not any(
        str(r.get("kind") or "rows") == "rows" and int(r.get("row_count") or 0) > 0
        for r in collected_results
    ):
        return None
    body, final_status = _write_block_body(
        ctx,
        collected_results,
        "answered",
        "block_supported",
        "",
        [],
        actual_query_count,
        actual_query_row_counts,
        audit_callback=audit_callback,
    )
    return SectionBlockResult(
        body=body,
        evidence_results=collected_results,
        iterations=max(len(collected_results), 1),
        status=final_status,
    )


def _run_block_pipeline(
    ctx: _BlockContext,
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    audit_callback=None,
) -> SectionBlockResult:
    """Benchmark early-return, seed prep, plan loop, and final write for one block."""
    # --- Benchmark early-return: structured answer available ---
    bench_result = _try_question_structured_answer(ctx, audit_callback)
    if bench_result is not None:
        return bench_result

    # --- Prepare: collect reusable data and execute seed keypoints ---
    collected_results: list[dict[str, Any]] = []
    actual_query_row_counts: list[int] = []
    actual_query_count, executed_seed_keypoints = _prepare_block_seed_data(
        ctx,
        collected_results,
        actual_query_row_counts,
    )
    # R3-07: Fast path — skip plan loop if we already have evidence rows
    fast_result = _try_fast_path_write(
        ctx,
        collected_results,
        actual_query_count,
        actual_query_row_counts,
        audit_callback=audit_callback,
    )
    if fast_result is not None:
        return fast_result

    # --- Plan/Execute/Check loop ---
    verdict, rationale, missing_questions, status, actual_query_count = (
        _run_plan_execute_check_loop(
            ctx,
            collected_results,
            actual_query_row_counts,
            actual_query_count,
            executed_seed_keypoints,
            context_sections,
            current_section_outline,
            ctx.template_catalog,
        )
    )

    # --- Finalize: evidence chain fallback + write ---
    force_chain = ctx.question_mode and status in {
        "wrong_query",
        "insufficient_evidence",
        "not_searched",
    }
    actual_query_count = _try_evidence_chain_fallback(
        ctx,
        collected_results,
        actual_query_count,
        actual_query_row_counts,
        force=force_chain,
    )
    body, final_status = _write_block_body(
        ctx,
        collected_results,
        status,
        verdict,
        rationale,
        missing_questions,
        actual_query_count,
        actual_query_row_counts,
        audit_callback=audit_callback,
    )
    return SectionBlockResult(
        body=body,
        evidence_results=collected_results,
        iterations=max(len(collected_results), 1),
        status=final_status,
    )


def run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    memory: MemoryManager | None = None,
    max_queries_per_section: int = 3,
    evidence_keypoints: list[str] | None = None,
    question_mode: bool = False,
    question_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    section_table_digest: str = "",
    audit_callback=None,
    review_audit_callback=None,
) -> SectionBlockResult:
    """Run the complete plan->query->check->write loop for one report section block.

    Iterates up to max_queries_per_section times: LLM plans the next action
    (keypoint/template/sql/facts/write), executes it, LLM checks sufficiency,
    and either continues or finalizes with a written body. Falls back to evidence
    chains when all queries return zero rows.
    """
    max_queries = max(1, int(max_queries_per_section or 1))
    ctx = prepare_block_context(
        case=case,
        db=db,
        section_key=section_key,
        title=title,
        block_heading=block_heading,
        template_body=template_body,
        base_url=base_url,
        model=model,
        memory=memory,
        max_queries=max_queries,
        evidence_keypoints=evidence_keypoints,
        question_mode=question_mode,
        question_id=question_id,
        answer_id=answer_id,
        answer_spec=answer_spec,
        question=question,
        section_table_digest=section_table_digest,
        audit_callback=audit_callback,
        review_audit_callback=review_audit_callback,
        report_brief=report_brief,
    )
    try:
        return _run_block_pipeline(
            ctx, context_sections, current_section_outline, audit_callback
        )
    except Exception as exc:
        return SectionBlockResult(
            body=f"**Status:** error\n\n*Section block failed: {str(exc)[:200]}*",
            evidence_results=[],
            iterations=0,
            status="error",
        )


async def async_run_section_block_agent(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    context_sections: dict[str, str],
    current_section_outline: list[dict],
    report_brief: dict[str, Any] | None,
    base_url: str,
    model: str,
    memory: MemoryManager | None = None,
    max_queries_per_section: int = 3,
    evidence_keypoints: list[str] | None = None,
    question_mode: bool = False,
    question_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    section_table_digest: str = "",
    audit_callback=None,
    review_audit_callback=None,
) -> SectionBlockResult:
    """Async wrapper around run_section_block_agent using asyncio.to_thread."""
    return await asyncio.to_thread(
        run_section_block_agent,
        case=case,
        db=db,
        section_key=section_key,
        title=title,
        block_heading=block_heading,
        template_body=template_body,
        context_sections=context_sections,
        current_section_outline=current_section_outline,
        report_brief=report_brief,
        base_url=base_url,
        model=model,
        memory=memory,
        max_queries_per_section=max_queries_per_section,
        evidence_keypoints=evidence_keypoints,
        question_mode=question_mode,
        question_id=question_id,
        answer_id=answer_id,
        answer_spec=answer_spec,
        question=question,
        section_table_digest=section_table_digest,
        audit_callback=audit_callback,
        review_audit_callback=review_audit_callback,
    )
