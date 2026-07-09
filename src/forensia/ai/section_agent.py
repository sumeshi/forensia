"""Section block agent entry point; helpers live in focused submodules.

Kept for backward compatibility: existing code and tests import these
names from forensia.ai.section_agent.
"""

from __future__ import annotations

import asyncio
from typing import Any

from forensia.ai.json_response import (  # noqa: F401 — import needed for test mocking
    async_request_llm_json,
    request_llm_json,
)
from forensia.ai.section_block_context import (  # noqa: F401
    _BlockContext,
    _prepare_block_context,
)
from forensia.ai.section_block_narrative import (  # noqa: F401
    _NARRATE_RETRY_PROMPT,
    _fallback_narrative_body,
    _label_key_points_with_verdicts,
    _narrate_paragraph_with_retry,
    _normalize_report_language,
    _postprocess_block_body,
    _review_and_rewrite_narrative,
    _write_block_body,
)
from forensia.ai.section_block_plan import (  # noqa: F401
    _execute_block_plan,
    _run_block_check,
    _run_block_plan,
    _select_columns_by_template,
    _try_evidence_chain_fallback,
)
from forensia.ai.section_blocks import (  # noqa: F401,E402
    _CONFIDENCE_KEYWORD_MAP,
    SectionBlockResult,
    SectionPlanAction,
    _add_json_fallback,
    _all_values_empty,
    _antiforensic_tool_names,
    _audit_bridge,
    _benchmark_report_brief,
    _build_daily_session_timeline,
    _cache_key,
    _classify_block_status,
    _coerce_confidence,
    _coerce_plan_action,
    _compact_narrative_value,
    _evidence_as_result,
    _execute_evidence_chain,
    _execute_keypoint,
    _execute_sql,
    _extract_answer_by_shape,
    _extract_daily_table,
    _extract_enumerated_services,
    _extract_full_scan,
    _extract_known_list,
    _extract_name_with_version,
    _extract_pair_list,
    _facts_as_result,
    _filter_template_catalog_by_section,
    _findings_snapshot,
    _flatten_sample_rows,
    _format_benchmark_answer,
    _format_structured_answer,
    _insufficient_evidence_placeholder,
    _is_effectively_empty_body,
    _is_valid_status,
    _keypoint_catalog,
    _known_keypoints,
    _load_cached_result,
    _load_evidence_chains,
    _load_prior_runs,
    _load_question_routing,
    _load_reusable_section_evidence,
    _load_reusable_section_facts,
    _now,
    _query_template_catalog,
    _question_routing_answer_spec,
    _question_routing_keypoints,
    _question_routing_rule,
    _report_language,
    _representative_ids,
    _resolve_benchmark_expected_shape,
    _resolve_structured_expected_shape,
    _result_count_summary,
    _result_source_label,
    _row_narrative,
    _row_text,
    _row_value,
    _safe_rows,
    _section_family,
    _split_keypoint_names,
    _store_cached_result,
    _store_section_evidence,
    _store_section_facts,
    _store_section_question,
    _store_section_run,
    _structured_digest_from_answers,
    _structured_report_brief,
    _substitute_placeholders,
    _summarize_sql_result,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.db.database import CaseDB
from forensia.knowledge import (  # noqa: F401 — re-export for test import
    load_event_class_definitions as _load_event_class_definitions,
)
from forensia.report.keypoints import (
    _default_keypoints_for_section,
)
from forensia.report.structured_answers import (
    _feed_structured_to_timeline,
    _render_structured_answer_markdown,
    build_structured_answer,
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
    benchmark_mode: bool = False,
    benchmark_id: str = "",
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
    ctx = _prepare_block_context(
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
        benchmark_mode=benchmark_mode,
        benchmark_id=benchmark_id,
        answer_id=answer_id,
        answer_spec=answer_spec,
        question=question,
        section_table_digest=section_table_digest,
        audit_callback=audit_callback,
        review_audit_callback=review_audit_callback,
        report_brief=report_brief,
    )
    try:
        if ctx.benchmark_mode and ctx.answer_spec:
            structured_answer = build_structured_answer(
                ctx.case,
                ctx.db,
                answer_spec=ctx.answer_spec,
                answer_id=ctx.answer_id or ctx.benchmark_id or ctx.answer_spec,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
            )
            if structured_answer is not None:
                body = _render_structured_answer_markdown(
                    structured_answer, ctx.block_heading
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
                    _feed_structured_to_timeline(
                        ctx.db, ctx.answer_spec, structured_answer
                    )
                return SectionBlockResult(
                    body=body,
                    evidence_results=[],
                    iterations=1,
                    status=str(
                        structured_answer.get("status") or "insufficient_evidence"
                    ),
                )

        collected_results: list[dict[str, Any]] = []
        if ctx.reusable_facts:
            collected_results.append(_facts_as_result(ctx.reusable_facts))
        if ctx.reusable_evidence:
            collected_results.append(_evidence_as_result(ctx.reusable_evidence))
        verdict = "block_needs_more"
        rationale = ""
        missing_questions: list[Any] = []
        status = "insufficient_evidence"
        actual_query_count = 0
        actual_query_row_counts: list[int] = []
        template_catalog = ctx.template_catalog
        seed_keypoints = (
            _default_keypoints_for_section(
                ctx.section_key, block_heading=ctx.block_heading
            )[:2]
            if not ctx.benchmark_mode
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
                        actual_query_row_counts.append(
                            int(result.get("row_count") or 0)
                        )
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
        # R3-07: Fast path — skip plan loop if we already have evidence rows
        if collected_results and any(
            str(r.get("kind") or "rows") == "rows" and int(r.get("row_count") or 0) > 0
            for r in collected_results
        ):
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

        for iteration in range(1, ctx.max_queries + 1):
            prior_runs = _load_prior_runs(db, section_key, block_heading)
            template_catalog = _filter_template_catalog_by_section(
                template_catalog, section_key, collected_results
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
        force_chain = ctx.benchmark_mode and status in {
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
    benchmark_mode: bool = False,
    benchmark_id: str = "",
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
        benchmark_mode=benchmark_mode,
        benchmark_id=benchmark_id,
        answer_id=answer_id,
        answer_spec=answer_spec,
        question=question,
        section_table_digest=section_table_digest,
        audit_callback=audit_callback,
        review_audit_callback=review_audit_callback,
    )

