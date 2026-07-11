"""Section-block planning and plan-action execution (LLM plan/check)."""

from __future__ import annotations

from typing import Any

from forensia.ai.llm import llm_gateway
from forensia.ai.prompts.prompt_context import (
    _enforce_system_budget,
)
from forensia.ai.prompts.prompt_sections import (
    build_section_agent_check_messages,
    build_section_agent_plan_messages,
)
from forensia.ai.sections.section_block_context import (
    _BlockContext,
)
from forensia.ai.sections.section_exec import (
    SectionPlanAction,
    _classify_block_status,
    _coerce_plan_action,
    _execute_evidence_chain,
    _execute_keypoint,
    _execute_sql,
    _is_valid_status,
    _split_keypoint_names,
    _summarize_sql_result,
)
from forensia.ai.sections.section_run_store import (
    _store_section_evidence,
    _store_section_facts,
    _store_section_run,
)
from forensia.report.answers.keypoint_catalog import (
    _default_keypoints_for_section,
)


def _run_block_plan(
    ctx: _BlockContext,
    iteration: int,
    prior_runs: list[dict[str, Any]],
    template_catalog: list[dict[str, Any]],
    context_sections: dict[str, str],
    current_section_outline: list[dict],
) -> SectionPlanAction | None:
    plan_messages, plan_schema = build_section_agent_plan_messages(
        section_key=ctx.section_key,
        section_title=ctx.title,
        block_heading=ctx.block_heading,
        template_body=ctx.template_body,
        report_brief=ctx.prompt_report_brief,
        context_sections=context_sections,
        current_section_outline=current_section_outline,
        findings_snapshot=ctx.findings_snapshot,
        keypoint_catalog=ctx.keypoint_catalog,
        query_template_catalog=template_catalog,
        prior_runs=prior_runs,
        reusable_facts=ctx.reusable_facts,
        reusable_evidence=ctx.reusable_evidence,
        memory_context_md=ctx.memory_context_md,
        evidence_keypoints=ctx.evidence_keypoints,
        question_spec=ctx.question_spec.to_prompt_dict()
        if ctx.question_spec is not None
        else None,
        db=ctx.db,
    )
    # R3-07: Enforce system message budget at message assembly level
    if plan_messages and plan_messages[0].get("role") == "system":
        plan_messages[0]["content"] = _enforce_system_budget(
            plan_messages[0]["content"]
        )
    try:
        plan = llm_gateway.request_llm_json(
            messages=plan_messages,
            model=ctx.model,
            base_url=ctx.base_url,
            json_schema=plan_schema,
            audit_callback=ctx.audit,
        )
    except Exception as exc:
        _store_section_run(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            iteration=iteration,
            phase="plan_error",
            payload={"error": str(exc)},
        )
        return None
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="plan",
        payload=plan,
    )
    return _coerce_plan_action(
        plan, section_key=ctx.section_key, iteration=iteration, db=ctx.db
    )


def _execute_block_plan(
    ctx: _BlockContext,
    plan_action: SectionPlanAction,
    iteration: int,
) -> tuple[str, dict[str, Any]] | None:
    if plan_action.action == "keypoint":
        keypoint = plan_action.keypoint
        if not keypoint:
            if ctx.question_mode:
                _store_section_run(
                    ctx.db,
                    section_key=ctx.section_key,
                    block_heading=ctx.block_heading,
                    iteration=iteration,
                    phase="plan_error",
                    payload={
                        "error": "question_mode: no keypoint name and default not allowed"
                    },
                )
                return None
            defaults = _default_keypoints_for_section(
                ctx.section_key, block_heading=ctx.block_heading
            )
            keypoint = defaults[0] if defaults else None
        if not keypoint:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="plan_error",
                payload={
                    "error": "planner returned action=keypoint without keypoint name and no default available"
                },
            )
            return None
        kp_parts = _split_keypoint_names(keypoint)
        source_query = None
        result = None
        for kp in kp_parts:
            sq, res = _execute_keypoint(ctx.case, ctx.db, kp)
            if result is None:
                source_query, result = sq, res
            else:
                for eid in res.get("evidence_ids") or []:
                    sid = str(eid).strip()
                    if sid and sid not in {
                        str(e).strip() for e in (result.get("evidence_ids") or [])
                    }:
                        result.setdefault("evidence_ids", []).append(sid)
                if res.get("sample_rows"):
                    result.setdefault("sample_rows", []).extend(res["sample_rows"])
                if res.get("row_count"):
                    result["row_count"] = (result.get("row_count") or 0) + int(
                        res["row_count"]
                    )
        if result is None:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": "all keypoint parts returned None"},
            )
            return None
    elif plan_action.action in {"template", "sql"}:
        planned_query = plan_action.planned_query
        if planned_query is None or not planned_query.sql:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": "No SQL in planned_query"},
            )
            return None
        try:
            source_query, result = _execute_sql(ctx.db, planned_query.sql)
        except Exception as exc:
            _store_section_run(
                ctx.db,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                iteration=iteration,
                phase="query_error",
                payload={"error": str(exc), "sql": planned_query.sql},
            )
            return None
    else:
        return None
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="query",
        payload={
            "source_kind": str(result.get("source_kind") or "unknown"),
            "source_ref": str(result.get("source_ref") or source_query),
            "result": result,
        },
    )
    if str(result.get("kind") or "rows") == "rows":
        _store_section_evidence(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            result=result,
            source_query=source_query,
        )
    return source_query, result


def _select_columns_by_template(
    raw_rows: list[dict[str, Any]],
    section_key: str,
    template_body: str,
) -> list[dict[str, Any]]:
    if not raw_rows:
        return raw_rows
    headers = list(raw_rows[0].keys())
    tpl_cf = template_body.casefold()
    mentioned = [h for h in headers if h.casefold() in tpl_cf]
    if mentioned:
        return [{c: row[c] for c in mentioned} for row in raw_rows]
    return raw_rows


def _run_block_check(
    ctx: _BlockContext,
    iteration: int,
    result: dict[str, Any],
    collected_results: list[dict[str, Any]],
    prior_runs: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    source_query: str,
) -> tuple[str, str, list[Any], str] | None:
    check_messages, check_schema = build_section_agent_check_messages(
        section_key=ctx.section_key,
        section_title=ctx.title,
        block_heading=ctx.block_heading,
        template_body=ctx.template_body,
        collected_results=collected_results,
        latest_result=result,
        prior_runs=prior_runs,
        reusable_facts=ctx.reusable_facts,
        reusable_evidence=ctx.reusable_evidence,
        memory_context_md=ctx.memory_context_md,
        question_spec=ctx.question_spec.to_prompt_dict()
        if ctx.question_spec is not None
        else None,
    )
    # R3-07: Enforce system message budget at message assembly level
    if check_messages and check_messages[0].get("role") == "system":
        check_messages[0]["content"] = _enforce_system_budget(
            check_messages[0]["content"]
        )
    try:
        check = llm_gateway.request_llm_json(
            messages=check_messages,
            model=ctx.model,
            base_url=ctx.base_url,
            json_schema=check_schema,
            audit_callback=ctx.audit,
        )
    except Exception as exc:
        _store_section_run(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            iteration=iteration,
            phase="check_error",
            payload={"error": str(exc)},
        )
        return None
    verdict = str(check.get("verdict") or "block_needs_more").strip().lower()
    rationale = str(check.get("rationale") or "")
    missing_questions = (
        check.get("missing_questions")
        if isinstance(check.get("missing_questions"), list)
        else []
    )
    status = str(check.get("status") or "").strip().lower()
    result["source_verdict"] = verdict
    if not _is_valid_status(status):
        reusable_rows_present = any(
            str(item.get("kind") or "rows") != "rows" for item in collected_results
        )
        status = _classify_block_status(
            verdict=verdict,
            actual_query_rows=actual_query_row_counts,
            actual_query_count=actual_query_count,
            reusable_rows_present=reusable_rows_present,
        )
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=iteration,
        phase="check",
        payload={**check, "status": status},
        verdict=verdict,
    )
    _store_section_facts(
        ctx.db,
        section_key=ctx.section_key,
        source_query=source_query,
        result=result,
        fact_updates=check.get("fact_updates")
        if isinstance(check.get("fact_updates"), list)
        else None,
    )
    return verdict, rationale, missing_questions, status


def _try_evidence_chain_fallback(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    *,
    force: bool = False,
) -> int:
    if (
        not force
        and actual_query_count > 0
        and any(c > 0 for c in actual_query_row_counts)
    ):
        return actual_query_count
    chain_rows = _execute_evidence_chain(
        ctx.db, ctx.block_heading, ctx.template_body, question=ctx.question
    )
    if chain_rows:
        chain_result = _summarize_sql_result("evidence_chain_fallback", chain_rows)
        chain_result["source_kind"] = "evidence_chain"
        collected_results.append(chain_result)
        actual_query_row_counts.append(
            int(chain_result.get("row_count") or len(chain_rows))
        )
        return actual_query_count + 1
    return actual_query_count
