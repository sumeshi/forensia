from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.ai.json_response import (  # noqa: F401 — import needed for test mocking
    async_request_llm_json,
    request_llm_json,
)
from forensia.ai.prompts import (
    _enforce_system_budget,
    build_paragraph_narrate_messages,
    build_section_agent_check_messages,
    build_section_agent_plan_messages,
    build_section_outline_messages,
    build_section_review_messages,
    build_structured_classify_messages,
)
from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.memory import MemoryManager
from forensia.core.textutil import normalize_localized_dates
from forensia.db.database import CaseDB
from forensia.knowledge import (  # noqa: F401 — re-export for test import
    load_event_class_definitions as _load_event_class_definitions,
)
from forensia.questions import (
    QuestionSpec,
    resolve_question_spec,
)
from forensia.report.keypoints import (
    _default_keypoints_for_section,
)
from forensia.report.narrative_review import review_narrative_body
from forensia.report.probes import (
    _collect_flat_evidence_rows,
    _summarize_flat_evidence_rows,
)
from forensia.report.quality_gates import _detect_body_language
from forensia.report.structured_answers import (
    _feed_structured_to_timeline,
    _render_structured_answer_markdown,
    build_structured_answer,
)

_CONFIDENCE_KEYWORD_MAP = {
    "critical": 0.95,
    "very high": 0.9,
    "high": 0.85,
    "medium-high": 0.75,
    "medium": 0.6,
    "moderate": 0.6,
    "low-medium": 0.45,
    "low": 0.3,
    "very low": 0.15,
    "none": 0.0,
    "n/a": 0.0,
    "unknown": 0.0,
}


# Block-support helpers moved to ai.section_blocks (R4 follow-up); re-exported
# here for backward compatibility with existing imports and tests.
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


@dataclass(slots=True)
class _BlockContext:
    case: Case
    db: CaseDB
    section_key: str
    title: str
    block_heading: str
    template_body: str
    base_url: str
    model: str
    audit: Callable | None
    keypoint_catalog: list[dict]
    template_catalog: list[dict]
    reusable_facts: list[dict[str, Any]]
    reusable_evidence: list[dict[str, Any]]
    memory_context_md: str
    benchmark_mode: bool
    max_queries: int
    findings_snapshot: list[dict[str, Any]]
    prompt_report_brief: dict[str, Any]
    question_spec: QuestionSpec | None = None
    question_confidence: float = 0.0
    evidence_keypoints: list[str] | None = None
    benchmark_id: str = ""
    answer_id: str = ""
    answer_spec: str = ""
    question: str = ""
    structured_digest: str = ""
    review_audit: Callable | None = None


def _prepare_block_context(
    *,
    case: Case,
    db: CaseDB,
    section_key: str,
    title: str,
    block_heading: str,
    template_body: str,
    base_url: str,
    model: str,
    memory: MemoryManager | None,
    max_queries: int,
    evidence_keypoints: list[str] | None,
    benchmark_mode: bool,
    benchmark_id: str = "",
    answer_id: str = "",
    answer_spec: str = "",
    question: str = "",
    section_table_digest: str = "",
    audit_callback=None,
    review_audit_callback=None,
    report_brief: dict[str, Any] | None = None,
) -> _BlockContext:
    routing_text = f"{question}\n{template_body}".strip() if question else template_body
    question_spec, question_confidence = resolve_question_spec(
        block_heading=block_heading,
        template_body=routing_text,
        question=question,
        answer_spec=answer_spec,
    )
    resolved_answer_spec = answer_spec or (
        question_spec.answer_spec if question_spec is not None else ""
    )
    _store_section_question(
        db,
        section_key=section_key,
        block_heading=block_heading,
        question_text=question or block_heading or template_body[:200],
        spec=question_spec,
        confidence=question_confidence,
    )
    memory_context_md = ""
    if memory is not None:
        memory_context_md = memory.load_investigation_context(
            None,
            max_bytes=max(1024, memory.max_bytes // 2),
            include_overview=False,
            include_scratch=False,
        )
    findings_snapshot = _findings_snapshot(db)
    keypoint_catalog = _keypoint_catalog(
        section_key,
        template_body,
        block_heading=block_heading,
        evidence_keypoints=evidence_keypoints,
    )
    template_catalog = _filter_template_catalog_by_section([], section_key, [])
    reusable_facts = _load_reusable_section_facts(
        db,
        section_key,
        include_case_probe=section_key == "6_appendix",
    )
    reusable_evidence = _load_reusable_section_evidence(db, section_key)
    if benchmark_mode:
        reusable_facts = []
        reusable_evidence = []
    audit = _audit_bridge(audit_callback)
    review_audit = _audit_bridge(review_audit_callback)
    prompt_report_brief = (
        _structured_report_brief(report_brief)
        if benchmark_mode
        else (report_brief or {})
    )
    structured_digest = (
        _structured_digest_from_answers(case)
        if section_key in {"1_overview", "2_timeline"}
        else ""
    )
    if section_table_digest:
        # R6-05: same-section table data, rendered moments earlier, becomes
        # part of the narrative blocks' observation context.
        structured_digest = (structured_digest + "\n" + section_table_digest).strip()
    return _BlockContext(
        case=case,
        db=db,
        section_key=section_key,
        title=title,
        block_heading=block_heading,
        template_body=template_body,
        base_url=base_url,
        model=model,
        audit=audit,
        keypoint_catalog=keypoint_catalog,
        template_catalog=template_catalog,
        reusable_facts=reusable_facts,
        reusable_evidence=reusable_evidence,
        memory_context_md=memory_context_md,
        benchmark_mode=benchmark_mode,
        max_queries=max_queries,
        findings_snapshot=findings_snapshot,
        prompt_report_brief=prompt_report_brief,
        question_spec=question_spec,
        question_confidence=question_confidence,
        evidence_keypoints=evidence_keypoints,
        benchmark_id=benchmark_id,
        answer_id=answer_id,
        answer_spec=resolved_answer_spec,
        question=question,
        structured_digest=structured_digest,
        review_audit=review_audit,
    )


# ====================================================================
# PLAN/CHECK — plan and check phase logic
# Lines: ~1177-1400
# ====================================================================


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
        plan = request_llm_json(
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
            if ctx.benchmark_mode:
                _store_section_run(
                    ctx.db,
                    section_key=ctx.section_key,
                    block_heading=ctx.block_heading,
                    iteration=iteration,
                    phase="plan_error",
                    payload={
                        "error": "benchmark_mode: no keypoint name and default not allowed"
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
        check = request_llm_json(
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


# ====================================================================
# BLOCK EXECUTION — _write_block_body, run_section_block_agent
# Lines: ~2082-2647
# ====================================================================


_NARRATE_RETRY_PROMPT = (
    "Your previous response had an empty or near-empty body. "
    'Retry: emit exactly one JSON object {"body": "<paragraph>"} '
    "where <paragraph> is at least 50 characters and cites the evidence_ids above. "
    "Do not return an empty string."
)


def _normalize_report_language(value: str) -> str:
    value = str(value or "").strip().lower()
    if value in {"ja", "jp", "japanese"}:
        return "ja"
    if value in {"en", "english"}:
        return "en"
    return value


def _postprocess_block_body(body: str, *, section_key: str, block_heading: str) -> str:
    """Apply deterministic post-generation cleanup to section block prose."""
    processed = normalize_localized_dates(str(body or ""))
    if processed != body:
        _log(
            "SECTION",
            f"normalized localized date format in {section_key}/{block_heading}",
        )
    expected = _normalize_report_language(_report_language())
    if expected in {"en", "ja"}:
        detected = _detect_body_language(processed)
        if detected not in {"unknown", expected}:
            _log(
                "SECTION",
                f"language mismatch in {section_key}/{block_heading}: "
                f"expected={expected}, detected={detected}",
            )
    return processed


def _narrate_paragraph_with_retry(
    *,
    narrate_messages: list[dict[str, str]],
    narrate_schema: dict,
    model: str,
    base_url: str,
    audit_callback,
    target_language: str = "",
) -> str:
    """Call paragraph_narrate once; retry with language/empty-body coaching as needed.

    Language enforcement: if the body is in a language other than the target, retry
    once with a language-coaching turn.  If the second attempt still mismatches,
    return empty so the caller falls back to deterministic prose.

    Empty-body retry: if the body is effectively empty, retry once with _NARRATE_RETRY_PROMPT.
    """
    target = target_language.strip().lower() if target_language else ""
    target = (
        "ja" if target in {"ja", "jp", "japanese"} else "en" if target == "en" else ""
    )

    def _call(messages: list[dict[str, str]]) -> str:
        parsed = request_llm_json(
            messages=messages,
            model=model,
            base_url=base_url,
            json_schema=narrate_schema,
            audit_callback=audit_callback,
        )
        return str(parsed.get("body", parsed.get("content", ""))).strip()

    if not target:
        body = _call(narrate_messages)
        if not _is_effectively_empty_body(body):
            return body
        retry_messages = list(narrate_messages)
        retry_messages.append({"role": "user", "content": _NARRATE_RETRY_PROMPT})
        return _call(retry_messages)

    body = _call(narrate_messages)
    if not _is_effectively_empty_body(body):
        detected = _detect_body_language(body)
        if detected not in ("unknown", target):
            # Language mismatch: retry once with coaching
            coaching = (
                "Write the entire paragraph in the target language. "
                f"Target language: {target}. "
                "Do not mix languages."
            )
            retry_messages = list(narrate_messages)
            retry_messages.append({"role": "user", "content": coaching})
            body = _call(retry_messages)
            if not _is_effectively_empty_body(body):
                detected2 = _detect_body_language(body)
                if detected2 not in ("unknown", target):
                    # second mismatch → return empty so caller falls back
                    return ""
                return body
            return ""
        return body
    # Empty body: retry with existing empty-body prompt
    retry_messages = list(narrate_messages)
    retry_messages.append({"role": "user", "content": _NARRATE_RETRY_PROMPT})
    body = _call(retry_messages)
    if not _is_effectively_empty_body(body):
        detected = _detect_body_language(body)
        if detected not in ("unknown", target):
            return ""  # Language mismatch, fall back
    return body


def _fallback_narrative_body(
    *,
    heading: str,
    status: str,
    collected_results: list[dict[str, Any]],
    flat_evidence: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    key_points: list[str] | None = None,
) -> str:
    """Build a deterministic paragraph when the LLM narrator returns an empty body.

    The prose states what was *observed* — never how much data was *reviewed*.
    Meta-diagnostic phrasing ("the collected evidence returned N rows",
    "Representative row: …") is deliberately avoided: the paragraph_narrate
    prompt forbids it, and such text shipped as an Executive Summary in the
    2026-07-05 run. Key points (already verdict-labelled observations) are the
    primary material; evidence rows are the fallback. ``check_fallback_stub``
    in report_validation guards against the old phrasing reappearing.
    """
    evidence_ids, finding_ids = _representative_ids(collected_results, flat_evidence)

    if status in {"not_found", "not_searched"} or (
        actual_query_count > 0 and not any(actual_query_row_counts)
    ):
        return (
            f"No supporting evidence was found for {heading}. This item is "
            "unsupported and is not part of the incident narrative."
        )

    ref_text = ""
    if evidence_ids:
        ref_text = f" (evidence: {', '.join(evidence_ids[:3])})"
    elif finding_ids:
        ref_text = f" (findings: {', '.join(finding_ids[:3])})"

    # Prefer already-observed, verdict-labelled key points: these are report
    # statements, not review metadata.
    clean_points: list[str] = []
    for point in key_points or []:
        text = str(point or "").strip()
        if text:
            clean_points.append(text)
    if clean_points:
        joined = "; ".join(clean_points[:4])
        paragraph = f"{joined}.{ref_text}"
    else:
        # No key points — describe representative observed rows factually.
        observed: list[str] = []
        for row in flat_evidence:
            if not isinstance(row, dict):
                continue
            ts = str(row.get("timestamp") or row.get("date") or "").strip()
            eid = str(row.get("event_id") or "").strip()
            desc = " ".join(p for p in (ts, f"event {eid}" if eid else "") if p)
            if desc:
                observed.append(desc)
            if len(observed) >= 3:
                break
        if observed:
            paragraph = (
                f"Observed activity relevant to {heading}: "
                + "; ".join(observed)
                + f".{ref_text}"
            )
        else:
            paragraph = (
                f"Evidence relevant to {heading} was collected, but the available "
                f"rows do not contain enough report-visible detail for a stronger "
                f"summary.{ref_text}"
            )
    if status == "partial":
        paragraph += (
            " Additional correlation is needed before this is fully established."
        )
    return paragraph.strip()


def _label_key_points_with_verdicts(
    outline_items: list[dict[str, Any]],
    collected_results: list[dict[str, Any]],
    overall_verdict: str,
) -> list[str]:
    """Prefix key_points with verdict labels: [confirmed], [refuted], [finding, confidence=N].

    Uses source_verdict from results that went through the check loop, and
    confidence from fact/finding results for fallback labeling.
    """
    eid_verdicts: dict[str, str] = {}
    eid_finding_conf: dict[str, float] = {}

    for result in collected_results:
        verdict = str(result.get("source_verdict") or "").strip().lower()
        evids = [
            str(e).strip() for e in (result.get("evidence_ids") or []) if str(e).strip()
        ]

        # Confidence from result-level field or sample_rows
        result_conf: float | None = None
        raw_conf = result.get("confidence")
        if raw_conf is not None:
            try:
                result_conf = float(raw_conf)
            except TypeError, ValueError:
                pass
        if result_conf is None:
            for row in result.get("sample_rows") or []:
                if isinstance(row, dict):
                    c = row.get("confidence")
                    if c is not None:
                        try:
                            result_conf = float(c)
                            break
                        except TypeError, ValueError:
                            pass

        if verdict and evids:
            for eid in evids:
                if eid not in eid_verdicts or verdict == "block_contradicted":
                    eid_verdicts[eid] = verdict

        if result_conf is not None and evids:
            for eid in evids:
                if eid not in eid_finding_conf:
                    eid_finding_conf[eid] = result_conf

    labeled: list[str] = []
    any_verdict_labels = False

    for item in outline_items:
        item_eids = {
            str(e).strip() for e in (item.get("evidence_ids") or []) if str(e).strip()
        }
        item_verdicts = {
            eid_verdicts.get(eid) for eid in item_eids if eid in eid_verdicts
        }
        item_verdicts.discard(None)

        if "block_contradicted" in item_verdicts:
            label = "[refuted]"
            any_verdict_labels = True
        elif "block_supported" in item_verdicts:
            label = "[confirmed]"
            any_verdict_labels = True
        elif item_eids and any(eid in eid_finding_conf for eid in item_eids):
            conf_val = max(
                eid_finding_conf.get(eid, 0.0)
                for eid in item_eids
                if eid in eid_finding_conf
            )
            label = f"[finding, confidence={conf_val}]"
            any_verdict_labels = True
        else:
            label = ""

        for kp in item.get("key_points") or []:
            labeled.append(f"{label} {kp}" if label else kp)

    # Fallback: if no per-result verdicts were found, use overall_verdict
    if not any_verdict_labels and overall_verdict in (
        "block_supported",
        "block_contradicted",
    ):
        fb_label = (
            "[confirmed]" if overall_verdict == "block_supported" else "[refuted]"
        )
        labeled = [f"{fb_label} {kp}" for kp in labeled]

    return labeled


def _review_and_rewrite_narrative(
    ctx: _BlockContext,
    body: str,
    narrate_messages: list[dict[str, str]],
    narrate_schema: dict[str, Any],
) -> str:
    """R7-01 section_reviewer: rewrite deterministic failures at most once.

    Deterministic rubric problems (citation overload, pseudo-citations,
    internal IDs) are computed in code. Clean bodies pass without an extra LLM
    call. Bodies with deterministic problems are handed to the LLM reviewer as
    ground truth; on a 'rewrite' verdict the narrator runs once more. The
    rewrite is kept only when it is no worse, and leftovers are recorded in
    the section run trace. Failures never block the section.
    """
    deterministic_problems = review_narrative_body(body)
    if not deterministic_problems:
        _store_section_run(
            ctx.db,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
            iteration=1,
            phase="review",
            payload={
                "verdict": "pass",
                "deterministic_problems": [],
                "remaining_problems": [],
                "reviewer": "deterministic",
            },
        )
        return body

    review: dict[str, Any] = {}
    remaining: list[str] = deterministic_problems
    try:
        review_msgs, review_schema = build_section_review_messages(
            ctx.block_heading,
            body,
            ctx.structured_digest or None,
            deterministic_problems,
        )
        review_audit = ctx.review_audit or ctx.audit
        review = request_llm_json(
            messages=review_msgs,
            model=ctx.model,
            base_url=ctx.base_url,
            json_schema=review_schema,
            audit_callback=review_audit,
        )
        if deterministic_problems or review.get("verdict") == "rewrite":
            guidance = str(review.get("guidance") or "")
            problems_str = "; ".join(
                str(p) for p in (review.get("problems") or deterministic_problems)
            )
            rewrite_msgs = [
                *narrate_messages,
                {
                    "role": "assistant",
                    "content": json.dumps({"body": body}, ensure_ascii=False),
                },
                {
                    "role": "user",
                    "content": (
                        f"Your previous paragraph (above) has these problems: {problems_str}. "
                        f"Guidance: {guidance}. Rewrite the paragraph fixing every problem; "
                        f"keep only claims supported by the evidence and at most 2-3 citations."
                    ),
                },
            ]
            rewritten = _narrate_paragraph_with_retry(
                narrate_messages=rewrite_msgs,
                narrate_schema=narrate_schema,
                model=ctx.model,
                base_url=ctx.base_url,
                audit_callback=review_audit,
                target_language=_report_language(),
            )
            rewritten_problems = review_narrative_body(rewritten)
            if rewritten.strip() and len(rewritten_problems) <= len(
                deterministic_problems
            ):
                body = rewritten
                remaining = rewritten_problems
            if remaining:
                print(
                    f"[review] {ctx.section_key}/{ctx.block_heading} — unresolved after rewrite: {remaining}"
                )
    except Exception as exc:
        print(
            f"[review] LLM review failed for {ctx.section_key}/{ctx.block_heading}: {exc}"
        )
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=1,
        phase="review",
        payload={
            "verdict": str(review.get("verdict") or ""),
            "deterministic_problems": deterministic_problems,
            "remaining_problems": remaining,
        },
    )
    return body


def _write_block_body(
    ctx: _BlockContext,
    collected_results: list[dict[str, Any]],
    status: str,
    verdict: str,
    rationale: str,
    missing_questions: list[Any],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    audit_callback=None,
) -> tuple[str, str]:
    if status == "insufficient_evidence":
        reusable_rows_present = any(
            str(item.get("kind") or "rows") != "rows" for item in collected_results
        )
        status_inner = _classify_block_status(
            verdict=verdict,
            actual_query_rows=actual_query_row_counts,
            actual_query_count=actual_query_count,
            reusable_rows_present=reusable_rows_present,
        )
    else:
        status_inner = status

    raw_rows = _collect_flat_evidence_rows(collected_results)
    if raw_rows:
        raw_rows = _select_columns_by_template(
            raw_rows, ctx.section_key, ctx.template_body
        )
    prompt_rows = _summarize_flat_evidence_rows(raw_rows) if raw_rows else None

    if ctx.benchmark_mode:
        structured_answer = build_structured_answer(
            ctx.case,
            ctx.db,
            answer_spec=ctx.answer_spec,
            answer_id=ctx.answer_id or ctx.benchmark_id,
            section_key=ctx.section_key,
            block_heading=ctx.block_heading,
        )
        if structured_answer is not None:
            status_inner = str(structured_answer.get("status") or status_inner)
            body = _render_structured_answer_markdown(
                structured_answer, ctx.block_heading
            )
            messages = []
        else:
            expected_shape = _resolve_structured_expected_shape(ctx.block_heading)

            extracted_rows = (
                _extract_answer_by_shape(
                    raw_rows, expected_shape, expected_shape.get("format", "")
                )
                if raw_rows and expected_shape
                else []
            )

            # BUG-030: Skip classify when rows already match expected_shape
            if (
                extracted_rows
                and expected_shape
                and all(
                    field in extracted_rows[0]
                    for field in expected_shape.get("fields") or []
                )
            ):
                # rows already match the expected shape — skip classify, use them directly
                picked_rows = extracted_rows
                classification = {
                    "status": "answered",
                    "picked_row_indices": [],
                    "rationale": "rows match expected_shape",
                }
            else:
                classify_messages, classify_schema = build_structured_classify_messages(
                    question=ctx.template_body or ctx.block_heading,
                    block_heading=ctx.block_heading,
                    evidence_rows=prompt_rows or [],
                    expected_shape=expected_shape,
                    time_range=ctx.case.time_range,
                )
                classification = request_llm_json(
                    messages=classify_messages,
                    model=ctx.model,
                    base_url=ctx.base_url,
                    json_schema=classify_schema,
                    audit_callback=ctx.audit,
                )
                # Handle picked_row_indices (int array) instead of picked_row_ids
                picked_row_indices = classification.get("picked_row_indices") or []
                if isinstance(picked_row_indices, list):
                    valid_indices = [
                        i
                        for i in picked_row_indices
                        if isinstance(i, int) and 0 <= i < len(raw_rows or [])
                    ]
                else:
                    valid_indices = []
                picked_rows = [raw_rows[i] for i in valid_indices] if raw_rows else []

            queries_run = [
                str(r.get("source_ref") or r.get("source_query") or "")
                for r in collected_results
                if r.get("source_ref") or r.get("source_query")
            ]
            body = _format_structured_answer(
                classification=classification,
                picked_rows=picked_rows,
                expected_shape=expected_shape,
                section_key=ctx.section_key,
                block_heading=ctx.block_heading,
                status=status_inner,
                case=ctx.case,
                benchmark_id=ctx.benchmark_id,
                queries_run=queries_run,
                evidence_rows=prompt_rows or [],
                answer_spec=ctx.answer_spec
                or (
                    ctx.question_spec.answer_spec
                    if ctx.question_spec is not None
                    else ""
                ),
            )
            messages = (
                classify_messages
                if not (
                    extracted_rows
                    and expected_shape
                    and all(
                        field in extracted_rows[0]
                        for field in expected_shape.get("fields") or []
                    )
                )
                else []
            )
    else:
        if (
            status_inner in {"not_searched", "not_found", "wrong_query"}
            and not ctx.structured_digest
        ):
            # Reader-facing insufficient-evidence placeholder. Must not contain
            # workflow markers ("Block skipped", "Section block failed") or
            # open-question markers — those trip the section quality gates and
            # would cap the whole section's confidence.
            # When structured observations exist (structured answers or the
            # section's own table data), narrate from them instead of
            # claiming insufficiency next to a populated table.
            body = _insufficient_evidence_placeholder()
            messages = []
        else:
            flat_evidence = _flatten_sample_rows(collected_results, rows_only=True)
            if flat_evidence:
                prior_section_keypoints = list(
                    {
                        str(r.get("keypoint") or r.get("source_kind") or "")
                        for r in collected_results
                        if r.get("keypoint") or r.get("source_kind")
                    }
                )
                outline_messages, outline_schema = build_section_outline_messages(
                    template_body=ctx.template_body,
                    relevant_evidence=flat_evidence,
                    time_range=ctx.case.time_range,
                    section_meta={"section": ctx.section_key, "title": ctx.title},
                    prior_section_keypoints=prior_section_keypoints,
                )
                outline = request_llm_json(
                    messages=outline_messages,
                    model=ctx.model,
                    base_url=ctx.base_url,
                    json_schema=outline_schema,
                    audit_callback=ctx.audit,
                )
                outline_items: list[dict[str, Any]] = outline.get("outline") or []
                all_key_points: list[str] = _label_key_points_with_verdicts(
                    outline_items,
                    collected_results,
                    verdict,
                )
            else:
                # No query evidence — the narrator works from the structured
                # digest alone; an outline call over zero rows is wasted.
                all_key_points = []
            narrate_messages, narrate_schema = build_paragraph_narrate_messages(
                heading=ctx.block_heading,
                key_points=all_key_points,
                evidence_rows=flat_evidence[:10],
                template_body=ctx.template_body,
                structured_digest=ctx.structured_digest,
            )
            body = _narrate_paragraph_with_retry(
                narrate_messages=narrate_messages,
                narrate_schema=narrate_schema,
                model=ctx.model,
                base_url=ctx.base_url,
                audit_callback=ctx.audit,
                target_language=_report_language(),
            )
            if _is_effectively_empty_body(body):
                _log(
                    "SECTION",
                    f"narrator returned empty body for '{ctx.block_heading}'; "
                    "using deterministic fallback",
                )
                body = _fallback_narrative_body(
                    heading=ctx.block_heading,
                    status=status_inner,
                    collected_results=collected_results,
                    flat_evidence=flat_evidence,
                    actual_query_count=actual_query_count,
                    actual_query_row_counts=actual_query_row_counts,
                    key_points=all_key_points,
                )
            body = _review_and_rewrite_narrative(
                ctx, body, narrate_messages, narrate_schema
            )
            messages = narrate_messages

    body = _postprocess_block_body(
        body, section_key=ctx.section_key, block_heading=ctx.block_heading
    )
    if audit_callback:
        audit_callback(messages, body)
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=max(len(collected_results), 1),
        phase="write",
        payload={"evidence_count": len(collected_results), "body_preview": body[:400]},
    )
    return body, status_inner


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
