"""Narrative writing for section blocks: narrate, review, fallbacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensia.ai.llm import llm_gateway
from forensia.ai.prompts.prompt_sections import (
    build_paragraph_narrate_messages,
    build_section_outline_messages,
    build_structured_classify_messages,
)
from forensia.ai.prompts.report_evidence_projection import (
    project_report_evidence_rows,
)
from forensia.ai.sections.section_answers import (
    _flatten_sample_rows,
    _format_structured_answer,
    _insufficient_evidence_placeholder,
    _report_language,
    _representative_ids,
    _resolve_structured_expected_shape,
    extract_answer_by_shape,
    is_effectively_empty_body,
)
from forensia.ai.sections.section_block_context import (
    _BlockContext,
)
from forensia.ai.sections.section_block_plan import (
    _select_columns_by_template,
)
from forensia.ai.sections.section_exec import _classify_block_status
from forensia.ai.sections.section_run_store import _store_section_run
from forensia.core.log import log as _log
from forensia.core.textutil import normalize_localized_dates
from forensia.report.answers.answer_registry import build_structured_answer
from forensia.report.answers.answer_store import _render_structured_answer_markdown
from forensia.report.answers.table_registry import (
    _collect_flat_evidence_rows,
    _summarize_flat_evidence_rows,
)
from forensia.report.render.formats import load_report_formats
from forensia.report.sections.narrative_review import review_narrative_body
from forensia.report.sections.quality_gates import _detect_body_language

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


def narrate_paragraph_with_retry(
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
        parsed = llm_gateway.request_llm_json(
            messages=messages,
            model=model,
            base_url=base_url,
            json_schema=narrate_schema,
            telemetry_phase="section-narrative",
            audit_callback=audit_callback,
        )
        return str(parsed.get("body", parsed.get("content", ""))).strip()

    if not target:
        body = _call(narrate_messages)
        if not is_effectively_empty_body(body):
            return body
        retry_messages = list(narrate_messages)
        retry_messages.append({"role": "user", "content": _NARRATE_RETRY_PROMPT})
        return _call(retry_messages)

    body = _call(narrate_messages)
    if not is_effectively_empty_body(body):
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
            if not is_effectively_empty_body(body):
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
    if not is_effectively_empty_body(body):
        detected = _detect_body_language(body)
        if detected not in ("unknown", target):
            return ""  # Language mismatch, fall back
    return body


def fallback_narrative_body(
    *,
    heading: str,
    status: str,
    collected_results: list[dict[str, Any]],
    flat_evidence: list[dict[str, Any]],
    actual_query_count: int,
    actual_query_row_counts: list[int],
    key_points: list[str] | None = None,
    template_dir: str | Path | None = None,
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
    formats = load_report_formats(template_dir)["narrative_fallback"]
    evidence_ids, finding_ids = _representative_ids(collected_results, flat_evidence)

    if status in {"not_found", "not_searched"} or (
        actual_query_count > 0 and not any(actual_query_row_counts)
    ):
        return str(formats["unsupported"]).format(heading=heading)

    ref_text = ""
    if evidence_ids:
        ref_text = str(formats["evidence_reference"]).format(
            ids=", ".join(evidence_ids[:3])
        )
    elif finding_ids:
        ref_text = str(formats["finding_reference"]).format(
            ids=", ".join(finding_ids[:3])
        )

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
            paragraph = str(formats["observed"]).format(
                heading=heading,
                observations="; ".join(observed),
                reference=ref_text,
            )
        else:
            paragraph = str(formats["insufficient_detail"]).format(
                heading=heading, reference=ref_text
            )
    if status == "partial":
        paragraph += str(formats["partial_suffix"])
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
    """R7-01 deterministic narrative review: rewrite flagged bodies at most once.

    Deterministic rubric problems (citation overload, pseudo-citations,
    internal IDs) are the decision owner. Clean bodies pass without any LLM
    call. Flagged bodies get one bounded narrator rewrite guided by those
    problems; no separate reviewer verdict step exists. The rewrite is kept
    only when deterministic review shows it is no worse, and leftovers are
    recorded in the section run trace. Failures never block the section.
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

    remaining: list[str] = deterministic_problems
    try:
        problems_str = "; ".join(str(p) for p in deterministic_problems)
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
                    f"Rewrite the paragraph fixing every problem; "
                    f"keep only claims supported by the evidence and at most 2-3 citations."
                ),
            },
        ]
        review_audit = ctx.review_audit or ctx.audit
        rewritten = narrate_paragraph_with_retry(
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
            _log(
                "REVIEW",
                f"{ctx.section_key}/{ctx.block_heading} — unresolved after rewrite: {remaining}",
                level="warning",
            )
    except Exception as exc:
        _log(
            "REVIEW",
            f"Narrative rewrite failed for {ctx.section_key}/{ctx.block_heading}: {exc}",
            level="error",
        )
    _store_section_run(
        ctx.db,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
        iteration=1,
        phase="review",
        payload={
            "verdict": "rewrite",
            "reviewer": "deterministic",
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
    projected_raw_rows = project_report_evidence_rows(raw_rows, db=ctx.db)
    prompt_rows = (
        _summarize_flat_evidence_rows(projected_raw_rows)
        if projected_raw_rows
        else None
    )

    if ctx.question_mode:
        body, messages, status_inner = _write_question_block(
            ctx,
            raw_rows,
            prompt_rows,
            collected_results,
            status_inner,
        )
    else:
        body, messages = _write_narrative_block(
            ctx,
            raw_rows,
            prompt_rows,
            collected_results,
            verdict,
            status_inner,
            actual_query_count,
            actual_query_row_counts,
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


def _write_question_block(
    ctx: _BlockContext,
    raw_rows: list[dict[str, Any]] | None,
    prompt_rows: list[dict[str, Any]] | None,
    collected_results: list[dict[str, Any]],
    status_inner: str,
) -> tuple[str, list, str]:
    """Benchmark-mode body: structured answer or classify-then-format."""
    structured_answer = build_structured_answer(
        ctx.case,
        ctx.db,
        answer_spec=ctx.answer_spec,
        answer_id=ctx.answer_id or ctx.question_id,
        section_key=ctx.section_key,
        block_heading=ctx.block_heading,
    )
    if structured_answer is not None:
        status_inner = str(structured_answer.get("status") or status_inner)
        body = _render_structured_answer_markdown(
            structured_answer,
            ctx.block_heading,
            template_dir=ctx.case.report_template_dir,
        )
        messages = []
    else:
        expected_shape = _resolve_structured_expected_shape(ctx.block_heading)

        extracted_rows = (
            extract_answer_by_shape(
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
                db=ctx.db,
            )
            classification = llm_gateway.request_llm_json(
                messages=classify_messages,
                model=ctx.model,
                base_url=ctx.base_url,
                json_schema=classify_schema,
                telemetry_phase="section-structured-classify",
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
            question_id=ctx.question_id,
            queries_run=queries_run,
            evidence_rows=prompt_rows or [],
            answer_spec=ctx.answer_spec
            or (ctx.question_spec.answer_spec if ctx.question_spec is not None else ""),
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
    return body, messages, status_inner


def _write_narrative_block(
    ctx: _BlockContext,
    raw_rows: list[dict[str, Any]] | None,
    prompt_rows: list[dict[str, Any]] | None,
    collected_results: list[dict[str, Any]],
    verdict: str,
    status_inner: str,
    actual_query_count: int,
    actual_query_row_counts: list[int],
) -> tuple[str, list]:
    """Narrative-mode body: outline -> narrate -> review."""
    flat_evidence = _flatten_sample_rows(collected_results, rows_only=True)
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
        prompt_flat_evidence = project_report_evidence_rows(flat_evidence, db=ctx.db)
        executive_from_brief = (
            ctx.block_heading.strip().lower() == "executive summary"
            and bool(ctx.structured_digest)
        )
        if prompt_flat_evidence and not executive_from_brief:
            prior_section_keypoints = list(
                {
                    str(r.get("keypoint") or r.get("source_kind") or "")
                    for r in collected_results
                    if r.get("keypoint") or r.get("source_kind")
                }
            )
            outline_messages, outline_schema = build_section_outline_messages(
                template_body=ctx.template_body,
                relevant_evidence=prompt_flat_evidence,
                time_range=ctx.case.time_range,
                section_meta={"section": ctx.section_key, "title": ctx.title},
                prior_section_keypoints=prior_section_keypoints,
                db=ctx.db,
            )
            outline = llm_gateway.request_llm_json(
                messages=outline_messages,
                model=ctx.model,
                base_url=ctx.base_url,
                json_schema=outline_schema,
                telemetry_phase="section-outline",
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
            evidence_rows=prompt_flat_evidence[:10],
            template_body=ctx.template_body,
            structured_digest=ctx.structured_digest,
            report_context={
                key: value
                for key in ("time_range", "source_timezone", "timezone_offset", "case_metrics")
                if (value := ctx.prompt_report_brief.get(key)) not in (None, "", {})
            },
            db=ctx.db,
        )
        body = narrate_paragraph_with_retry(
            narrate_messages=narrate_messages,
            narrate_schema=narrate_schema,
            model=ctx.model,
            base_url=ctx.base_url,
            audit_callback=ctx.audit,
            target_language=_report_language(),
        )
        if is_effectively_empty_body(body):
            _log(
                "SECTION",
                f"narrator returned empty body for '{ctx.block_heading}'; "
                "using deterministic fallback",
            )
            body = fallback_narrative_body(
                heading=ctx.block_heading,
                status=status_inner,
                collected_results=collected_results,
                flat_evidence=prompt_flat_evidence,
                actual_query_count=actual_query_count,
                actual_query_row_counts=actual_query_row_counts,
                key_points=all_key_points,
                template_dir=ctx.case.report_template_dir,
            )
        body = _review_and_rewrite_narrative(
            ctx, body, narrate_messages, narrate_schema
        )
        messages = narrate_messages
    return body, messages

    body = _postprocess_block_body(
        body, section_key=ctx.section_key, block_heading=ctx.block_heading
    )
