from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.llm_client import chat_completion
from forensia.ai.report_gap import _build_report_status
from forensia.core.case import Case
from forensia.core.memory import MemoryManager, memory_for_section
from forensia.db.database import CaseDB
from forensia.report.writer import (
    _assemble_section_body,
    _body_starts_with_heading,
    _collect_flat_evidence_rows,
    _dump_section_evidence_json,
    _dump_section_questions_json,
    _dump_section_trace_json,
    _verify_block_output,
    collect_gaps,
    ensure_universal_question_probes,
    finalize_section,
    load_report_sections_map,
    prepare_section_request,
    write_report_brief,
)
from forensia.ai.section_agent import SectionBlockResult, async_run_section_block_agent, run_section_block_agent
from forensia.report.markdown import _markdown_table
from forensia.report.probes import _TABLE_BLOCK_BUILDERS, _table_block_columns
from forensia.api.cache import write_api_snapshots


def _log_report(message: str) -> None:
    print(f"[bold white][REPORT][/bold white] {message}")


def _collect_section_requests(
    case: Case,
    db: CaseDB,
    template_paths: list[Path],
    prior_filled: dict[str, str],
    report_brief: dict[str, Any],
) -> list[dict[str, Any]]:
    stale_section_keys = {
        str(row["section_key"])
        for row in db.execute("SELECT section_key FROM report_sections WHERE stale = TRUE").fetchall()
    }
    requests: list[dict[str, Any]] = []
    for template_path in template_paths:
        request = prepare_section_request(case, db, template_path, prior_filled, report_brief=report_brief)
        request["template_path"] = str(template_path)
        request["is_stale"] = request.get("section_key") in stale_section_keys
        request["needs_refresh"] = request["is_stale"] or not str(prior_filled.get(request["section_key"]) or "").strip()
        if request["needs_refresh"]:
            requests.append(request)
    return requests


def _sort_section_requests(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _section_key_re = re.compile(r"^(\d+)_")

    def sort_key(req: dict[str, Any]) -> tuple[int, int, str]:
        section_key = str(req.get("section_key") or "")
        is_stale = req.get("is_stale", False)
        priority = 0 if is_stale else 1
        match = _section_key_re.match(section_key)
        if match:
            order = int(match.group(1))
        else:
            logging.warning(
                "section_key %r does not match '<int>_*' convention; sorting to end. "
                "Rename the template file to [0-9]+_<slug>.md or set 'section' frontmatter.",
                section_key,
            )
            order = 9999
        return (priority, order, section_key)

    requests.sort(key=sort_key)
    return requests


def _emit_section_failure(
    progress_callback: Callable[[dict[str, Any]], None] | None,
    iteration: int,
    exc: Exception,
    db: CaseDB,
    focus_sections: list[str] | None,
) -> None:
    if progress_callback:
        progress_callback(
            {
                "stage": "investigate/report-section-done",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] section failed: {exc}",
                "report_sections": _build_report_status(db, focus_sections=focus_sections),
            }
        )


async def _render_section_blocks(
    request: dict[str, Any],
    case: Case,
    db: CaseDB,
    memory: MemoryManager,
    base_url: str,
    model: str,
    max_queries_per_section: int,
    llm_logger: LLMCallLogger,
    iteration: int,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str] | None,
) -> tuple[dict[str, Any], str]:
    section_key = request["section_key"]
    is_stale = request.get("is_stale", False)
    blocks = request.get("block_requests") or []
    all_structured = bool(blocks) and all(
        str(b.get("mode") or "").strip().casefold() in {"benchmark", "structured"}
        or bool(b.get("answer_spec") or b.get("question"))
        for b in blocks
    )
    if all_structured and not is_stale:
        existing = db.execute(
            "SELECT body FROM report_sections WHERE section_key = ? AND stale = FALSE AND length(body) > 100",
            [section_key],
        ).fetchone()
        if existing:
            _log_report(f"{section_key} — structured answers already written, skipping")
            return request, existing[0]
    _log_report(f"{section_key} — writing")
    if progress_callback:
        progress_callback(
            {
                "stage": "investigate/report-section",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] {section_key} writing...",
                "current_report_section": section_key,
                "report_sections": _build_report_status(
                    db,
                    current_section=section_key,
                    focus_sections=focus_sections,
                ),
            }
        )

    rendered_blocks: list[str] = []
    block_gaps: list[str] = []
    block_outline: list[dict] = []
    all_evidence_results: list[dict[str, Any]] = []

    try:
        for block in request.get("block_requests") or []:
            try:
                block_mode = str(block.get("mode") or "").strip().casefold()
                is_structured_mode = block_mode in {"benchmark", "structured"} or bool(block.get("answer_spec") or block.get("question"))
                block_result = await async_run_section_block_agent(
                    case=request["case"],
                    db=db,
                    section_key=str(request["section_key"]),
                    title=str(request["title"]),
                    block_heading=str(block.get("heading") or ""),
                    template_body=str(block.get("template_body") or ""),
                    context_sections={} if is_structured_mode else (request.get("context_sections") or {}),
                    current_section_outline=[] if is_structured_mode else block_outline,
                    report_brief=request.get("report_brief") or {},
                    base_url=base_url,
                    model=model,
                    memory=memory_for_section(memory, structured_mode=is_structured_mode),
                    max_queries_per_section=max_queries_per_section,
                    evidence_keypoints=list(block.get("evidence_keypoints") or []),
                    benchmark_mode=is_structured_mode,
                    benchmark_id=str(block.get("benchmark_id") or block.get("answer_id") or ""),
                    answer_id=str(block.get("answer_id") or block.get("benchmark_id") or ""),
                    answer_spec=str(block.get("answer_spec") or ""),
                    question=str(block.get("question") or ""),
                    audit_callback=lambda messages, body, section=request["section_key"], heading=block.get("heading", ""): llm_logger.write(
                        iteration=iteration,
                        phase="report-section-block",
                        input_messages=messages,
                        output=body,
                        model=model,
                        base_url=base_url,
                        suffix=f"{request['section_key']}-{heading}",
                    ),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _log_report(f"{section_key} — block failed: {exc}")
                raise
            block_body = block_result.body
            heading = str(block.get("heading") or "").strip()
            if heading and not _body_starts_with_heading(block_body, heading):
                block_body = f"## {heading}\n\n{block_body}"
            rendered_blocks.append(block_body)
            if heading:
                block_outline.append({
                    "heading": heading,
                    "summary": (block_result.body.split("\n", 1)[0])[:120],
                })
            all_evidence_results.extend(block_result.evidence_results)
            block_body_gaps, _ = _verify_block_output(db, block_result.body)
            for gap in block_body_gaps:
                label = f"{heading}: {gap}" if heading else gap
                if label not in block_gaps:
                    block_gaps.append(label)

        body = _assemble_section_body(str(request.get("template_preamble") or ""), rendered_blocks)
        request["block_gaps"] = block_gaps
        request["evidence_results"] = all_evidence_results
        return request, body
    except asyncio.CancelledError:
        _log_report(f"{section_key} — cancelled")
        raise


def _render_section_from_request(
    *,
    db: CaseDB,
    request: dict[str, Any],
    base_url: str,
    model: str,
    max_queries_per_section: int = 3,
    audit_callback: Callable[[list[dict[str, str]], str], None] | None = None,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Iterate block requests through the section agent and stitch them into a single section body with evidence results."""
    memory = MemoryManager(request["case"], summarize=lambda messages, m: chat_completion(messages=messages, model=m, base_url=base_url))
    rendered_blocks: list[str] = []
    block_gaps: list[str] = []
    block_outline: list[dict] = []
    all_evidence_results: list[dict[str, Any]] = []
    for block in request.get("block_requests") or []:
        block_mode = str(block.get("mode") or "").strip().casefold()
        is_structured_mode = block_mode in {"benchmark", "structured"} or bool(block.get("answer_spec") or block.get("question"))
        if block_mode == "table":
            builder_name = str(block.get("builder") or "")
            builder_fn = _TABLE_BLOCK_BUILDERS.get(builder_name)
            if builder_fn is not None:
                rows = builder_fn(db)
                columns = _table_block_columns(builder_name, rows)
                table_body = _markdown_table(rows, columns, max_rows=12)
                block_result = SectionBlockResult(body=table_body, evidence_results=[])
            else:
                block_result = run_section_block_agent(
                    case=request["case"],
                    db=db,
                    section_key=str(request["section_key"]),
                    title=str(request["title"]),
                    block_heading=str(block.get("heading") or ""),
                    template_body=str(block.get("template_body") or ""),
                    context_sections=request.get("context_sections") or {},
                    current_section_outline=block_outline,
                    report_brief=request.get("report_brief") or {},
                    base_url=base_url,
                    model=model,
                    memory=memory_for_section(memory, structured_mode=False),
                    max_queries_per_section=max_queries_per_section,
                    evidence_keypoints=list(block.get("evidence_keypoints") or []),
                    benchmark_mode=False,
                    benchmark_id="",
                    answer_id="",
                    answer_spec="",
                    question="",
                    audit_callback=audit_callback,
                )
        else:
            block_result = run_section_block_agent(
                case=request["case"],
                db=db,
                section_key=str(request["section_key"]),
                title=str(request["title"]),
                block_heading=str(block.get("heading") or ""),
                template_body=str(block.get("template_body") or ""),
                context_sections={} if is_structured_mode else (request.get("context_sections") or {}),
                current_section_outline=[] if is_structured_mode else block_outline,
                report_brief=request.get("report_brief") or {},
                base_url=base_url,
                model=model,
                memory=memory_for_section(memory, structured_mode=is_structured_mode),
                max_queries_per_section=max_queries_per_section,
                evidence_keypoints=list(block.get("evidence_keypoints") or []),
                benchmark_mode=is_structured_mode,
                benchmark_id=str(block.get("benchmark_id") or block.get("answer_id") or ""),
                answer_id=str(block.get("answer_id") or block.get("benchmark_id") or ""),
                answer_spec=str(block.get("answer_spec") or ""),
                question=str(block.get("question") or ""),
                audit_callback=audit_callback,
            )
        block_body = block_result.body
        heading = str(block.get("heading") or "").strip()
        if heading and not _body_starts_with_heading(block_body, heading):
            block_body = f"## {heading}\n\n{block_body}"
        rendered_blocks.append(block_body)
        if heading:
            block_outline.append({
                "heading": heading,
                "summary": (block_body.split("\n", 1)[0])[:120],
            })
        all_evidence_results.extend(block_result.evidence_results)
        block_level_gaps, _ = _verify_block_output(db, block_body)
        for gap in block_level_gaps:
            label = f"{heading}: {gap}" if heading else gap
            if label not in block_gaps:
                block_gaps.append(label)
    body = _assemble_section_body(str(request.get("template_preamble") or ""), rendered_blocks)
    return body, all_evidence_results, block_gaps


def _persist_section_result(
    case: Case,
    db: CaseDB,
    request: dict[str, Any],
    body: str,
    session_id: str,
    focus_sections: list[str] | None,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    iteration: int,
) -> str:
    section_key = request["section_key"]
    flat_rows = _collect_flat_evidence_rows(request.get("evidence_results") or [])
    _dump_section_evidence_json(case, section_key, flat_rows)
    _dump_section_trace_json(case, section_key, request.get("evidence_results") or [])
    _dump_section_questions_json(case, db, section_key)
    finalize_section(
        db=db,
        section_key=section_key,
        title=request["title"],
        body=body,
        evidence_results=request.get("evidence_results") or [],
        session_id=session_id,
        extra_gaps=request.get("block_gaps") or [],
        template_meta=request.get("template_meta"),
    )
    write_api_snapshots(case, db)
    if progress_callback:
        status = _build_report_status(db, focus_sections=focus_sections)
        progress_callback(
            {
                "stage": "investigate/report-section-done",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] {section_key} done",
                "report_sections": status,
            }
        )
    return body


async def async_refresh_report_sections(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    template_paths: list[Path],
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str] | None,
    max_queries_per_section: int,
) -> dict[str, Any]:
    """Orchestrate async report section refresh: prepare, render blocks, finalize.

    Processes sections sequentially (not parallel), prioritising stale sections
    over empty ones. Each section runs the agentic block loop via
    async_run_section_block_agent, then finalizes (stores body, evidence, gaps).
    """
    prior_filled = load_report_sections_map(db)
    ensure_universal_question_probes(case, db)
    report_brief = write_report_brief(case, db)
    memory = MemoryManager(case, summarize=lambda messages, m: chat_completion(messages=messages, model=m, base_url=base_url))
    requests = _collect_section_requests(case, db, template_paths, prior_filled, report_brief)
    requests = _sort_section_requests(requests)
    filled_sections: dict[str, str] = {}
    for request in requests:
        try:
            request, body = await _render_section_blocks(
                request, case, db, memory, base_url, model,
                max_queries_per_section, llm_logger, iteration,
                progress_callback, focus_sections,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _emit_section_failure(progress_callback, iteration, exc, db, focus_sections)
            continue
        body = _persist_section_result(case, db, request, body, session_id, focus_sections, progress_callback, iteration)
        filled_sections[request["section_key"]] = body

    return _build_refresh_result(
        filled_sections=filled_sections,
        db=db,
        focus_sections=focus_sections,
        iteration=iteration,
        updated=len(filled_sections),
        progress_callback=progress_callback,
        summary="[report] cycle done (sections={updated}, gaps={gap_count}, sequential)",
    )


def _build_refresh_result(
    *,
    filled_sections: dict[str, str],
    db: CaseDB,
    focus_sections: list[str] | None,
    iteration: int,
    updated: int,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    summary: str,
) -> dict[str, Any]:
    """Build the final result dict for a report refresh cycle.

    Collects gaps, builds report status, fires progress callback, and returns
    a structured result for the investigation loop.
    """
    all_gaps = collect_gaps(filled_sections)
    report_status = _build_report_status(db, focus_sections=focus_sections)
    if progress_callback:
        progress_callback(
            {
                "stage": "investigate/report-cycle-done",
                "status": "running",
                "iteration": iteration,
                "summary": summary.format(updated=updated, gap_count=len(all_gaps)),
                "report_sections": report_status,
            }
        )
    return {
        "filled_sections": filled_sections,
        "gaps": all_gaps,
        "report_status": report_status,
        "updated_sections": updated,
    }
