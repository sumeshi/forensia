"""Refresh stale report sections: collect section requests, render blocks, finalize and persist."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.llm.llm_client import LLMServerUnavailableError, chat_completion
from forensia.ai.report_gap import _build_report_status
from forensia.ai.sections.section_agent import (
    async_run_section_block_agent,
)
from forensia.ai.sections.section_exec import SectionBlockResult
from forensia.api.cache import write_api_snapshots
from forensia.core.case import Case
from forensia.core.memory import MemoryManager, memory_for_section
from forensia.core.progress_event import progress_event
from forensia.db.database import CaseDB
from forensia.report.answers.answer_registry import ensure_universal_question_probes
from forensia.report.answers.table_registry import (
    _collect_flat_evidence_rows,
    render_table_block,
)
from forensia.report.report_brief import write_report_brief
from forensia.report.sections.section_assembly import (
    assemble_section_body,
    body_starts_with_heading,
    prepare_section_request,
)
from forensia.report.sections.section_finalize import finalize_section
from forensia.report.sections.section_quality import _verify_block_output, collect_gaps
from forensia.report.sections.section_store import (
    _dump_section_evidence_json,
    _dump_section_questions_json,
    _dump_section_trace_json,
    load_report_sections_map,
)


def _log_report(message: str) -> None:
    print(f"[bold white][REPORT][/bold white] {message}")


def _collect_section_requests(
    case: Case,
    db: CaseDB,
    template_paths: list[Path],
    prior_filled: dict[str, str],
    report_brief: dict[str, Any],
    *,
    force_all: bool = False,
) -> list[dict[str, Any]]:
    if force_all:
        # R7-04: Force-refresh all sections — bypass the stale query and
        # update_count cap. Each template section gets is_stale=True and
        # needs_refresh=True regardless of DB state.
        result: list[dict[str, Any]] = []
        for template_path in template_paths:
            request = prepare_section_request(
                case, db, template_path, prior_filled, report_brief=report_brief
            )
            request["template_path"] = str(template_path)
            request["is_stale"] = True
            request["needs_refresh"] = True
            result.append(request)
        return result

    # Raw fetchall() returns tuples (dict rows come from fetch_records) —
    # dict-style access here crashed every refresh once stale rows existed.
    stale_section_keys = {
        str(row[0])
        for row in db.execute(
            "SELECT section_key FROM report_sections WHERE stale = TRUE"
        ).fetchall()
    }
    requests: list[dict[str, Any]] = []
    for template_path in template_paths:
        request = prepare_section_request(
            case, db, template_path, prior_filled, report_brief=report_brief
        )
        request["template_path"] = str(template_path)
        request["is_stale"] = request.get("section_key") in stale_section_keys
        request["needs_refresh"] = (
            request["is_stale"]
            or not str(prior_filled.get(request["section_key"]) or "").strip()
        )
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
            progress_event(
                "investigate/report-section-done",
                "running",
                iteration=iteration,
                summary=f"[report] section failed: {exc}",
                report_sections=_build_report_status(db, focus_sections=focus_sections),
            )
        )


def _table_first_order(blocks: list[dict[str, Any]]) -> list[int]:
    """Render order: `mode: table` blocks first (template order within each group)."""

    def _key(index: int) -> tuple[int, int]:
        mode = str(blocks[index].get("mode") or "").strip().casefold()
        return (0 if mode == "table" else 1, index)

    return sorted(range(len(blocks)), key=_key)


_TABLE_DIGEST_PART_LIMIT = 1200
_TABLE_DIGEST_TOTAL_LIMIT = 4000


def _append_table_digest(parts: list[str], heading: str, table_body: str) -> None:
    """Collect a bounded per-table digest for same-section narrative blocks."""
    digest = (
        table_body
        if len(table_body) <= _TABLE_DIGEST_PART_LIMIT
        else table_body[: _TABLE_DIGEST_PART_LIMIT - 3] + "..."
    )
    parts.append(f"### {heading}\n{digest}" if heading else digest)


def _section_table_digest(parts: list[str]) -> str:
    """Assemble collected table digests into one bounded observation block."""
    if not parts:
        return ""
    digest = "<SECTION_TABLES>\n" + "\n\n".join(parts) + "\n</SECTION_TABLES>"
    if len(digest) > _TABLE_DIGEST_TOTAL_LIMIT:
        digest = digest[: _TABLE_DIGEST_TOTAL_LIMIT - 3] + "..."
    return digest


def _is_structured_block(block: dict[str, Any]) -> bool:
    """True when the block is answered in structured question mode (not free narrative)."""
    block_mode = str(block.get("mode") or "").strip().casefold()
    return block_mode in {"question", "benchmark", "structured"} or bool(
        block.get("answer_spec") or block.get("question")
    )


def _existing_structured_body(request: dict[str, Any], db: CaseDB) -> str | None:
    """Return the already-written body when every block is structured and the section is fresh."""
    blocks = request.get("block_requests") or []
    all_structured = bool(blocks) and all(_is_structured_block(b) for b in blocks)
    if not all_structured or request.get("is_stale", False):
        return None
    existing = db.execute(
        "SELECT body FROM report_sections WHERE section_key = ? AND stale = FALSE AND length(body) > 100",
        [request["section_key"]],
    ).fetchone()
    return existing[0] if existing else None


@dataclass
class _SectionRenderCtx:
    """Per-section rendering state shared by the block helpers."""

    request: dict[str, Any]
    db: CaseDB
    memory: MemoryManager
    base_url: str
    model: str
    max_queries_per_section: int
    llm_logger: LLMCallLogger
    iteration: int
    table_digest_parts: list[str] = field(default_factory=list)
    block_outline: list[dict] = field(default_factory=list)
    block_gaps: list[str] = field(default_factory=list)
    all_evidence_results: list[dict[str, Any]] = field(default_factory=list)


async def _render_single_block(
    ctx: _SectionRenderCtx, block: dict[str, Any]
) -> SectionBlockResult:
    """Render one block: deterministic table builder if available, else the section agent."""
    request = ctx.request
    is_structured_mode = _is_structured_block(block)
    if str(block.get("mode") or "").strip().casefold() == "table":
        table_body = render_table_block(ctx.db, str(block.get("builder") or ""))
        if table_body is not None:
            _append_table_digest(
                ctx.table_digest_parts,
                str(block.get("heading") or ""),
                table_body,
            )
            return SectionBlockResult(
                body=table_body,
                evidence_results=[],
                iterations=0,
                status="answered",
            )

    def _audit(phase: str):
        def _callback(
            messages,
            body,
            section=request["section_key"],
            heading=block.get("heading", ""),
        ):
            ctx.llm_logger.write(
                iteration=ctx.iteration,
                phase=phase,
                input_messages=messages,
                output=body,
                model=ctx.model,
                base_url=ctx.base_url,
                suffix=f"{request['section_key']}-{heading}",
            )

        return _callback

    return await async_run_section_block_agent(
        case=request["case"],
        db=ctx.db,
        section_key=str(request["section_key"]),
        title=str(request["title"]),
        block_heading=str(block.get("heading") or ""),
        template_body=str(block.get("template_body") or ""),
        context_sections={}
        if is_structured_mode
        else (request.get("context_sections") or {}),
        current_section_outline=[] if is_structured_mode else ctx.block_outline,
        report_brief=request.get("report_brief") or {},
        base_url=ctx.base_url,
        model=ctx.model,
        memory=memory_for_section(ctx.memory, structured_mode=is_structured_mode),
        max_queries_per_section=ctx.max_queries_per_section,
        evidence_keypoints=list(block.get("evidence_keypoints") or []),
        question_mode=is_structured_mode,
        question_id=str(block.get("question_id") or block.get("answer_id") or ""),
        answer_id=str(block.get("answer_id") or block.get("question_id") or ""),
        answer_spec=str(block.get("answer_spec") or ""),
        question=str(block.get("question") or ""),
        section_table_digest=""
        if is_structured_mode
        else _section_table_digest(ctx.table_digest_parts),
        audit_callback=_audit("report-section-block"),
        review_audit_callback=_audit("report-section-review"),
    )


def _collect_block_output(
    ctx: _SectionRenderCtx, block: dict[str, Any], block_result: SectionBlockResult
) -> str:
    """Prefix the heading, record outline/evidence/gaps, and return the block body."""
    block_body = block_result.body
    heading = str(block.get("heading") or "").strip()
    if heading and not body_starts_with_heading(block_body, heading):
        block_body = f"## {heading}\n\n{block_body}"
    if heading:
        ctx.block_outline.append(
            {
                "heading": heading,
                "summary": (block_result.body.split("\n", 1)[0])[:120],
            }
        )
    ctx.all_evidence_results.extend(block_result.evidence_results)
    block_body_gaps, _ = _verify_block_output(ctx.db, block_result.body)
    for gap in block_body_gaps:
        label = f"{heading}: {gap}" if heading else gap
        if label not in ctx.block_gaps:
            ctx.block_gaps.append(label)
    return block_body


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
    existing_body = _existing_structured_body(request, db)
    if existing_body is not None:
        _log_report(f"{section_key} — structured answers already written, skipping")
        return request, existing_body
    _log_report(f"{section_key} — writing")
    if progress_callback:
        progress_callback(
            progress_event(
                "investigate/report-section",
                "running",
                iteration=iteration,
                summary=f"[report] {section_key} writing...",
                current_report_section=section_key,
                report_sections=_build_report_status(
                    db,
                    current_section=section_key,
                    focus_sections=focus_sections,
                ),
            )
        )

    blocks: list[dict[str, Any]] = list(request.get("block_requests") or [])
    ctx = _SectionRenderCtx(
        request=request,
        db=db,
        memory=memory,
        base_url=base_url,
        model=model,
        max_queries_per_section=max_queries_per_section,
        llm_logger=llm_logger,
        iteration=iteration,
    )
    rendered_bodies: dict[int, str] = {}
    try:
        # Two-pass render: deterministic table blocks first so narrative
        # blocks can consume their data; assembly keeps template order.
        for index in _table_first_order(blocks):
            block = blocks[index]
            try:
                block_result = await _render_single_block(ctx, block)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _log_report(f"{section_key} — block failed: {exc}")
                raise
            rendered_bodies[index] = _collect_block_output(ctx, block, block_result)

        rendered_blocks = [rendered_bodies[index] for index in sorted(rendered_bodies)]
        body = assemble_section_body(
            str(request.get("template_preamble") or ""), rendered_blocks
        )
        request["block_gaps"] = ctx.block_gaps
        request["evidence_results"] = ctx.all_evidence_results
        return request, body
    except asyncio.CancelledError:
        _log_report(f"{section_key} — cancelled")
        raise


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
            progress_event(
                "investigate/report-section-done",
                "running",
                iteration=iteration,
                summary=f"[report] {section_key} done",
                report_sections=status,
            )
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
    force_all: bool = False,
) -> dict[str, Any]:
    """Orchestrate async report section refresh: prepare, render blocks, finalize.

    Processes sections sequentially (not parallel), prioritising stale sections
    over empty ones. Each section runs the agentic block loop via
    async_run_section_block_agent, then finalizes (stores body, evidence, gaps).

    When *force_all* is True, every template section is treated as stale regardless
    of DB state (bypasses update_count cap). Used only by the final-refresh pass.
    """
    prior_filled = load_report_sections_map(db)
    ensure_universal_question_probes(case, db)
    # The active template set governs the leading-thesis ranking policy
    # (report/ranking.py reads it from the section templates' frontmatter), so
    # pass the dir the templates were loaded from rather than letting core decide.
    active_template_dir = template_paths[0].parent if template_paths else None
    report_brief = write_report_brief(case, db, template_dir=active_template_dir)
    memory = MemoryManager(
        case,
        summarize=lambda messages, m: chat_completion(
            messages=messages, model=m, base_url=base_url
        ),
    )
    requests = _collect_section_requests(
        case, db, template_paths, prior_filled, report_brief, force_all=force_all
    )
    requests = _sort_section_requests(requests)
    filled_sections: dict[str, str] = {}
    for request in requests:
        try:
            request, body = await _render_section_blocks(
                request,
                case,
                db,
                memory,
                base_url,
                model,
                max_queries_per_section,
                llm_logger,
                iteration,
                progress_callback,
                focus_sections,
            )
        except asyncio.CancelledError:
            raise
        except LLMServerUnavailableError:
            # Don't downgrade an outage to a per-section failure: propagate so
            # the caller's wait-for-recovery logic can pause and retry.
            raise
        except Exception as exc:
            _emit_section_failure(progress_callback, iteration, exc, db, focus_sections)
            continue
        body = _persist_section_result(
            case,
            db,
            request,
            body,
            session_id,
            focus_sections,
            progress_callback,
            iteration,
        )
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
            progress_event(
                "investigate/report-cycle-done",
                "running",
                iteration=iteration,
                summary=summary.format(updated=updated, gap_count=len(all_gaps)),
                report_sections=report_status,
            )
        )
    return {
        "filled_sections": filled_sections,
        "gaps": all_gaps,
        "report_status": report_status,
        "updated_sections": updated,
    }
