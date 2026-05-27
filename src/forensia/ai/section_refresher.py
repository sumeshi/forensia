from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich import print

from forensia.ai.audit import LLMCallLogger
from forensia.ai.report_gap import _build_report_status
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.writer import (
    _collect_flat_evidence_rows,
    _dump_section_evidence_json,
    collect_gaps,
    finalize_section,
    load_report_sections_map,
    prepare_section_request,
    write_report_brief,
)
from forensia.ai.section_agent import async_run_section_block_agent
from forensia.api.cache import write_api_snapshots


def _log_report(message: str) -> None:
    print(f"[bold white][REPORT][/bold white] {message}")


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
    max_workers: int,
    max_queries_per_section: int,
) -> dict[str, Any]:
    prior_filled = load_report_sections_map(db)
    report_brief = write_report_brief(case, db)
    requests: list[dict[str, Any]] = []
    for template_path in template_paths:
        request = prepare_section_request(case, db, template_path, prior_filled, report_brief=report_brief)
        request["template_path"] = str(template_path)
        requests.append(request)

    async def process_section(request: dict[str, Any]) -> tuple[dict[str, Any], str]:
        section_key = request["section_key"]
        _log_report(f"{section_key} — writing (async parallel)")
        if progress_callback:
            # Build report_sections payload so the frontend can highlight the
            # writing section via is_writing flags + report_sections.current_section.
            # (stores.ts reads payload.report_sections.current_section; sending only
            # current_report_section at top level was the regression.)
            progress_callback(
                {
                    "stage": "investigate/report-section",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} writing... (async parallel)",
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
        block_outputs: dict[str, str] = {}
        all_evidence_results: list[dict[str, Any]] = []

        try:
            for block in request.get("block_requests") or []:
                try:
                    block_result = await async_run_section_block_agent(
                        case=request["case"],
                        db=db,
                        section_key=str(request["section_key"]),
                        title=str(request["title"]),
                        block_heading=str(block.get("heading") or ""),
                        template_body=str(block.get("template_body") or ""),
                        context_sections=request.get("context_sections") or {},
                        current_section_outputs=block_outputs,
                        report_brief=request.get("report_brief") or {},
                        base_url=base_url,
                        model=model,
                        max_queries_per_section=max_queries_per_section,
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
                rendered_blocks.append(block_result.body)
                heading = str(block.get("heading") or "").strip()
                if heading:
                    block_outputs[heading] = block_result.body
                all_evidence_results.extend(block_result.evidence_results)
                from forensia.report.writer import collect_gaps, _verify_block_output
                block_body_gaps, _ = _verify_block_output(db, block_result.body)
                for gap in block_body_gaps:
                    label = f"{heading}: {gap}" if heading else gap
                    if label not in block_gaps:
                        block_gaps.append(label)

            body = "\n\n".join(rendered_blocks).strip()
            request["block_gaps"] = block_gaps
            request["evidence_results"] = all_evidence_results
            return request, body
        except asyncio.CancelledError:
            _log_report(f"{section_key} — cancelled")
            raise

    workers = max(1, min(max_workers, len(requests)))
    filled_sections: dict[str, str] = {}
    for request in requests:
        try:
            request, body = await process_section(request)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if progress_callback:
                # Include report_sections so the frontend clears the writing
                # highlight even when a section fails mid-write.
                progress_callback(
                    {
                        "stage": "investigate/report-section-done",
                        "status": "running",
                        "iteration": iteration,
                        "summary": f"[report] section failed: {exc}",
                        "report_sections": _build_report_status(db, focus_sections=focus_sections),
                    }
                )
            continue
        section_key = request["section_key"]
        flat_rows = _collect_flat_evidence_rows(request.get("evidence_results") or [])
        _dump_section_evidence_json(case, section_key, flat_rows)
        finalize_section(
            db=db,
            section_key=section_key,
            title=request["title"],
            body=body,
            evidence_results=request.get("evidence_results") or [],
            session_id=session_id,
            extra_gaps=request.get("block_gaps") or [],
        )
        filled_sections[section_key] = body
        write_api_snapshots(case, db)
        if progress_callback:
            status = _build_report_status(db, focus_sections=focus_sections)
            progress_callback(
                {
                    "stage": "investigate/report-section-done",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} done (workers={workers})",
                    "report_sections": status,
                }
            )

    return _build_refresh_result(
        filled_sections=filled_sections,
        db=db,
        focus_sections=focus_sections,
        iteration=iteration,
        updated=len(filled_sections),
        progress_callback=progress_callback,
        summary=f"[report] cycle done (sections={{updated}}, gaps={{gap_count}}, parallel={workers})",
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
