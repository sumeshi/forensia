from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from forensia.ai.audit import LLMCallLogger
from forensia.ai.lmstudio import chat_completion
from forensia.ai.report_gap import _build_report_status
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.writer import (
    collect_gaps,
    fill_section,
    finalize_section,
    load_report_sections_map,
    prepare_section_request,
    write_report_brief,
)


def _refresh_report_sections(
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    template_root: Path,
    llm_logger: LLMCallLogger,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    focus_sections: list[str] | None = None,
    max_workers: int = 1,
) -> dict[str, Any]:
    template_paths = sorted(template_root.glob("[0-9]*_*.md"))
    if max_workers <= 1:
        return _refresh_report_sections_sequential(
            case=case,
            db=db,
            session_id=session_id,
            iteration=iteration,
            base_url=base_url,
            model=model,
            template_paths=template_paths,
            llm_logger=llm_logger,
            progress_callback=progress_callback,
            focus_sections=focus_sections,
        )
    return _refresh_report_sections_parallel(
        case=case,
        db=db,
        session_id=session_id,
        iteration=iteration,
        base_url=base_url,
        model=model,
        template_paths=template_paths,
        llm_logger=llm_logger,
        progress_callback=progress_callback,
        focus_sections=focus_sections,
        max_workers=max_workers,
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


def _refresh_report_sections_sequential(
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
) -> dict[str, Any]:
    filled_sections: dict[str, str] = {}
    updated = 0
    report_brief = write_report_brief(case, db)
    for template_path in template_paths:
        section_key = template_path.stem
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
        context_sections = dict(filled_sections)
        filled_sections[section_key] = fill_section(
            case=case,
            db=db,
            template_path=template_path,
            context_sections=context_sections,
            report_brief=report_brief,
            base_url=base_url,
            model=model,
            session_id=session_id,
            audit_callback=lambda messages, body, section=section_key: llm_logger.write(
                iteration=iteration,
                phase="report-section",
                input_messages=messages,
                output=body,
                model=model,
                base_url=base_url,
                suffix=section,
            ),
        )
        status = _build_report_status(db, focus_sections=focus_sections)
        updated += 1
        current_row = next((item for item in status["items"] if item["section_key"] == section_key), None)
        gap_count = int(current_row["gap_count"]) if current_row else 0
        confidence = float(current_row["confidence"]) if current_row else 0.0
        if progress_callback:
            progress_callback(
                {
                    "stage": "investigate/report-section-done",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} done (gaps={gap_count}, confidence={confidence:.2f})",
                    "report_sections": status,
                }
            )
    return _build_refresh_result(
        filled_sections=filled_sections,
        db=db,
        focus_sections=focus_sections,
        iteration=iteration,
        updated=updated,
        progress_callback=progress_callback,
        summary="[report] cycle done (sections={updated}, gaps={gap_count})",
    )


def _refresh_report_sections_parallel(
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
) -> dict[str, Any]:
    prior_filled = load_report_sections_map(db)
    report_brief = write_report_brief(case, db)
    requests: list[dict[str, Any]] = []
    for template_path in template_paths:
        request = prepare_section_request(case, db, template_path, prior_filled, report_brief=report_brief)
        request["template_path"] = str(template_path)
        requests.append(request)

    progress_lock = threading.Lock()

    def emit(payload: dict[str, Any]) -> None:
        if not progress_callback:
            return
        with progress_lock:
            progress_callback(payload)

    def worker(request: dict[str, Any]) -> tuple[dict[str, Any], str]:
        emit(
            {
                "stage": "investigate/report-section",
                "status": "running",
                "iteration": iteration,
                "summary": f"[report] {request['section_key']} writing... (parallel)",
                "current_report_section": request["section_key"],
            }
        )
        body = chat_completion(
            messages=request["messages"],
            model=model,
            base_url=base_url,
        ).strip()
        llm_logger.write(
            iteration=iteration,
            phase="report-section",
            input_messages=request["messages"],
            output=body,
            model=model,
            base_url=base_url,
            suffix=str(request["section_key"]),
        )
        return request, body

    filled_sections: dict[str, str] = {}
    updated = 0
    workers = max(1, min(max_workers, len(requests)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, request) for request in requests]
        for future in as_completed(futures):
            try:
                request, body = future.result()
            except Exception as exc:  # pragma: no cover
                emit(
                    {
                        "stage": "investigate/report-section-done",
                        "status": "running",
                        "iteration": iteration,
                        "summary": f"[report] section failed: {exc}",
                    }
                )
                continue
            section_key = request["section_key"]
            finalize_section(
                db=db,
                section_key=section_key,
                title=request["title"],
                body=body,
                evidence_results=request.get("evidence_results") or [],
                session_id=session_id,
            )
            filled_sections[section_key] = body
            updated += 1
            status = _build_report_status(db, focus_sections=focus_sections)
            current_row = next((item for item in status["items"] if item["section_key"] == section_key), None)
            gap_count = int(current_row["gap_count"]) if current_row else 0
            confidence = float(current_row["confidence"]) if current_row else 0.0
            emit(
                {
                    "stage": "investigate/report-section-done",
                    "status": "running",
                    "iteration": iteration,
                    "summary": f"[report] {section_key} done (gaps={gap_count}, confidence={confidence:.2f})",
                    "report_sections": status,
                }
            )

    return _build_refresh_result(
        filled_sections=filled_sections,
        db=db,
        focus_sections=focus_sections,
        iteration=iteration,
        updated=updated,
        progress_callback=progress_callback,
        summary=f"[report] cycle done (sections={{updated}}, gaps={{gap_count}}, parallel={workers})",
    )
