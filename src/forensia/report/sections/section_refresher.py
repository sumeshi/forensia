"""Refresh report projections from adopted requirements and current evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from forensia.core.case import Case
from forensia.core.log import log as _log
from forensia.core.progress_event import progress_event
from forensia.core.session import LLMBudgetExceededError
from forensia.db.database import CaseDB
from forensia.llm import json_response
from forensia.llm.llm_client import LLMServerUnavailableError
from forensia.report.answers.answer_registry import build_structured_answer
from forensia.report.answers.answer_store import _render_structured_answer_markdown
from forensia.report.answers.keypoint_catalog import _default_keypoints_for_section
from forensia.report.answers.table_registry import (
    TABLE_BLOCKS,
    render_table_block,
)
from forensia.report.evidence_refs import (
    EVIDENCE_ID_PATTERN,
    _extract_evidence_ids_from_value,
)
from forensia.report.render.formats import load_report_formats
from forensia.report.render.markdown import _markdown_table
from forensia.report.report_brief import write_report_brief
from forensia.report.sections.prompts import build_paragraph_narrate_messages
from forensia.report.sections.report_input import SectionSource
from forensia.report.sections.section_assembly import (
    assemble_section_body,
    body_starts_with_heading,
    prepare_section_request,
)
from forensia.report.sections.section_exec import _execute_keypoint
from forensia.report.sections.section_finalize import (
    assess_section_candidate,
    finalize_section,
)
from forensia.report.sections.section_run_store import (
    _store_section_run,
    load_section_signature,
    replace_section_evidence,
)
from forensia.report.sections.status import build_report_status

_EVIDENCE_COUNT_TABLES = (
    "evtx_events",
    "mft_entries",
    "prefetch_executions",
    "prefetch_timeline",
    "registry_artifacts",
)


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _case_evidence_signature(db: CaseDB) -> str:
    """Hash small source/control state; section projections hash relevant rows."""
    sources = db.execute(
        """
        SELECT source_id, artifact_family, ingest_status, parser_name, parser_version,
               row_count, channel, hosts, volume_id, min_time, max_time, error_code
        FROM evidence_sources ORDER BY source_id
        """
    ).fetchall()
    counts = {
        table: int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        for table in _EVIDENCE_COUNT_TABLES
    }
    hypotheses = db.execute(
        """
        SELECT hypothesis_id, status, verdict, sufficiency_status,
               human_review_required
        FROM hypotheses ORDER BY hypothesis_id
        """
    ).fetchall()
    gaps = db.execute(
        "SELECT gap_id, status, kind, task_id FROM report_gaps ORDER BY gap_id"
    ).fetchall()
    tasks = db.execute(
        "SELECT task_id, status, gap_id, hypothesis_id FROM investigation_tasks ORDER BY task_id"
    ).fetchall()
    investigation = db.execute(
        "SELECT objective, status FROM investigation_state WHERE state_id = 'case'"
    ).fetchall()
    stage_receipts: dict[str, dict[str, str]] = {}
    for phase in ("pipeline-normalize", "pipeline-analyze"):
        receipt = db.execute(
            "SELECT output_json FROM trace.investigation_steps "
            "WHERE phase = ? ORDER BY created_at DESC, step_id DESC LIMIT 1",
            [phase],
        ).fetchone()
        if receipt is None:
            continue
        try:
            payload = json.loads(str(receipt[0]))
        except TypeError, ValueError:
            continue
        if isinstance(payload, dict):
            stage_receipts[phase] = {
                key: str(payload.get(key) or "")
                for key in ("status", "revision", "parser_revision")
                if payload.get(key) is not None
            }
    return _canonical_hash(
        {
            "evidence_sources": sources,
            "evidence_row_counts": counts,
            "hypotheses": hypotheses,
            "gaps": gaps,
            "tasks": tasks,
            "investigation": investigation,
            "stage_receipts": stage_receipts,
        }
    )


def _report_input_digest(db: CaseDB) -> str:
    row = db.execute(
        "SELECT output_json FROM trace.investigation_steps "
        "WHERE phase = 'report-input' ORDER BY created_at DESC, step_id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return ""
    try:
        value = json.loads(str(row[0]))
    except TypeError, ValueError:
        return ""
    return str(value.get("content_sha256") or "") if isinstance(value, dict) else ""


def _is_structured_block(block: dict[str, Any]) -> bool:
    mode = str(block.get("mode") or "").strip().casefold()
    return mode in {"question", "benchmark", "structured"} or bool(
        block.get("answer_spec") or block.get("question")
    )


def _result_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in ("sample_rows", "head_rows", "tail_rows"):
        for item in result.get(key) or []:
            if not isinstance(item, dict):
                continue
            fingerprint = json.dumps(
                item, ensure_ascii=False, sort_keys=True, default=str
            )
            if fingerprint not in seen:
                seen.add(fingerprint)
                rows.append(dict(item))
    return rows


def _result_table(result: dict[str, Any]) -> str:
    rows = _result_rows(result)[:10]
    if not rows:
        ids = [str(item) for item in result.get("evidence_ids") or [] if str(item)]
        if ids:
            return "Evidence references: " + ", ".join(ids[:10])
        return "_No matching records were returned._"
    preferred = (
        "timestamp",
        "date",
        "computer",
        "host",
        "user_name",
        "target_user",
        "event_id",
        "process_name",
        "file_name",
        "file_path",
        "evidence_id",
    )
    keys = list(dict.fromkeys(key for row in rows for key in row))
    columns = [key for key in preferred if key in keys]
    columns.extend(
        key for key in keys if key not in columns and not key.startswith("_")
    )
    columns = columns[:6]
    if not columns:
        return "_No reportable fields were returned._"
    return _markdown_table(
        rows, [(key, key.replace("_", " ").title()) for key in columns], max_rows=10
    )


def _evidence_ids(results: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for result in results:
        for evidence_id in result.get("evidence_ids") or []:
            item = str(evidence_id or "").strip()
            if item and item not in seen:
                seen.add(item)
                values.append(item)
        for row in _result_rows(result):
            for evidence_id in _extract_evidence_ids_from_value(row):
                item = str(evidence_id or "").strip()
                if item and item not in seen:
                    seen.add(item)
                    values.append(item)
    return values


def _block_projection(
    case: Case,
    db: CaseDB,
    section_key: str,
    block: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    heading = str(block.get("heading") or "").strip()
    mode = str(block.get("mode") or "").strip().casefold()
    result_rows: list[dict[str, Any]] = []
    projection: dict[str, Any] = {"heading": heading, "mode": mode}

    builder = str(block.get("builder") or "").strip()
    if mode == "table" and builder:
        table_body = render_table_block(db, builder)
        rows = TABLE_BLOCKS.get(builder)
        evidence_results: list[dict[str, Any]] = []
        if rows is not None:
            rendered_ids = sorted(set(EVIDENCE_ID_PATTERN.findall(table_body or "")))
            evidence_results.append(
                {
                    "kind": "rows",
                    "source_ref": f"table:{builder}",
                    "block_heading": heading,
                    "row_count": len(rendered_ids),
                    "evidence_ids": rendered_ids,
                }
            )
        body = table_body or "_No rows available._"
        projection.update({"builder": builder, "body": body})
        return body, evidence_results, projection

    answer_spec = str(block.get("answer_spec") or "").strip()
    question = str(block.get("question") or "").strip()
    if _is_structured_block(block):
        if not answer_spec:
            from forensia.knowledge.questions import resolve_question_spec

            spec, _confidence = resolve_question_spec(
                block_heading=heading,
                template_body=str(block.get("template_body") or ""),
                question=question,
            )
            answer_spec = str(spec.answer_spec or "") if spec is not None else ""
        if answer_spec:
            answer = build_structured_answer(
                case,
                db,
                answer_spec=answer_spec,
                answer_id=str(
                    block.get("answer_id") or block.get("question_id") or answer_spec
                ),
                section_key=section_key,
                block_heading=heading,
            )
            if answer is not None:
                answer_rows = [
                    item
                    for item in answer.get("answer") or []
                    if isinstance(item, dict)
                ]
                result = {
                    "kind": "rows",
                    "source_ref": f"structured:{answer_spec}",
                    "block_heading": heading,
                    "row_count": len(answer_rows),
                    "sample_rows": answer_rows[:10],
                    "evidence_ids": _evidence_ids([{"sample_rows": answer_rows}]),
                }
                result_rows.append(result)
                body = _render_structured_answer_markdown(
                    answer,
                    heading,
                    template_dir=case.report_template_dir,
                )
                projection.update({"answer_spec": answer_spec, "answer": answer})
                return body, result_rows, projection

    keypoints = [
        str(value)
        for value in block.get("evidence_keypoints") or []
        if str(value).strip()
    ]
    if not keypoints:
        keypoints = list(
            _default_keypoints_for_section(section_key, block_heading=heading)
        )
    for keypoint in keypoints:
        source_ref, result = _execute_keypoint(case, db, keypoint)
        result["source_ref"] = source_ref
        result["block_heading"] = heading
        result_rows.append(result)
    rendered = []
    for result in result_rows:
        description = str(
            result.get("description") or result.get("source_ref") or "Evidence"
        )
        rendered.append(f"**{description}**\n\n{_result_table(result)}")
    body = "\n\n".join(rendered) or "_No matching records were returned._"
    projection.update({"keypoints": keypoints, "results": result_rows, "body": body})
    return body, result_rows, projection


def _prepare_projection(
    case: Case,
    db: CaseDB,
    source: SectionSource,
    report_brief: dict[str, Any],
    case_signature: str,
) -> dict[str, Any]:
    request = prepare_section_request(case, db, source, {}, report_brief=report_brief)
    rendered: list[str] = []
    blocks: list[dict[str, Any]] = list(request.get("block_requests") or [])
    evidence_results: list[dict[str, Any]] = []
    block_projections: list[dict[str, Any]] = []
    first_narrative_index: int | None = None
    for index, block in enumerate(blocks):
        body, block_results, block_projection = _block_projection(
            case, db, source.section_key, block
        )
        heading = str(block.get("heading") or "").strip()
        if heading and not body_starts_with_heading(body, heading):
            body = f"## {heading}\n\n{body}"
        if (
            first_narrative_index is None
            and str(block.get("mode") or "").strip().casefold() != "table"
            and not _is_structured_block(block)
        ):
            first_narrative_index = index
        rendered.append(body)
        evidence_results.extend(block_results)
        block_projections.append(block_projection)
    deterministic_body = assemble_section_body(
        str(request.get("template_preamble") or ""), rendered
    )
    report_context = {
        key: report_brief[key]
        for key in (
            "time_range",
            "source_timezone",
            "timezone_offset",
            "case_metrics",
            "investigation_objective",
        )
        if report_brief.get(key) not in (None, "", [], {})
    }
    projection = {
        "block_projections": block_projections,
        "report_context": report_context,
    }
    signature = _canonical_hash(
        {
            "report_input": {
                "section_key": source.section_key,
                "body": source.body,
                "meta": asdict(source.meta),
            },
            "case_evidence_signature": case_signature,
            "projection": projection,
        }
    )
    return {
        "request": request,
        "blocks": blocks,
        "rendered": rendered,
        "body": deterministic_body,
        "evidence_results": evidence_results,
        "projection": projection,
        "input_signature": signature,
        "projection_signature": _canonical_hash(projection),
        "report_context": report_context,
        "first_narrative_index": first_narrative_index,
    }


def _fallback_paragraph(
    heading: str, evidence_results: list[dict[str, Any]], template_dir: Any
) -> str:
    formats = load_report_formats(template_dir)["narrative_fallback"]
    evidence_ids = _evidence_ids(evidence_results)
    rows = [row for result in evidence_results for row in _result_rows(result)]
    if not rows:
        return str(formats["unsupported"]).format(heading=heading)
    observations = []
    for row in rows[:3]:
        parts = [
            str(row.get(key) or "").strip()
            for key in (
                "timestamp",
                "date",
                "computer",
                "host",
                "event_id",
                "process_name",
                "file_path",
            )
            if str(row.get(key) or "").strip()
        ]
        if parts:
            observations.append(" ".join(parts))
    reference = (
        " (evidence: " + ", ".join(evidence_ids[:3]) + ")" if evidence_ids else ""
    )
    if observations:
        return str(formats["observed"]).format(
            heading=heading,
            observations="; ".join(observations),
            reference=reference,
        )
    return str(formats["insufficient_detail"]).format(
        heading=heading, reference=reference
    )


def _narrate_projection(
    case: Case,
    db: CaseDB,
    projection: dict[str, Any],
    *,
    base_url: str,
    model: str,
    session_id: str,
) -> str:
    request = projection["request"]
    results = projection["evidence_results"]
    key_points = []
    for result in results:
        description = str(
            result.get("description") or result.get("source_ref") or "Evidence"
        )
        count = int(result.get("row_count") or 0)
        key_points.append(f"{description}: {count} matching records")
    evidence_rows = [row for result in results for row in _result_rows(result)]
    template_body = (
        str(request.get("template_preamble") or "")
        + "\n\n"
        + "\n\n".join(
            str(block.get("template_body") or "") for block in projection["blocks"]
        )
    )
    digest_parts: list[str] = []
    omitted_blocks = 0
    selected_chars = 0
    for item in projection["rendered"]:
        if not item.strip():
            continue
        extra = len(item) + (2 if digest_parts else 0)
        if selected_chars + extra > 4000:
            omitted_blocks += 1
            continue
        digest_parts.append(item)
        selected_chars += extra
    if omitted_blocks:
        digest_parts.append(
            f"[{omitted_blocks} complete deterministic block(s) omitted from narration context.]"
        )
    structured_digest = "\n\n".join(digest_parts)
    messages, schema = build_paragraph_narrate_messages(
        heading=str(
            request.get("title") or request.get("section_key") or "Report section"
        ),
        key_points=key_points,
        evidence_rows=evidence_rows[:10],
        template_body=template_body,
        structured_digest=structured_digest,
        report_context=projection["report_context"],
        db=db,
        session_id=session_id,
    )
    response = json_response.request_llm_json(
        messages=messages,
        model=model,
        base_url=base_url,
        json_schema=schema,
        telemetry_phase="section-narrative",
    )
    return str(response.get("body") or "").strip()


def _body_with_narration(projection: dict[str, Any], paragraph: str) -> str:
    index = projection["first_narrative_index"]
    if index is None or not paragraph:
        return projection["body"]
    rendered = list(projection["rendered"])
    heading = str(projection["blocks"][index].get("heading") or "").strip()
    rendered[index] = f"## {heading}\n\n{paragraph}" if heading else paragraph
    request = projection["request"]
    return assemble_section_body(str(request.get("template_preamble") or ""), rendered)


def _narration_admission_reasons(
    db: CaseDB,
    projection: dict[str, Any],
    fallback: str,
    candidate: str,
) -> list[str]:
    """Reject narration that adds section-gate gaps or fatal claim-traceability findings."""
    request = projection["request"]
    section_key = str(request.get("section_key") or "")
    title = str(request.get("title") or section_key)
    fallback_assessment = assess_section_candidate(
        db, section_key, title, fallback, projection["evidence_results"]
    )
    candidate_assessment = assess_section_candidate(
        db, section_key, title, candidate, projection["evidence_results"]
    )
    baseline_gaps = set(fallback_assessment["gaps"])
    reasons = [
        f"section_quality:{gap}"
        for gap in candidate_assessment["gaps"]
        if gap not in baseline_gaps
    ]
    from forensia.report.report_validation import check_claim_traceability

    baseline_findings = check_claim_traceability(fallback_assessment["body"])
    candidate_findings = check_claim_traceability(candidate_assessment["body"])
    baseline_fingerprints = {
        (finding.check_name, finding.message, finding.details)
        for finding in baseline_findings
    }
    new_findings = [
        finding
        for finding in candidate_findings
        if (finding.check_name, finding.message, finding.details)
        not in baseline_fingerprints
    ]
    if new_findings:
        reasons.append(
            "claim_traceability:"
            + "; ".join(finding.message for finding in new_findings[:3])
        )
    return reasons


def _persist_projection(
    db: CaseDB,
    section_key: str,
    title: str,
    body: str,
    evidence_results: list[dict[str, Any]],
    *,
    session_id: str,
) -> str:
    with db.transaction():
        replace_section_evidence(db, section_key, evidence_results)
        result = finalize_section(
            db=db,
            section_key=section_key,
            title=title,
            body=body,
            evidence_results=evidence_results,
            session_id=session_id,
        )
        if not result.get("updated", True):
            raise RuntimeError(
                f"human-reviewed section was not replaced: {section_key}"
            )
        row = db.execute(
            "SELECT body FROM report_sections WHERE section_key = ?", [section_key]
        ).fetchone()
        return str(row[0] or "") if row else body


def _projection_receipts(
    evidence_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "source_ref": str(result.get("source_ref") or ""),
            "block_heading": str(result.get("block_heading") or ""),
            "row_count": int(result.get("row_count") or 0),
            "evidence_count": len(_evidence_ids([result])),
        }
        for result in evidence_results
    ]


def _emit_section_failure(
    progress_callback: Callable[[dict[str, Any]], None] | None,
    iteration: int,
    session_id: str,
    section_key: str,
    exc: Exception,
) -> None:
    if progress_callback:
        progress_callback(
            progress_event(
                "report.section",
                "failed",
                severity="error",
                reason=f"exception:{type(exc).__name__}",
                refs={"section_key": section_key},
                stage="render",
                iteration=iteration,
                session_id=session_id,
                summary="report section rendering failed",
            )
        )


def _record_projection(
    db: CaseDB,
    projection: dict[str, Any],
    *,
    iteration: int,
    report_input_digest: str,
    narration_status: str,
    narration_rejection_reasons: list[str] | None = None,
) -> None:
    request = projection["request"]
    _store_section_run(
        db,
        section_key=str(request.get("section_key") or ""),
        block_heading="",
        iteration=iteration,
        phase="projection",
        payload={
            "input_signature": projection["input_signature"],
            "projection_signature": projection["projection_signature"],
            "report_input_sha256": report_input_digest,
            "query_receipts": _projection_receipts(projection["evidence_results"]),
            "narration_status": narration_status,
            "narration_rejection_reasons": narration_rejection_reasons or [],
        },
    )


def _emit_section_completed(
    progress_callback: Callable[[dict[str, Any]], None] | None,
    iteration: int,
    session_id: str,
    section_key: str,
    summary: str,
) -> None:
    if progress_callback:
        progress_callback(
            progress_event(
                "report.section",
                "completed",
                severity="success",
                stage="render",
                iteration=iteration,
                session_id=session_id,
                summary=summary,
                refs={"section_key": section_key},
            )
        )


def _emit_narration_outcome(
    progress_callback: Callable[[dict[str, Any]], None] | None,
    iteration: int,
    session_id: str,
    section_key: str,
    status: str,
    reason: str,
) -> None:
    if not progress_callback:
        return
    severity = (
        "success"
        if status == "completed"
        else "warning"
        if reason.startswith("fallback:") or status == "cancelled"
        else "info"
    )
    progress_callback(
        progress_event(
            "report.narration",
            status,
            severity=severity,
            reason=reason,
            refs={"section_key": section_key},
            stage="narrate",
            iteration=iteration,
            session_id=session_id,
            summary=(
                f"[report] {section_key} narration completed"
                if status == "completed"
                else f"[report] {section_key} narration ended ({reason})"
            ),
        )
    )


def _section_is_current(db: CaseDB, section_key: str, signature: str) -> bool:
    row = db.execute(
        "SELECT body, stale FROM report_sections WHERE section_key = ?", [section_key]
    ).fetchone()
    if row is None or not str(row[0] or "").strip() or bool(row[1]):
        return False
    from forensia.report.report_validation import has_failure_marker

    return (
        not has_failure_marker(str(row[0]))
        and load_section_signature(db, section_key) == signature
    )


async def _refresh_section(
    *,
    case: Case,
    db: CaseDB,
    source: SectionSource,
    report_brief: dict[str, Any],
    case_signature: str,
    report_input_digest: str,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    progress_callback: Callable[[dict[str, Any]], None] | None,
) -> tuple[str, bool]:
    projection = _prepare_projection(case, db, source, report_brief, case_signature)
    request = projection["request"]
    section_key = source.section_key
    if _section_is_current(db, section_key, projection["input_signature"]):
        replace_section_evidence(db, section_key, projection["evidence_results"])
        body_row = db.execute(
            "SELECT body FROM report_sections WHERE section_key = ?", [section_key]
        ).fetchone()
        body = str(body_row[0] or "") if body_row else ""
        narrated = False
        _record_projection(
            db,
            projection,
            iteration=iteration,
            report_input_digest=report_input_digest,
            narration_status="unchanged",
        )
        _emit_section_completed(
            progress_callback,
            iteration,
            session_id,
            section_key,
            f"[report] {section_key} current (input signature unchanged)",
        )
        _emit_narration_outcome(
            progress_callback,
            iteration,
            session_id,
            section_key,
            "skipped",
            "input_unchanged",
        )
    else:
        fallback = projection["body"]
        body = _persist_projection(
            db,
            section_key,
            str(request.get("title") or section_key),
            fallback,
            projection["evidence_results"],
            session_id=session_id,
        )
        # Persist the usable baseline and its receipt before optional narration.
        _record_projection(
            db,
            projection,
            iteration=iteration,
            report_input_digest=report_input_digest,
            narration_status="pending",
        )
        _emit_section_completed(
            progress_callback,
            iteration,
            session_id,
            section_key,
            f"[report] {section_key} deterministic projection persisted",
        )
        narrated = False
        narration_status = "skipped:no_evidence"
        narration_rejection_reasons: list[str] = []
        narrative_index = projection["first_narrative_index"]
        has_evidence = any(
            int(result.get("row_count") or 0) > 0
            or bool(result.get("evidence_ids"))
            or bool(_result_rows(result))
            for result in projection["evidence_results"]
        )
        if narrative_index is not None and has_evidence:
            narration_status = "fallback:empty_response"
            try:
                paragraph = await asyncio.to_thread(
                    _narrate_projection,
                    case,
                    db,
                    projection,
                    base_url=base_url,
                    model=model,
                    session_id=session_id,
                )
            except asyncio.CancelledError:
                _record_projection(
                    db,
                    projection,
                    iteration=iteration,
                    report_input_digest=report_input_digest,
                    narration_status="cancelled",
                )
                _emit_narration_outcome(
                    progress_callback,
                    iteration,
                    session_id,
                    section_key,
                    "cancelled",
                    "narration_cancelled",
                )
                raise
            except LLMBudgetExceededError as exc:
                _log(
                    "REPORT",
                    f"{section_key} — optional narration skipped: LLM budget exceeded ({exc})",
                    level="warning",
                )
                narration_status = "fallback:budget_exceeded"
                paragraph = ""
            except LLMServerUnavailableError as exc:
                _log(
                    "REPORT",
                    f"{section_key} — optional narration skipped: LLM unavailable ({exc})",
                    level="warning",
                )
                narration_status = "fallback:llm_unavailable"
                paragraph = ""
            except Exception as exc:
                _log(
                    "REPORT",
                    f"{section_key} — optional narration failed: {exc}",
                    level="warning",
                )
                narration_status = f"fallback:error:{type(exc).__name__}"
                paragraph = ""
            narrated_body = _body_with_narration(projection, paragraph)
            if paragraph and narrated_body != fallback:
                narration_rejection_reasons = _narration_admission_reasons(
                    db, projection, fallback, narrated_body
                )
                if narration_rejection_reasons:
                    narration_status = "rejected:quality_gate"
                else:
                    try:
                        body = _persist_projection(
                            db,
                            section_key,
                            str(request.get("title") or section_key),
                            narrated_body,
                            projection["evidence_results"],
                            session_id=session_id,
                        )
                        narrated = True
                        narration_status = "narrated"
                    except Exception as exc:
                        _log(
                            "REPORT",
                            f"{section_key} — narrated output was not persisted: {exc}",
                            level="warning",
                        )
                        narration_status = (
                            f"fallback:persist_error:{type(exc).__name__}"
                        )
                        body = fallback
        if not narrated:
            _log("REPORT", f"{section_key} — deterministic projection persisted")
        _record_projection(
            db,
            projection,
            iteration=iteration,
            report_input_digest=report_input_digest,
            narration_status=narration_status,
            narration_rejection_reasons=narration_rejection_reasons,
        )
        _emit_narration_outcome(
            progress_callback,
            iteration,
            session_id,
            section_key,
            "completed" if narrated else "skipped",
            "; ".join(narration_rejection_reasons) or narration_status,
        )
    return body, narrated


async def async_refresh_report_sections(
    *,
    case: Case,
    db: CaseDB,
    session_id: str,
    iteration: int,
    base_url: str,
    model: str,
    sections: list[SectionSource],
    progress_callback: Callable[[dict[str, Any]], None] | None,
    focus_sections: list[str] | None,
) -> dict[str, Any]:
    """Recompute every adopted section; narrate changed sections once at most."""
    write_report_brief(case, db)
    from forensia.report.report_brief import build_report_brief

    report_brief = build_report_brief(db, case)
    case_signature = _case_evidence_signature(db)
    report_input_digest = _report_input_digest(db)
    _log("REPORT", f"refreshing {len(sections)} adopted sections")
    updated = 0
    for source in sections:
        section_key = source.section_key
        if progress_callback:
            progress_callback(
                progress_event(
                    "report.section",
                    "running",
                    stage="render",
                    iteration=iteration,
                    session_id=session_id,
                    summary=f"[report] {section_key} projecting...",
                    refs={"section_key": section_key},
                )
            )
        try:
            await _refresh_section(
                case=case,
                db=db,
                source=source,
                report_brief=report_brief,
                case_signature=case_signature,
                report_input_digest=report_input_digest,
                session_id=session_id,
                iteration=iteration,
                base_url=base_url,
                model=model,
                progress_callback=progress_callback,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _emit_section_failure(
                progress_callback, iteration, session_id, section_key, exc
            )
            continue
        updated += 1
    report_status = build_report_status(db, focus_sections=focus_sections)
    gaps = [
        gap for item in report_status.get("items", []) for gap in item.get("gaps", [])
    ]
    if progress_callback:
        progress_callback(
            progress_event(
                "report.cycle",
                "completed",
                severity="success",
                stage="render",
                iteration=iteration,
                session_id=session_id,
                summary=f"[report] cycle done (sections={updated}, gaps={len(gaps)})",
            )
        )
    return {
        "gaps": gaps,
        "report_status": report_status,
        "updated_sections": updated,
        "complete": bool(report_status.get("complete")),
    }
