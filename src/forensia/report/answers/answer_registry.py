"""Deterministic structured-answer recipes for explicit report requirements."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import expand_catalog_sql_placeholders
from forensia.knowledge.questions import (
    QuestionSpec,
    evaluate_question_spec_status,
    project_rows_for_question_spec,
    question_spec_for_answer_spec,
)
from forensia.report.answers.answer_builders_artifacts import (
    _build_antiforensic_activity,
    _build_browser_usage,
    _build_cloud_service_traces,
    _build_desktop_rename_candidates,
)
from forensia.report.answers.answer_builders_host import (
    _build_application_execution_history,
    _build_daily_session_activity,
    _build_daily_session_timeline,
    _build_host_identity,
    _build_last_human_logon,
    _build_last_shutdown_event,
)
from forensia.report.answers.answer_store import (
    _coerce_string_list,
    _structured_answer,
    _structured_rows,
    _write_structured_answer_export,
)


def _build_generic_question_spec_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    spec = question_spec_for_answer_spec(answer_spec)
    if spec is None or not spec.evidence_chain:
        return None

    rows: list[dict[str, Any]] = []
    queries_run: list[str] = []
    errors: list[str] = []
    for index, entry in enumerate(spec.evidence_chain, start=1):
        query = str(entry.get("query") or "").strip()
        if not query:
            continue
        query = expand_catalog_sql_placeholders(query)
        source = str(entry.get("source") or f"query_{index}").strip()
        queries_run.append(f"structured:{spec.semantic_id}:{source}")
        try:
            rows.extend(
                {**row, "_question_source": source}
                for row in _structured_rows(db, query)
            )
        except Exception as exc:
            errors.append(f"{source}: {str(exc)[:120]}")

    rows = _rank_rows_first(project_rows_for_question_spec(spec, rows), spec)
    status, reasons = evaluate_question_spec_status(spec, rows, queries_run=queries_run)
    if errors:
        reasons.extend(errors)
        if status == "answered":
            status = "partial"
    columns = list(spec.render_columns)
    if not columns and rows:
        columns = [str(key) for key in rows[0] if not str(key).startswith("_")]
    answer = _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=columns,
        queries_run=queries_run,
        status=status,
        missing_reason=reasons,
        source="question_spec",
    )
    answer["answer_spec"] = answer_spec
    _write_structured_answer_export(case, answer)
    return answer


StructuredAnswerBuilder = Callable[[Case, CaseDB, str, str, str], dict[str, Any]]


def _rank_rows_first(
    rows: list[dict[str, Any]], spec: QuestionSpec | None
) -> list[dict[str, Any]]:
    if spec is None or not spec.rank_field or not spec.rank_priority:
        return rows
    priority = [part.strip().lower() for part in spec.rank_priority if part.strip()]

    def rank_key(row: dict[str, Any]) -> tuple[int, int]:
        value = str(row.get(spec.rank_field) or "").strip().lower()
        for index, token in enumerate(priority):
            if token in value:
                return 0, index
        return 1, len(priority)

    return sorted(rows, key=rank_key)


_STRUCTURED_ANSWER_BUILDERS: dict[str, StructuredAnswerBuilder] = {
    "host_identity": _build_host_identity,
    "last_human_logon": _build_last_human_logon,
    "last_shutdown_event": _build_last_shutdown_event,
    "application_execution_history": _build_application_execution_history,
    "daily_session_activity": _build_daily_session_activity,
    "daily_session_timeline": _build_daily_session_timeline,
    "browser_usage": _build_browser_usage,
    "desktop_rename_candidates": _build_desktop_rename_candidates,
    "cloud_service_traces": _build_cloud_service_traces,
    "antiforensic_activity": _build_antiforensic_activity,
}


def register_structured_answer_builder(
    answer_spec: str,
    builder: StructuredAnswerBuilder,
    *,
    replace: bool = False,
) -> None:
    """Register a deterministic builder for an explicit answer requirement."""
    normalized = str(answer_spec).strip().casefold().replace("-", "_")
    if not normalized:
        raise ValueError("answer_spec must not be empty")
    if normalized in _STRUCTURED_ANSWER_BUILDERS and not replace:
        raise ValueError(f"structured answer builder already registered: {normalized}")
    _STRUCTURED_ANSWER_BUILDERS[normalized] = builder


def structured_answer_builder_names() -> frozenset[str]:
    return frozenset(_STRUCTURED_ANSWER_BUILDERS)


def build_structured_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_spec: str,
    answer_id: str,
    section_key: str,
    block_heading: str,
) -> dict[str, Any] | None:
    """Recompute the named answer from current CaseDB rows; exports are projections."""
    normalized_spec = str(answer_spec or "").strip().casefold().replace("-", "_")
    if not normalized_spec:
        return None
    spec = question_spec_for_answer_spec(normalized_spec)
    builder_policy = str(getattr(spec, "builder_policy", "") or "").strip().casefold()
    if builder_policy in {"generic", "question_spec", "declarative"}:
        return _build_generic_question_spec_answer(
            case,
            db,
            answer_spec=normalized_spec,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
        )
    builder = _STRUCTURED_ANSWER_BUILDERS.get(normalized_spec)
    if builder is None:
        return _build_generic_question_spec_answer(
            case,
            db,
            answer_spec=normalized_spec,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
        )
    resolved_id = str(answer_id or normalized_spec).strip() or normalized_spec
    answer = builder(case, db, resolved_id, section_key, block_heading)
    answer["answer_spec"] = normalized_spec
    if spec is not None:
        status, reasons = evaluate_question_spec_status(
            spec,
            [item for item in answer.get("answer") or [] if isinstance(item, dict)],
            queries_run=_coerce_string_list(answer.get("queries_run")),
            fallback_status=str(answer.get("status") or ""),
        )
        if status != answer.get("status") or reasons:
            answer["status"] = status
            missing = _coerce_string_list(answer.get("missing_reason"))
            for reason in reasons:
                if reason and reason not in missing:
                    missing.append(reason)
            answer["missing_reason"] = missing
    _write_structured_answer_export(case, answer)
    return answer
