"""Structured answer registry and universal question probe execution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import (
    expand_catalog_sql_placeholders,
)
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
    _persist_structured_answer,
    _structured_answer,
    _structured_rows,
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
        label = f"structured:{spec.semantic_id}:{source}"
        queries_run.append(label)
        try:
            source_rows = _structured_rows(db, query)
        except Exception as exc:
            errors.append(f"{source}: {str(exc)[:120]}")
            continue
        for row in source_rows:
            rows.append({**row, "_question_source": source})

    rows = project_rows_for_question_spec(spec, rows)
    rows = _rank_rows_first(rows, spec)
    status, reasons = evaluate_question_spec_status(spec, rows, queries_run=queries_run)
    if errors:
        reasons.extend(errors)
        if status == "answered":
            status = "partial"
    columns = list(spec.render_columns)
    if not columns and rows:
        columns = [str(key) for key in rows[0].keys() if not str(key).startswith("_")]
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
    if not answer.get("answer_spec"):
        answer["answer_spec"] = answer_spec
        _persist_structured_answer(case, answer)
    return answer


StructuredAnswerBuilder = Callable[[Case, CaseDB, str, str, str], dict[str, Any]]


def _rank_rows_first(
    rows: list[dict[str, Any]], spec: QuestionSpec | None
) -> list[dict[str, Any]]:
    """Rank answer-first: rows whose ``rank_field`` matches a ``rank_priority`` token.

    This is a generic, declarative contract — no benchmark answers are encoded
    as special-case branches for specific question numbers. The decisive primary
    answer (e.g. the correct OST among OAB noise, or Outlook among Windows Mail
    rows) is surfaced first so composite answers lead with the answer.
    """
    if spec is None or not spec.rank_field or not spec.rank_priority:
        return rows
    priority = [p.strip().lower() for p in spec.rank_priority if p.strip()]

    def rank_key(row: dict[str, Any]) -> tuple[int, int]:
        value = str(row.get(spec.rank_field) or "").strip().lower()
        for index, token in enumerate(priority):
            if token in value:
                return (0, index)
        return (1, len(priority))

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
    """Register a deterministic builder for one normalized answer spec."""
    normalized = str(answer_spec).strip().casefold().replace("-", "_")
    if not normalized:
        raise ValueError("answer_spec must not be empty")
    if normalized in _STRUCTURED_ANSWER_BUILDERS and not replace:
        raise ValueError(f"structured answer builder already registered: {normalized}")
    _STRUCTURED_ANSWER_BUILDERS[normalized] = builder


def structured_answer_builder_names() -> frozenset[str]:
    """Return registered deterministic answer specs for audits and docs."""
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
    if not answer.get("answer_spec"):
        answer["answer_spec"] = normalized_spec
        _persist_structured_answer(case, answer)
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
            _persist_structured_answer(case, answer)
    return answer


UNIVERSAL_QUESTION_SPECS: tuple[str, ...] = (
    "host_identity",
    "last_human_logon",
    "last_shutdown_event",
    "application_execution_history",
    "daily_session_activity",
    "daily_session_timeline",
    "browser_usage",
    "email_data_files",
    "cloud_service_traces",
    "antiforensic_activity",
)


def _collect_answer_evidence_ids(value: Any) -> list[str]:
    found: list[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            single = item.get("evidence_id")
            if single is not None:
                text = str(single).strip()
                if text:
                    found.append(text)
            many = item.get("evidence_ids")
            if isinstance(many, (list, tuple, set)):
                for part in many:
                    text = str(part).strip()
                    if text:
                        found.append(text)
            elif many is not None:
                text = str(many).strip()
                if text:
                    found.append(text)
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)

    visit(value)
    return list(dict.fromkeys(found))


def ensure_universal_question_probes(case: Case, db: CaseDB) -> None:
    try:
        existing = db.execute(
            """
            SELECT COUNT(*)
            FROM section_questions
            WHERE section_key = '__case_probe__'
              AND status = 'case_probe'
            """
        ).fetchone()
        if existing is not None and int(existing[0] or 0) >= len(
            UNIVERSAL_QUESTION_SPECS
        ):
            return
    except Exception:
        return

    now = datetime.now(UTC).replace(tzinfo=None)
    for answer_spec in UNIVERSAL_QUESTION_SPECS:
        spec = question_spec_for_answer_spec(answer_spec)
        if spec is None:
            continue
        try:
            answer = build_structured_answer(
                case,
                db,
                answer_spec=answer_spec,
                answer_id=f"probe_{answer_spec}",
                section_key="__case_probe__",
                block_heading=spec.intent or spec.name,
            )
        except Exception:
            answer = None
        question_id = hashlib.sha1(
            f"__case_probe__\n{answer_spec}".encode()
        ).hexdigest()[:20]
        required_evidence = {
            "required_fields": list(spec.required_fields),
            "required_sources": list(spec.required_sources),
            "keypoints": list(spec.keypoints),
            "render_columns": list(spec.render_columns),
            "status_rules": spec.status_rules,
        }
        db.execute(
            """
            INSERT INTO section_questions (
                question_id, section_key, block_heading, question_text, question_type,
                answer_spec, intent, confidence, matched_rule, required_evidence,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (question_id) DO UPDATE SET
                confidence = excluded.confidence,
                required_evidence = excluded.required_evidence,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                question_id,
                "__case_probe__",
                spec.intent or spec.name,
                spec.intent or spec.name,
                spec.name,
                spec.answer_spec,
                spec.intent,
                1.0,
                spec.name,
                json.dumps(required_evidence, ensure_ascii=False, default=str),
                "case_probe",
                now,
                now,
            ),
        )
        if answer is not None:
            evidence_ids = _collect_answer_evidence_ids(answer.get("answer"))
            fact_value = {
                "status": answer.get("status"),
                "answer": answer.get("answer"),
                "columns": answer.get("columns"),
                "evidence_ids": evidence_ids,
            }
            fact_id = hashlib.sha1(
                f"universal_question:{answer_spec}".encode()
            ).hexdigest()[:20]
            db.execute(
                """
                INSERT INTO section_facts (
                    fact_id, fact_type, fact_key, fact_value, evidence_ids,
                    source_query, source_section, confidence, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fact_id) DO UPDATE SET
                    fact_value = excluded.fact_value,
                    evidence_ids = excluded.evidence_ids,
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at
                """,
                (
                    fact_id,
                    "universal_question",
                    answer_spec,
                    json.dumps(fact_value, ensure_ascii=False, default=str),
                    json.dumps(evidence_ids, ensure_ascii=False),
                    f"structured:{answer_spec}",
                    "__case_probe__",
                    0.9 if answer.get("status") == "answered" else 0.5,
                    now,
                    now,
                ),
            )
        if (
            answer is not None
            and answer.get("status") in {"answered", "partial"}
            and spec.timeline
        ):
            _feed_structured_to_timeline(db, answer_spec, answer)


def _feed_structured_to_timeline(
    db: CaseDB, spec_name: str, answer: dict[str, Any]
) -> None:
    answer_rows = [
        item for item in (answer.get("answer") or []) if isinstance(item, dict)
    ]
    if not answer_rows:
        return
    for index, row in enumerate(answer_rows[:3]):
        ts = (
            row.get("timestamp")
            or row.get("logon_time")
            or row.get("shutdown_time")
            or row.get("last_exec_time")
            or row.get("artifact_time")
            or row.get("si_modified")
            or row.get("date")
        )
        if not ts:
            continue
        host = row.get("computer") or row.get("host") or ""
        evidence_id = row.get("evidence_id") or ""
        summary_parts = [
            str(row.get(k) or "")
            for k in (
                "event_id",
                "executable_name",
                "file_name",
                "service_name",
                "target_user",
                "message",
            )
            if row.get(k)
        ]
        summary = " ".join(summary_parts)[:200] or spec_name
        entry_id = f"tl-structured-{spec_name}-{index}"
        db.execute(
            """
            INSERT INTO case_timeline (entry_id, timestamp, source, ref_id, host, summary, evidence_id)
            VALUES (?, ?, 'structured', ?, ?, ?, ?)
            ON CONFLICT (entry_id) DO NOTHING
            """,
            (entry_id, ts, spec_name, host, summary, evidence_id),
        )
