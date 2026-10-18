"""Deterministic structured-answer recipes for explicit report requirements."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from forensia.core.case import Case
from forensia.core.identifiers import report_gap_id
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records, routed_family
from forensia.evidence.links import load_evidence_links
from forensia.knowledge.catalog import expand_catalog_sql_placeholders
from forensia.knowledge.questions import (
    QuestionSpec,
    admitted_question_receipt,
    evaluate_question_spec_status,
    gap_operational_reason,
    project_rows_for_question_spec,
    question_contract_match_reason,
    question_scope_evidence_ids,
    question_spec_for_answer_spec,
    question_timestamp_coverage,
    verification_spec_payload,
)
from forensia.llm.schemas import QuestionRequestContract
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


def _build_investigated_question_answer(
    case: Case,
    db: CaseDB,
    *,
    answer_id: str,
    section_key: str,
    block_heading: str,
    question_text: str,
) -> dict[str, Any]:
    gap_id = report_gap_id(
        question_text, section_key=section_key, block_heading=block_heading
    )
    gap = db.execute(
        "SELECT status, coverage_reason, hypothesis_id FROM report_gaps WHERE gap_id = ?",
        [gap_id],
    ).fetchone()
    canonical_hypothesis_id = str(gap[2] or "") if gap else ""
    rows_by_evidence: dict[str, dict[str, Any]] = {}
    row_query_ids: dict[str, set[str]] = {}
    query_ids: set[str] = set()
    contract = None
    hypothesis_row = (
        db.execute(
            "SELECT status, verification_spec FROM hypotheses WHERE hypothesis_id = ?",
            [canonical_hypothesis_id],
        ).fetchone()
        if canonical_hypothesis_id
        else None
    )
    receipt = (
        admitted_question_receipt(
            db,
            gap_id=gap_id,
            question_text=question_text,
            hypothesis_id=canonical_hypothesis_id,
            verification_spec=hypothesis_row[1],
        )
        if gap and hypothesis_row
        else None
    )
    if receipt and receipt.get("status") == "completed":
        try:
            contract = QuestionRequestContract.model_validate(
                receipt.get("request_contract")
            )
        except Exception:
            contract = None
        if contract:
            contract_fingerprint = hashlib.sha256(
                json.dumps(
                    contract.model_dump(mode="json"),
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if contract_fingerprint != receipt.get("contract_id"):
                contract = None

    spec_payload = (
        verification_spec_payload(hypothesis_row[1]) if hypothesis_row else {}
    )
    returned_ids = set(receipt.get("scoped_evidence_ids") or []) if receipt else set()
    receipt_scope_ids: set[str] = set()
    receipt_scope_reason: str | None = None
    if contract and receipt and receipt.get("status") == "completed":
        try:
            receipt_ids, receipt_scope_truncated = question_scope_evidence_ids(
                db,
                contract.model_dump(mode="json"),
                evidence_ids=sorted(returned_ids),
            )
            if receipt_scope_truncated or set(receipt_ids) != returned_ids:
                receipt_scope_reason = "question_scope_changed_or_unverifiable"
            else:
                receipt_scope_ids = set(receipt_ids)
        except Exception:
            receipt_scope_reason = "question_scope_unverifiable"
    links = (
        load_evidence_links(db, canonical_hypothesis_id, current_only=True)
        if canonical_hypothesis_id
        else []
    )
    usable_links = [
        link
        for link in links
        if link.assessment_id
        and link.evidence_id in returned_ids
        and link.evidence_id in receipt_scope_ids
        and link.role in {"supporting", "corroborating", "contradictory"}
    ]
    records = fetch_evidence_records(
        db, sorted({link.evidence_id for link in usable_links})
    )
    usable_links = [link for link in usable_links if link.evidence_id in records]
    timestamp_fields, timestamp_missing = question_timestamp_coverage(
        db,
        question_text,
        contract.model_dump(mode="json") if contract else {},
        records,
    )
    request_reason = receipt_scope_reason or (
        question_contract_match_reason(
            contract.model_dump(mode="json"),
            spec_payload,
            observation_records=records,
        )
        if contract
        else "question_relevance_unverified"
    )
    current_scope_ids: set[str] = set()
    current_scope_truncated = True
    if (
        contract
        and not request_reason
        and hypothesis_row
        and hypothesis_row[0] in {"confirmed", "refuted"}
    ):
        try:
            scope_ids, current_scope_truncated = question_scope_evidence_ids(
                db, contract.model_dump(mode="json")
            )
            current_scope_ids = set(scope_ids)
        except Exception:
            request_reason = "question_scope_unverifiable"
    if (
        contract
        and not request_reason
        and hypothesis_row
        and hypothesis_row[0] in {"confirmed", "refuted"}
    ):
        for link in usable_links:
            record = records[link.evidence_id]
            requirement_fields = list(
                dict.fromkeys(
                    [item.field for item in contract.requirements]
                    + list(timestamp_fields)
                )
            )
            answer_row = {
                field: record.get(field)
                for field in requirement_fields
                if record.get(field) is not None
            }
            if not answer_row:
                continue
            rows_by_evidence.setdefault(
                link.evidence_id,
                answer_row
                | {
                    "hypothesis_id": canonical_hypothesis_id,
                    "evidence_id": link.evidence_id,
                },
            )
            if link.query_id:
                row_query_ids.setdefault(link.evidence_id, set()).add(link.query_id)
                query_ids.add(link.query_id)
    linked_ids = {link.evidence_id for link in usable_links}
    complete = bool(
        contract
        and not request_reason
        and gap
        and gap[0] == "resolved"
        and hypothesis_row
        and hypothesis_row[0] in {"confirmed", "refuted"}
        and receipt
        and not receipt.get("truncated")
        and not receipt.get("canonical_scope_truncated")
        and not current_scope_truncated
        and set(receipt.get("canonical_scope_evidence_ids") or []) == current_scope_ids
        and set(receipt.get("canonical_scope_evidence_ids") or [])
        == returned_ids
        == linked_ids
        and not timestamp_missing
    )
    status = (
        "answered"
        if complete
        else "partial"
        if rows_by_evidence
        else "insufficient_evidence"
    )
    rows = [
        row
        | {
            "status": (
                str(hypothesis_row[0]) if complete and hypothesis_row else "observed"
            ),
            "query_ids": sorted(row_query_ids.get(evidence_id, set())),
        }
        for evidence_id, row in sorted(rows_by_evidence.items())
    ]
    candidate_search: dict[str, Any] | None = None
    unassessed_candidates: list[dict[str, Any]] = []
    if contract and receipt and receipt.get("status") == "completed":
        raw_candidate_ids = receipt.get("scoped_evidence_ids")
        raw_query_ids = receipt.get("evidence_ids")
        discovery_step_id = str(receipt.get("discovery_step_id") or "")
        try:
            candidate_ids = list(dict.fromkeys(raw_candidate_ids or []))
            query_evidence_ids = list(dict.fromkeys(raw_query_ids or []))
            families = {item.family for item in contract.requirements}
            candidate_records = fetch_evidence_records(db, candidate_ids)
            answer_ids = {
                str(row["evidence_id"]) for row in rows if row.get("evidence_id")
            }
            valid_candidates = bool(
                discovery_step_id
                and isinstance(raw_candidate_ids, list)
                and isinstance(raw_query_ids, list)
                and all(isinstance(item, str) and item for item in candidate_ids)
                and all(isinstance(item, str) and item for item in query_evidence_ids)
                and set(candidate_ids).issubset(set(query_evidence_ids))
                and set(candidate_ids) == receipt_scope_ids
                and set(candidate_records) == set(candidate_ids)
                and len(families) == 1
                and all(routed_family(item) in families for item in candidate_ids)
                and bool(receipt.get("sql"))
            )
            if valid_candidates:
                requirement_fields = list(
                    dict.fromkeys(
                        [item.field for item in contract.requirements]
                        + list(timestamp_fields)
                    )
                )
                for evidence_id in candidate_ids:
                    if evidence_id in answer_ids:
                        continue
                    record = candidate_records[evidence_id]
                    if record.get("evidence_id") != evidence_id:
                        continue
                    unassessed_candidates.append(
                        {
                            **{
                                field: record.get(field) for field in requirement_fields
                            },
                            "candidate_state": "unassessed",
                            "evidence_id": evidence_id,
                            "discovery_step_id": discovery_step_id,
                        }
                    )
                candidate_search = {
                    "discovery_step_id": discovery_step_id,
                    "contract_id": receipt.get("contract_id"),
                    "sql": str(receipt.get("sql")),
                    "candidate_count": len(unassessed_candidates),
                    "query_truncated": bool(receipt.get("truncated")),
                    "omitted_scoped_evidence_count": int(
                        receipt.get("omitted_scoped_evidence_count") or 0
                    ),
                }
        except TypeError, ValueError, KeyError:
            unassessed_candidates = []
            candidate_search = None
    if not gap:
        status = "not_searched"
    operational_reason = gap_operational_reason(db, gap_id) if gap else None
    operational_reason = operational_reason or (
        str(gap[1])
        if gap
        and gap[1]
        in {"investigation_attempt_failed", "investigation_attempt_in_progress"}
        else None
    )
    timestamp_reason = None
    if timestamp_missing:
        missing_fields = sorted(
            {field for fields in timestamp_missing.values() for field in fields}
        )
        timestamp_reason = (
            "Requested timestamp coverage is incomplete: "
            + ", ".join(missing_fields)
            + "."
        )
    if complete:
        reasons = []
    elif gap and operational_reason == "investigation_attempt_in_progress":
        reasons = ["The investigation is in progress; no conclusion is available."]
    elif gap and operational_reason == "investigation_attempt_failed":
        reasons = [
            "The investigation attempt failed; the requested evidence remains unresolved."
        ]
    elif (
        gap
        and gap[1]
        and gap[1] != "question_timestamp_coverage_incomplete"
        and gap[1]
        not in {
            "investigation_attempt_failed",
            "investigation_attempt_in_progress",
        }
    ):
        reasons = [str(gap[1])]
    elif timestamp_reason:
        reasons = [timestamp_reason]
    elif gap and gap[1]:
        reasons = [str(gap[1])]
    elif request_reason:
        reasons = [request_reason]
    else:
        reasons = [
            "The requested investigation has incomplete current assessed coverage."
        ]
    if not complete and timestamp_reason and timestamp_reason not in reasons:
        reasons.append(timestamp_reason)
    answer = _structured_answer(
        case,
        answer_id=answer_id,
        section_key=section_key,
        block_heading=block_heading,
        rows=rows,
        columns=(
            list(dict.fromkeys(item.field for item in contract.requirements))
            + [
                field_name
                for field_name in timestamp_fields
                if field_name not in {item.field for item in contract.requirements}
            ]
            + ["status", "evidence_id", "query_ids"]
            if contract
            else ["description", "status", "summary", "evidence_ids", "query_ids"]
        ),
        queries_run=sorted(query_ids),
        status=status,
        missing_reason=reasons,
        source="investigation",
        unassessed_candidates=unassessed_candidates,
        candidate_search=candidate_search,
    )
    evidence_ids = sorted(
        {str(row["evidence_id"]) for row in rows if row.get("evidence_id")}
    )
    answer.update(
        question_text=question_text,
        gap_id=gap_id,
        evidence=fetch_evidence_records(db, evidence_ids),
    )
    _write_structured_answer_export(case, answer)
    return answer


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


StructuredAnswerBuilder = Callable[[Case, CaseDB, str, str, str, str], dict[str, Any]]


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
    question_text: str = "",
) -> dict[str, Any] | None:
    """Recompute the named answer from current CaseDB rows; exports are projections."""
    normalized_spec = str(answer_spec or "").strip().casefold().replace("-", "_")
    spec = question_spec_for_answer_spec(normalized_spec)
    if question_text.strip():
        return _build_investigated_question_answer(
            case,
            db,
            answer_id=str(answer_id or normalized_spec).strip() or normalized_spec,
            section_key=section_key,
            block_heading=block_heading,
            question_text=question_text,
        )
    if not normalized_spec:
        return None
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
    answer = builder(
        case,
        db,
        resolved_id,
        section_key,
        block_heading,
        "\n".join((block_heading, question_text)),
    )
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
