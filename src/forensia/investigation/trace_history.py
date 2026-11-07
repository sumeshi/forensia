"""Bounded, case-wide search leads projected from existing query receipts.

History is planning input only. It neither certifies a current observation nor
reuses a previous Assessment, verdict, or execution authorization.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sqlglot.errors import SqlglotError

from forensia.context.sql_templates import query_referenced_tables
from forensia.core.session import Hypothesis
from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.evidence.content_identity import bulk_evidence_content_fingerprints
from forensia.evidence.links import verification_spec_fingerprint
from forensia.investigation.hypotheses.execution import _evidence_scope_fingerprint
from forensia.knowledge.coverage import load_artifact_capabilities

_SEARCH_LIMIT = 64
_DETAIL_LIMIT = 2
_MAX_SQL_CHARS = 8192
_STOP_WORDS = frozenset(
    "a an and are artifact artifacts check confirm data database determine did "
    "does event events evidence execution file files find for from get has host "
    "hypothesis in inspect investigate investigation is it name observed of on "
    "or query records search select show table that the this to user verify was "
    "were what when whether which with".split()
)


@dataclass(frozen=True)
class CaseHistory:
    summaries: tuple[dict[str, Any], ...] = ()
    details: tuple[dict[str, Any], ...] = ()
    query_terms: tuple[str, ...] = ()
    candidate_count: int = 0
    omitted_count: int = 0
    char_budget: int = 4000


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except TypeError, ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _values(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [
            term
            for key, child in value.items()
            if key not in {"family", "field", "operator", "capability", "spec_version"}
            for term in _values(child)
        ]
    if isinstance(value, (list, tuple)):
        return [term for child in value for term in _values(child)]
    if isinstance(value, bool) or value is None:
        return []
    return [str(value)]


def _search_terms(
    hypothesis: Hypothesis, spec: dict[str, Any], tables: set[str]
) -> tuple[tuple[str, ...], set[str]]:
    """Literal entities/condition values precede Unicode-aware description terms."""
    explicit = [*hypothesis.required_entities]
    for key in ("support_conditions", "scope", "correlation"):
        explicit.extend(_values(spec.get(key, {})))
    terms: list[str] = []
    strong: set[str] = set()

    def add(value: str, *, stable: bool) -> None:
        term = value.strip().lower()
        if (
            len(term) < 2
            or len(term) > 160
            or term in _STOP_WORDS
            or term in tables
            or term
            in {"equals", "contains", "greater_than", "less_than", "true", "false"}
        ):
            return
        if term not in terms:
            terms.append(term)
        if stable:
            strong.add(term)

    for term in explicit:
        add(term, stable=not term.isdecimal())
    for term in re.findall(r"\w+(?:[.\\:/-]\w+)*", hypothesis.description):
        add(term, stable=False)
    return tuple(terms[:20]), strong


def search_case_attempts(
    db: CaseDB,
    hypothesis: Hypothesis,
    *,
    spec_payload: dict[str, Any] | None = None,
    eligible_tables: tuple[str, ...] | list[str] | None = None,
    max_entries: int = 4,
) -> tuple[tuple[dict[str, Any], ...], tuple[str, ...], int]:
    """Search in SQL, returning bounded metadata instead of loading all Trace.

    candidate_count counts lexical matches before the bounded SQL/table safety
    inspection. Rejected or uninspected candidates are included in omissions.
    """
    families = load_artifact_capabilities().get("families", {})
    catalog_tables = {
        str(table).lower()
        for family in families.values()
        for table in family.get("tables", [])
    }
    allowed = (
        {str(table).lower() for table in eligible_tables}
        if eligible_tables is not None
        else catalog_tables
    )
    spec = spec_payload or hypothesis.verification_spec.model_dump(mode="json")
    terms, strong = _search_terms(hypothesis, spec, catalog_tables | set(families))
    if not terms or not allowed or max_entries <= 0:
        return (), terms, 0
    tests = ["contains(search_text, ?)" for _ in terms]
    score = " + ".join(
        f"CASE WHEN {test} THEN {8 if term in strong else 1} ELSE 0 END"
        for test, term in zip(tests, terms, strict=True)
    )
    rows = db.execute(
        f"""
        WITH attempts AS (
            SELECT s.step_id, s.session_id, s.hypothesis_id, s.created_at,
                COALESCE(json_extract_string(s.input_json, '$.planned_query.purpose'), '') AS purpose,
                COALESCE(NULLIF(json_extract_string(s.input_json, '$.planned_query.sql'), ''),
                    json_extract_string(s.output_json, '$.tool_receipt.arguments.normalized_sql'), '') AS sql,
                COALESCE(json_extract_string(s.output_json, '$.attempt.attempt_ref'),
                    json_extract_string(s.output_json, '$.tool_receipt.receipt_id'), s.step_id) AS attempt_ref,
                COALESCE(json_extract_string(s.output_json, '$.attempt.status'),
                    json_extract_string(s.output_json, '$.tool_receipt.status'), 'unknown') AS status,
                TRY_CAST(COALESCE(json_extract_string(s.output_json, '$.attempt.returned_count'),
                    json_extract_string(s.output_json, '$.tool_receipt.returned_count')) AS BIGINT) AS returned_count,
                lower(concat_ws(' ', h.description, h.required_entities,
                    h.verification_spec, purpose, sql,
                    json_extract(s.input_json, '$.planned_query.params'),
                    json_extract(s.output_json, '$.attempt.evidence_ids'),
                    json_extract(s.output_json, '$.tool_receipt.result_refs.evidence_ids'))) AS search_text
            FROM trace.investigation_steps s
            LEFT JOIN hypotheses h ON h.hypothesis_id = s.hypothesis_id
            WHERE s.phase = 'do' AND s.hypothesis_id <> ?
        ), scored AS (
            SELECT *, ({score}) AS relevance FROM attempts
        )
        SELECT step_id, session_id, hypothesis_id, attempt_ref, left(purpose, 180),
            status, returned_count,
            CASE WHEN length(sql) <= ? THEN sql ELSE '' END,
            count(*) OVER () AS candidate_count
        FROM scored WHERE relevance > 0 AND sql <> '' AND regexp_matches(sql, ?)
        ORDER BY relevance DESC, created_at DESC, step_id
        LIMIT ?
        """,
        [
            hypothesis.id,
            *terms,
            _MAX_SQL_CHARS,
            r"(?i)\b(?:"
            + "|".join(re.escape(table) for table in sorted(allowed))
            + r")\b",
            _SEARCH_LIMIT,
        ],
    ).fetchall()
    summaries = []
    for row in rows:
        try:
            tables = set(query_referenced_tables(str(row[7])))
        except ValueError, SqlglotError:
            continue
        if not tables or not tables <= allowed:
            continue
        summaries.append(
            {
                "step_id": str(row[0]),
                "session_id": str(row[1] or ""),
                "hypothesis_id": str(row[2]),
                "attempt_ref": str(row[3]),
                "purpose": str(row[4]),
                "status": _status(row[5]),
                "returned_count": row[6],
                "tables": sorted(tables),
                "currentness": {
                    "source_revision": "unknown",
                    "originating_spec": "unknown",
                    "evidence_content": "unknown",
                },
            }
        )
        if len(summaries) >= min(max_entries, 16):
            break
    return tuple(summaries), terms, int(rows[0][8]) if rows else 0


def _status(value: Any) -> str:
    return (
        str(value)
        if value
        in {"ok", "empty", "partial", "unavailable", "error", "completed", "skipped"}
        else "unknown"
    )


def _currentness(stored: Any, current: Any) -> str:
    if not stored or not current:
        return "unknown"
    return "current" if stored == current else "stale"


def _spec_fingerprint(payload: Any) -> str:
    if not payload:
        return ""
    try:
        return verification_spec_fingerprint(VerificationSpec.model_validate(payload))
    except ValueError:
        return ""


def load_case_attempt_details(
    db: CaseDB, summaries: tuple[dict[str, Any], ...], *, sql_budget: int = 1400
) -> tuple[dict[str, Any], ...]:
    """Read at most two selected receipts; never expose checks' model narrative."""
    details = []
    for summary in summaries[:_DETAIL_LIMIT]:
        row = db.execute(
            "SELECT COALESCE(NULLIF(json_extract_string(input_json, '$.planned_query.sql'), ''), "
            "json_extract_string(output_json, '$.tool_receipt.arguments.normalized_sql')), "
            "json_extract(output_json, '$.attempt.evidence_ids'), "
            "json_extract(output_json, '$.tool_receipt.result_refs.evidence_ids'), "
            "json_extract(output_json, '$.evidence_ids'), "
            "json_extract_string(output_json, '$.attempt.evidence_scope_fingerprint'), "
            "json_extract_string(output_json, '$.attempt.verification_spec_fingerprint'), "
            "json_extract(output_json, '$.tool_receipt.truncated'), "
            "json_extract_string(output_json, '$.retrieval_evaluation.scope_status'), "
            "hypothesis_id, COALESCE(json_extract_string(output_json, '$.attempt.attempt_ref'), "
            "json_extract_string(output_json, '$.tool_receipt.receipt_id'), step_id) "
            "FROM trace.investigation_steps "
            "WHERE step_id = ? AND phase = 'do'",
            [summary["step_id"]],
        ).fetchone()
        if row is None or (row[8], row[9]) != (
            summary["hypothesis_id"],
            summary["attempt_ref"],
        ):
            continue
        sql = str(row[0] or "")
        origin_row = db.execute(
            "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
            [summary["hypothesis_id"]],
        ).fetchone()
        origin_spec = _object(origin_row[0]) if origin_row else {}
        check_row = db.execute(
            "SELECT json_extract(output_json, '$.assessment.content_fingerprints') "
            "FROM trace.investigation_steps WHERE phase = 'check' "
            "AND hypothesis_id = ? "
            "AND json_extract_string(output_json, '$.attempt_ref') = ? "
            "ORDER BY created_at DESC, step_id DESC LIMIT 1",
            [summary["hypothesis_id"], summary["attempt_ref"]],
        ).fetchone()
        stored_content = _object(check_row[0]) if check_row else {}
        evidence_ids = []
        for value in row[1:4]:
            if value is not None:
                try:
                    parsed = json.loads(value) if isinstance(value, str) else value
                except TypeError, ValueError:
                    continue
                if isinstance(parsed, list) and parsed:
                    evidence_ids = parsed
                    break
        evidence_ids = (
            sorted({str(value) for value in evidence_ids if isinstance(value, str)})
            if isinstance(evidence_ids, list)
            else []
        )
        content_state = "unknown"
        if evidence_ids and len(evidence_ids) <= 200 and stored_content:
            current = bulk_evidence_content_fingerprints(db, evidence_ids)
            states = [
                _currentness(stored_content.get(eid), current.get(eid))
                for eid in evidence_ids
            ]
            content_state = (
                "stale"
                if "stale" in states
                else (
                    "current"
                    if all(state == "current" for state in states)
                    else "unknown"
                )
            )
        truncated = {"true": True, "false": False}.get(str(row[6]))
        detail: dict[str, Any] = {
            "attempt_ref": summary["attempt_ref"],
            "evidence_ids": evidence_ids[:8],
            "evidence_refs_omitted_count": max(0, len(evidence_ids) - 8),
            "retrieval_completeness": (
                "partial"
                if truncated is True
                else "complete"
                if truncated is False
                else "unknown"
            ),
            "scope_status": row[7] if row[7] in {"valid", "rejected"} else "unknown",
            "currentness": {
                "source_revision": _currentness(
                    row[4],
                    _evidence_scope_fingerprint(db, sql) if sql else None,
                ),
                "originating_spec": _currentness(
                    row[5],
                    _spec_fingerprint(origin_spec),
                ),
                "evidence_content": content_state,
            },
        }
        if sql and len(sql) <= max(0, sql_budget):
            detail["normalized_sql"] = sql
        else:
            detail["sql_omitted_reason"] = (
                "exceeds_detail_budget" if sql else "not_recorded"
            )
        details.append(detail)
    return tuple(details)


def _render(history: CaseHistory) -> str:
    if not history.candidate_count:
        return ""
    body = (
        json.dumps(
            {
                "query_terms": history.query_terms,
                "candidate_count": history.candidate_count,
                "omitted_count": history.omitted_count,
                "summaries": history.summaries,
                "details": history.details,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    return (
        "<CASE_ATTEMPT_HISTORY>\n"
        "Historical search leads, not current evidence or conclusions. Validate any new "
        "query and assess current canonical evidence against the current verification "
        "conditions. Empty or complete retrieval does not establish absence.\n"
        + body
        + "\n</CASE_ATTEMPT_HISTORY>\n"
    )


def build_case_history(
    db: CaseDB,
    hypothesis: Hypothesis,
    *,
    spec_payload: dict[str, Any] | None = None,
    eligible_tables: tuple[str, ...] | list[str] | None = None,
    max_entries: int = 4,
    char_budget: int = 4000,
) -> CaseHistory:
    """Select summaries first, then bounded details; budget includes all framing."""
    summaries, terms, count = search_case_attempts(
        db,
        hypothesis,
        spec_payload=spec_payload,
        eligible_tables=eligible_tables,
        max_entries=max_entries,
    )
    details = load_case_attempt_details(
        db, summaries, sql_budget=min(1400, char_budget // 2)
    )
    by_ref = {detail["attempt_ref"]: detail["currentness"] for detail in details}
    summaries = tuple(
        {
            **summary,
            "currentness": by_ref.get(summary["attempt_ref"], summary["currentness"]),
        }
        for summary in summaries
    )
    while True:
        history = CaseHistory(
            summaries,
            details,
            terms,
            count,
            max(0, count - len(summaries)),
            max(0, char_budget),
        )
        if len(_render(history)) <= history.char_budget:
            return history
        if details:
            details = details[:-1]
        elif summaries:
            summaries = summaries[:-1]
        elif terms:
            terms = terms[:-1]
        else:
            return history


def render_case_history(history: CaseHistory) -> str:
    """Never emit a partially sliced receipt, SQL statement, or framing block."""
    rendered = _render(history)
    return rendered if len(rendered) <= history.char_budget else ""
