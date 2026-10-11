"""Deterministic helpers for existing hypothesis SQL execution."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import sqlglot
from sqlglot import exp

from forensia.context.retrieval import ToolReceipt, coverage_snapshot
from forensia.context.sql_templates import query_referenced_tables
from forensia.core.log import log as _log
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.investigation.hypotheses.hypothesis_store import load_hypothesis_attempts
from forensia.knowledge.rules.engine import (
    execute_event_keyword_fallback_search,
    execute_fallback_search,
)
from forensia.knowledge.rules.loader import load_rule_by_id
from forensia.llm.telemetry import get_active_telemetry


def _query_artifact_families(sql: str) -> list[str]:
    """Find catalogued evidence families named by the validated SQL."""
    from forensia.knowledge.coverage import load_artifact_capabilities

    family_by_table = {
        str(table).lower(): str(family)
        for family, config in load_artifact_capabilities().get("families", {}).items()
        for table in config.get("tables", [])
    }
    try:
        tables = query_referenced_tables(sql)
    except ValueError:
        return []
    return sorted(
        {family_by_table[table] for table in tables if table in family_by_table}
    )


def _evidence_scope_fingerprint(db: CaseDB, sql: str) -> str:
    """Fingerprint source revisions for the artifact families a query reads."""
    receipt_row = db.execute(
        "SELECT output_json FROM trace.investigation_steps "
        "WHERE phase = 'pipeline-normalize' "
        "ORDER BY created_at DESC, step_id DESC LIMIT 1"
    ).fetchone()
    normalize_revision = None
    if receipt_row is not None:
        try:
            receipt = json.loads(str(receipt_row[0]))
        except TypeError, ValueError:
            receipt = {}
        if isinstance(receipt, dict) and receipt.get("status") == "completed":
            revision = str(receipt.get("revision") or "")
            if revision:
                normalize_revision = {
                    "revision": revision,
                    "parser_revision": str(receipt.get("parser_revision") or ""),
                }
    source_fields = (
        "source_id, artifact_family, ingest_status, parser_name, parser_version, "
        "row_count, channel, hosts, volume_id, min_time, max_time, error_code, "
        "error_summary"
    )
    families = _query_artifact_families(sql)
    if families:
        placeholders = ", ".join("?" for _ in families)
        rows = db.execute(
            f"SELECT {source_fields} "
            f"FROM evidence_sources WHERE artifact_family IN ({placeholders}) "
            "ORDER BY artifact_family, source_id",
            families,
        ).fetchall()
    else:
        rows = db.execute(
            f"SELECT {source_fields} FROM evidence_sources "
            "ORDER BY artifact_family, source_id"
        ).fetchall()
    normalized_rows = []
    for row in rows:
        values = list(row)
        hosts = values[7]
        if isinstance(hosts, str):
            try:
                hosts = json.loads(hosts)
            except TypeError, ValueError:
                hosts = []
        values[7] = (
            sorted({str(host) for host in hosts if host})
            if isinstance(hosts, (list, tuple, set))
            else []
        )
        normalized_rows.append(values)
    encoded = json.dumps(
        {"sources": normalized_rows, "pipeline_normalize": normalize_revision},
        ensure_ascii=False,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _repeat_gate_decision(
    db: CaseDB,
    hypothesis: Hypothesis,
    *,
    query_fp: str,
    verification_fp: str,
    scope_fp: str,
) -> dict[str, Any]:
    """Apply the bounded same-input retry policy to one canonical query."""
    attempts = load_hypothesis_attempts(db, hypothesis.id)
    matching = [
        attempt
        for attempt in attempts
        if attempt.get("query_fingerprint") == query_fp
        and attempt.get("verification_spec_fingerprint") == verification_fp
        and attempt.get("evidence_scope_fingerprint") == scope_fp
    ]
    if not matching:
        return {"decision": "execute", "reason_code": "new_attempt_fingerprint"}

    retry_count = sum(
        1
        for attempt in matching
        if (attempt.get("repeat_gate") or {}).get("decision") == "retry"
    )
    previous = matching[-1]
    previous_status = str(previous.get("status") or "")
    if previous_status == "skipped":
        return {
            "decision": "skip",
            "reason_code": "duplicate_attempt_already_blocked",
            "attempt_ref": previous.get("attempt_ref"),
        }
    if previous_status == "error":
        if previous.get("retryable") and retry_count < 1:
            return {
                "decision": "retry",
                "reason_code": "bounded_transient_execution_retry",
                "retry_of": previous.get("attempt_ref"),
            }
        return {
            "decision": "skip",
            "reason_code": "same_revision_execution_failure",
            "attempt_ref": previous.get("attempt_ref"),
        }
    if not previous.get("check_verdict") and retry_count < 1:
        return {
            "decision": "retry",
            "reason_code": "bounded_retry_after_missing_check",
            "retry_of": previous.get("attempt_ref"),
        }
    return {
        "decision": "skip",
        "reason_code": "duplicate_query_same_verification_and_evidence_scope",
        "attempt_ref": previous.get("attempt_ref"),
    }


def sql_absence_scope(hypothesis: Hypothesis, sql: str) -> tuple[str, list[str] | None]:
    """Certify the small case-wide EVTX scope represented by current Coverage.

    SQL safety/schema validation belongs to the planner. For negative evidence
    we additionally require a direct lookup of exactly the declared event IDs,
    with no joins, host/time/keyword narrowing, sampling, offset, or derived
    rows. Only column projections and an ordinary positive row limit qualify.
    More complex scopes remain unknown; executing a valid SELECT alone is not
    proof of their observability. This is a conservative recognition rule, not
    a second query planner or a general SQL equivalence engine.
    """
    spec = hypothesis.verification_spec
    if spec is None or spec.scope or spec.correlation:
        return "unknown", None
    declared = spec.support_conditions.get("co_observed_event_ids") or []
    try:
        required_ids = {int(value) for value in declared}
        tree = sqlglot.parse_one(sql, read="duckdb")
    except TypeError, ValueError, sqlglot.errors.ParseError:
        return "unknown", None
    if not required_ids or not isinstance(tree, exp.Select):
        return "unknown", None
    if any(
        not isinstance(column.unalias(), (exp.Column, exp.Star))
        for column in tree.expressions
    ):
        return "unknown", None
    limit = tree.args.get("limit")
    if limit and limit.args.get("limit_options"):
        return "unknown", None
    tables = list(tree.find_all(exp.Table))
    if (
        len(tables) != 1
        or tables[0].name.lower() != "evtx_events"
        or tables[0].db
        or tables[0].catalog
        or len(list(tree.find_all(exp.Select))) != 1
        or any(
            tree.args.get(key)
            for key in (
                "with_",
                "joins",
                "offset",
                "group",
                "having",
                "qualify",
                "sample",
            )
        )
        or any(tables[0].args.get(key) for key in ("sample", "pivots"))
    ):
        return "unknown", None
    where = tree.args.get("where")
    predicate = where.this if where else None
    while isinstance(predicate, exp.Paren):
        predicate = predicate.this
    if isinstance(predicate, exp.EQ):
        column, values = predicate.this, [predicate.expression]
    elif isinstance(predicate, exp.In) and not predicate.args.get("query"):
        column, values = predicate.this, predicate.expressions
    else:
        return "unknown", None
    if not isinstance(column, exp.Column) or column.name.lower() != "event_id":
        return "unknown", None
    if any(
        not isinstance(value, exp.Literal) or not value.this.isdigit()
        for value in values
    ):
        return "unknown", None
    if {int(value.this) for value in values} != required_ids:
        return "unknown", None
    return "valid", ["evtx"]


def resolve_zero_row_fallbacks(
    db: CaseDB,
    hypothesis: Hypothesis,
    planned_query: Any,
    rows: list[Any],
) -> tuple[list[Any], dict[str, Any] | None]:
    """Run the existing rule/event fallbacks after a zero-row primary query."""

    fallback_info = None
    if len(rows) == 0 and hypothesis.source_rule_ids:
        for source_rule_id in hypothesis.source_rule_ids:
            rule = load_rule_by_id(source_rule_id)
            if rule and rule.fallback_search:
                for fallback in rule.fallback_search:
                    if not isinstance(fallback, dict):
                        continue
                    phase = fallback.get("phase")
                    if phase not in {
                        "keyword_in_raw_json",
                        "related_event_ids",
                        "artifact_table",
                    }:
                        continue
                    fallback_rows = execute_fallback_search(db, fallback)
                    if not fallback_rows:
                        continue
                    _log(
                        "FALLBACK",
                        f"{hypothesis.id} — found {len(fallback_rows)} rows via {phase}",
                    )
                    for row in fallback_rows[:20]:
                        if isinstance(row, dict):
                            row["_fallback_phase"] = phase
                            row["_fallback_source_rule_id"] = source_rule_id
                    rows = fallback_rows[:20]
                    fallback_info = {
                        "phase": phase,
                        "source_rule_id": source_rule_id,
                        "original_row_count": len(fallback_rows),
                        "row_limit": 20,
                        "truncated": len(fallback_rows) > 20,
                    }
                    break
                if fallback_info:
                    break
    if len(rows) == 0 and fallback_info is None:
        fallback_rows, fallback_meta = execute_event_keyword_fallback_search(
            db, planned_query.sql
        )
        if fallback_rows:
            _log(
                "FALLBACK",
                f"{hypothesis.id} — found {len(fallback_rows)} rows via keyword_in_raw_json"
                + (
                    f" event_ids={fallback_meta.get('event_ids', [])} "
                    f"keywords={fallback_meta.get('keywords', [])}"
                    if fallback_meta
                    else ""
                ),
            )
            for row in fallback_rows[:20]:
                if isinstance(row, dict):
                    row["_fallback_phase"] = "keyword_in_raw_json"
                    row["_fallback_source_rule_id"] = "event_id_schema"
            rows = fallback_rows[:20]
            fallback_info = fallback_meta or {
                "phase": "keyword_in_raw_json",
                "source_rule_id": "event_id_schema",
            }
            fallback_info["query_sql"] = planned_query.sql
            fallback_info["original_row_count"] = len(fallback_rows)
            fallback_info["row_limit"] = 20
            fallback_info["truncated"] = len(fallback_rows) > 20
    return rows, fallback_info


def _row_source_refs(rows: list[dict[str, Any]]) -> set[str]:
    refs = {
        str(row.get(key)).strip()
        for row in rows
        for key in ("source_id", "source_file")
        if row.get(key)
    }
    for row in rows:
        source_ids = row.get("source_ids")
        if isinstance(source_ids, str):
            try:
                source_ids = json.loads(source_ids)
            except TypeError, ValueError:
                source_ids = None
        if isinstance(source_ids, (list, tuple, set)):
            refs.update(str(item).strip() for item in source_ids if item)
    return refs


def build_sql_receipt(
    *,
    db: CaseDB,
    session_id: str,
    plan_cycle: int,
    query_index: int,
    hypothesis: Hypothesis,
    planned_query: Any,
    query_hash: str,
    duration_ms: float,
    rows: list[dict[str, Any]] | None,
    original_row_count: int | None,
    fallback_info: dict[str, Any] | None = None,
    error: str | None = None,
    validator_info: dict[str, Any] | None = None,
) -> ToolReceipt:
    """Build a deterministic receipt from values observed by the runner.

    The SQL execution is pure host work: it is recorded as a deterministic op
    (never LLM work) and the receipt carries stable evidence/finding references,
    a continuation handle for the same line of investigation, and the host
    validator reason when validation constrained the query.
    """

    is_error = error is not None
    used_fallback = fallback_info is not None
    result_summary = rows if rows is not None else []
    evidence_ids = [
        str(row.get("evidence_id") or row.get("artifact_id"))
        for row in result_summary
        if row.get("evidence_id") or row.get("artifact_id")
    ]
    finding_ids = [
        str(row.get("finding_id")) for row in result_summary if row.get("finding_id")
    ]
    source_refs = _row_source_refs(result_summary)
    derivation_refs = {
        str(row.get(key)).strip()
        for row in result_summary
        for key in ("derivation_group", "derivation_source")
        if row.get(key)
    }
    continuation_handle = f"sql:{session_id}:{hypothesis.id}:{query_hash}"
    receipt_id = f"receipt-{session_id}-{plan_cycle}-{query_index}-{query_hash}"

    tel = get_active_telemetry()
    if tel is not None:
        try:
            tel.record_deterministic_op(
                phase="do",
                op_type="query",
                target="sql.query",
                session_id=session_id,
                hypothesis_id=hypothesis.id,
                duration_ms=int(round(duration_ms))
                if duration_ms is not None
                else None,
                note="host-executed SELECT",
            )
        except Exception:
            # Telemetry must never break the deterministic execution path.
            pass

    if is_error:
        status = "error"
        reason = error[:500] if error else None
        returned_count = sampled_count = truncated = None
        retry_hints = ["repair or pivot the SQL after reviewing the execution error"]
    elif used_fallback:
        fallback_row_count = fallback_info.get("original_row_count")
        status = "partial"
        reason = "bounded fallback result after empty primary query"
        returned_count = len(result_summary)
        sampled_count = min(len(result_summary), 10)
        truncated = bool(
            fallback_info.get("truncated")
            or (
                fallback_row_count is not None
                and int(fallback_row_count) > len(result_summary)
            )
        )
        retry_hints = [
            "inspect fallback provenance and verify Coverage before interpreting result"
        ]
    else:
        status = "empty" if not result_summary else "ok"
        reason = "no rows returned" if not result_summary else None
        returned_count = len(result_summary)
        sampled_count = None
        truncated = False
        retry_hints = (
            ["pivot retrieval or verify Coverage before interpreting empty results"]
            if not result_summary
            else []
        )
    return ToolReceipt(
        receipt_id=receipt_id,
        call_id=planned_query.query_id,
        session_id=session_id,
        hypothesis_id=hypothesis.id,
        phase="do",
        tool_id="sql.query",
        arguments={
            "query_id": planned_query.query_id,
            "test_intent": planned_query.test_intent,
            "template_id": planned_query.template_id,
            "params": planned_query.params,
            "normalized_sql": planned_query.sql,
            "original_returned_count": original_row_count,
            "fallback_row_count": fallback_info.get("original_row_count")
            if fallback_info
            else None,
            "fallback": fallback_info,
            "validator": validator_info or {},
            "continuation_handle": continuation_handle,
        },
        preconditions={
            "sql_validation": "planner_observed",
            "dry_run": "planner_observed",
        },
        coverage_snapshot=coverage_snapshot(db),
        query_hash=query_hash,
        cache={"status": "not_applicable"},
        duration_ms=round(duration_ms, 3),
        returned_count=returned_count,
        sampled_count=sampled_count,
        truncated=truncated,
        result_refs={
            "evidence_ids": evidence_ids,
            "finding_ids": finding_ids,
            "hypothesis_ids": [],
        },
        contributor_sources=sorted(source_refs),
        derivation_sources=sorted(derivation_refs),
        status=status,
        reason=reason,
        retry_hints=retry_hints,
        fingerprint=query_hash,
    )


def build_receipt_step_payload(
    receipt: ToolReceipt,
    evaluation: Any,
    result_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose trace JSON without adding assessment or verdict semantics.

    Surfaces the stable continuation handle and the host validator reason so the
    next planning step can resume the same investigation line without re-asking
    the model for facts the host already validated.
    """

    validator_info = receipt.arguments.get("validator") or {}
    continuation_handle = receipt.arguments.get("continuation_handle")
    return {
        **(result_summary or {}),
        "tool_receipt": receipt.model_dump(mode="json"),
        "retrieval_evaluation": evaluation.model_dump(mode="json"),
        "continuation_handle": continuation_handle,
        "validator_reason": validator_info.get("reason"),
    }
