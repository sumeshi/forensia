"""Hypothesis query planning: one SQL decision plus deterministic host validation."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

import duckdb
from pydantic import ValidationError

from forensia.context.case_profile import CaseEvidenceProfile
from forensia.context.prompt_context import (
    _build_schema_guidance,
)
from forensia.context.sql_templates import (
    MAX_SQL_ROWS,
    query_referenced_tables,
    query_template_catalog_for_tables,
    render_query_template,
    validate_select_sql,
    validate_select_sql_with_dryrun,
)
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import canonical_record_table
from forensia.evidence.links import verification_spec_fingerprint
from forensia.investigation.hypotheses.execution import (
    _evidence_scope_fingerprint,
    _repeat_gate_decision,
)
from forensia.investigation.hypotheses.hypothesis_store import load_hypothesis_attempts
from forensia.investigation.progress import query_fingerprint
from forensia.investigation.prompts import (
    build_gap_discovery_messages,
    build_query_intent_messages,
)
from forensia.investigation.verification.assessment import _observation_value_matches
from forensia.knowledge.coverage import (
    derive_required_capabilities,
    disclosure_tables_for_spec,
    load_artifact_capabilities,
    observation_catalog,
    observation_condition_error,
)
from forensia.knowledge.questions import (
    extract_time_qualifiers,
    normalize_directory_scope,
    question_requests_local_time,
    question_requests_utc,
    question_scope_evidence_ids,
    question_scope_sql_predicate,
    strip_section_instructions,
    validate_question_scope_operator,
)
from forensia.llm import json_response
from forensia.llm.schemas import (
    QUERY_INTENT_SCHEMA,
    QueryIntentResponse,
    QuestionRequestContract,
    QuestionRequirement,
    QuestionScopeFilter,
    SQLQueryAction,
    query_intent_schema_for_catalog,
)

logger = logging.getLogger(__name__)


def normalize_query_intent_action(
    payload: dict[str, Any],
) -> tuple[SQLQueryAction | None, str | None]:
    """Validate the single action envelope emitted by the current planner."""
    if not isinstance(payload, dict):
        return None, "action payload is not an object"

    try:
        action = QueryIntentResponse.model_validate(payload).action
    except ValidationError as exc:
        errors = exc.errors(include_url=False, include_input=False)
        return None, "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'action'}: "
            f"{error['type']} — {error['msg']}"
            for error in errors[:3]
        )[:500]

    return action, None


def _materialize_planned_query(
    payload: dict[str, Any],
    db: CaseDB | None = None,
    eligible_tables: tuple[str, ...] | None = None,
) -> PlannedQuery:
    planned_query = PlannedQuery.model_validate(payload)
    tid = planned_query.template_id
    if tid:
        planned_query.sql = render_query_template(tid, planned_query.params)
    else:
        planned_query.sql = validate_select_sql(planned_query.sql)
    used_tables = query_referenced_tables(planned_query.sql)
    target = str(payload.get("target_table") or "").casefold()
    if target not in used_tables:
        raise ValueError("target_table must name a table used by the query")
    if eligible_tables is not None:
        allowed = {str(table).casefold() for table in eligible_tables}
        if not used_tables or not used_tables <= allowed:
            rejected = ", ".join(sorted(used_tables - allowed)) or "no artifact table"
            raise ValueError(
                f"query table is outside this work's eligible catalog: {rejected}"
            )
    if db is not None:
        planned_query.sql = validate_select_sql_with_dryrun(planned_query.sql, db)
    return planned_query


def _typed_observation_query(
    *,
    hypothesis: Hypothesis,
    spec_payload: dict[str, Any] | None,
    query_index: int,
    db: CaseDB | None,
) -> PlannedQuery | None:
    """Build the first bounded query directly from an admitted typed observation."""
    if query_index != 1 or not isinstance(spec_payload, dict):
        return None
    conditions = spec_payload.get("support_conditions") or {}
    observation = (
        conditions.get("observation") if isinstance(conditions, dict) else None
    )
    if observation is None:
        return None
    if (
        observation_condition_error(conditions)
        or spec_payload.get("scope")
        or spec_payload.get("correlation")
    ):
        return None
    family = str(observation["family"]).strip().lower()
    capability = str(observation["capability"]).strip()
    field = str(observation["field"]).strip()
    operator = str(observation["operator"]).strip()
    expected = observation["value"]
    table = canonical_record_table(family)
    catalog = observation_catalog().get(family)
    if not table or not catalog or capability not in catalog["capabilities"]:
        return None
    if field not in catalog["fields"]:
        return None

    if db is None:
        return None
    id_column = "artifact_id" if family == "registry" else "evidence_id"
    matching_ids: list[str] = []
    targets = observation.get("evidence_ids") or []
    target_filter = (
        f" WHERE {id_column} IN ({', '.join('?' for _ in targets)})" if targets else ""
    )
    cursor = db.execute(
        f"SELECT {id_column}, {field} FROM {table}{target_filter} ORDER BY {id_column}",
        targets,
    )
    while batch := cursor.fetchmany(512):
        for evidence_id, value in batch:
            if _observation_value_matches(value, operator, expected):
                matching_ids.append(str(evidence_id))
                if len(matching_ids) == MAX_SQL_ROWS:
                    break
        if len(matching_ids) == MAX_SQL_ROWS:
            break
    id_filter = ", ".join(
        "'" + evidence_id.replace("'", "''") + "'" for evidence_id in matching_ids
    )
    predicate = f"{id_column} IN ({id_filter})" if matching_ids else "FALSE"
    sql = (
        f"SELECT {id_column} AS evidence_id FROM {table} WHERE {predicate} "
        f"ORDER BY {id_column} LIMIT {MAX_SQL_ROWS}"
    )
    return PlannedQuery(
        query_id=f"{hypothesis.id}-q{query_index}",
        hypothesis_id=hypothesis.id,
        purpose=(
            f"primary verification: {family}.{field} "
            f"{observation['operator']} {observation['value']}"
        ),
        sql=sql,
        test_intent="primary_verification",
    )


@dataclass(slots=True)
class _QueryIntentResult:
    """Keep host validation and selected context separate from raw model output."""

    action: SQLQueryAction | None
    raw_response: dict[str, Any]
    error: str | None = None


@dataclass(slots=True)
class HypothesisPlanResult:
    query: PlannedQuery | None
    stop_reason: str | None
    raw_response: dict[str, Any]
    #: Deterministic disclosure this planner attempt adopted (V2-08): selected
    #: schema cards, playbook artifact tables, and executable template ids.
    #: Knowledge sections are recorded per prompt in the Trace retrieval
    #: events; this rides the existing plan step payload.
    disclosure: dict[str, Any] | None = None
    test_intent: str | None = None


def _eligible_planner_tables(
    spec_payload: dict[str, Any] | None,
    disclosed_tables: tuple[str, ...],
    *,
    include_corroboration: bool,
) -> tuple[str, ...] | None:
    if not isinstance(spec_payload, dict):
        return None
    support_conditions = spec_payload.get("support_conditions") or {}
    if not disclosed_tables and not (
        spec_payload.get("required_capabilities") or support_conditions
    ):
        return None
    tables = dict.fromkeys(disclosed_tables)
    if include_corroboration:
        capabilities = derive_required_capabilities(
            list(spec_payload.get("required_capabilities") or []), support_conditions
        )
        catalog = load_artifact_capabilities()
        families = catalog.get("families") or {}
        for capability in capabilities:
            cross = (catalog.get("cross_artifact_corroboration") or {}).get(
                capability, {}
            )
            for family in cross.get("preferred_families") or []:
                for table in (families.get(family) or {}).get("tables") or []:
                    tables.setdefault(str(table), None)
    return tuple(tables)


def persist_hypothesis_plan_result(
    *,
    db: CaseDB,
    session_id: str,
    iteration: int,
    hypothesis: Hypothesis,
    query_index: int,
    plan: HypothesisPlanResult,
    state: SessionState,
    attempt_number: int = 1,
    correction_budget: list[int] | None = None,
    emit: Callable[..., None] | None = None,
) -> str:
    """Persist query planning without changing the admitted hypothesis."""
    from forensia.investigation.investigation_session import (
        _save_step,
        append_hypothesis_reasoning,
    )
    from forensia.investigation.work_judgment import work_progress_snapshot

    work = work_progress_snapshot(db, hypothesis.id)
    retry_available = bool(
        plan.stop_reason
        and plan.stop_reason.startswith("invalid_action:")
        and correction_budget is not None
        and correction_budget[0] > 0
    )
    step_suffix = f"{hypothesis.id}-{query_index:02d}-{attempt_number:02d}"
    step_id = f"{session_id}-{iteration:02d}-plan-hypothesis-{step_suffix}"
    output = dict(plan.raw_response)
    output["_plan_status"] = {
        "query_materialized": plan.query is not None,
        "stop_reason": plan.stop_reason,
        "retry_available": retry_available,
        "work_identity": work["identity"] if work is not None else None,
        "test_intent": (
            plan.query.test_intent
            if plan.query is not None
            else plan.test_intent or plan.raw_response.get("test_intent")
        ),
    }
    if plan.disclosure is not None:
        output["_disclosure"] = plan.disclosure
    _save_step(
        db=db,
        session_id=session_id,
        iteration=iteration,
        phase="plan-hypothesis",
        hypothesis_id=hypothesis.id,
        input_json={
            "hypothesis": hypothesis.model_dump(),
            "query_index": query_index,
            "attempt_number": attempt_number,
        },
        output_json=output,
        suffix=step_suffix,
    )
    if plan.query:
        return "ok"
    if not plan.stop_reason:
        return "break"
    reason = str(plan.stop_reason)
    append_hypothesis_reasoning(
        db=db,
        hypothesis_id=hypothesis.id,
        session_id=session_id,
        iteration=iteration,
        phase="plan",
        body=f"[planner-validation] {reason}",
    )
    # This is consumed by the next query-intent call; no SQL ran here.
    state.last_planner_error = {
        "hypothesis_id": hypothesis.id,
        "reason": reason[:500],
        "step_id": step_id,
        "rejected_action": json.dumps(
            plan.raw_response, ensure_ascii=False, default=str
        )[:500],
    }
    if emit:
        emit(
            "investigate/plan",
            f"[plan] planner rejected {hypothesis.id}: {reason}",
            iteration=iteration,
            kind="hypothesis.plan_rejected",
            status="failed",
            severity="error" if reason == "planner_failed" else "warning",
            reason="planner_validation_failed"
            if reason.startswith("invalid_action:")
            else reason.split(":", 1)[0],
            hypothesis_id=hypothesis.id,
            step_id=step_id,
        )
    logger.warning("%s planner validation rejected the plan: %s", hypothesis.id, reason)
    return "continue" if retry_available else "break"


def request_query_intent(
    messages: list[dict[str, str]],
    *,
    base_url: str,
    model: str,
    status_callback: Callable[[str], None] | None = None,
    json_schema: dict[str, Any] = QUERY_INTENT_SCHEMA,
    correction_budget: list[int] | None = None,
) -> _QueryIntentResult:
    """Make one bounded query decision from the supplied Case/Trace context."""
    parsed = json_response.request_llm_json(
        messages=messages,
        model=model,
        base_url=base_url,
        json_schema=json_schema,
        telemetry_phase="hypothesis-plan",
        status_callback=status_callback,
        correction_budget=correction_budget,
    )
    action, error = normalize_query_intent_action(parsed)
    return _QueryIntentResult(action, parsed, error)


def discover_gap_evidence(
    question: str,
    *,
    db: CaseDB,
    base_url: str,
    model: str,
    case_policy: Any | None = None,
    status_callback: Callable[[str], None] | None = None,
    correction_budget: list[int],
    feedback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Retrieve candidate evidence before a question has a verification claim."""
    import sqlglot
    from sqlglot import exp

    from forensia.context.sql_templates import bounded_select_sql
    from forensia.db.evidence_lookup import fetch_evidence_records, routed_family
    from forensia.db.query import fetch_bounded_records
    from forensia.db.schema import load_live_schema

    live_schema = load_live_schema(db)
    catalog = observation_catalog()
    tables = [
        table
        for family in catalog
        if (table := canonical_record_table(family)) in live_schema
        and db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
    ]
    if not tables:
        return {"status": "no_evidence", "reason": "discovery_no_available_records"}
    question_fields = {
        family: catalog[family]["fields"]
        for family in catalog
        if canonical_record_table(family) in tables
    }
    fixed_contract_retry = (
        isinstance(feedback, dict) and feedback.get("contract_validated") is True
    )
    fixed_contract = None
    fixed_contract_payload = None
    fixed_contract_id = None
    if fixed_contract_retry:
        try:
            fixed_contract = QuestionRequestContract.model_validate(
                feedback.get("request_contract")
            )
        except ValidationError as exc:
            return {
                "status": "invalid",
                "reason": f"verified_question_contract_invalid: {str(exc)[:300]}",
                "contract_validated": False,
            }
        if fixed_contract.status != "resolved":
            fixed_contract_payload = fixed_contract.model_dump(mode="json")
            return {
                "status": "invalid",
                "reason": "verified_question_contract_not_resolved",
                "request_contract": fixed_contract_payload,
                "contract_validated": False,
            }
        fixed_contract_payload = fixed_contract.model_dump(mode="json")
        fixed_contract_id = hashlib.sha256(
            json.dumps(
                fixed_contract_payload, sort_keys=True, ensure_ascii=False
            ).encode()
        ).hexdigest()
    messages = build_gap_discovery_messages(
        question,
        schema_context=_build_schema_guidance(tables, db=db),
        request_catalog=question_fields,
        case_policy=case_policy,
        feedback=feedback,
    )
    result = request_query_intent(
        messages,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        json_schema=query_intent_schema_for_catalog(
            tables, [], require_request_contract=not fixed_contract_retry
        ),
        correction_budget=correction_budget,
    )
    receipt: dict[str, Any] = {"response": result.raw_response}
    if fixed_contract_retry:
        receipt.update(
            request_contract=fixed_contract_payload,
            contract_id=fixed_contract_id,
            contract_validated=True,
        )
    try:
        if result.error or result.action is None:
            raise ValueError(result.error or "SQL action was not selected")
        if fixed_contract_retry:
            contract = fixed_contract
            contract_payload = fixed_contract_payload
            if "request_contract" in result.raw_response:
                raise ValueError("request_contract_returned_during_action_only_retry")
        else:
            raw_contract = result.raw_response.get("request_contract")
            contract = QuestionRequestContract.model_validate(raw_contract)
            contract_payload = contract.model_dump(mode="json")
            receipt.update(
                request_contract=contract_payload,
                contract_id=hashlib.sha256(
                    json.dumps(
                        contract_payload, sort_keys=True, ensure_ascii=False
                    ).encode()
                ).hexdigest(),
                contract_validated=False,
            )
            if contract.status == "unresolved":
                return receipt | {
                    "status": "unresolved",
                    "reason": "question_scope_unresolved",
                }
        _validate_question_request_contract(
            contract, tables, strip_section_instructions(question), db
        )
        try:
            canonical_scope_ids, canonical_scope_truncated = (
                _canonical_question_scope_ids(db, contract)
            )
        except (
            duckdb.ProgrammingError,
            duckdb.DataError,
            duckdb.NotSupportedError,
        ) as exc:
            raise ValueError(
                f"question_scope_invalid_query: {str(exc).splitlines()[0][:300]}"
            ) from exc
        receipt["contract_validated"] = True
        action = result.action
        if fixed_contract_retry:
            contract_families = {
                item["family"].strip().lower()
                for item in [
                    *contract_payload["scope_filters"],
                    *contract_payload["requirements"],
                ]
            }
            contract_table = (
                canonical_record_table(next(iter(contract_families)))
                if len(contract_families) == 1
                else None
            )
            if (
                not contract_table
                or contract_table.casefold() != action.target_table.casefold()
            ):
                raise ValueError("request_contract_family_changed_during_sql_retry")
        query = _materialize_planned_query(
            {
                "query_id": "discovery",
                "hypothesis_id": "",
                "purpose": action.intent,
                "target_table": action.target_table,
                "sql": action.sql,
                "template_id": action.template_id,
                "params": action.params,
            },
            db,
            tuple(tables),
        )
        receipt["proposed_sql"] = query.sql
        tree = sqlglot.parse_one(query.sql, read="duckdb")
        tree = _apply_question_scope_filters(
            tree, contract, canonical_record_table, sqlglot.exp, db=db
        )
        query.sql = validate_select_sql_with_dryrun(tree.sql(dialect="duckdb"), db)
        source = tree.args.get("from_")
        source = source.this if source is not None else None
        canonical_id = (
            "artifact_id"
            if action.target_table == "registry_artifacts"
            else "evidence_id"
        )
        identity_column = None
        # A plain row SELECT retains its rows/order when a canonical ID is appended.
        if (
            isinstance(tree, exp.Select)
            and isinstance(source, exp.Table)
            and source.name.casefold() == action.target_table.casefold()
            and not any(
                tree.args.get(key)
                for key in ("distinct", "group", "having", "joins", "with_", "qualify")
            )
            and not any(
                tree.find_all(exp.AggFunc, exp.Window, exp.Subquery, exp.Unnest)
            )
        ):
            identity_column = "_forensia_evidence_id"
            if identity_column in tree.named_selects:
                raise ValueError("Discovery uses a reserved identity column")
            tree = tree.select(
                exp.alias_(
                    exp.column(canonical_id, table=source.alias_or_name),
                    identity_column,
                ),
                append=True,
            )
            query.sql = validate_select_sql_with_dryrun(tree.sql(dialect="duckdb"), db)
        receipt["sql"] = query.sql
        if (
            isinstance(feedback, dict)
            and feedback.get("status") == "empty"
            and feedback.get("contract_validated") is True
            and feedback.get("sql")
        ):
            try:
                previous_sql = sqlglot.parse_one(feedback["sql"], read="duckdb").sql(
                    dialect="duckdb", comments=False, normalize=True
                )
            except sqlglot.errors.ParseError:
                previous_sql = None
            if previous_sql == sqlglot.parse_one(query.sql, read="duckdb").sql(
                dialect="duckdb", comments=False, normalize=True
            ):
                return receipt | {
                    "status": "empty",
                    "reason": "discovery_repeated_empty_query",
                    "row_count": feedback.get("row_count", 0),
                    "repeated_query": True,
                }
        try:
            rows, truncated = fetch_bounded_records(
                db, bounded_select_sql(query.sql), max_rows=MAX_SQL_ROWS
            )
        except (
            duckdb.ProgrammingError,
            duckdb.DataError,
            duckdb.NotSupportedError,
        ) as exc:
            raise ValueError(str(exc).splitlines()[0]) from exc
        identifiers = [
            row.get(identity_column)
            if identity_column
            else row.get("evidence_id") or row.get("artifact_id")
            for row in rows
        ]
        ids = list(dict.fromkeys(str(value) for value in identifiers if value))
        records = fetch_evidence_records(db, ids)
        receipt.update(
            row_count=len(rows),
            truncated=truncated,
            evidence_ids=list(records),
            canonical_scope_evidence_ids=canonical_scope_ids,
            canonical_scope_truncated=canonical_scope_truncated,
        )
        if not rows:
            return receipt | {
                "status": "empty",
                "reason": "discovery_no_matching_records",
            }
        if not all(identifiers) or len(records) != len(ids):
            raise ValueError(
                "Discovery must return existing evidence_id or artifact_id values"
            )
        # Discovery rows only nominate candidates; canonical records supply their values.
        for eid in records:
            records[eid]["source_family"] = routed_family(eid)
        # The scope list is a capped receipt sample, so check candidates against DuckDB.
        candidate_scope_ids, _ = question_scope_evidence_ids(
            db,
            contract.model_dump(mode="json"),
            max_rows=MAX_SQL_ROWS,
            evidence_ids=ids,
        )
        canonical_id_set = set(candidate_scope_ids)
        evidence = [
            records[eid] for eid in ids if eid in canonical_id_set and eid in records
        ]
        scoped_ids = [str(record["evidence_id"]) for record in evidence]
        receipt["scoped_evidence_ids"] = scoped_ids
        receipt["omitted_scoped_evidence_count"] = max(0, len(scoped_ids) - 3)
        evidence = evidence[:3]
        if not evidence:
            return receipt | {
                "status": "empty",
                "reason": "discovery_no_scope_matching_records",
            }
        receipt.update(
            sampled_count=len(evidence),
            omitted_evidence_count=len(records) - len(evidence),
        )
        families = {routed_family(row["evidence_id"]) for row in evidence}
        return receipt | {
            "status": "completed",
            "candidate": {
                "title": question,
                "summary": "Search results are leads, not proof of the whole question.",
                "scope": {
                    "source_family": next(iter(families)) if len(families) == 1 else ""
                },
                "evidence": evidence,
                "evidence_ids": [row["evidence_id"] for row in evidence],
                "request_contract": contract_payload,
                "contract_id": receipt["contract_id"],
                "discovery_step_id": "",
            },
        }
    except ValueError as exc:
        return receipt | {
            "status": "invalid",
            "reason": f"discovery_invalid_query: {str(exc)[:300]}",
        }


def _validate_question_request_contract(
    contract: QuestionRequestContract,
    tables: list[str],
    question: str,
    db: CaseDB,
) -> None:
    catalog = observation_catalog()
    allowed_tables = {str(table).casefold() for table in tables}
    for item in [*contract.scope_filters, *contract.requirements]:
        family = item.family.strip().lower()
        fields = catalog.get(family)
        table = canonical_record_table(family)
        if (
            not fields
            or table not in allowed_tables
            or item.field not in fields["fields"]
        ):
            raise ValueError(
                f"request_contract_field_unsupported:{family}.{item.field}"
            )
        if isinstance(item, QuestionScopeFilter):
            validate_question_scope_operator(
                family, item.field, item.operator, item.value
            )
            if item.operator == "greater_than" and isinstance(item.value, bool):
                raise ValueError("request_contract_scope_value_invalid")
            _validate_question_scope_literal(item, question, db)
        elif isinstance(item, QuestionRequirement) and item.kind == "predicate":
            if item.field in fields["boolean_fields"]:
                if item.operator != "equals" or not isinstance(item.value, bool):
                    raise ValueError("request_contract_predicate_value_invalid")
            elif isinstance(item.value, bool):
                raise ValueError("request_contract_predicate_value_invalid")
    families = {
        item.family.strip().lower()
        for item in [*contract.scope_filters, *contract.requirements]
    }
    if len(families) != 1:
        raise ValueError("request_contract_requires_one_artifact_family")


def _validate_question_scope_literal(
    item: QuestionScopeFilter, question: str, db: CaseDB
) -> None:
    """Require string scope values to be stated or implied by explicit time bounds."""
    value = item.value
    if not isinstance(value, str):
        return
    text = question.casefold()
    literal = value.strip()
    if not literal:
        raise ValueError("question_scope_invalid_query: scope_literal_ungrounded")
    if item.operator == "path_under":
        normalized_question = re.sub(
            r"/{2,}", "//", question.replace("\\", "/")
        ).casefold()
        if normalize_directory_scope(literal) not in normalized_question:
            raise ValueError("question_scope_invalid_query: scope_literal_ungrounded")
        return
    column = db.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema = 'main' AND table_name = ? AND column_name = ?",
        [canonical_record_table(item.family), item.field],
    ).fetchone()
    column_type = str(column[0]).upper() if column else ""
    if column_type != "DATE" and "TIMESTAMP" not in column_type:
        if literal.casefold() not in text:
            raise ValueError("question_scope_invalid_query: scope_literal_ungrounded")
        return

    qualifiers = extract_time_qualifiers(question)
    explicit_dates = {d for d in (qualifiers["date_from"], qualifiers["date_to"]) if d}
    timestamp_pattern = (
        r"(?<![\d])\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"
        r"(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
        r"(?![\d:]|\.\d|[+-]\d)"
    )
    question_timestamps = []
    for raw in re.findall(timestamp_pattern, question, re.IGNORECASE):
        try:
            question_timestamps.append(
                datetime.fromisoformat(
                    raw.replace("z", "+00:00").replace("Z", "+00:00")
                )
            )
        except ValueError:
            continue

    aware_scope = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"
        r"(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})",
        literal,
        re.IGNORECASE,
    )
    if aware_scope:
        scoped = datetime.fromisoformat(
            literal.replace("z", "+00:00").replace("Z", "+00:00")
        )
        if any(
            candidate.utcoffset() is not None and candidate == scoped
            for candidate in question_timestamps
        ):
            return
        raise ValueError("question_scope_invalid_query: scope_datetime_ungrounded")

    if (
        column_type != "DATE"
        and "TIMESTAMP" in column_type
        and question_requests_local_time(question)
        and not question_requests_utc(question)
    ):
        raise ValueError("question_scope_invalid_query: scope_time_basis_unresolved")

    naive_scope = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}"
        r"(?::\d{2}(?:\.\d+)?)?",
        literal,
        re.IGNORECASE,
    )
    if naive_scope:
        scoped = datetime.fromisoformat(literal.replace(" ", "T"))
        if any(
            candidate.utcoffset() is None and candidate == scoped
            for candidate in question_timestamps
        ):
            return
    date_match = re.search(r"\d{4}-\d{2}-\d{2}", literal)
    if date_match is None:
        raise ValueError("question_scope_invalid_query: scope_datetime_ungrounded")
    scoped_date = date_match.group()
    date_grounded = scoped_date in explicit_dates
    if not date_grounded and item.operator == "less_than" and explicit_dates:
        try:
            date_grounded = (
                scoped_date
                == (
                    date.fromisoformat(max(explicit_dates)) + timedelta(days=1)
                ).isoformat()
            )
        except ValueError:
            pass
    if not date_grounded:
        raise ValueError("question_scope_invalid_query: scope_literal_ungrounded")

    # A timestamp inferred from a date/hour range must match the stated boundary.
    scoped_dt_match = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?",
        literal,
        re.IGNORECASE,
    )
    if scoped_dt_match:
        qualifiers = extract_time_qualifiers(question)
        scoped_date = scoped_dt_match.group()[:10]
        scoped_time = scoped_dt_match.group().split("T")[-1].split(" ")[-1]
        next_day_end = False
        if explicit_dates:
            try:
                next_day_end = (
                    scoped_date
                    == (
                        date.fromisoformat(max(explicit_dates)) + timedelta(days=1)
                    ).isoformat()
                )
            except ValueError:
                pass
        is_midnight = bool(re.fullmatch(r"00:00(?::00(?:\.0+)?)?", scoped_time))
        if is_midnight and (
            (item.operator == "greater_than" and scoped_date == qualifiers["date_from"])
            or (item.operator == "less_than" and next_day_end)
        ):
            return
        scope_clock = datetime.fromisoformat(
            scoped_dt_match.group().replace(" ", "T")
        ).time()
        if (
            scope_clock.second != 0
            or scope_clock.microsecond != 0
            or scoped_time[:5] not in {qualifiers["hour_from"], qualifiers["hour_to"]}
        ):
            raise ValueError("question_scope_invalid_query: scope_datetime_ungrounded")


def _apply_question_scope_filters(
    tree: Any,
    contract: QuestionRequestContract,
    canonical_table: Any,
    exp: Any,
    *,
    db: CaseDB,
) -> Any:
    """Bind literal request scope to discovery SQL before reading any rows."""
    for item in contract.scope_filters:
        table_name = canonical_table(item.family)
        matches = [
            table
            for table in tree.find_all(exp.Table)
            if table.name.casefold() == str(table_name).casefold()
        ]
        if len(matches) != 1:
            raise ValueError(f"request_contract_scope_table_ambiguous:{item.family}")
        column = exp.column(item.field, table=matches[0].alias_or_name)
        tree = tree.where(
            question_scope_sql_predicate(
                db,
                item.family,
                item.field,
                item.operator,
                item.value,
                column,
            ),
            append=True,
        )
    return tree


def _canonical_question_scope_ids(
    db: CaseDB, contract: QuestionRequestContract
) -> tuple[list[str], bool]:
    return question_scope_evidence_ids(
        db, contract.model_dump(mode="json"), max_rows=MAX_SQL_ROWS
    )


def _compute_uncovered_keypoints(
    observed: list[str],
    active: list[Hypothesis],
    resolved: list[Hypothesis],
) -> list[dict[str, str]]:
    """Compute uncovered keypoints using round-robin across families.

    A keypoint is considered covered (excluded from output) when:
    - Any active/resolved hypothesis has target_keypoint_id == keypoint name (exact match)
    - It is already targeted by current active/resolved work.

    Remaining candidates are grouped by family (first underscore token) and
    selected round-robin across families up to 8 items.
    """
    if not observed:
        return []

    covered: set[str] = set()
    for hyp in list(active) + list(resolved):
        if hyp.target_keypoint_id:
            covered.add(hyp.target_keypoint_id.strip().lower())

    groups: dict[str, list[str]] = {}
    for item in observed:
        name = (
            item.split(" (")[0].strip().lower()
            if " (" in item
            else item.strip().lower()
        )
        if not name or name in covered:
            continue
        family = name.split("_")[0] if "_" in name else name
        groups.setdefault(family, []).append(name)

    result: list[dict[str, str]] = []
    families = sorted(groups.keys())
    indices = {f: 0 for f in families}
    while len(result) < 8 and families:
        advanced = False
        for family in families:
            if indices[family] < len(groups[family]):
                advanced = True
                result.append({"name": groups[family][indices[family]]})
                indices[family] += 1
                if len(result) >= 8:
                    break
        if not advanced:
            break
    return result


def _build_hypothesis_history(
    state: SessionState,
    hypothesis: Hypothesis,
    db: CaseDB | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Build chronological attempt history without deduplicating display IDs."""
    if db is not None:
        attempts = load_hypothesis_attempts(db, hypothesis.id)
        return attempts[-limit:] if limit > 0 else attempts
    return [
        item.model_dump()
        for item in state.history
        if item.hypothesis_id == hypothesis.id
    ][-limit:]


def _build_working_state_block(db: CaseDB | None, hypothesis_id: str) -> str:
    """Build the current bounded Case/Trace prompt block on demand."""
    if db is None or not hypothesis_id:
        return ""
    from forensia.investigation.working_state import (
        build_working_state,
        render_working_state,
    )

    return render_working_state(build_working_state(db, hypothesis_id=hypothesis_id))


def _load_prior_check_feedback(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Summarize recent sufficiency/settlement gate feedback for this hypothesis.

    Free text is a supplement only — the structured attempt history
    (``<PRIOR_ATTEMPTS>`` in the intent prompt) carries the signal, including
    the per-check reasoning bodies.  This feedback therefore reads only the
    gate phases that ``<PRIOR_ATTEMPTS>`` does not already show, so the same
    Trace reasoning row is not delivered through two prompt layers (V2-07).
    """
    if db is None or not hypothesis.id:
        return ""
    recent_checks = db.execute(
        """
        SELECT phase, body FROM (
            SELECT phase, body, created_at, entry_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY phase ORDER BY created_at DESC, entry_id DESC
                   ) AS phase_rank
            FROM trace.hypothesis_reasoning
            WHERE hypothesis_id = ?
              AND phase IN ('sufficiency', 'settlement')
        ) recent
        WHERE phase_rank = 1
        ORDER BY created_at DESC, entry_id DESC
    """,
        (hypothesis.id,),
    ).fetchall()
    if not recent_checks:
        return ""
    return "\n".join(
        f"- [{str(row[0] or 'feedback')}] {str(row[1] or '')[:120]}"
        for row in recent_checks
        if str(row[1] or "").strip()
    )


def _consume_execution_error_block(state: SessionState) -> str:
    """Format (and clear) the last SQL execution error as a prompt block."""
    if not state.last_execution_error:
        return ""
    block = (
        f"\n<EXECUTION_ERROR>\n"
        f"The previous SQL failed at execute time. Do NOT repeat the same SQL.\n"
        f"query_id: {state.last_execution_error['query_id']}\n"
        f"failing_sql: {state.last_execution_error['sql']}\n"
        f"error: {state.last_execution_error['error']}\n"
        f"</EXECUTION_ERROR>\n"
    )
    state.last_execution_error = None
    return block


def _consume_planner_error_block(state: SessionState, hypothesis_id: str) -> str:
    """Format and clear host planner validation feedback for the next call."""
    if (
        not state.last_planner_error
        or state.last_planner_error.get("hypothesis_id") != hypothesis_id
    ):
        return ""
    block = (
        f"\n<PLANNER_VALIDATION_ERROR>\n"
        "The previous planner action was rejected by host validation. "
        "Correct the action before trying again; do not repeat the rejected payload.\n"
        f"reason: {state.last_planner_error.get('reason', 'unknown validation error')}\n"
        f"rejected_action: {state.last_planner_error.get('rejected_action', '(not recorded)')}\n"
        "</PLANNER_VALIDATION_ERROR>\n"
    )
    state.last_planner_error = None
    return block


def plan_hypothesis_query(
    state: SessionState,
    hypothesis: Hypothesis,
    base_url: str,
    model: str,
    db: CaseDB | None = None,
    status_callback: Callable[[str], None] | None = None,
    query_index: int = 1,
    time_range: dict[str, str] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
    correction_budget: list[int] | None = None,
) -> HypothesisPlanResult:
    """Plan the next query for a single hypothesis.

    Collapsed to a single SQL decision plus deterministic host validation (T-20):
    the query_intent_planner makes one model decision choosing a recipe
    (template_id+params) or a bounded fallback SELECT; the host then validates
    table/column/SELECT-only/allow-list/row-limit/dry-run before execution.

    The former second "schema-readiness" LLM self-check call was removed."""
    hypothesis_history = _build_hypothesis_history(state, hypothesis, db, limit=10)
    # V2-08 single disclosure pathway: one spec/capability correspondence
    # (the artifact capability catalog shared with Coverage and the work
    # judgment) selects the schema cards, playbook artifact gating, and the
    # executable template subset disclosed in the intent prompt. The db
    # canonical spec is authoritative when a row exists; otherwise the
    # in-session hypothesis spec is used (same contract, admission seam).
    if db is not None and hypothesis.id:
        row = db.execute(
            "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
            [hypothesis.id],
        ).fetchone()
    else:
        row = None
    if row is not None and row[0]:
        spec_payload = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    else:
        spec_obj = getattr(hypothesis, "verification_spec", None)
        spec_payload = (
            spec_obj.model_dump(mode="json") if spec_obj is not None else None
        )
    from forensia.core.verification import VerificationSpec
    from forensia.knowledge.coverage import observation_claim_scope_error

    if spec_payload:
        scope_error = observation_claim_scope_error(
            hypothesis.description, VerificationSpec.model_validate(spec_payload)
        )
        if scope_error:
            return HypothesisPlanResult(
                query=None, raw_response={}, stop_reason=scope_error
            )
    declared_conditions = (
        spec_payload.get("support_conditions")
        if isinstance(spec_payload, dict)
        else None
    )
    if (
        isinstance(declared_conditions, dict)
        and "observation" in declared_conditions
        and (condition_error := observation_condition_error(declared_conditions))
    ):
        return HypothesisPlanResult(
            query=None,
            stop_reason=f"invalid_typed_primary: {condition_error}",
            raw_response={"test_intent": "primary_verification"},
        )
    deterministic_query = _typed_observation_query(
        hypothesis=hypothesis,
        spec_payload=spec_payload,
        query_index=query_index,
        db=db,
    )
    primary_query = deterministic_query
    test_intent = "corroboration" if query_index > 1 else "primary_verification"
    already_attempted = False
    if deterministic_query is not None and db is not None:
        try:
            deterministic_query.sql = validate_select_sql(deterministic_query.sql)
            deterministic_query.sql = validate_select_sql_with_dryrun(
                deterministic_query.sql, db
            )
            query_fp = query_fingerprint(deterministic_query.sql)
            spec_fp = verification_spec_fingerprint(hypothesis.verification_spec)
            scope_fp = _evidence_scope_fingerprint(db, deterministic_query.sql)
            repeat_gate = _repeat_gate_decision(
                db,
                hypothesis,
                query_fp=query_fp,
                verification_fp=spec_fp,
                scope_fp=scope_fp,
            )
            already_attempted = repeat_gate["decision"] == "skip"
        except (ValueError, ValidationError) as exc:
            return HypothesisPlanResult(
                query=None,
                stop_reason=f"invalid_typed_primary: {str(exc).splitlines()[0][:300]}",
                raw_response={"test_intent": "primary_verification"},
            )
        if already_attempted:
            deterministic_query = None
            test_intent = "corroboration"
    _disclosure_tables, _primary_tables = disclosure_tables_for_spec(spec_payload)
    eligible_tables = _eligible_planner_tables(
        spec_payload,
        _disclosure_tables,
        include_corroboration=test_intent == "corroboration",
    )
    if eligible_tables == ():
        return HypothesisPlanResult(
            query=None,
            stop_reason="no_eligible_capability",
            raw_response={"test_intent": test_intent},
            disclosure={"schema_cards": [], "playbook_tables": [], "template_ids": []},
        )
    disclosure_record = {
        "schema_cards": (
            list(eligible_tables)
            if test_intent == "corroboration" and eligible_tables is not None
            else list(_primary_tables)
        )
        or ["evtx_events"],
        "playbook_tables": sorted(eligible_tables or _disclosure_tables) or None,
        "template_ids": [
            entry["template_id"]
            for entry in query_template_catalog_for_tables(
                eligible_tables or _disclosure_tables or ()
            )
        ],
    }
    if deterministic_query is not None:
        return HypothesisPlanResult(
            query=deterministic_query,
            stop_reason=None,
            raw_response={"test_intent": "primary_verification"},
            disclosure={
                "schema_cards": [],
                "playbook_tables": [],
                "template_ids": [],
            },
        )
    schema_tables = (
        list(eligible_tables)
        if test_intent == "corroboration" and eligible_tables is not None
        else list(_primary_tables)
    ) or ["evtx_events"]
    schema_card = _build_schema_guidance(
        schema_tables,
        db=db,
        session_id=state.session_id,
    )
    prior_check_feedback = _load_prior_check_feedback(db, hypothesis)
    working_state_block = _build_working_state_block(db, hypothesis.id)
    execution_error_block = _consume_execution_error_block(state)
    planner_error_block = _consume_planner_error_block(state, hypothesis.id)

    messages = build_query_intent_messages(
        hypothesis=hypothesis,
        recent_history=hypothesis_history,
        active_hypotheses=state.active_hypotheses,
        time_range=time_range or {},
        schema_context=schema_card,
        host_feedback=execution_error_block + planner_error_block,
        prior_check_feedback=prior_check_feedback,
        case_profile=case_profile,
        case_policy=case_policy,
        findings_snapshot=state.findings_snapshot,
        working_state_block=working_state_block,
        db=db,
        session_id=state.session_id,
        spec_payload=spec_payload,
        eligible_tables=eligible_tables,
        test_intent=test_intent,
    )

    intent_response = request_query_intent(
        messages,
        base_url=base_url,
        model=model,
        status_callback=status_callback,
        json_schema=(
            query_intent_schema_for_catalog(
                list(eligible_tables),
                [
                    entry["template_id"]
                    for entry in query_template_catalog_for_tables(eligible_tables)
                ],
            )
            if eligible_tables is not None
            else QUERY_INTENT_SCHEMA
        ),
        correction_budget=correction_budget,
    )
    action = intent_response.action
    error = intent_response.error
    planned_query = None
    if not error and isinstance(action, SQLQueryAction):
        try:
            planned_query = _materialize_planned_query(
                {
                    "query_id": f"{hypothesis.id}-q{query_index}",
                    "hypothesis_id": hypothesis.id,
                    "purpose": action.intent,
                    "target_table": action.target_table,
                    "template_id": action.template_id,
                    "params": action.params,
                    "sql": action.sql,
                    "test_intent": test_intent,
                },
                db,
                eligible_tables,
            )
            if (
                planned_query is not None
                and primary_query is not None
                and test_intent == "corroboration"
                and query_fingerprint(planned_query.sql)
                == query_fingerprint(primary_query.sql)
            ):
                planned_query = None
                error = (
                    "duplicate primary query; choose an eligible corroboration query"
                )
        except (ValueError, ValidationError) as exc:
            error = str(exc).splitlines()[0][:300]
            logger.debug("planned SQL rejected by host validation: %s", error)
    elif not error:
        error = "SQL action was not selected"
    return HypothesisPlanResult(
        query=planned_query,
        stop_reason=f"invalid_action: {error}" if error else None,
        raw_response=intent_response.raw_response,
        disclosure=disclosure_record,
        test_intent=test_intent,
    )
