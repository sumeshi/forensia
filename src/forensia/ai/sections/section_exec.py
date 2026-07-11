"""Section block execution: plan actions, keypoint/SQL execution, routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from forensia.ai.checking.check_normalize import summarize_query_result
from forensia.ai.prompts.sql_templates import (
    query_template_catalog,
    validate_select_sql,
)
from forensia.ai.sections.section_run_store import (
    _load_cached_result,
    _store_cached_result,
    _store_section_run,
)
from forensia.core.case import Case
from forensia.core.session import PlannedQuery
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records
from forensia.knowledge.catalog import expand_catalog_sql_placeholders
from forensia.knowledge.questions import (
    QuestionSpec,
    extract_time_qualifiers,
    load_question_specs,
    resolve_question_spec,
)
from forensia.report.answers.answer_store import (
    _load_structured_answers,
)
from forensia.report.answers.keypoint_catalog import (
    REPORT_KEYPOINT_ALIASES,
    REPORT_KEYPOINTS,
    _default_keypoints_for_section,
    _resolve_evidence_results,
)
from forensia.report.sections.section_taxonomy import (
    section_family as _section_family,
)


@dataclass(slots=True)
class SectionBlockResult:
    body: str
    evidence_results: list[dict[str, Any]]
    iterations: int
    status: str


@dataclass(slots=True)
class SectionPlanAction:
    action: str
    purpose: str
    keypoint: str | None = None
    planned_query: PlannedQuery | None = None
    enough_to_write: bool = False


# _section_family: canonical implementation moved to report/section_taxonomy.py
# Re-exported via the import at the top of this file.


def _known_keypoints(catalog: list[dict]) -> set[str]:
    return {kp.get("name") or "" for kp in (catalog or [])}


def _split_keypoint_names(value: str | None) -> list[str]:
    """Split planner keypoint output while preserving each exact catalog name."""
    if not value:
        return []
    return [item.strip() for item in re.split(r"[，,;]\s*", str(value)) if item.strip()]


def _is_valid_status(status: str) -> bool:
    return status in {
        "answered",
        "partial",
        "not_found",
        "not_searched",
        "insufficient_evidence",
        "wrong_query",
    }


def _question_routing_rule(
    block_heading: str, template_body: str
) -> QuestionSpec | None:
    spec, _confidence = resolve_question_spec(
        block_heading=block_heading, template_body=template_body
    )
    return spec


def _question_routing_keypoints(block_heading: str, template_body: str) -> list[str]:
    rule = _question_routing_rule(block_heading, template_body)
    if rule is not None:
        return list(rule.keypoints)
    return []


def _question_routing_answer_spec(block_heading: str, template_body: str) -> str:
    rule = _question_routing_rule(block_heading, template_body)
    return rule.answer_spec if rule is not None else ""


def _classify_block_status(
    *,
    verdict: str,
    actual_query_rows: list[int],
    actual_query_count: int,
    reusable_rows_present: bool,
) -> str:
    """Map LLM verdict + query stats to a canonical status string.

    Combines the LLM's semantic verdict with observed query outcomes to produce
    one of the valid statuses used for block result tracking.
    """
    if _is_valid_status(verdict):
        return verdict
    if actual_query_count <= 0:
        return "not_searched" if reusable_rows_present else "not_searched"
    if verdict == "block_supported":
        return "answered"
    if verdict == "block_contradicted":
        if any(count > 0 for count in actual_query_rows):
            return "wrong_query"
        return "not_found"
    if any(count > 0 for count in actual_query_rows):
        return "partial"
    if actual_query_count >= 2 and all(count == 0 for count in actual_query_rows):
        return "not_found"
    return "insufficient_evidence"


def _structured_digest_from_answers(case: Case) -> str:
    """Build a compact <STRUCTURED_OBSERVATIONS> block from persisted structured answers.

    Returns a block (≤1.5 KB) listing each non-zero structured answer spec with
    status, row_count, top values from the first render column, and first/last
    timestamps. Only includes specs with status != 'not_searched' and non-empty
    answer rows.
    """
    answers = _load_structured_answers(case)
    if not answers:
        return ""

    lines: list[str] = []
    for answer in answers:
        status = str(answer.get("status") or "").strip().lower()
        if status == "not_searched":
            continue
        answer_rows = answer.get("answer") or []
        if not isinstance(answer_rows, list) or not answer_rows:
            continue

        answer_spec = str(answer.get("answer_spec") or "").strip() or str(
            answer.get("id") or "?"
        )
        row_count = len(answer_rows)
        first_row = answer_rows[0] if isinstance(answer_rows[0], dict) else None
        columns = answer.get("columns") or []
        first_col = columns[0] if columns else ""
        if not first_col and first_row:
            keys = [k for k in first_row.keys() if not k.startswith("_")]
            first_col = keys[0] if keys else ""

        top_values: list[str] = []
        timestamps: list[str] = []
        for row in answer_rows:
            if not isinstance(row, dict):
                continue
            if first_col:
                val = str(row.get(first_col) or "").strip()
                if val and val not in top_values:
                    top_values.append(val)
            for ts_key in (
                "timestamp",
                "logon_time",
                "last_exec_time",
                "si_modified",
                "date",
                "shutdown_time",
                "first_event_time",
            ):
                ts = str(row.get(ts_key) or "").strip()
                if ts:
                    timestamps.append(ts)
                    break

        first_ts = min(timestamps) if timestamps else ""
        last_ts = max(timestamps) if timestamps else ""
        top_str = " | ".join(top_values[:3])

        line = f"  - {answer_spec}: status={status}, rows={row_count}"
        if top_str:
            line += f", [{first_col}]={top_str}"
        if first_ts and last_ts:
            line += f", ts_range={first_ts[:19]}..{last_ts[:19]}"
        lines.append(line)

    if not lines:
        return ""

    digest = (
        "<STRUCTURED_OBSERVATIONS>\n"
        + "\n".join(lines)
        + "\n</STRUCTURED_OBSERVATIONS>"
    )
    if len(digest) > 1500:
        digest = digest[:1497] + "..."
    return digest


def _question_report_brief(report_brief: dict[str, Any] | None) -> dict[str, Any]:
    """Strip narrative-heavy fields from report_brief for question mode.

    Benchmark blocks must only receive factual inventories, not LLM-generated
    narratives, to prevent answer leakage.
    """
    brief = dict(report_brief or {})
    keys_to_keep = {
        "evidence_inventory",
        "table_inventory",
        "row_counts",
        "time_range",
        "time_window",
        "source_inventory",
    }
    if "evidence_inventory" in brief:
        evidence_inventory = brief.get("evidence_inventory")
        if isinstance(evidence_inventory, dict):
            brief["evidence_inventory"] = {
                key: value
                for key, value in evidence_inventory.items()
                if key in keys_to_keep
            }
    for key in list(brief.keys()):
        if key in keys_to_keep or key == "evidence_inventory":
            continue
        brief.pop(key, None)
    return brief


def _structured_report_brief(report_brief: dict[str, Any] | None) -> dict[str, Any]:
    """Neutral alias for structured question blocks."""
    return _question_report_brief(report_brief)


def _keypoint_catalog(
    section_key: str | None = None,
    template_body: str | None = None,
    *,
    block_heading: str | None = None,
    evidence_keypoints: list[str] | None = None,
) -> list[dict[str, str]]:
    """Return keypoint catalog filtered for this section, plus a few cross-cutting ones.

    Returning all ~40 keypoints to the planner on every iteration wastes
    tokens. Each report section only needs its own family (e.g. timeline_*)
    plus a small set of universally useful keypoints.

    Explicit evidence_keypoints from template hints win first. If absent, use
    heading/body routing hints, then fall back to the section family default.
    """

    def resolve_name(name: str) -> str:
        normalized = str(name or "").strip()
        return REPORT_KEYPOINT_ALIASES.get(normalized, normalized)

    if evidence_keypoints:
        catalog: list[dict[str, str]] = []
        seen: set[str] = set()
        for keypoint in evidence_keypoints:
            resolved_name = resolve_name(keypoint)
            entry = REPORT_KEYPOINTS.get(resolved_name)
            if entry is None or resolved_name in seen:
                continue
            seen.add(resolved_name)
            catalog.append({"name": keypoint, "description": entry[0]})
        if catalog:
            return catalog

    routed_keypoints = _question_routing_keypoints(
        block_heading or "", template_body or ""
    )
    if routed_keypoints:
        catalog: list[dict[str, str]] = []
        seen: set[str] = set()
        for keypoint in routed_keypoints:
            resolved_name = resolve_name(keypoint)
            entry = REPORT_KEYPOINTS.get(resolved_name)
            if entry is None or resolved_name in seen:
                continue
            seen.add(resolved_name)
            catalog.append({"name": keypoint, "description": entry[0]})
        if catalog:
            return catalog

    if not section_key:
        template_body = template_body or ""
        keywords = {
            "logon",
            "user",
            "host",
            "ip",
            "service",
            "task",
            "powershell",
            "process",
            "execution",
            "event",
            "finding",
            "persistence",
            "defender",
        }
        filtered: list[dict[str, str]] = []
        for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items()):
            lowered = template_body.lower()
            if any(
                kw in lowered and (kw in keypoint.lower() or kw in description.lower())
                for kw in keywords
            ):
                filtered.append({"name": keypoint, "description": description})
            if len(filtered) >= 10:
                break
        if filtered:
            return filtered
        return [
            {"name": keypoint, "description": description}
            for keypoint, (description, _) in sorted(REPORT_KEYPOINTS.items())[:10]
        ]

    preferred = _default_keypoints_for_section(
        section_key, block_heading=block_heading or ""
    )
    catalog: list[dict[str, str]] = []
    seen: set[str] = set()
    for keypoint in preferred:
        entry = REPORT_KEYPOINTS.get(keypoint)
        if entry is None or keypoint in seen:
            continue
        seen.add(keypoint)
        catalog.append({"name": keypoint, "description": entry[0]})
    return catalog


def _filter_template_catalog_by_section(
    full_catalog: list[dict[str, Any]],
    section_key: str,
    collected_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Filter template catalog to relevant subset based on section_key and evidence types.

    Pass empty list to get full catalog filtered; otherwise filters already-loaded catalog.
    """
    if not full_catalog:
        full_catalog = query_template_catalog()
    if not full_catalog:
        return []
    family = _section_family(section_key)
    already_used_templates = {
        str(result.get("keypoint") or result.get("description") or "").split()[0]
        for result in collected_results
        if str(result.get("keypoint", "")).startswith("template:")
    }
    keywords = {
        "logon",
        "user",
        "host",
        "ip",
        "service",
        "task",
        "powershell",
        "process",
        "execution",
    }
    if section_key.startswith("1_") or section_key.startswith("overview"):
        keywords = keywords | {"event", "range", "hosts", "findings"}
    elif section_key.startswith("2_") or section_key.startswith("timeline"):
        keywords = keywords | {"timeline", "event", "mft", "prefetch"}
    elif section_key.startswith("3_") or section_key.startswith("technical"):
        keywords = keywords | {
            "host",
            "account",
            "persistence",
            "ioc",
            "execution",
            "defender",
        }
    elif section_key.startswith("4_") or section_key.startswith("gaps"):
        keywords = keywords | {"gap", "missing"}
    elif section_key.startswith("5_") or section_key.startswith("recommendations"):
        keywords = keywords | {"recommend", "action"}
    filtered: list[dict[str, Any]] = []
    for template in full_catalog:
        template_id = str(template.get("template_id", "")).lower()
        if template_id in already_used_templates:
            continue
        template_desc = str(template.get("description", "")).lower()
        if family in template_id.lower() or any(
            kw in template_id or kw in template_desc for kw in keywords
        ):
            filtered.append(template)
    return filtered[:8] if len(filtered) > 8 else filtered


def _summarize_sql_result(sql: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize raw SQL query results into a structured dict for the section agent.

    Delegates to summarize_query_result for evidence IDs, sample rows, and distinct counts.
    """
    summary = summarize_query_result(rows, sample_size=10)
    return {
        "keypoint": "raw_sql",
        "description": sql,
        "kind": "rows",
        "source_kind": "sql",
        "source_ref": sql,
        "row_count": int(summary.get("row_count") or 0),
        "evidence_ids": list(summary.get("evidence_ids") or []),
        "finding_ids": [],
        "hypothesis_ids": [],
        "sample_rows": list(summary.get("sample_rows") or []),
        "head_rows": list(summary.get("head_rows") or []),
        "tail_rows": list(summary.get("tail_rows") or []),
        "distinct_counts": dict(summary.get("distinct_counts") or {}),
    }


def _execute_keypoint(
    case: Case, db: CaseDB, keypoint: str
) -> tuple[str, dict[str, Any]]:
    """Execute a single keypoint and cache the result.

    Returns (source_query, result_dict). Uses query_cache to avoid re-resolving
    the same keypoint within a single report refresh.
    """
    source_query = str(keypoint or "").strip()
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    resolved = _resolve_evidence_results(case, db, keypoints=[keypoint])
    result = (
        resolved[0]
        if resolved
        else {
            "keypoint": keypoint,
            "description": "",
            "kind": "rows",
            "source_kind": "keypoint",
            "source_ref": keypoint,
            "row_count": 0,
            "evidence_ids": [],
            "finding_ids": [],
            "hypothesis_ids": [],
            "sample_rows": [],
        }
    )
    _store_cached_result(db, source_query, result)
    return source_query, result


def _add_json_fallback(sql: str) -> str:
    """Rewrite SELECT columns to add COALESCE fallback for user_name etc."""
    if not sql or "SELECT" not in sql.upper():
        return sql
    if "evtx_events" not in sql.lower():
        return sql

    import re

    select_match = re.search(r"SELECT\s+(.+?)\s+FROM", sql, re.IGNORECASE | re.DOTALL)
    if not select_match:
        return sql

    select_clause = select_match.group(1)

    nullable_cols = {
        "user_name": "COALESCE(user_name, json_extract_string(raw_json, '$.TargetUserName'), json_extract_string(raw_json, '$.SubjectUserName')) AS user_name",
        "target_user": "COALESCE(target_user, json_extract_string(raw_json, '$.TargetUserName'), json_extract_string(raw_json, '$.SubjectUserName')) AS target_user",
        "subject_user": "COALESCE(subject_user, json_extract_string(raw_json, '$.SubjectUserName')) AS subject_user",
        "src_ip": "COALESCE(src_ip, json_extract_string(raw_json, '$.IpAddress')) AS src_ip",
        "logon_type": "COALESCE(CAST(logon_type AS VARCHAR), CAST(json_extract_string(raw_json, '$.LogonType') AS VARCHAR)) AS logon_type",
    }

    new_select = select_clause
    for col_name, replacement in nullable_cols.items():
        pattern = r"(?:evtx_events\.)?\b" + re.escape(col_name) + r"\b"
        if re.search(pattern, select_clause, re.IGNORECASE):
            new_select = re.sub(pattern, replacement, new_select, flags=re.IGNORECASE)

    if new_select == select_clause:
        return sql

    return sql[: select_match.start(1)] + new_select + sql[select_match.end(1) :]


def _execute_sql(db: CaseDB, sql: str) -> tuple[str, dict[str, Any]]:
    """Execute SQL via validate+fetch and cache the summarized result.

    Applies JSON fallback rewrites (via _add_json_fallback) before execution.
    """
    sql = _add_json_fallback(sql)
    validated = validate_select_sql(sql)
    source_query = validated
    cached = _load_cached_result(db, source_query)
    if cached is not None:
        return source_query, cached
    rows = fetch_records(db, validated)
    result = _summarize_sql_result(validated, rows)
    _store_cached_result(db, source_query, result)
    return source_query, result


def _coerce_plan_action(
    plan: dict[str, Any], *, section_key: str, iteration: int, db: CaseDB | None = None
) -> SectionPlanAction | None:
    """Parse and normalize the LLM plan output into a typed SectionPlanAction.

    Handles default action/keypoint assignment, template vs SQL vs keypoint routing,
    and builds a PlannedQuery for template/sql actions.
    """
    action = str(plan.get("action") or "").strip().lower() or "keypoint"
    purpose = (
        str(plan.get("purpose") or "").strip()
        or f"report block {section_key} iteration {iteration}"
    )
    enough_to_write = bool(plan.get("enough_to_write"))
    keypoint = (
        str(plan.get("keypoint") or "").strip()
        or str(plan.get("keypoint_id") or "").strip()
        or str(plan.get("keypoint_name") or "").strip()
        or str(plan.get("name") or "").strip()
        or None
    )
    if action == "keypoint" and not keypoint:
        if db is not None:
            _store_section_run(
                db,
                section_key=section_key,
                block_heading="",
                iteration=iteration,
                phase="plan_error",
                payload={
                    "error": "planner returned action=keypoint without keypoint name"
                },
            )
        return None
    planned_query: PlannedQuery | None = None
    template_id = str(plan.get("template_id") or "").strip() or None
    params = plan.get("params") if isinstance(plan.get("params"), dict) else {}
    sql = str(plan.get("sql") or "").strip()
    if action in {"template", "sql"}:
        planned_query = PlannedQuery(
            query_id=f"RS-{section_key}-{iteration}",
            hypothesis_id=f"report-{section_key}",
            purpose=purpose,
            sql=sql,
            template_id=template_id,
            params=params,
        )
    return SectionPlanAction(
        action=action,
        purpose=purpose,
        keypoint=keypoint,
        planned_query=planned_query,
        enough_to_write=enough_to_write,
    )


def _load_evidence_chains() -> dict[str, list[dict[str, str]]]:
    """Load evidence_chain definitions from question_routing.yaml."""
    chains: dict[str, list[dict[str, str]]] = {}
    for spec in load_question_specs():
        if spec.evidence_chain:
            chains[spec.name] = [dict(item) for item in spec.evidence_chain]
    return chains


def _substitute_placeholders(
    sql: str, qualifiers: dict[str, str | None], defaults: dict[str, str]
) -> str:
    """Substitute {{date_from}}, {{date_to}}, {{hour_from}}, {{hour_to}} placeholders.
    Values from qualifiers (extracted from question text) take priority;
    defaults provide fallback. Placeholders with no resolved value are left untouched.
    """
    result = sql
    for placeholder in ("date_from", "date_to", "hour_from", "hour_to"):
        value = qualifiers.get(placeholder) or defaults.get(placeholder)
        if value is not None:
            result = result.replace("{{" + placeholder + "}}", str(value))
    return result


def _execute_evidence_chain(
    db: CaseDB, block_heading: str, template_body: str, question: str = ""
) -> list[dict[str, Any]]:
    """Execute deterministic evidence chain for the block.
    Tries each chain entry in order until one returns rows.

    Supports optional {{date_from}}, {{date_to}}, {{hour_from}}, {{hour_to}}
    placeholders in query SQL. Time qualifiers extracted from question override
    per-entry time_qualifiers defaults declared in question_routing.yaml.
    """
    chains = _load_evidence_chains()
    if not chains:
        return []
    spec, _confidence = resolve_question_spec(
        block_heading=block_heading, template_body=template_body
    )
    chain_name = spec.name if spec is not None else None
    if chain_name is None or chain_name not in chains:
        return []
    chain = chains[chain_name]
    time_qualifiers = extract_time_qualifiers(question) if question else {}
    for entry in chain:
        if isinstance(entry, dict):
            query = entry.get("query", "")
            if query:
                defaults = dict(entry.get("time_qualifiers") or {})
                query = _substitute_placeholders(query, time_qualifiers, defaults)
                query = expand_catalog_sql_placeholders(query)
                try:
                    from forensia.db.query import fetch_records

                    rows = fetch_records(db, query)
                    if rows:
                        return rows[:50]
                except Exception:
                    continue
    return []
