from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from string import Formatter
from typing import Any

import orjson
import yaml

from forensia.core.case import Case
from forensia.core.textutil import sanitize_ingest_path
from forensia.core.timeutil import parse_timestamp
from forensia.db.database import CaseDB
from forensia.knowledge import (
    load_event_id_hints as _load_event_id_hints,
)
from forensia.knowledge import (
    load_finding_benign_context_rules as _load_finding_benign_context_rules,
)
from forensia.rules.models import Finding, FindingTemplate, Rule

_MISSING_TEXT_VALUES = {"", "-", "n/a", "na", "none", "null", "unknown"}
_BUILTIN_ALLOWLIST_PATH = (
    Path(__file__).resolve().parent.parent
    / "rulepacks"
    / "_schema"
    / "suppression"
    / "allowlist_services.yaml"
)

FALLBACK_PHASES = {"keyword_in_raw_json", "related_event_ids", "artifact_table"}

# Allowed tables for fallback search - validated against schema
_ALLOWED_FALLBACK_TABLES = {
    "evtx_events",
    "mft_entries",
    "mft_timeline",
    "prefetch_executions",
}


def run_rule(db: CaseDB, rule: Rule) -> list[dict[str, Any]]:
    result = db.execute(rule.query)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _is_missing_value(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip().lower()
    return text in _MISSING_TEXT_VALUES


def _template_fields(template: str) -> list[str]:
    fields: list[str] = []
    for _, field_name, _, _ in Formatter().parse(template):
        if field_name and field_name not in fields:
            fields.append(field_name)
    return fields


def _render_template(template: str, row: dict[str, Any]) -> str:
    output = template
    for _, field_name, _, _ in Formatter().parse(template):
        if field_name:
            value = row.get(field_name, "")
            rendered = "" if _is_missing_value(value) else str(value)
            output = output.replace("{" + field_name + "}", rendered)
    return output


def _confidence_with_missing_fields(
    base_confidence: float, missing_fields: list[str]
) -> float:
    penalty = min(0.45, 0.15 * len(missing_fields))
    return max(0.0, min(1.0, base_confidence - penalty))


def generate_findings(rule: Rule, rows: list[dict[str, Any]]) -> list[Finding]:
    """Create Finding objects from rule query result rows by rendering title/summary templates.

    Auto-detects missing required fields per row and reduces the finding's confidence
    score proportionally (up to 0.45 penalty). Each finding ID is derived from rule_id
    plus a zero-padded row index.
    """
    findings = []
    for index, row in enumerate(rows, start=1):
        # Path-bearing columns may carry the analyst's local ingest tree
        # (e.g. a pre-basename-fix DB whose prefetch source_file is the
        # raw ingest path). Sanitize before the row is rendered into the
        # title/summary and embedded as evidence, so the local filesystem
        # layout never reaches case output.
        sanitized = {
            key: sanitize_ingest_path(row[key])
            for key in ("source_file", "prefetch_file")
            if row.get(key)
        }
        if sanitized:
            row = {**row, **sanitized}
        referenced_fields = rule.required_fields or [
            *_template_fields(rule.finding.title),
            *[
                field
                for field in _template_fields(rule.finding.summary)
                if field not in _template_fields(rule.finding.title)
            ],
        ]
        missing_fields = [
            field for field in referenced_fields if _is_missing_value(row.get(field))
        ]
        findings.append(
            Finding(
                finding_id=f"{rule.id}-{index:04d}",
                rule_id=rule.id,
                title=_render_template(rule.finding.title, row),
                summary=_render_template(rule.finding.summary, row),
                severity=rule.severity,
                confidence=_confidence_with_missing_fields(
                    rule.confidence, missing_fields
                ),
                tags=rule.tags,
                attack=[item.model_dump() for item in (rule.attack or [])],
                evidence=[row],
                missing_checks=(
                    [
                        f"Missing key fields for this finding: {', '.join(missing_fields)}"
                    ]
                    if missing_fields
                    else []
                ),
            )
        )
    return findings


def _load_allowlist(case: Case) -> list[dict[str, Any]]:
    if not case.allowlist_path.exists():
        return []
    data = yaml.safe_load(case.allowlist_path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules")
    if isinstance(rules, list):
        return [item for item in rules if isinstance(item, dict)]
    return []


def _load_builtin_benign_allowlist() -> dict[str, list[str]]:
    if not _BUILTIN_ALLOWLIST_PATH.exists():
        return {"service_names": [], "process_names": [], "title_keywords": []}
    data = yaml.safe_load(_BUILTIN_ALLOWLIST_PATH.read_text(encoding="utf-8")) or {}
    return {
        "rule_ids": [
            str(item).strip()
            for item in data.get("rule_ids") or []
            if str(item).strip()
        ],
        "service_names": [
            str(item).strip().lower()
            for item in data.get("service_names") or []
            if str(item).strip()
        ],
        "process_names": [
            str(item).strip().lower()
            for item in data.get("process_names") or []
            if str(item).strip()
        ],
        "title_keywords": [
            str(item).strip().lower()
            for item in data.get("title_keywords") or []
            if str(item).strip()
        ],
    }


def _value_matches(actual: Any, expected_values: Any) -> bool:
    if not isinstance(expected_values, list):
        return False
    actual_text = str(actual or "")
    return any(actual_text == str(expected or "") for expected in expected_values)


def _is_suppressed(finding: Finding, allowlist_rules: list[dict[str, Any]]) -> bool:
    """Check whether a finding matches a user-defined allowlist suppression rule.

    A finding is suppressed when all field-value pairs in the allowlist rule's
    'when' clause match the finding's first evidence row for the same rule_id.
    """
    row = (
        finding.evidence[0]
        if finding.evidence and isinstance(finding.evidence[0], dict)
        else {}
    )
    for item in allowlist_rules:
        if str(item.get("rule_id") or "") != finding.rule_id:
            continue
        when = item.get("when") or {}
        if not isinstance(when, dict) or not when:
            continue
        if all(
            _value_matches(row.get(field), expected_values)
            for field, expected_values in when.items()
        ):
            return True
    return False


def _builtin_benign_match(
    finding: Finding, allowlist_data: dict[str, list[str]]
) -> str | None:
    """Return a description string if the finding matches built-in benign allowlists.

    Checks service_name, process_name, and title/summary keywords in that order.
    Returns a description of the first match (e.g. 'service_name=wuauserv') or None.
    """
    row = (
        finding.evidence[0]
        if finding.evidence and isinstance(finding.evidence[0], dict)
        else {}
    )
    scoped_rule_ids = set(allowlist_data.get("rule_ids") or [])
    if scoped_rule_ids and finding.rule_id not in scoped_rule_ids:
        return None
    service_name = str(row.get("service_name") or "").strip().lower()
    process_name = str(row.get("process_name") or "").strip().lower()
    title = str(finding.title or "").strip().lower()
    summary = str(finding.summary or "").strip().lower()
    for candidate in allowlist_data.get("service_names") or []:
        if candidate and candidate in service_name:
            return f"service_name={candidate}"
    for candidate in allowlist_data.get("process_names") or []:
        if candidate and candidate in process_name:
            return f"process_name={candidate}"
    for candidate in allowlist_data.get("title_keywords") or []:
        if candidate and (candidate in title or candidate in summary):
            return f"title_keyword={candidate}"
    return None


def _downgrade_builtin_benign_finding(
    finding: Finding, allowlist_data: dict[str, list[str]]
) -> None:
    """Downgrade severity and confidence for findings matching built-in benign allowlists.

    Sets status to 'suppressed', caps confidence at 0.2, and reduces severity to 'low'.
    Appends the matched rule detail to missing_checks for auditability.
    """
    matched = _builtin_benign_match(finding, allowlist_data)
    if not matched:
        return
    finding.status = "suppressed"
    finding.confidence = min(float(finding.confidence), 0.2)
    if finding.severity in {"critical", "high", "medium"}:
        finding.severity = "low"
    note = f"Matched built-in benign allowlist: {matched}"
    if note not in finding.missing_checks:
        finding.missing_checks.append(note)


def _parse_event_ts(value: Any) -> datetime | None:
    """Parse an evidence-row timestamp string into a naive datetime."""
    return parse_timestamp(value)


def build_co_occur_index(
    db: CaseDB, rules: list[dict[str, Any]] | None = None
) -> dict[int, list[tuple[datetime, str]]]:
    """Prefetch timestamps of every event ID referenced by co_occurs_event_ids conditions.

    Returns {event_id: [(timestamp, canonical_computer), ...]} so that
    benign-context proximity checks run in memory without per-finding queries.
    """
    rules = rules if rules is not None else _load_finding_benign_context_rules()
    event_ids: set[int] = set()
    for rule in rules:
        for condition in rule.get("when_all") or []:
            for eid in condition.get("co_occurs_event_ids") or []:
                try:
                    event_ids.add(int(eid))
                except TypeError, ValueError:
                    continue
    if not event_ids:
        return {}
    id_list = ", ".join(str(eid) for eid in sorted(event_ids))
    index: dict[int, list[tuple[datetime, str]]] = {}
    try:
        rows = db.execute(
            f"SELECT event_id, timestamp, computer FROM evtx_events WHERE event_id IN ({id_list}) AND timestamp IS NOT NULL"
        ).fetchall()
    except Exception:
        return {}
    for eid, ts, computer in rows:
        parsed = _parse_event_ts(ts)
        if parsed is None:
            continue
        index.setdefault(int(eid), []).append(
            (parsed, str(computer or "").strip().upper())
        )
    return index


def _co_occurs_satisfied(
    condition: dict[str, Any],
    row: dict[str, Any],
    co_occur_index: dict[int, list[tuple[datetime, str]]],
) -> bool:
    """True when any listed event ID occurs within within_minutes of the row's timestamp.

    Conservative: when the row has no parseable timestamp or the index is empty,
    the condition is NOT satisfied (the finding keeps its original confidence).
    Host matching applies when both sides carry a computer value.
    """
    row_ts = _parse_event_ts(row.get("timestamp"))
    if row_ts is None or not co_occur_index:
        return False
    within_minutes = int(condition.get("within_minutes") or 10)
    window = within_minutes * 60
    row_host = str(row.get("computer") or "").strip().upper()
    for eid in condition.get("co_occurs_event_ids") or []:
        try:
            entries = co_occur_index.get(int(eid)) or []
        except TypeError, ValueError:
            continue
        for ts, host in entries:
            if row_host and host and row_host != host:
                continue
            if abs((ts - row_ts).total_seconds()) <= window:
                return True
    return False


def _annotate_finding_benign_context(
    finding: Finding,
    co_occur_index: dict[int, list[tuple[datetime, str]]] | None = None,
) -> None:
    """Annotate findings with benign-context tags if they match finding-level rules.

    Tags are added to the finding's tags list, and confidence is multiplied by 0.4.
    The finding is never suppressed outright (visibility preserved).
    All when_all conditions must positively match: a missing column or an
    unverifiable co-occurrence means NO downgrade (conservative default).
    """
    rules = _load_finding_benign_context_rules()
    if not rules:
        return

    row = (
        finding.evidence[0]
        if finding.evidence and isinstance(finding.evidence[0], dict)
        else {}
    )
    if not row:
        return

    for rule in rules:
        rule_id = rule.get("id", "")
        applies_to_tags = rule.get("applies_to_tags") or []
        when_all = rule.get("when_all") or []

        # Check if finding tags overlap with applies_to_tags
        finding_tags_lower = {t.lower() for t in (finding.tags or [])}
        if applies_to_tags and not any(
            t.lower() in finding_tags_lower for t in applies_to_tags
        ):
            continue

        # Check when_all conditions — every condition must positively match.
        all_match = bool(when_all)
        for condition in when_all:
            column = condition.get("column", "")
            regex = condition.get("regex", "")
            if column and regex:
                value = str(row.get(column) or "")
                if not value or not re.search(regex, value):
                    all_match = False
                    break
                continue
            if condition.get("co_occurs_event_ids"):
                if not _co_occurs_satisfied(condition, row, co_occur_index or {}):
                    all_match = False
                    break
                continue
            # Unknown condition shape: fail loud-ish by not matching.
            all_match = False
            break
        if not all_match:
            continue

        # Match found: annotate with benign-context tag
        benign_tag = f"benign-context:{rule_id}"
        if benign_tag not in finding.tags:
            finding.tags = list(finding.tags or []) + [benign_tag]
        finding.confidence = min(
            float(finding.confidence), float(finding.confidence) * 0.4
        )
        note = f"Matched benign-context rule: {rule_id} — {rule.get('note', '')}"
        if note not in finding.missing_checks:
            finding.missing_checks = list(finding.missing_checks or []) + [note]


def clear_rule_findings(case: Case, db: CaseDB, rule_id: str) -> None:
    rows = db.execute(
        "SELECT finding_id FROM findings WHERE rule_id = ?", (rule_id,)
    ).fetchall()
    for row in rows:
        finding_id = str(row[0] or "")
        if finding_id:
            db.execute(
                "DELETE FROM case_timeline WHERE entry_id = ?",
                (f"tl-finding-{finding_id}",),
            )
    db.execute("DELETE FROM findings WHERE rule_id = ?", (rule_id,))
    for path in case.findings_dir.glob(f"{rule_id}-*.json"):
        path.unlink(missing_ok=True)


def feed_findings_to_timeline(db: CaseDB) -> None:
    """Feeder (a): Insert finding rows with severity >= medium into case_timeline.

    Extracts the first evidence row's timestamp and evidence_id from each
    finding's JSON evidence array. Deduplicates by (source, ref_id).
    """
    db.execute("""
        INSERT INTO case_timeline (entry_id, timestamp, source, ref_id, host, summary, evidence_id)
        SELECT
            'tl-finding-' || f.finding_id,
            COALESCE(
                TRY_CAST(NULLIF(json_extract_string(f.evidence, '$[0].timestamp'), '') AS TIMESTAMP),
                f.created_at
            ),
            'finding',
            f.finding_id,
            NULLIF(json_extract_string(f.evidence, '$[0].computer'), ''),
            COALESCE(NULLIF(f.title, ''), f.finding_id),
            NULLIF(json_extract_string(f.evidence, '$[0].evidence_id'), '')
        FROM findings f
        WHERE f.severity IN ('critical', 'high', 'medium')
          AND COALESCE(f.status, 'new') != 'suppressed'
          AND f.evidence IS NOT NULL
        ON CONFLICT (entry_id) DO NOTHING
    """)


def save_findings(case: Case, db: CaseDB, findings: list[Finding]) -> None:
    """Persist findings to individual JSON files and the findings database table.

    Applies built-in benign allowlist downgrading and user-defined suppression
    before writing. Each finding is written as a JSON file for easy inspection
    and inserted as a row in the findings table for structured querying.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    allowlist_rules = _load_allowlist(case)
    builtin_allowlist = _load_builtin_benign_allowlist()
    co_occur_index = build_co_occur_index(db)
    for finding in findings:
        _downgrade_builtin_benign_finding(finding, builtin_allowlist)
        _annotate_finding_benign_context(finding, co_occur_index)
        if _is_suppressed(finding, allowlist_rules):
            finding.status = "suppressed"
        path = case.findings_dir / f"{finding.finding_id}.json"
        path.write_bytes(orjson.dumps(finding.model_dump(), option=orjson.OPT_INDENT_2))
        db.execute(
            """
            INSERT INTO findings (
                finding_id, rule_id, title, summary, severity, confidence,
                status, tags, attack, evidence, ai_summary, missing_checks, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.finding_id,
                finding.rule_id,
                finding.title,
                finding.summary,
                finding.severity,
                finding.confidence,
                finding.status,
                json.dumps(finding.tags, ensure_ascii=False),
                json.dumps(
                    [a.model_dump() for a in finding.attack], ensure_ascii=False
                ),
                json.dumps(finding.evidence, ensure_ascii=False, default=str),
                finding.ai_summary,
                json.dumps(finding.missing_checks, ensure_ascii=False),
                now,
            ),
        )
    feed_findings_to_timeline(db)


def _escape_like_pattern(keyword: str) -> str:
    """Escape SQL LIKE wildcards in keyword pattern.

    Uses '!' as escape character to avoid backslash conflicts.
    """
    escaped = str(keyword).replace("!", "!!")  # Escape escape char itself
    escaped = escaped.replace("%", "!%")  # Escape wildcard
    escaped = escaped.replace("_", "!_")  # Escape wildcard
    escaped = escaped.replace("'", "''")  # Escape single quote
    return escaped


def _extract_event_ids_from_sql(sql: str) -> list[int]:
    """Extract integer event_id values from SQL WHERE clauses.

    Supports both `event_id IN (4624, 4625)` and `event_id = 4624` syntax.
    Returns a deduplicated list in order of first appearance in the SQL.
    """
    raw = re.findall(r"event_id\s*(?:IN\s*\(([^)]+)\)|=\s*(\d+))", sql, re.IGNORECASE)
    event_ids: list[int] = []
    seen: set[int] = set()
    for in_group, eq_val in raw:
        candidates: list[str] = []
        if in_group:
            candidates.extend(v.strip() for v in in_group.split(","))
        if eq_val:
            candidates.append(eq_val.strip())
        for candidate in candidates:
            try:
                event_id = int(candidate)
            except TypeError, ValueError:
                continue
            if event_id in seen:
                continue
            seen.add(event_id)
            event_ids.append(event_id)
    return event_ids


def _keywords_for_event_ids(event_ids: list[int]) -> tuple[list[str], list[int]]:
    """Look up string-search keywords from the event_id schema for given event IDs.

    Returns (keywords, matched_event_ids) where matched_event_ids is the subset
    that had entries in the schema. Keywords are deduplicated by casefold to avoid
    redundant LIKE clauses in the fallback query.
    """
    hints = _load_event_id_hints()
    keywords: list[str] = []
    seen_keywords: set[str] = set()
    matched_event_ids: list[int] = []
    for event_id in event_ids:
        hint = hints.get(event_id)
        if not hint:
            continue
        matched_event_ids.append(event_id)
        for keyword in hint.get("keywords_for_string_search") or []:
            text = str(keyword).strip()
            if not text:
                continue
            normalized = text.casefold()
            if normalized in seen_keywords:
                continue
            seen_keywords.add(normalized)
            keywords.append(text)
    return keywords, matched_event_ids


def _execute_keyword_search(db: CaseDB, keywords: list[str]) -> list[dict[str, Any]]:
    """Search evtx_events.raw_json with LIKE clauses for the given keywords.

    Constructs an OR'd WHERE clause with proper escaping for SQL LIKE wildcards.
    Capped at 100 rows to prevent runaway queries on large datasets.
    """
    if not keywords:
        return []
    like_clauses = " OR ".join(
        f"LOWER(CAST(raw_json AS VARCHAR)) LIKE '%{_escape_like_pattern(keyword.casefold())}%' ESCAPE '!'"
        for keyword in keywords
    )
    sql = f"SELECT * FROM evtx_events WHERE {like_clauses} LIMIT 100"
    result = db.execute(sql)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def execute_event_keyword_fallback_search(
    db: CaseDB, sql: str
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Fallback for queries that explicitly reference event_ids but return no rows.

    Looks up event-specific string search keywords in rulepacks/_schema/event_ids.yaml,
    then re-queries evtx_events by matching raw_json text.
    """
    event_ids = _extract_event_ids_from_sql(sql)
    if not event_ids:
        return [], None
    keywords, matched_event_ids = _keywords_for_event_ids(event_ids)
    if not keywords:
        return [], None
    rows = _execute_keyword_search(db, keywords)
    if not rows:
        return [], None
    return rows, {
        "phase": "keyword_in_raw_json",
        "event_ids": matched_event_ids,
        "keywords": keywords,
        "source": "event_id_schema",
    }


def execute_fallback_search(
    db: CaseDB, fallback: dict[str, Any]
) -> list[dict[str, Any]]:
    """Execute a fallback search phase based on phase type and parameters.

    Returns empty list for invalid phase or missing required fields.
    Logs warnings for unknown phases or invalid table names.
    """
    phase = fallback.get("phase")
    if phase == "keyword_in_raw_json":
        keywords = fallback.get("keywords") or []
        if not keywords or not isinstance(keywords, list):
            return []
        valid_keywords = []
        for kw in keywords:
            if isinstance(kw, str):
                valid_keywords.append(kw)
        if not valid_keywords:
            return []
        like_clauses = " OR ".join(
            f"raw_json LIKE '%{_escape_like_pattern(kw)}%' ESCAPE '!'"
            for kw in valid_keywords
        )
        sql = f"SELECT * FROM evtx_events WHERE {like_clauses} LIMIT 100"
        return run_rule(
            db,
            Rule(
                id="fallback-keyword",
                title="",
                query=sql,
                finding=FindingTemplate(title="", summary=""),
            ),
        )
    if phase == "related_event_ids":
        event_ids = fallback.get("event_ids") or []
        if not event_ids:
            return []
        # Validate event_ids are integers
        valid_event_ids = []
        for eid in event_ids:
            try:
                valid_event_ids.append(int(eid))
            except TypeError, ValueError:
                import logging

                logging.warning(f"Invalid event_id in fallback: {eid}")
                continue
        if not valid_event_ids:
            return []
        event_list = ",".join(str(eid) for eid in valid_event_ids)
        sql = f"SELECT * FROM evtx_events WHERE event_id IN ({event_list}) LIMIT 100"
        return run_rule(
            db,
            Rule(
                id="fallback-correlation",
                title="",
                query=sql,
                finding=FindingTemplate(title="", summary=""),
            ),
        )
    if phase == "artifact_table":
        table = fallback.get("table")
        if not table:
            return []
        # Validate table name against allowed tables
        table_name = str(table).strip().lower()
        if table_name not in _ALLOWED_FALLBACK_TABLES:
            import logging

            logging.warning(
                f"Invalid fallback table '{table}'; allowed: {_ALLOWED_FALLBACK_TABLES}"
            )
            return []
        sql = f"SELECT * FROM {table_name} LIMIT 100"
        return run_rule(
            db,
            Rule(
                id="fallback-artifact",
                title="",
                query=sql,
                finding=FindingTemplate(title="", summary=""),
            ),
        )
    if phase and phase not in FALLBACK_PHASES:
        import logging

        logging.warning(
            f"Unknown fallback phase '{phase}'; valid phases: {FALLBACK_PHASES}"
        )
    return []
