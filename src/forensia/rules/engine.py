from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from string import Formatter
from typing import Any

import orjson
import yaml

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.rules.models import Finding, Rule


def run_rule(db: CaseDB, rule: Rule) -> list[dict[str, Any]]:
    result = db.execute(rule.query)
    columns = [item[0] for item in result.description]
    return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]


def _render_template(template: str, row: dict[str, Any]) -> str:
    output = template
    for _, field_name, _, _ in Formatter().parse(template):
        if field_name:
            output = output.replace("{" + field_name + "}", str(row.get(field_name, "")))
    return output


def generate_findings(rule: Rule, rows: list[dict[str, Any]]) -> list[Finding]:
    findings = []
    for index, row in enumerate(rows, start=1):
        findings.append(
            Finding(
                finding_id=f"{rule.id}-{index:04d}",
                rule_id=rule.id,
                title=_render_template(rule.finding.title, row),
                summary=_render_template(rule.finding.summary, row),
                severity=rule.severity,
                confidence=rule.confidence,
                tags=rule.tags,
                attack=rule.attack,
                evidence=[row],
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


def _value_matches(actual: Any, expected_values: Any) -> bool:
    if not isinstance(expected_values, list):
        return False
    actual_text = str(actual or "")
    return any(actual_text == str(expected or "") for expected in expected_values)


def _is_suppressed(finding: Finding, allowlist_rules: list[dict[str, Any]]) -> bool:
    row = finding.evidence[0] if finding.evidence and isinstance(finding.evidence[0], dict) else {}
    for item in allowlist_rules:
        if str(item.get("rule_id") or "") != finding.rule_id:
            continue
        when = item.get("when") or {}
        if not isinstance(when, dict) or not when:
            continue
        if all(_value_matches(row.get(field), expected_values) for field, expected_values in when.items()):
            return True
    return False


def clear_rule_findings(case: Case, db: CaseDB, rule_id: str) -> None:
    db.execute("DELETE FROM findings WHERE rule_id = ?", (rule_id,))
    for path in case.findings_dir.glob(f"{rule_id}-*.json"):
        path.unlink(missing_ok=True)


def save_findings(case: Case, db: CaseDB, findings: list[Finding]) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    allowlist_rules = _load_allowlist(case)
    for finding in findings:
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
                json.dumps(finding.attack, ensure_ascii=False),
                json.dumps(finding.evidence, ensure_ascii=False, default=str),
                finding.ai_summary,
                json.dumps(finding.missing_checks, ensure_ascii=False),
                now,
            ),
        )
