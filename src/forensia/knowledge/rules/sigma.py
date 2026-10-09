"""Compile a bounded Sigma subset into the existing DuckDB Rule execution path."""

from __future__ import annotations

from typing import Any

import yaml
from sigma.conditions import ConditionFieldEqualsValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import SigmaString

from forensia.knowledge.resources import schema_dir
from forensia.knowledge.rules.models import FindingTemplate, Rule


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class DuckDBBackend(TextQueryBackend):
    """Use pySigma's condition semantics, with SQL NULL and LIKE semantics explicit."""

    name = "Forensia DuckDB"
    formats = {"default": "DuckDB predicate"}
    requires_pipeline = False
    or_token = "OR"
    and_token = "AND"
    not_token = "NOT"
    eq_token = " = "
    group_expression = "({expr})"
    field_null_expression = "{field} IS NULL"
    field_exists_expression = "{field} IS NOT NULL"
    field_not_exists_expression = "{field} IS NULL"

    def __init__(self, fields: dict[str, str]) -> None:
        super().__init__()
        self.fields = fields

    def escape_and_quote_field(self, field_name: str) -> str:
        try:
            return self.fields[field_name]
        except KeyError as exc:
            raise ValueError(f"Unsupported Sigma field: {field_name}") from exc

    def convert_value_str(self, value: SigmaString, state: ConversionState) -> str:
        # Sigma wildcards become LIKE wildcards; literal %, _ and \ remain literal.
        return _literal(value.convert("\\", "%", "_", add_escaped="\\"))

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = self.convert_value_str(cond.value, state)
        return f"COALESCE(CAST({field} AS VARCHAR) ILIKE {value} ESCAPE '\\', FALSE)"

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        return f"COALESCE({field} = {cond.value}, FALSE)"

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = "TRUE" if cond.value.boolean else "FALSE"
        return f"COALESCE(TRY_CAST({field} AS BOOLEAN) = {value}, FALSE)"


_MODIFIERS = {"contains", "startswith", "endswith", "all", "exists"}
_RULE_FIELDS = {
    "title",
    "id",
    "name",
    "status",
    "description",
    "author",
    "license",
    "references",
    "date",
    "modified",
    "tags",
    "logsource",
    "detection",
    "fields",
    "falsepositives",
    "level",
    "related",
}


def _validate_selection(selection: Any, fields: dict[str, str]) -> None:
    if isinstance(selection, list) and selection:
        for item in selection:
            _validate_selection(item, fields)
        return
    if not isinstance(selection, dict) or not selection:
        raise ValueError(
            "Sigma selections must be nonempty field mappings (no keywords)"
        )
    for key in selection:
        field, *modifiers = str(key).split("|")
        if field not in fields:
            raise ValueError(f"Unsupported Sigma field: {field}")
        if set(modifiers) - _MODIFIERS:
            raise ValueError(f"Unsupported Sigma modifiers: {key}")


def compile_sigma_rule(data: dict[str, Any]) -> Rule:
    """Reject unsupported semantics before returning a common executable Rule."""
    if unknown := set(data) - _RULE_FIELDS:
        raise ValueError(f"Unsupported Sigma rule fields: {sorted(unknown)}")
    mapping = yaml.safe_load((schema_dir() / "sigma.yaml").read_text(encoding="utf-8"))
    source = data.get("logsource") or {}
    if (
        not isinstance(source, dict)
        or set(source) - {"product", "service", "definition"}
        or source.get("product") != "windows"
        or source.get("service") not in mapping["services"]
    ):
        raise ValueError(f"Unsupported Sigma logsource: {source}")
    detection = data.get("detection") or {}
    if (
        not isinstance(detection, dict)
        or "timeframe" in detection
        or not isinstance(detection.get("condition"), str)
    ):
        raise ValueError("Sigma requires one string condition, without timeframe")
    for name, selection in detection.items():
        if name != "condition":
            _validate_selection(selection, mapping["fields"])
    try:
        sigma = SigmaRule.from_dict(data)
        predicates = DuckDBBackend(mapping["fields"]).convert_rule(sigma)
    except Exception as exc:
        raise ValueError(
            f"Invalid or unsupported Sigma rule {data.get('id')}: {exc}"
        ) from exc
    if len(predicates) != 1 or not sigma.id:
        raise ValueError("Sigma requires an ID and exactly one executable condition")
    channel = _literal(mapping["services"][source["service"]])
    description = sigma.description or sigma.title
    query = (
        "SELECT evidence_id, source_file, timestamp, channel, event_id, computer, "
        "target_user, subject_user, src_ip, process_name, command_line, service_name, "
        f"{_literal(sigma.title)} AS sigma_title, "
        f"{_literal(description)} AS sigma_description FROM evtx_events "
        f"WHERE channel = {channel} AND ({predicates[0]}) "
        "ORDER BY timestamp NULLS LAST, evidence_id"
    )
    return Rule(
        id=str(sigma.id),
        title=sigma.title,
        rule_format="sigma",
        severity=sigma.level.name.lower() if sigma.level else "medium",
        confidence=0.5,
        required_fields=["evidence_id"],
        query=query,
        finding=FindingTemplate(
            title="{sigma_title}",
            summary="{sigma_description} Rule match is an investigative lead; validate intent and context.",
        ),
        tags=[str(tag) for tag in sigma.tags],
    )
