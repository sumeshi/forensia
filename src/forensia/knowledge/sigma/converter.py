"""Compile Sigma rules through the pinned Windows pipelines to DuckDB SQL."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import yaml
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.exceptions import (
    SigmaFeatureNotSupportedByBackendError,
    SigmaTransformationError,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaString,
)

from forensia.knowledge.resources import schema_dir
from forensia.knowledge.rules.models import FindingTemplate, Rule

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
    # SigmaHQ uses this for development fixtures; it is not detection semantics.
    "regression_tests_path",
    "simulation",
}
_SUPPORTED_MODIFIERS = {
    "SigmaContainsModifier",
    "SigmaStartswithModifier",
    "SigmaEndswithModifier",
    "SigmaAllModifier",
    "SigmaExistsModifier",
    "SigmaCaseSensitiveModifier",
    "SigmaGreaterThanModifier",
    "SigmaGreaterThanOrEqualModifier",
    "SigmaLessThanModifier",
    "SigmaLessThanOrEqualModifier",
    "SigmaNotEqualModifier",
    "SigmaWindowsDashModifier",
}


class UnsupportedSigmaRule(ValueError):
    """A valid Sigma rule uses semantics or fields with no verified mapping."""


@dataclass(frozen=True)
class SigmaTargetCompilation:
    target_key: str
    target_binding: dict[str, Any]
    sigma_id: str
    rule: Rule | None
    status: str
    reason_code: str = ""
    reason: str = ""


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class DuckDBBackend(TextQueryBackend):
    """Translate the verified Sigma AST subset with explicit DuckDB semantics."""

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
    compare_op_expression = "{field} {operator} {value}"
    compare_operators = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
        SigmaCompareExpression.CompareOperators.NEQ: "!=",
    }

    def __init__(
        self, fields: dict[str, dict[str, Any]], *, service: str | None = None
    ) -> None:
        super().__init__()
        self.fields = fields
        self.service = service

    def _field(self, field_name: str) -> dict[str, Any]:
        field = self.fields.get(field_name)
        if field is not None and "expression" in field:
            return field
        # Native EVTX event_data keys are case-sensitive and are read directly.
        # Restrict key syntax so a Sigma field cannot alter the SQL/JSON path.
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_. -]*", field_name):
            service_paths = (field or {}).get("paths", {})
            path = (
                service_paths.get(self.service)
                or (field or {}).get("path")
                or ("$.winlog.event_data." + json.dumps(field_name))
            )
            scalar = f"json_extract_string(raw_json, '{path}')"
            value_type = f"json_type(raw_json, '{path}')"
            return {
                **(field or {}),
                "expression": (
                    f"CASE WHEN {value_type} IN ('VARCHAR', 'BIGINT', 'UBIGINT', 'DOUBLE', 'BOOLEAN') "
                    f"THEN [{scalar}] WHEN {value_type} = 'ARRAY' THEN "
                    f"json_extract_string(raw_json, '{path}[*]') ELSE NULL END"
                ),
                "type": (field or {}).get("type", "string"),
                "array_aware": True,
            }
        raise UnsupportedSigmaRule(f"Unsupported Sigma field: {field_name}")

    def escape_and_quote_field(self, field_name: str) -> str:
        return str(self._field(field_name)["expression"])

    def convert_value_str(self, value: SigmaString, state: ConversionState) -> str:
        return _literal(value.convert("\\", "%", "_", add_escaped="\\"))

    def _string_predicate(
        self, cond: ConditionFieldEqualsValueExpression, *, case_sensitive: bool
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = self.convert_value_str(cond.value, ConversionState())
        operator = "LIKE" if case_sensitive else "ILIKE"
        if self._field(cond.field).get("array_aware"):
            return (
                "COALESCE(list_contains(list_transform("
                f"{field}, sigma_item -> COALESCE(CAST(sigma_item AS VARCHAR) {operator} "
                f"{value} ESCAPE '\\', FALSE)), TRUE), FALSE)"
            )
        return (
            f"COALESCE(CAST({field} AS VARCHAR) {operator} {value} ESCAPE '\\', FALSE)"
        )

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        if isinstance(cond.value, SigmaCasedString):
            return self._string_predicate(cond, case_sensitive=True)
        return self._string_predicate(cond, case_sensitive=False)

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        return self._string_predicate(cond, case_sensitive=True)

    def _compact_string_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> str | None:
        """Use one DuckDB list transform for a same-field string disjunction."""
        if len(cond.args) < 2 or not all(
            isinstance(arg, ConditionFieldEqualsValueExpression) for arg in cond.args
        ):
            return None
        expressions = cond.args
        field_name = expressions[0].field
        if any(expression.field != field_name for expression in expressions):
            return None
        case_sensitive = isinstance(expressions[0].value, SigmaCasedString)
        if any(
            not isinstance(expression.value, SigmaString)
            or isinstance(expression.value, SigmaCasedString) != case_sensitive
            for expression in expressions
        ):
            return None

        # Sigma modifiers have already made contains/starts/ends values into
        # wildcard patterns. Keep their escapes and case mode exactly as in the
        # ordinary string conversion, and remove duplicate converted patterns.
        patterns = list(
            dict.fromkeys(
                self.convert_value_str(expression.value, state)
                for expression in expressions
            )
        )
        field = self.escape_and_quote_field(field_name)
        operator = "LIKE" if case_sensitive else "ILIKE"
        pattern_list = ", ".join(patterns)
        if self._field(field_name).get("array_aware"):
            return (
                "list_contains(list_transform("
                f"[{pattern_list}], sigma_pattern -> list_contains(list_transform("
                f"{field}, sigma_item -> COALESCE(CAST(sigma_item AS VARCHAR) {operator} "
                "sigma_pattern ESCAPE '\\', FALSE)), TRUE)), TRUE)"
            )
        return (
            "list_contains(list_transform("
            f"[{pattern_list}], sigma_pattern -> "
            f"COALESCE(CAST({field} AS VARCHAR) {operator} sigma_pattern ESCAPE '\\', FALSE)"
            "), TRUE)"
        )

    def convert_condition_or(
        self, cond: ConditionOR, state: ConversionState
    ) -> str | None:
        compact = self._compact_string_or(cond, state)
        if compact is not None:
            return compact
        return super().convert_condition_or(cond, state)

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field_info = self._field(cond.field)
        if field_info["type"] != "number":
            raise UnsupportedSigmaRule(
                f"Numeric Sigma value is unsupported for string field {cond.field}"
            )
        field = self.escape_and_quote_field(cond.field)
        return f"COALESCE(TRY_CAST({field} AS BIGINT) = {cond.value}, FALSE)"

    def convert_condition_field_compare_op_val(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field_info = self._field(cond.field)
        if field_info["type"] != "number":
            raise UnsupportedSigmaRule(
                f"Numeric comparison is unsupported for string field {cond.field}"
            )
        field = self.escape_and_quote_field(cond.field)
        value = cond.value
        if not isinstance(value, SigmaCompareExpression):
            raise UnsupportedSigmaRule("Sigma numeric comparison value is malformed")
        operator = self.compare_operators[value.op]
        return f"COALESCE(TRY_CAST({field} AS BIGINT) {operator} {value.number}, FALSE)"

    def convert_condition_field_eq_val_bool(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        value = "TRUE" if cond.value.boolean else "FALSE"
        return f"COALESCE(TRY_CAST({field} AS BOOLEAN) = {value}, FALSE)"

    def convert_condition_field_eq_val_exists(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> str:
        field = self.escape_and_quote_field(cond.field)
        return f"({field} IS {'NOT ' if cond.value.exists else ''}NULL)"


def _mapping() -> dict[str, Any]:
    return yaml.safe_load((schema_dir() / "sigma.yaml").read_text(encoding="utf-8"))


def _windows_pipelines() -> tuple[ProcessingPipeline, ProcessingPipeline]:
    """Apply the pinned upstream pipelines in order without copying their items."""
    try:
        from sigma.pipelines.windows import (
            windows_audit_pipeline,
            windows_logsource_pipeline,
        )
    except ImportError as exc:  # dependency errors must not silently narrow coverage
        raise RuntimeError("The pinned pySigma Windows pipeline is required") from exc
    return windows_logsource_pipeline(), windows_audit_pipeline()


def _parse_rule(data: dict[str, Any]) -> SigmaRule:
    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a mapping")
    if unknown := set(data) - _RULE_FIELDS:
        if unknown & {"correlation", "timeframe"}:
            raise UnsupportedSigmaRule(
                f"Unsupported Sigma correlation/timeframe fields: {sorted(unknown)}"
            )
        raise ValueError(f"Unsupported Sigma rule fields: {sorted(unknown)}")
    source = data.get("logsource")
    if not isinstance(source, dict) or source.get("product") != "windows":
        raise UnsupportedSigmaRule(f"Unsupported Sigma logsource: {source}")
    if set(source) - {"product", "service", "category", "definition"}:
        raise UnsupportedSigmaRule(f"Unsupported Sigma logsource: {source}")
    if ("service" in source) == ("category" in source):
        raise UnsupportedSigmaRule(
            "Sigma logsource requires exactly one service or category"
        )
    detection = data.get("detection")
    if not isinstance(detection, dict) or not isinstance(
        detection.get("condition"), str
    ):
        raise UnsupportedSigmaRule("Sigma requires one string condition")
    if "timeframe" in detection:
        raise UnsupportedSigmaRule(
            "Sigma timeframe/correlation semantics are unsupported"
        )

    # Keep upstream development metadata in the source input, but do not pass this
    # non-semantic path to pySigma's core parser.
    sigma_data = {
        key: value
        for key, value in data.items()
        if key not in {"regression_tests_path", "simulation"}
    }
    try:
        sigma = SigmaRule.from_dict(sigma_data)
    except Exception as exc:
        raise ValueError(f"Invalid Sigma rule {data.get('id')}: {exc}") from exc

    return sigma


def _items(sigma: SigmaRule) -> Iterable[Any]:
    def walk(detection: SigmaDetection) -> Iterable[SigmaDetectionItem]:
        for item in detection.detection_items:
            if isinstance(item, SigmaDetectionItem):
                if item.field is None:
                    raise UnsupportedSigmaRule(
                        "Fieldless Sigma keyword detections are unsupported"
                    )
                yield item
            elif isinstance(item, SigmaDetection):
                yield from walk(item)
            else:
                raise UnsupportedSigmaRule(
                    f"Unsupported fieldless Sigma detection item: {type(item).__name__}"
                )

    for detection in sigma.detection.detections.values():
        yield from walk(detection)


def _possible_event_ids(condition: Any) -> set[int] | None:
    """Return finite EventID values guaranteed by the parsed boolean AST."""
    if isinstance(condition, ConditionFieldEqualsValueExpression):
        if condition.field == "EventID" and isinstance(condition.value, SigmaNumber):
            return {int(condition.value.number)}
        return None
    if isinstance(condition, ConditionNOT):
        return None
    if isinstance(condition, ConditionAND):
        constrained = [
            result
            for child in condition.args
            if (result := _possible_event_ids(child)) is not None
        ]
        if not constrained:
            return None
        possible = set(constrained[0])
        for constraint in constrained[1:]:
            possible.intersection_update(constraint)
        return possible
    if isinstance(condition, ConditionOR):
        alternatives = [_possible_event_ids(child) for child in condition.args]
        if any(alternative is None for alternative in alternatives):
            return None
        return set().union(*(alternative or set() for alternative in alternatives))
    return None


def _condition_event_ids(sigma: SigmaRule) -> set[int] | None:
    alternatives = [
        _possible_event_ids(condition.parsed)
        for condition in sigma.detection.parsed_condition
    ]
    if not alternatives or any(alternative is None for alternative in alternatives):
        return None
    return set().union(*(alternative or set() for alternative in alternatives))


def _validate_ast(
    sigma: SigmaRule,
    mapping: dict[str, Any],
    target_binding: dict[str, Any],
) -> None:
    fields = mapping["fields"]
    condition_ids = _condition_event_ids(sigma)
    channels = target_binding["channels"]
    target_ids = set(target_binding["event_ids"])
    for item in _items(sigma):
        field = item.field
        field_info = DuckDBBackend(
            fields, service=target_binding.get("service")
        )._field(field)
        bad_modifiers = {
            modifier.__name__
            for modifier in item.modifiers
            if modifier.__name__ not in _SUPPORTED_MODIFIERS
        }
        if bad_modifiers:
            raise UnsupportedSigmaRule(
                f"Unsupported Sigma modifiers for {field}: {sorted(bad_modifiers)}"
            )
        allowed_channels = field_info.get("channels")
        if allowed_channels and not set(channels).issubset(set(allowed_channels)):
            raise UnsupportedSigmaRule(
                f"Sigma field {field} is not verified for channel(s) {channels}"
            )
        allowed_services = field_info.get("services")
        if allowed_services and target_binding["service"] not in allowed_services:
            raise UnsupportedSigmaRule(
                f"Sigma field {field} is not verified for service {target_binding['service']}"
            )
        allowed_ids = field_info.get("event_ids")
        scoped_ids = condition_ids or target_ids or None
        if allowed_ids and not scoped_ids:
            raise UnsupportedSigmaRule(
                f"Sigma field {field} requires an EventID-bound logsource"
            )
        if allowed_ids and scoped_ids and not scoped_ids.issubset(set(allowed_ids)):
            raise UnsupportedSigmaRule(
                f"Sigma field {field} is not verified for EventID(s) {sorted(scoped_ids)}"
            )
        for value in item.value:
            if isinstance(value, (SigmaExists, SigmaNull)):
                continue
            if isinstance(value, SigmaCompareExpression):
                if field_info["type"] != "number":
                    raise UnsupportedSigmaRule(
                        f"Numeric comparison is unsupported for string field {field}"
                    )
                continue
            if isinstance(value, SigmaBool):
                if field_info["type"] != "boolean":
                    raise UnsupportedSigmaRule(
                        f"Boolean Sigma value is unsupported for {field_info['type']} field {field}"
                    )
                continue
            if isinstance(value, SigmaNumber):
                if field_info["type"] != "number":
                    raise UnsupportedSigmaRule(
                        f"Numeric Sigma value is unsupported for {field_info['type']} field {field}"
                    )
                continue
            if isinstance(value, SigmaString):
                if field_info["type"] != "string":
                    raise UnsupportedSigmaRule(
                        f"String Sigma value is unsupported for {field_info['type']} field {field}"
                    )
                continue
            if isinstance(value, SigmaExpansion):
                if not all(
                    isinstance(expanded, SigmaString) for expanded in value.values
                ):
                    raise UnsupportedSigmaRule(
                        f"Unsupported expansion value type for {field}: {type(value).__name__}"
                    )
                continue
            raise UnsupportedSigmaRule(
                f"Unsupported Sigma value type for {field}: {type(value).__name__}"
            )


def _applied_pipeline_ids(pipelines: Iterable[ProcessingPipeline]) -> set[str]:
    return {item_id for pipeline in pipelines for item_id in pipeline.applied_ids}


def _target_specs(
    data: dict[str, Any], mapping: dict[str, Any]
) -> list[dict[str, Any]]:
    source = data.get("logsource")
    if not isinstance(source, dict) or source.get("product") != "windows":
        raise UnsupportedSigmaRule(f"Unsupported Sigma logsource: {source}")
    if source.get("service"):
        service = source["service"]
        channel = mapping["services"].get(service)
        provider = mapping.get("providers", {}).get(service)
        if channel is None or provider is None:
            raise UnsupportedSigmaRule(
                f"Windows service has no verified channel/provider binding: {service}"
            )
        return [
            {
                "key": service,
                "service": service,
                "channel": channel,
                "provider": provider,
            }
        ]
    if source.get("category"):
        # Each upstream target pipeline gets its own result, including its own
        # unsupported reason. This prevents a limitation on one target erasing
        # a valid sibling conversion.
        targets = [
            {"key": "security", "service": "security", "pipeline": "windows_audit"},
            {"key": "sysmon", "service": "sysmon", "pipeline": "sysmon"},
        ]
        probe = _parse_rule(deepcopy(data))
        logsource, _ = _windows_pipelines()
        logsource.apply(probe)
        service = probe.logsource.service if probe.logsource else None
        if service:
            targets.append({"key": service, "service": service})
        return targets
    raise UnsupportedSigmaRule("Sigma logsource requires one service or category")


def _target_pipelines(
    sigma: SigmaRule, target: dict[str, Any]
) -> list[ProcessingPipeline]:
    logsource, audit = _windows_pipelines()
    kind = target.get("pipeline")
    if kind == "windows_audit":
        pipelines = [logsource, audit]
    elif kind == "sysmon":
        from sigma.pipelines.sysmon import sysmon_pipeline

        pipelines = [sysmon_pipeline(), logsource]
    else:
        pipelines = [logsource]
    for pipeline in pipelines:
        pipeline.apply(sigma)
    if (
        not sigma.logsource
        or (target["service"] and sigma.logsource.service != target["service"])
        or not sigma.logsource.service
    ):
        raise UnsupportedSigmaRule(
            "Upstream pipeline does not map this category to a Windows service"
        )
    return pipelines


def _compile_target(
    data: dict[str, Any],
    target: dict[str, Any],
    mapping: dict[str, Any],
    *,
    source_uri: str = "",
) -> SigmaTargetCompilation:
    sigma_id = str(data.get("id") or "")
    target_key = str(target.get("key") or target.get("service") or "windows")
    service = target.get("service")
    channel = target.get("channel", mapping["services"].get(service))
    provider = target.get("provider", mapping.get("providers", {}).get(service))
    base_binding = {
        "product": "windows",
        "service": service,
        "category": (data.get("logsource") or {}).get("category"),
        "source_logsource": dict(data.get("logsource") or {}),
        "channels": [channel] if isinstance(channel, str) else list(channel or []),
        "providers": [provider] if isinstance(provider, str) else list(provider or []),
        "event_ids": [],
        "pipeline_ids": [],
        "target_key": target_key,
    }
    try:
        sigma = _parse_rule(deepcopy(data))
        pipelines = _target_pipelines(sigma, target)
        service = target["service"] or sigma.logsource.service
        target_key = target["key"] or service
        channel = target.get("channel", mapping["services"].get(service))
        provider = target.get("provider", mapping.get("providers", {}).get(service))
        if channel is None or provider is None:
            raise UnsupportedSigmaRule(
                f"Target {target_key} has no channel/provider contract"
            )
        channels = [channel] if isinstance(channel, str) else list(channel)
        providers = [provider] if isinstance(provider, str) else list(provider)
        provider_scopes = (
            [
                {"channel": channel_name, "provider": provider_name}
                for channel_name, provider_name in zip(channels, providers, strict=True)
            ]
            if len(channels) == len(providers) and len(channels) > 1
            else []
        )
        event_ids = _condition_event_ids(sigma)
        binding = {
            "product": "windows",
            "service": service,
            "category": (data.get("logsource") or {}).get("category"),
            "source_logsource": dict(data.get("logsource") or {}),
            "channels": channels,
            "providers": providers,
            "provider_scopes": provider_scopes,
            "provider_event_ids": mapping.get("provider_event_ids", {}).get(
                service, {}
            ),
            "event_ids": sorted(event_ids or []),
            "pipeline_ids": sorted(_applied_pipeline_ids(pipelines)),
            "target_key": target_key,
        }
        _validate_ast(sigma, mapping, binding)
        predicates = DuckDBBackend(mapping["fields"], service=service).convert_rule(
            sigma
        )
        if len(predicates) != 1 or not sigma.id:
            raise UnsupportedSigmaRule(
                "Sigma requires an ID and exactly one executable condition"
            )
        provider_expression = "json_extract_string(raw_json, '$.winlog.provider.name')"
        provider_event_ids = mapping.get("provider_event_ids", {}).get(service, {})
        if provider_scopes:
            filters = [
                "("
                + " OR ".join(
                    "(channel = "
                    + _literal(scope["channel"])
                    + " AND "
                    + provider_expression
                    + " = "
                    + _literal(scope["provider"])
                    + ")"
                    for scope in provider_scopes
                )
                + ")"
            ]
        else:
            filters = [
                "channel IN (" + ", ".join(_literal(value) for value in channels) + ")"
            ]
        if not provider_scopes and not provider_event_ids and providers:
            filters.append(
                provider_expression
                + " IN ("
                + ", ".join(_literal(value) for value in providers)
                + ")"
            )
        elif not provider_scopes and provider_event_ids:
            alternatives = []
            specially_scoped = set().union(
                *(set(ids) for ids in provider_event_ids.values())
            )
            for provider_name, provider_ids in provider_event_ids.items():
                matching_ids = sorted(
                    set(provider_ids)
                    if event_ids is None
                    else set(event_ids) & set(provider_ids)
                )
                if matching_ids:
                    alternatives.append(
                        "("
                        + provider_expression
                        + " = "
                        + _literal(provider_name)
                        + " AND event_id IN ("
                        + ", ".join(map(str, matching_ids))
                        + "))"
                    )
            default_providers = [
                value for value in providers if value not in provider_event_ids
            ]
            default_ids = (
                sorted(set(event_ids) - specially_scoped)
                if event_ids is not None
                else []
            )
            if (default_ids or event_ids is None) and default_providers:
                alternatives.append(
                    "("
                    + provider_expression
                    + " IN ("
                    + ", ".join(_literal(value) for value in default_providers)
                    + ") AND "
                    + (
                        "event_id IN (" + ", ".join(map(str, default_ids)) + ")"
                        if event_ids is not None
                        else "event_id NOT IN ("
                        + ", ".join(map(str, sorted(specially_scoped)))
                        + ")"
                    )
                    + ")"
                )
            if alternatives:
                filters.append("(" + " OR ".join(alternatives) + ")")
            else:
                raise UnsupportedSigmaRule(
                    "No provider matches the constrained EventID set"
                )
        if event_ids:
            filters.append(
                "event_id IN (" + ", ".join(map(str, sorted(event_ids))) + ")"
            )
        description = sigma.description or sigma.title
        author = str(sigma.author or "not supplied")
        query = (
            "SELECT evidence_id, source_file, timestamp, channel, event_id, computer, "
            "target_user, subject_user, src_ip, process_name, command_line, service_name, "
            f"{_literal(sigma.title)} AS sigma_title, "
            f"{_literal(description)} AS sigma_description, "
            f"{_literal(author)} AS sigma_author, "
            f"{_literal(source_uri)} AS sigma_source FROM evtx_events WHERE "
            + " AND ".join(filters)
            + f" AND ({predicates[0]}) ORDER BY timestamp NULLS LAST, evidence_id"
        )
        rule = Rule(
            id=f"sigma-{sigma.id}-{target_key}",
            title=sigma.title,
            rule_format="sigma",
            severity=sigma.level.name.lower() if sigma.level else "medium",
            confidence=0.5,
            required_fields=["evidence_id"],
            query=query,
            finding=FindingTemplate(
                title="{sigma_title}",
                summary=(
                    "{sigma_description} Rule match is an investigative lead; validate intent and context. "
                    "Author: {sigma_author}. Source: {sigma_source}."
                ),
            ),
            tags=[str(tag) for tag in sigma.tags],
        )
        return SigmaTargetCompilation(target_key, binding, sigma_id, rule, "converted")
    except UnsupportedSigmaRule as exc:
        return SigmaTargetCompilation(
            target_key,
            base_binding,
            sigma_id,
            None,
            "unsupported",
            "unsupported_semantics",
            str(exc),
        )
    except RuntimeError as exc:
        return SigmaTargetCompilation(
            target_key,
            base_binding,
            sigma_id,
            None,
            "failed",
            "pipeline_dependency_missing",
            str(exc),
        )
    except (
        NotImplementedError,
        SigmaFeatureNotSupportedByBackendError,
        SigmaTransformationError,
    ) as exc:
        return SigmaTargetCompilation(
            target_key,
            base_binding,
            sigma_id,
            None,
            "unsupported",
            "unsupported_semantics",
            str(exc),
        )
    except ValueError as exc:
        return SigmaTargetCompilation(
            target_key, base_binding, sigma_id, None, "failed", "parse_error", str(exc)
        )


def compile_sigma_targets(
    data: dict[str, Any], *, source_uri: str = ""
) -> list[SigmaTargetCompilation]:
    """Compile every candidate telemetry target independently."""
    mapping = _mapping()
    try:
        targets = _target_specs(data, mapping)
    except UnsupportedSigmaRule as exc:
        source = (
            data.get("logsource") if isinstance(data.get("logsource"), dict) else {}
        )
        key = str(source.get("service") or source.get("category") or "windows")
        return [
            SigmaTargetCompilation(
                key,
                {"source_logsource": dict(source)},
                str(data.get("id") or ""),
                None,
                "unsupported",
                "unsupported_logsource",
                str(exc),
            )
        ]
    return [
        _compile_target(data, target, mapping, source_uri=source_uri)
        for target in targets
    ]
