"""JSON schemas passed to the LLM for structured (schema-constrained) responses."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class SQLQueryAction(BaseModel):
    """The intent-to-SQL operation selectable by the hypothesis planner.

    One model response chooses exactly one bounded execution path:

    * a recipe (``template_id`` + ``params``) rendered from the catalog, with
      ``sql`` set to an empty string, or
    * a bounded ``sql`` fallback written directly by the model, with
      ``template_id`` set to null.

    The host validates the chosen path deterministically before execution
    (SELECT-only, table/column allow-list, row-limit, dry-run).
    """

    model_config = ConfigDict(extra="forbid")

    intent: str = Field(min_length=1)
    target_table: str = Field(min_length=1)
    # Recipe path: a bounded template id chosen from the catalog.
    template_id: str | None = Field(
        default=None,
        description="Set a non-empty template ID for template execution; set null for raw SQL.",
    )
    params: dict[str, Any] = Field(default_factory=dict)
    # Fallback path: a bounded SELECT written directly by the model.
    sql: str = Field(
        default="",
        description="Empty when template_id is set (whitespace-only is also empty to the host); otherwise a non-blank bounded SELECT.",
    )

    @model_validator(mode="after")
    def _one_execution_path(self) -> SQLQueryAction:
        if bool(self.template_id) == bool(self.sql.strip()):
            raise ValueError("Choose exactly one of template_id or bounded SELECT")
        if self.template_id and "params" not in self.model_fields_set:
            raise ValueError("params is required for template execution")
        if self.sql.strip() and "params" in self.model_fields_set:
            raise ValueError("params is only valid for template execution")
        return self


class QuestionScopeFilter(BaseModel):
    """A literal subject or time constraint stated by the question."""

    model_config = ConfigDict(extra="forbid")

    family: str = Field(min_length=1)
    field: str = Field(min_length=1)
    operator: Literal["equals", "greater_than", "less_than", "path_under"] = Field(
        description=(
            "Use equals for exact values. path_under selects descendants of a "
            "directory and is available only on artifact fields declared for it."
        )
    )
    value: str | int | float | bool


class QuestionRequirement(BaseModel):
    """One requested value, or one proposition with a known expected value."""

    model_config = ConfigDict(extra="forbid")

    family: str = Field(min_length=1)
    field: str = Field(min_length=1)
    kind: Literal["observed_value", "predicate"]
    operator: Literal["equals", "contains", "greater_than"] | None = None
    value: str | int | float | bool | None = None

    @model_validator(mode="after")
    def _predicate_has_expected_value(self) -> QuestionRequirement:
        if self.kind == "predicate" and (self.operator is None or self.value is None):
            raise ValueError("predicate requires operator and value")
        if self.kind == "observed_value" and (
            self.operator is not None or self.value is not None
        ):
            raise ValueError("observed_value must leave its value unknown")
        return self


class QuestionRequestContract(BaseModel):
    """Question meaning fixed before discovery sees any candidate records."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["resolved", "unresolved"]
    scope_filters: list[QuestionScopeFilter] = Field(default_factory=list)
    requirements: list[QuestionRequirement] = Field(default_factory=list)

    @model_validator(mode="after")
    def _resolved_request_has_requirements(self) -> QuestionRequestContract:
        if self.status == "resolved" and not self.requirements:
            raise ValueError("resolved request requires at least one requirement")
        if self.status == "unresolved" and self.requirements:
            raise ValueError("unresolved request cannot carry requirements")
        return self


class QueryIntentResponse(BaseModel):
    """The complete planner response: exactly one bounded action."""

    model_config = ConfigDict(extra="forbid")

    action: SQLQueryAction
    request_contract: QuestionRequestContract | None = None


QUERY_INTENT_SCHEMA: dict[str, Any] = QueryIntentResponse.model_json_schema()

# Pydantic's after-validator is a host-side check and is not present in its
# generated schema. Add the same mutually exclusive execution paths to the
# schema sent to the planner. The response-format wrapper passes this generated
# schema through unchanged; the two ``anyOf`` branches are disjoint, so exactly
# one can match. Every SQL action property is required in each branch so the
# unused path is explicit on the wire.
_sql_action_schema = QUERY_INTENT_SCHEMA["$defs"]["SQLQueryAction"]
_sql_properties = _sql_action_schema["properties"]
_sql_required = list(_sql_properties)
_sql_action_schema["required"] = [key for key in _sql_required if key != "params"]
_sql_action_schema["anyOf"] = []
for _template_mode in (True, False):
    _branch_properties = dict(_sql_properties)
    if _template_mode:
        _branch_properties["template_id"] = {
            "type": "string",
            "minLength": 1,
            "pattern": r"^[\s\S]*\S[\s\S]*$",
            "description": _sql_properties["template_id"]["description"],
        }
        _branch_properties["sql"] = {
            "type": "string",
            "pattern": r"^\s*$",
            "description": _sql_properties["sql"]["description"],
        }
        _branch_properties["params"] = _sql_properties["params"]
    else:
        _branch_properties["template_id"] = {
            "type": "null",
            "description": _sql_properties["template_id"]["description"],
        }
        _branch_properties["sql"] = {
            "type": "string",
            "pattern": r"^[\s\S]*\S[\s\S]*$",
            "description": _sql_properties["sql"]["description"],
        }
        _branch_properties.pop("params")
    _sql_action_schema["anyOf"].append(
        {
            "type": "object",
            "additionalProperties": False,
            "required": [
                key for key in _sql_required if _template_mode or key != "params"
            ],
            "properties": _branch_properties,
        }
    )


def query_intent_schema_for_catalog(
    tables: list[str] | tuple[str, ...],
    template_ids: list[str] | tuple[str, ...],
    *,
    require_request_contract: bool = False,
) -> dict[str, Any]:
    """Narrow the planner's structured action to its disclosed work catalog."""
    schema = deepcopy(QUERY_INTENT_SCHEMA)
    if require_request_contract:
        from forensia.db.evidence_lookup import canonical_record_table
        from forensia.knowledge.coverage import observation_catalog
        from forensia.knowledge.questions import question_directory_scope_fields

        catalog = observation_catalog()
        family_fields = {
            family: details["fields"]
            for family, details in catalog.items()
            if canonical_record_table(family) in tables
        }
        scope_definition = schema["$defs"]["QuestionScopeFilter"]
        scope_properties = scope_definition["properties"]
        scope_required = list(scope_properties)
        scope_definition.clear()
        scope_definition.update(
            {
                "title": "QuestionScopeFilter",
                "description": "A literal subject or time constraint stated by the question.",
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": scope_required,
                        "properties": {
                            **deepcopy(scope_properties),
                            "family": {"const": family},
                            "field": {"type": "string", "enum": sorted(fields)},
                            "operator": {
                                "enum": ["equals", "greater_than", "less_than"]
                            },
                        },
                    }
                    for family, fields in family_fields.items()
                ]
                + [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": scope_required,
                        "properties": {
                            **deepcopy(scope_properties),
                            "family": {"const": family},
                            "field": {
                                "type": "string",
                                "enum": sorted(question_directory_scope_fields(family)),
                            },
                            "operator": {"const": "path_under"},
                            "value": {"type": "string"},
                        },
                    }
                    for family in family_fields
                    if question_directory_scope_fields(family)
                ],
            }
        )

        requirement_definition = schema["$defs"]["QuestionRequirement"]
        requirement_properties = requirement_definition["properties"]
        requirement_definition.clear()
        requirement_definition.update(
            {
                "title": "QuestionRequirement",
                "description": "One requested value, or one proposition with a known expected value.",
                "oneOf": [],
            }
        )
        non_null_operator = deepcopy(requirement_properties["operator"])
        non_null_operator["anyOf"] = [
            branch
            for branch in non_null_operator["anyOf"]
            if branch.get("type") != "null"
        ]
        non_null_operator.pop("default", None)
        non_null_value = deepcopy(requirement_properties["value"])
        non_null_value["anyOf"] = [
            branch for branch in non_null_value["anyOf"] if branch.get("type") != "null"
        ]
        non_null_value.pop("default", None)
        for family, fields in family_fields.items():
            for kind in ("observed_value", "predicate"):
                branch_properties = deepcopy(requirement_properties)
                branch_properties.update(
                    {
                        "family": {"const": family},
                        "field": {"type": "string", "enum": sorted(fields)},
                        "kind": {
                            "type": "string",
                            "const": kind,
                            "title": requirement_properties["kind"]["title"],
                        },
                    }
                )
                if kind == "observed_value":
                    branch_required = ["family", "field", "kind"]
                    for name in ("operator", "value"):
                        annotations = {
                            key: requirement_properties[name][key]
                            for key in ("title", "description")
                            if key in requirement_properties[name]
                        }
                        branch_properties[name] = {
                            **annotations,
                            "type": "null",
                        }
                else:
                    branch_required = [
                        "family",
                        "field",
                        "kind",
                        "operator",
                        "value",
                    ]
                    branch_properties["operator"] = non_null_operator
                    branch_properties["value"] = non_null_value
                requirement_definition["oneOf"].append(
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": branch_required,
                        "properties": branch_properties,
                    }
                )

        contract = schema["$defs"]["QuestionRequestContract"]
        contract_properties = contract["properties"]
        scope_items = scope_definition["oneOf"]
        requirement_items = requirement_definition["oneOf"]
        unresolved = {
            "type": "object",
            "additionalProperties": False,
            "required": ["status", "scope_filters", "requirements"],
            "properties": {
                "status": {"const": "unresolved"},
                "scope_filters": contract_properties["scope_filters"],
                "requirements": {
                    **contract_properties["requirements"],
                    "maxItems": 0,
                },
            },
        }
        contract.clear()
        contract.update(
            {
                "title": "QuestionRequestContract",
                "description": "Question meaning fixed before discovery sees any candidate records.",
                "oneOf": [
                    *[
                        {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["status", "scope_filters", "requirements"],
                            "properties": {
                                "status": {"const": "resolved"},
                                "scope_filters": {
                                    **contract_properties["scope_filters"],
                                    "items": {
                                        "oneOf": [
                                            branch
                                            for branch in scope_items
                                            if branch["properties"]["family"]["const"]
                                            == family
                                        ]
                                    },
                                },
                                "requirements": {
                                    **contract_properties["requirements"],
                                    "minItems": 1,
                                    "items": {
                                        "oneOf": [
                                            branch
                                            for branch in requirement_items
                                            if branch["properties"]["family"]["const"]
                                            == family
                                        ]
                                    },
                                },
                            },
                        }
                        for family in family_fields
                    ],
                    unresolved,
                ],
            }
        )
        schema["required"].append("request_contract")
        schema["properties"]["request_contract"] = {
            "$ref": "#/$defs/QuestionRequestContract"
        }
    else:
        schema["properties"].pop("request_contract", None)
        for definition in (
            "QuestionRequestContract",
            "QuestionRequirement",
            "QuestionScopeFilter",
        ):
            schema["$defs"].pop(definition, None)
    action = schema["$defs"]["SQLQueryAction"]
    table_enum = list(dict.fromkeys(str(table) for table in tables))
    template_enum = list(dict.fromkeys(str(item) for item in template_ids))
    action["properties"]["target_table"]["enum"] = table_enum
    action["properties"]["template_id"]["enum"] = [*template_enum, None]
    for branch in action["anyOf"]:
        branch_props = branch["properties"]
        branch_props["target_table"]["enum"] = table_enum
        if branch_props["template_id"].get("type") == "string":
            branch_props["template_id"]["enum"] = template_enum
        else:
            branch_props["template_id"]["enum"] = [None]
    if not template_enum:
        raw_branch = action.pop("anyOf")[-1]
        action.update(raw_branch)
    return schema


SNAKE_CASE_COLUMNS: list[str] = [
    "computer",
    "target_user",
    "src_ip",
    "logon_type",
    "auth_package",
    "process_name",
    "command_line",
    "parent_process",
    "file_path",
    "file_name",
    "service_name",
    "service_type",
    "image_path",
    "task_name",
    "task_content",
    "account_name",
    "target_domain",
    "subject_user_name",
    "failure_reason",
    "status",
    "sub_status",
    "event_id",
    "timestamp",
    "session_id",
    "share_name",
    "access_mask",
    "object_name",
    "object_type",
    "registry_path",
    "evidence_id",
    "executable_name",
    "exec_count",
    "last_exec_time",
    "host_id",
    "date",
    "startup",
    "logons",
    "logoff",
    "shutdown",
]

DEFAULT_AUDITED_EVENT_IDS: list[int] = [
    4624,
    4625,
    4634,
    4647,
    4648,
    4672,
    4673,
    4688,
    4697,
    4698,
    4699,
    4700,
    4701,
    4702,
    4720,
    4722,
    4723,
    4724,
    4725,
    4726,
    4727,
    4728,
    4729,
    4730,
    4732,
    4733,
    4734,
    4735,
    4737,
    4738,
    4740,
    4768,
    4769,
    4776,
    4778,
    4779,
    5140,
    5156,
    5157,
    7036,
    7040,
    7045,
    1102,
    104,
    1100,
]


def _verification_declaration_fields() -> dict[str, Any]:
    """Return the same declaration schema used by hypothesis drafting."""
    return {
        "confirm_when": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "co_observed_event_ids": {
                    "type": "array",
                    "items": {"enum": DEFAULT_AUDITED_EVENT_IDS},
                },
                "event_contexts": {
                    "type": "array",
                    "description": (
                        "Optional catalog-qualified context for each event ID; "
                        "required when channel/provider changes event semantics."
                    ),
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["event_id", "channel", "provider"],
                        "properties": {
                            "event_id": {"type": "integer"},
                            "channel": {"type": "string"},
                            "provider": {"type": "string"},
                        },
                    },
                },
                "observation": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "family",
                        "capability",
                        "field",
                        "operator",
                        "value",
                    ],
                    "properties": {
                        "family": {"type": "string", "minLength": 1},
                        "capability": {"type": "string", "minLength": 1},
                        "field": {"type": "string", "minLength": 1},
                        "operator": {"enum": ["equals", "contains", "greater_than"]},
                        "value": {
                            "anyOf": [
                                {"type": "string", "minLength": 1},
                                {"type": "number"},
                                {"type": "boolean"},
                            ]
                        },
                    },
                },
                "same_host": {"type": "boolean"},
                "within_minutes": {"type": "integer"},
                "same_entities": {
                    "type": "array",
                    "items": {"enum": SNAKE_CASE_COLUMNS},
                },
                "min_count": {"type": "integer", "minimum": 1},
            },
        },
        "refute_when": {"type": "object"},
    }


VERDICT_REVIEW_SCHEMA: dict[str, Any] = {
    "title": "VerdictReview",
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "rationale", "missing_questions"],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "inconclusive", "refuted", "newlead"],
        },
        "rationale": {"type": "string", "minLength": 20},
        "missing_questions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Non-empty only when verdict is inconclusive.",
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "new_hypotheses": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["description"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "description": {"type": "string", "minLength": 1},
                    "required_entities": {
                        "type": "array",
                        "maxItems": 8,
                        "items": {"type": "string"},
                    },
                    "source_rule_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    **_verification_declaration_fields(),
                },
            },
        },
    },
}

FINDING_EXTRACTOR_SCHEMA: dict[str, Any] = {
    "title": "FindingExtractor",
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                    },
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    "claim_type": {
                        "type": "string",
                        "enum": ["observation", "interpretation"],
                    },
                },
                "required": ["title", "severity", "evidence_ids", "claim_type"],
            },
        },
    },
}


def gap_identifier_schema(available_keypoints: list[str]) -> dict[str, Any]:
    return {
        "title": "GapIdentifier",
        "type": "object",
        "additionalProperties": False,
        "required": ["gap_areas"],
        "properties": {
            "gap_areas": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["keypoint_id", "why_uncovered"],
                    "additionalProperties": False,
                    "properties": {
                        "keypoint_id": {"enum": available_keypoints},
                        "why_uncovered": {"type": "string"},
                        "required_entities": {
                            "type": "array",
                            "items": {"enum": SNAKE_CASE_COLUMNS},
                        },
                    },
                },
            },
        },
    }


def hypothesis_drafter_schema(
    *,
    observation_only: bool = False,
    allowed_entities: list[str] | None = None,
) -> dict[str, Any]:
    schema = {
        "title": "HypothesisDrafter",
        "type": "object",
        "additionalProperties": False,
        "required": ["hypothesis"],
        "properties": {
            "hypothesis": {
                "type": "object",
                "required": ["description", "required_entities", "confirm_when"],
                "additionalProperties": False,
                "properties": {
                    "description": {
                        "type": "string",
                        "minLength": 30,
                    },
                    "required_entities": {
                        "type": "array",
                        "items": {
                            "enum": allowed_entities
                            if allowed_entities
                            else SNAKE_CASE_COLUMNS
                        },
                    },
                    "source_rule_ids": {"type": "array", "items": {"type": "string"}},
                    **_verification_declaration_fields(),
                },
            },
        },
    }
    confirm = schema["properties"]["hypothesis"]["properties"]["confirm_when"]
    required_entities = schema["properties"]["hypothesis"]["properties"][
        "required_entities"
    ]
    if allowed_entities == []:
        required_entities["maxItems"] = 0
    if observation_only:
        hypothesis_schema = schema["properties"]["hypothesis"]
        hypothesis_schema["required"].remove("description")
        hypothesis_schema["properties"].pop("description")
        confirm_properties = confirm["properties"]
        confirm["properties"] = {
            key: value
            for key, value in confirm_properties.items()
            if key in {"min_count", "observation"}
        }
        if "observation" in confirm["properties"]:
            confirm["required"] = ["observation"]
    return schema


PARAGRAPH_NARRATE_SCHEMA: dict[str, Any] = {
    "title": "ParagraphNarrate",
    "type": "object",
    "additionalProperties": False,
    "required": ["body"],
    "properties": {
        "body": {"type": "string", "minLength": 50},
    },
}


def question_classify_schema(n_rows: int) -> dict[str, Any]:
    return {
        "title": "BenchmarkClassifier",
        "type": "object",
        "additionalProperties": False,
        "required": ["status", "picked_row_indices"],
        "properties": {
            "status": {
                "type": "string",
                "enum": [
                    "answered",
                    "partial",
                    "not_found",
                    "not_searched",
                    "wrong_query",
                ],
            },
            "picked_row_indices": {
                "type": "array",
                "items": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": max(0, n_rows - 1),
                },
            },
            "rationale": {"type": "string"},
        },
    }


def structured_classify_schema(n_rows: int) -> dict[str, Any]:
    schema = question_classify_schema(n_rows)
    schema["title"] = "StructuredClassifier"
    return schema
