from __future__ import annotations

from typing import Any

SNAKE_CASE_COLUMNS: list[str] = [
    "computer", "target_user", "src_ip", "logon_type", "auth_package",
    "process_name", "command_line", "parent_process", "file_path",
    "file_name", "service_name", "service_type", "image_path",
    "task_name", "task_content", "account_name", "target_domain",
    "subject_user_name", "failure_reason", "status", "sub_status",
    "event_id", "timestamp", "session_id", "share_name", "access_mask",
    "object_name", "object_type", "registry_path", "evidence_id",
    "executable_name", "exec_count", "last_exec_time",
    "host_id", "date", "startup", "logons", "logoff", "shutdown",
]

DEFAULT_AUDITED_EVENT_IDS: list[int] = [
    4624, 4625, 4634, 4647, 4648, 4672, 4673, 4688,
    4697, 4698, 4699, 4700, 4701, 4702, 4720, 4722,
    4723, 4724, 4726, 4728, 4729, 4730, 4732, 4733,
    4734, 4735, 4737, 4738, 4740, 4768, 4769, 4776,
    4778, 4779, 5140, 5156, 5157, 7036, 7040, 7045,
    1102, 104, 1100,
]

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
            "minItems": 1,
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
    },
}

FINDING_EXTRACTOR_SCHEMA: dict[str, Any] = {
    "title": "FindingExtractor",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "new_hypotheses": {"type": "array", "items": {"type": "object"}},
        "new_findings": {"type": "array", "items": {"type": "object"}},
        "finding_title": {"type": "string"},
        "finding_summary": {"type": "string"},
        "finding_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "suspicious_evidence_report": {"type": "string"},
    },
}

MEMORY_UPDATER_SCHEMA: dict[str, Any] = {
    "title": "MemoryUpdater",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "memory_updates": {
            "type": "object",
            "properties": {
                "facts": {"type": "array", "items": {"type": "object"}},
                "timeline": {"type": "array", "items": {"type": "object"}},
                "tasks": {"type": "array", "items": {"type": "object"}},
                "overview": {"type": "array", "items": {"type": "string"}},
                "refuted_hypotheses": {"type": "array", "items": {"type": "object"}},
                "resolved_gaps": {"type": "array", "items": {"type": "object"}},
                "entities": {"type": "array", "items": {"type": "object"}},
            },
        },
        "new_hypotheses": {"type": "array", "items": {"type": "object"}},
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


def hypothesis_drafter_schema() -> dict[str, Any]:
    return {
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
                    "description": {"type": "string", "minLength": 30},
                    "required_entities": {"type": "array", "items": {"enum": SNAKE_CASE_COLUMNS}},
                    "source_rule_ids": {"type": "array", "items": {"type": "string"}},
                    "confirm_when": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "co_observed_event_ids": {
                                "type": "array",
                                "items": {"enum": DEFAULT_AUDITED_EVENT_IDS},
                            },
                            "same_host": {"type": "boolean"},
                            "within_minutes": {"type": "integer"},
                        },
                    },
                    "refute_when": {"type": "object"},
                },
            },
        },
    }


SECTION_AGENT_PLAN_SCHEMA: dict[str, Any] = {
    "title": "SectionAgentPlan",
    "type": "object",
    "additionalProperties": False,
    "required": ["action", "enough_to_write"],
    "properties": {
        "action": {"enum": ["sql", "template", "keypoint", "facts", "write"]},
        "keypoint": {"type": "string"},
        "sql": {"type": "string"},
        "template_id": {"type": "string"},
        "params": {"type": "object"},
        "purpose": {"type": "string"},
        "enough_to_write": {"type": "boolean"},
    },
}

SECTION_OUTLINE_SCHEMA: dict[str, Any] = {
    "title": "SectionOutline",
    "type": "object",
    "additionalProperties": False,
    "required": ["outline"],
    "properties": {
        "outline": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["heading", "key_points", "evidence_ids"],
                "additionalProperties": False,
                "properties": {
                    "heading": {"type": "string"},
                    "key_points": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
}

SECTION_AGENT_CHECK_SCHEMA: dict[str, Any] = {
    "title": "SectionAgentCheck",
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict"],
    "properties": {
        "verdict": {"enum": ["block_supported", "block_contradicted", "partial", "needs_more"]},
        "rationale": {"type": "string"},
        "missing_questions": {"type": "array", "items": {"type": "string"}},
    },
}

SQL_SELF_CHECK_SCHEMA: dict[str, Any] = {
    "title": "SQLSelfCheck",
    "type": "object",
    "additionalProperties": False,
    "required": ["ready_to_compose", "target_table_exists", "missing_columns", "blockers"],
    "properties": {
        "ready_to_compose": {"type": "boolean"},
        "target_table_exists": {"type": "boolean"},
        "required_columns_present": {"type": "array", "items": {"type": "string"}},
        "missing_columns": {"type": "array", "items": {"type": "string"}},
        "join_keys": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "left_table": {"type": "string"},
                    "left_col": {"type": "string"},
                    "right_table": {"type": "string"},
                    "right_col": {"type": "string"},
                },
            },
        },
        "time_column": {"type": "string"},
        "blockers": {"type": "string"},
    },
}

PARAGRAPH_NARRATE_SCHEMA: dict[str, Any] = {
    "title": "ParagraphNarrate",
    "type": "object",
    "additionalProperties": False,
    "required": ["body"],
    "properties": {
        "body": {"type": "string", "minLength": 50},
    },
}


def benchmark_classify_schema(n_rows: int) -> dict[str, Any]:
    return {
        "title": "BenchmarkClassifier",
        "type": "object",
        "additionalProperties": False,
        "required": ["status", "picked_row_indices"],
        "properties": {
            "status": {
                "type": "string",
                "enum": ["answered", "partial", "not_found", "not_searched", "wrong_query"],
            },
            "picked_row_indices": {
                "type": "array",
                "items": {"type": "integer", "minimum": 0, "maximum": max(0, n_rows - 1)},
            },
            "rationale": {"type": "string"},
        },
    }
