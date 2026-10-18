from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from typing import Any

import sqlglot
import yaml
from sqlglot import exp

from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import canonical_record_table
from forensia.db.query import normalize_value
from forensia.knowledge.catalog import load_schema_hints
from forensia.knowledge.coverage import observation_catalog
from forensia.knowledge.resources import schema_dir

# Aliases normalised to the canonical structured_status vocabulary.
_STATUS_ALIASES = {
    "not_observable": "unobservable",
    "no_observation": "unobservable",
    "unobservble": "unobservable",
}


@lru_cache(maxsize=1)
def _valid_structured_statuses() -> frozenset[str]:
    """Return the canonical structured_status values from the YAML taxonomy."""
    from forensia.core.verdicts import valid_verdicts

    return frozenset(valid_verdicts("structured_status"))


def normalize_structured_status(status: str) -> str:
    """Normalise a raw status string to a canonical structured status."""
    value = str(status or "").strip().lower()
    if value in _STATUS_ALIASES:
        return _STATUS_ALIASES[value]
    return value


def _schema_dir() -> Path:
    # The packaged catalog is independent from Python module locations.
    return schema_dir()


def gap_operational_reason(db: CaseDB, gap_id: str) -> str | None:
    """Project the latest typed broad-draft outcome as a stable status code."""
    row = db.execute(
        "SELECT output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-candidate' "
        "AND json_extract_string(input_json, '$.gap_id') = ? "
        "ORDER BY created_at DESC, step_id DESC LIMIT 1",
        [gap_id],
    ).fetchone()
    if not row:
        return None
    output = row[0]
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            return None
    if not isinstance(output, dict):
        return None
    if output.get("status") in {"attempting", "correcting"}:
        return "investigation_attempt_in_progress"
    if output.get("error_type"):
        return "investigation_attempt_failed"
    return None


def _clean_text(value: Any) -> str:
    text = str(value or "").casefold()
    text = text.replace("_", " ").replace("-", " ")
    return " ".join(re.split(r"\s+", text)).strip()


def strip_section_instructions(question_text: str) -> str:
    """Remove injected section-wide prose before interpreting question scope."""
    return re.sub(
        r"<!--\s*section_instructions\s*:.*?-->\s*",
        "",
        str(question_text or ""),
        flags=re.IGNORECASE | re.DOTALL,
    )


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    text = str(value or "").strip()
    return (text,) if text else ()


def _coerce_dict_list(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, dict))


def verification_spec_payload(raw: Any) -> dict[str, Any]:
    """Return the mapping form of a stored verification specification."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _same_observed_value(actual: Any, expected: Any) -> bool:
    actual_is_datetime = isinstance(actual, datetime)
    expected_is_datetime = isinstance(expected, datetime)
    actual, expected = normalize_value(actual), normalize_value(expected)
    if isinstance(actual, bool) or isinstance(expected, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and actual is expected
        )
    numeric_types = (int, float, Decimal)
    if isinstance(actual, numeric_types) and isinstance(expected, numeric_types):
        return actual == expected
    if isinstance(actual, str) and isinstance(expected, str):
        if actual_is_datetime or expected_is_datetime:

            def as_utc(value: str) -> datetime:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return (
                    parsed.replace(tzinfo=UTC)
                    if parsed.utcoffset() is None
                    else parsed.astimezone(UTC)
                )

            try:
                return as_utc(actual) == as_utc(expected)
            except ValueError:
                return False
        return actual.strip().casefold() == expected.strip().casefold()
    return type(actual) is type(expected) and actual == expected


def question_contract_match_reason(
    contract: dict[str, Any] | None,
    verification_spec: Any,
    *,
    observation_records: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Check that a verification spec contains a typed observation for a request."""
    if not isinstance(contract, dict):
        return "question_contract_invalid"
    requirements = contract.get("requirements")
    if contract.get("status") != "resolved" or not isinstance(requirements, list):
        return "question_scope_unresolved"
    conditions = (
        verification_spec.get("support_conditions", {})
        if isinstance(verification_spec, dict)
        else getattr(verification_spec, "support_conditions", {})
    )
    observation = (
        conditions.get("observation") if isinstance(conditions, dict) else None
    )
    if not isinstance(observation, dict):
        return "question_contract_requires_typed_observation"
    matched_observation = False
    for requirement in requirements:
        if not isinstance(requirement, dict):
            return "question_contract_invalid"
        same_field = str(requirement.get("family") or "").strip().casefold() == str(
            observation.get("family") or ""
        ).strip().casefold() and str(requirement.get("field") or "") == str(
            observation.get("field") or ""
        )
        if not same_field:
            continue
        if requirement.get("kind") == "observed_value":
            operator = observation.get("operator")
            if operator not in {"equals", "contains"}:
                continue
            if observation_records is not None:
                ids = observation.get("evidence_ids")
                if (
                    not isinstance(ids, list)
                    or not ids
                    or any(not isinstance(evidence_id, str) for evidence_id in ids)
                ):
                    continue
                selected_records = [
                    observation_records.get(str(evidence_id))
                    for evidence_id in dict.fromkeys(ids)
                ]
                selected_records = [
                    record for record in selected_records if isinstance(record, dict)
                ]
                expected = observation.get("value")
                matching_count = 0
                for record in selected_records:
                    if requirement["field"] not in record:
                        continue
                    actual = record[requirement["field"]]
                    if isinstance(actual, str):
                        actual = normalize_value(actual)
                    if isinstance(actual, (list, tuple, set)):
                        matches = operator == "contains" and any(
                            _same_observed_value(item, expected) for item in actual
                        )
                    else:
                        matches = operator == "equals" and _same_observed_value(
                            actual, expected
                        )
                    matching_count += bool(matches)
                min_count = conditions.get("min_count", 1)
                if (
                    not isinstance(min_count, int)
                    or isinstance(min_count, bool)
                    or min_count < 1
                    or matching_count < min_count
                ):
                    continue
            matched_observation = True
        elif requirement.get("operator") == observation.get(
            "operator"
        ) and requirement.get("value") == observation.get("value"):
            matched_observation = True
    return None if matched_observation else "question_contract_observation_mismatch"


def question_scope_evidence_ids(
    db: CaseDB,
    contract: dict[str, Any],
    *,
    max_rows: int = 1000,
    evidence_ids: list[str] | None = None,
) -> tuple[list[str], bool]:
    """Return the current canonical evidence IDs matching a frozen request scope."""
    requirements = contract.get("requirements")
    filters = contract.get("scope_filters", [])
    if contract.get("status") != "resolved" or not isinstance(requirements, list):
        raise ValueError("question_scope_contract_unresolved")
    families = {
        str(item.get("family") or "").strip().casefold()
        for item in requirements
        if isinstance(item, dict)
    }
    if len(families) != 1 or "" in families:
        raise ValueError("question_scope_requires_one_artifact_family")
    family = next(iter(families))
    catalog = observation_catalog().get(family)
    table = canonical_record_table(family)
    if not catalog or not table:
        raise ValueError("question_scope_family_unsupported")
    allowed_fields = set(catalog["fields"])
    for item in requirements:
        if not isinstance(item, dict) or item.get("field") not in allowed_fields:
            raise ValueError("question_scope_requirement_field_unsupported")
    if not isinstance(filters, list):
        raise ValueError("question_scope_filters_invalid")
    id_column = "artifact_id" if family == "registry" else "evidence_id"
    query = sqlglot.parse_one(f"SELECT {id_column} FROM {table}", read="duckdb")
    for item in filters:
        if (
            not isinstance(item, dict)
            or str(item.get("family") or "").strip().casefold() != family
            or item.get("field") not in allowed_fields
        ):
            raise ValueError("question_scope_filter_unsupported")
        query = query.where(
            question_scope_sql_predicate(
                db,
                family,
                str(item["field"]),
                str(item.get("operator") or ""),
                item.get("value"),
                exp.column(str(item["field"])),
            ),
            append=True,
        )
    if evidence_ids is not None:
        if not evidence_ids:
            return [], False
        query = query.where(exp.column(id_column).isin(*evidence_ids))
    query = query.limit(max_rows + 1)
    result = db.execute(query.sql(dialect="duckdb"))
    fetched = result.fetchmany(max_rows + 1)
    truncated = len(fetched) > max_rows
    ids = list(dict.fromkeys(str(row[0]) for row in fetched[:max_rows] if row[0]))
    return ids, truncated


def question_directory_scope_fields(family: str) -> frozenset[str]:
    """Return fields whose artifact contract defines directory ancestry."""
    table = canonical_record_table(family)
    hints = load_schema_hints().get(table or "", {})
    fields = hints.get("directory_scope_fields", [])
    return frozenset(str(field) for field in fields if isinstance(field, str))


def normalize_directory_scope(value: Any) -> str:
    """Normalize a literal directory path while preserving its root semantics."""
    if not isinstance(value, str):
        raise ValueError("question_scope_path_value_invalid")
    path = value.strip().replace("\\", "/")
    if not path or "\x00" in path:
        raise ValueError("question_scope_path_value_invalid")
    unc = path.startswith("//")
    if unc:
        tail = re.sub(r"/+", "/", path[2:]).strip("/")
        if len(tail.split("/")) < 2:
            raise ValueError("question_scope_path_value_invalid")
        path = "//" + tail
    else:
        path = re.sub(r"/+", "/", path)
        if re.match(r"^[A-Za-z]:($|[^/])", path):
            raise ValueError("question_scope_path_value_invalid")
        drive_root = bool(re.fullmatch(r"[A-Za-z]:/", path))
        if path != "/" and not drive_root:
            path = path.rstrip("/")
    components = [component for component in path.strip("/").split("/") if component]
    if any(component in {".", ".."} for component in components):
        raise ValueError("question_scope_path_value_invalid")
    if not components and path != "/":
        raise ValueError("question_scope_path_value_invalid")
    return path.lower()


def validate_question_scope_operator(
    family: str, field: str, operator: str, value: Any
) -> None:
    """Validate scope operators against the declared artifact field semantics."""
    if operator == "path_under":
        if field not in question_directory_scope_fields(family):
            raise ValueError("question_scope_filter_operator_unsupported")
        normalize_directory_scope(value)
    elif operator not in {"equals", "greater_than", "less_than"}:
        raise ValueError("question_scope_filter_operator_unsupported")


def question_scope_sql_predicate(
    db: CaseDB,
    family: str,
    field: str,
    operator: str,
    value: Any,
    column: exp.Expression,
) -> exp.Expression:
    """Build the shared SQL predicate used for discovery and scope evidence IDs."""
    validate_question_scope_operator(family, field, operator, value)
    if operator == "path_under":
        path = exp.func(
            "lower",
            exp.func(
                "replace",
                column,
                exp.Literal.string("\\"),
                exp.Literal.string("/"),
            ),
        )
        normalized = normalize_directory_scope(value)
        if normalized.startswith("/") or re.match(r"^[a-z]:/", normalized):
            prefix = normalized if normalized.endswith("/") else normalized + "/"
            return exp.and_(
                exp.func("starts_with", path, exp.Literal.string(prefix)),
                exp.NEQ(this=path.copy(), expression=exp.Literal.string(normalized)),
                exp.NEQ(this=path.copy(), expression=exp.Literal.string(prefix)),
            )
        # The trailing slash belongs after the candidate directory, not after
        # the whole artifact path: a matching basename is not a descendant.
        path_without_trailing_slashes = exp.func("rtrim", path, exp.Literal.string("/"))
        wrapped_path = exp.func(
            "concat", exp.Literal.string("/"), path_without_trailing_slashes
        )
        return exp.func(
            "contains",
            exp.Paren(this=wrapped_path),
            exp.Literal.string(f"/{normalized.strip('/')}/"),
        )

    value = canonical_scope_value(db, family, field, value)
    literal = (
        exp.Boolean(this=value)
        if isinstance(value, bool)
        else exp.Literal.number(str(value))
        if isinstance(value, (int, float))
        else exp.Literal.string(str(value))
    )
    comparison = {
        "equals": exp.EQ,
        "greater_than": exp.GT,
        "less_than": exp.LT,
    }[operator]
    return comparison(this=column, expression=literal)


def canonical_scope_value(db: CaseDB, family: str, field: str, value: Any) -> Any:
    """Normalize explicit offsets for canonical DuckDB TIMESTAMP comparisons."""
    if not isinstance(value, str):
        return value
    column = db.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema = 'main' AND table_name = ? AND column_name = ?",
        [canonical_record_table(family), field],
    ).fetchone()
    if not column or str(column[0]).upper() != "TIMESTAMP":
        return value
    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("z", "+00:00").replace("Z", "+00:00")
        )
    except ValueError:
        return value
    if parsed.tzinfo is None:
        return value
    return parsed.astimezone(UTC).replace(tzinfo=None).isoformat(sep="T")


def admitted_question_receipt(
    db: CaseDB,
    *,
    gap_id: str,
    question_text: str,
    hypothesis_id: str,
    verification_spec: Any,
) -> dict[str, Any] | None:
    """Read the exact discovery receipt admitted for this question and spec."""
    try:
        spec_payload = VerificationSpec.model_validate(
            verification_spec_payload(verification_spec)
        ).model_dump(mode="json")
    except Exception:
        return None
    spec_fingerprint = _question_fingerprint(spec_payload)
    for raw_input, raw_output in db.execute(
        "SELECT input_json, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-candidate' "
        "ORDER BY created_at DESC, step_id DESC"
    ).fetchall():
        try:
            attempt_input, attempt = json.loads(raw_input), json.loads(raw_output)
        except TypeError, json.JSONDecodeError:
            continue
        discovery_step_id = attempt.get("discovery_step_id")
        contract_id = attempt.get("contract_id")
        if (
            attempt_input.get("gap_id") != gap_id
            or attempt_input.get("question") != question_text
            or attempt.get("status") != "admitted"
            or attempt.get("admitted_hypothesis_id") != hypothesis_id
            or attempt.get("admitted_spec_fingerprint") != spec_fingerprint
            or not discovery_step_id
            or not contract_id
        ):
            continue
        discovery_row = db.execute(
            "SELECT input_json, output_json FROM trace.investigation_steps "
            "WHERE step_id = ? AND phase = 'plan-gap-discovery'",
            [discovery_step_id],
        ).fetchone()
        if not discovery_row:
            continue
        try:
            discovery_input = json.loads(discovery_row[0])
            receipt = json.loads(discovery_row[1])
        except TypeError, json.JSONDecodeError:
            continue
        contract = receipt.get("request_contract")
        observation = (
            spec_payload.get("support_conditions", {}).get("observation", {})
            if isinstance(spec_payload.get("support_conditions"), dict)
            else {}
        )
        observation_ids = (
            observation.get("evidence_ids") if isinstance(observation, dict) else None
        )
        from forensia.db.evidence_lookup import fetch_evidence_records

        observation_records = (
            fetch_evidence_records(db, observation_ids)
            if isinstance(observation_ids, list)
            and all(isinstance(item, str) for item in observation_ids)
            else {}
        )
        if (
            discovery_input.get("gap_id") != gap_id
            or discovery_input.get("question") != question_text
            or receipt.get("status") != "completed"
            or receipt.get("discovery_step_id") != discovery_step_id
            or receipt.get("contract_id") != contract_id
            or not isinstance(contract, dict)
            or _question_fingerprint(contract) != contract_id
            or not isinstance(observation_ids, list)
            or any(not isinstance(item, str) for item in observation_ids)
            or not set(observation_ids).issubset(observation_records)
            or question_contract_match_reason(
                contract, spec_payload, observation_records=observation_records
            )
        ):
            continue
        return receipt
    return None


def _question_fingerprint(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode(
            "utf-8"
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class QuestionSpec:
    """Semantic contract for one reusable report question.

    The registry is intentionally independent from report templates. Template
    headings, comments, and natural-language questions all resolve to this
    stable contract before evidence is gathered.
    """

    name: str
    answer_spec: str = ""
    intent: str = ""
    keywords: tuple[str, ...] = ()
    keypoints: tuple[str, ...] = ()
    expected_answer_shape: dict[str, Any] = field(default_factory=dict)
    evidence_chain: tuple[dict[str, Any], ...] = ()
    required_fields: tuple[str, ...] = ()
    required_sources: tuple[str, ...] = ()
    render_columns: tuple[str, ...] = ()
    render_max_rows: int | None = None
    negative_evidence_policy: str = ""
    status_rules: dict[str, Any] = field(default_factory=dict)
    timeline: bool = False
    builder_policy: str = ""
    sub_requirements: tuple[dict[str, Any], ...] = ()
    version_aware: bool = False
    answer_first: bool = False
    rank_field: str = ""
    rank_priority: tuple[str, ...] = ()
    lead_timestamp: str = ""

    @property
    def semantic_id(self) -> str:
        return self.answer_spec or self.name

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> QuestionSpec | None:
        name = str(raw.get("name") or "").strip()
        if not name:
            return None
        answer_spec = str(raw.get("answer_spec") or "").strip()
        expected_shape = raw.get("expected_answer_shape")
        if not isinstance(expected_shape, dict):
            expected_shape = {}
        status_rules = raw.get("status_rules")
        if not isinstance(status_rules, dict):
            status_rules = {}
        evidence_chain = _coerce_dict_list(raw.get("evidence_chain"))
        timeline = bool(raw.get("timeline", False))
        builder_policy = str(
            raw.get("builder_policy") or raw.get("implementation") or ""
        ).strip()
        required_sources = _coerce_str_tuple(raw.get("required_sources"))
        if not required_sources:
            required_sources = tuple(
                str(item.get("source") or "").strip()
                for item in evidence_chain
                if str(item.get("source") or "").strip()
            )
        render_columns = _coerce_str_tuple(raw.get("render_columns"))
        if not render_columns:
            render_columns = _coerce_str_tuple(expected_shape.get("fields"))
        rank = raw.get("rank") if isinstance(raw.get("rank"), dict) else {}
        lead_timestamp = str(raw.get("lead_timestamp") or "").strip()
        return cls(
            name=name,
            answer_spec=answer_spec,
            intent=str(raw.get("intent") or expected_shape.get("note") or "").strip(),
            keywords=_coerce_str_tuple(raw.get("keywords")),
            keypoints=_coerce_str_tuple(raw.get("keypoints")),
            expected_answer_shape=dict(expected_shape),
            evidence_chain=evidence_chain,
            required_fields=_coerce_str_tuple(raw.get("required_fields")),
            required_sources=tuple(dict.fromkeys(required_sources)),
            render_columns=tuple(dict.fromkeys(render_columns)),
            render_max_rows=(
                max(1, int(raw["render_max_rows"]))
                if raw.get("render_max_rows") is not None
                else None
            ),
            negative_evidence_policy=str(
                raw.get("negative_evidence_policy") or ""
            ).strip(),
            status_rules=dict(status_rules),
            timeline=timeline,
            builder_policy=builder_policy,
            sub_requirements=_coerce_dict_list(raw.get("sub_requirements")),
            version_aware=bool(raw.get("version_aware", False)),
            answer_first=bool(raw.get("answer_first", False)),
            rank_field=str(rank.get("field") or "").strip(),
            rank_priority=_coerce_str_tuple(rank.get("priority")),
            lead_timestamp=lead_timestamp,
        )

    def to_prompt_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "answer_spec": self.answer_spec,
            "intent": self.intent,
            "required_fields": list(self.required_fields),
            "required_sources": list(self.required_sources),
            "render_columns": list(self.render_columns),
            "render_max_rows": self.render_max_rows,
            "status_rules": self.status_rules,
            "builder_policy": self.builder_policy,
            "timeline": self.timeline,
            "sub_requirements": [
                {
                    "key": sub.get("key"),
                    "label": sub.get("label"),
                    "required_fields": list(sub.get("required_fields", ())),
                    "require_value": sub.get("require_value", {}),
                    "min_rows": sub.get("min_rows", 1),
                }
                for sub in self.sub_requirements
            ],
            "version_aware": self.version_aware,
            "answer_first": self.answer_first,
            "rank_field": self.rank_field,
            "rank_priority": list(self.rank_priority),
            "lead_timestamp": self.lead_timestamp,
        }


@lru_cache(maxsize=1)
def load_question_specs() -> tuple[QuestionSpec, ...]:
    path = _schema_dir() / "question_routing.yaml"
    if not path.exists():
        return ()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_items = data.get("question_types") if isinstance(data, dict) else []
    specs: list[QuestionSpec] = []
    for raw in raw_items or []:
        if not isinstance(raw, dict):
            continue
        spec = QuestionSpec.from_mapping(raw)
        if spec is not None:
            specs.append(spec)
    return tuple(specs)


def question_spec_for_answer_spec(answer_spec: str) -> QuestionSpec | None:
    normalized = str(answer_spec or "").strip().casefold().replace("-", "_")
    if not normalized:
        return None
    for spec in load_question_specs():
        candidates = {spec.answer_spec, spec.name, spec.semantic_id}
        if normalized in {
            str(item).strip().casefold().replace("-", "_")
            for item in candidates
            if item
        }:
            return spec
    return None


def _score_spec(spec: QuestionSpec, text: str) -> int:
    cleaned = _clean_text(text)
    if not cleaned:
        return 0
    score = 0
    for keyword in spec.keywords:
        normalized = _clean_text(keyword)
        if not normalized:
            continue
        if normalized in cleaned:
            score += 100 + len(normalized)
        else:
            tokens = [token for token in normalized.split() if len(token) >= 3]
            if tokens and all(token in cleaned for token in tokens):
                score += 25 + sum(len(token) for token in tokens)
    for label in (spec.name, spec.answer_spec):
        normalized = _clean_text(label)
        if normalized and normalized in cleaned:
            score += 80 + len(normalized)
    return score


def resolve_question_spec(
    *,
    block_heading: str = "",
    template_body: str = "",
    question: str = "",
    answer_spec: str = "",
) -> tuple[QuestionSpec | None, float]:
    """Resolve a template block to a stable QuestionSpec with a rough confidence."""
    explicit = question_spec_for_answer_spec(answer_spec)
    if explicit is not None:
        return explicit, 1.0

    text = "\n".join(
        part
        for part in (question, block_heading, template_body)
        if str(part or "").strip()
    )
    best: QuestionSpec | None = None
    best_score = 0
    for spec in load_question_specs():
        score = _score_spec(spec, text)
        if score > best_score:
            best = spec
            best_score = score

    # Composite questions: when a time-of-day window is requested, prefer a
    # timeline spec (actual event trace) over a pure aggregate/count spec. This is
    # generic — it keys on the presence of an hour window, not on a question number.
    hour_qualifiers = extract_time_qualifiers(text)
    if (
        best is not None
        and not best.timeline
        and hour_qualifiers.get("hour_from")
        and hour_qualifiers.get("hour_to")
    ):
        timeline_best: QuestionSpec | None = None
        timeline_best_score = 0
        for spec in load_question_specs():
            if not spec.timeline:
                continue
            score = _score_spec(spec, text)
            if score > timeline_best_score:
                timeline_best = spec
                timeline_best_score = score
        if timeline_best is not None and timeline_best_score > 0:
            best = timeline_best
            best_score = timeline_best_score

    if best is None or best_score <= 0:
        return None, 0.0
    return best, min(0.99, max(0.25, best_score / 300.0))


def project_rows_for_question_spec(
    spec: QuestionSpec | None, rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if spec is None or not spec.render_columns:
        return rows
    projected: list[dict[str, Any]] = []
    reference_fields = ("evidence_id", "finding_id", "evidence_ids", "finding_ids")
    for row in rows:
        item = {
            column: row.get(column, "")
            for column in spec.render_columns
            if column in row
        }
        for field_name in reference_fields:
            if field_name in row:
                item[field_name] = row[field_name]
        if item:
            projected.append(item)
    return projected or rows


def question_requests_local_time(question_text: str) -> bool:
    question_text = strip_section_instructions(question_text)
    return bool(
        re.search(
            r"\b(?:local|timezone|time zone)\b|現地|タイムゾーン",
            question_text,
            re.IGNORECASE,
        )
    )


def question_requests_utc(question_text: str) -> bool:
    question_text = strip_section_instructions(question_text)
    return bool(re.search(r"\bUTC\b(?!\s*[+-])", question_text, re.IGNORECASE))


def local_time_basis_unresolved(question_text: str, source_timezone: str) -> bool:
    return (
        question_requests_local_time(question_text)
        and not question_requests_utc(question_text)
        and source_timezone == "UTC"
    )


def extract_time_qualifiers(
    question_text: str, tz_name: str | None = None
) -> dict[str, str | None]:
    """Parse time qualifiers from question text using regex.

    Supports:
      - ISO date ranges: 'between 2026-03-01 and 2026-03-31'
      - 'from YYYY-MM-DD to YYYY-MM-DD'
      - JP wave-dash: '2026-03-01〜2026-03-31'
      - Time-of-day: 'between 09:00 and 17:00'
      - Time range: '9 AM to 5 PM'

    Hour values remain in the stated time basis. The query owner converts each
    evidence timestamp at its own date, preserving daylight-saving transitions.

    Returns {date_from, date_to, hour_from, hour_to, timezone_note, basis}.
    Missing qualifiers are set to None.
    """
    result: dict[str, str | None] = {
        "date_from": None,
        "date_to": None,
        "hour_from": None,
        "hour_to": None,
        "timezone_note": None,
        "basis": None,
    }
    text = strip_section_instructions(question_text)

    date_from: str | None = None
    date_to: str | None = None

    m = re.search(
        r"(?:between|from)\s+(\d{4}-\d{2}-\d{2})\s+(?:and|to)\s+(\d{4}-\d{2}-\d{2})",
        text,
        re.IGNORECASE,
    )
    if m:
        date_from, date_to = m.group(1), m.group(2)
    else:
        m = re.search(r"(\d{4}-\d{2}-\d{2})\s*[〜~]\s*(\d{4}-\d{2}-\d{2})", text)
        if m:
            date_from, date_to = m.group(1), m.group(2)
        else:
            m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", text)
            if m:
                date_from = date_to = m.group(1)

    hour_from: str | None = None
    hour_to: str | None = None

    m = re.search(
        r"(?:between|from)\s+(\d{2}:\d{2})\s+(?:and|to)\s+(\d{2}:\d{2})",
        text,
        re.IGNORECASE,
    )
    if m:
        hour_from, hour_to = m.group(1), m.group(2)
    else:
        m = re.search(
            r"(\d{1,2})(?::\d{2})?\s*(?:AM|am)\s*(?:to|and|[-–])\s*(\d{1,2})(?::\d{2})?\s*(?:PM|pm)",
            text,
        )
        if m:
            hour_from = f"{int(m.group(1)):02d}:00"
            hour_to = f"{int(m.group(2)) + 12:02d}:00"

    # Preserve local clock values; convert each evidence timestamp at its own date.
    result["basis"] = tz_name or "UTC"
    if hour_from and hour_to:
        result["timezone_note"] = (
            f"Time-of-day window uses {result['basis']} local time"
        )

    result["date_from"] = date_from
    result["date_to"] = date_to
    result["hour_from"] = hour_from
    result["hour_to"] = hour_to
    return result


def _has_value(row: dict[str, Any], field_name: str) -> bool:
    value = row.get(field_name)
    if value is None:
        return False
    if isinstance(value, (list, tuple, dict)):
        return bool(value)
    return bool(str(value).strip())


def _has_stable_reference(row: dict[str, Any]) -> bool:
    """Return whether an answer row can be traced to durable evidence."""
    for field_name in ("evidence_id", "finding_id"):
        if _has_value(row, field_name):
            return True
    for field_name in ("evidence_ids", "finding_ids"):
        value = row.get(field_name)
        if isinstance(value, (list, tuple, set)):
            if any(item is not None and str(item).strip() for item in value):
                return True
        elif value is not None and str(value).strip():
            return True
    return False


def sub_requirement_coverage(
    spec: QuestionSpec | None,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return per-sub-requirement fulfilment for a spec.

    Each returned item has ``key``, ``label``, ``required_fields``,
    ``require_value``, ``min_rows``, ``matched_rows``, and ``satisfied``. A
    sub-requirement is satisfied when at least ``min_rows`` rows contain every
    declared ``required_fields`` value and — when ``require_value`` is present —
    the row's field value is one of the allowed values.
    """
    if spec is None:
        return []
    coverage: list[dict[str, Any]] = []
    for sub in spec.sub_requirements:
        key = str(sub.get("key") or "").strip()
        label = str(sub.get("label") or key or "sub-requirement").strip()
        req_fields = _coerce_str_tuple(sub.get("required_fields"))
        require_value = sub.get("require_value")
        if not isinstance(require_value, dict):
            require_value = {}
        min_rows = max(1, int(sub.get("min_rows") or 1))
        matched = 0
        for row in rows:
            if not all(_has_value(row, field_name) for field_name in req_fields):
                continue
            ok = True
            for value_field, allowed in require_value.items():
                row_value = str(row.get(value_field) or "").strip().lower()
                if isinstance(allowed, (list, tuple, set)):
                    allowed_values = [str(value).strip().lower() for value in allowed]
                else:
                    allowed_values = [str(allowed).strip().lower()]
                value_ok = row_value in allowed_values
                if not value_ok:
                    ok = False
                    break
            if ok:
                matched += 1
        coverage.append(
            {
                "key": key,
                "label": label,
                "required_fields": list(req_fields),
                "require_value": {
                    str(k): [str(v) for v in vs] for k, vs in require_value.items()
                },
                "min_rows": min_rows,
                "matched_rows": matched,
                "satisfied": matched >= min_rows,
            }
        )
    return coverage


def evaluate_question_spec_status(
    spec: QuestionSpec | None,
    rows: list[dict[str, Any]],
    *,
    queries_run: list[str] | None = None,
    fallback_status: str | None = None,
    coverage_observable: bool | None = None,
) -> tuple[str, list[str]]:
    """Evaluate answer status from a QuestionSpec contract without using an LLM.

    Status is one of ``answered``, ``partial``, ``unobservable``, ``not_found``,
    ``not_searched``, or ``wrong_query``. Composite questions declare
    ``sub_requirements``; a partial composite answer (some, but not all,
    sub-requirements met) must never be reported as ``answered``.
    """
    rules = spec.status_rules if spec is not None else {}
    fallback = normalize_structured_status(fallback_status or "")

    if not rows:
        if fallback in {"unobservable", "not_searched", "wrong_query"}:
            return fallback, []
        if coverage_observable is False:
            return "unobservable", [
                str(
                    rules.get("empty_reason")
                    or "No matching data is observable under the available evidence coverage."
                )
            ]
        empty_status = normalize_structured_status(
            str(rules.get("empty_status") or "").strip()
            or ("not_found" if queries_run else "not_searched")
        )
        if empty_status not in _valid_structured_statuses():
            empty_status = normalize_structured_status(
                "not_found" if queries_run else "not_searched"
            )
        return empty_status, [
            str(
                rules.get("empty_reason")
                or "No matching structured database rows were found."
            )
        ]

    if fallback in _valid_structured_statuses():
        base_status = fallback
    else:
        base_status = "answered"

    reasons: list[str] = []
    min_rows = int(rules.get("min_rows_for_answer") or 1)
    if len(rows) < min_rows:
        reasons.append(
            f"Only {len(rows)} rows matched; {min_rows} rows are required for a complete answer."
        )
        base_status = "partial"

    required_fields = tuple(
        rules.get("required_fields") or spec.required_fields if spec is not None else ()
    )
    # Spec-level required_fields only gate the answer when there are no
    # declarative sub-requirements; sub-requirements own composite coverage.
    if required_fields and not (spec is not None and spec.sub_requirements):
        any_required_value = any(
            any(_has_value(row, field_name) for field_name in required_fields)
            for row in rows
        )
        if not any_required_value:
            empty_status = normalize_structured_status(
                str(rules.get("empty_status") or "not_found")
            )
            if empty_status not in _valid_structured_statuses():
                empty_status = "not_found"
            return empty_status, [
                str(
                    rules.get("empty_reason")
                    or "Rows matched structurally, but required answer fields were empty."
                )
            ]
        if not any(
            all(_has_value(row, field_name) for field_name in required_fields)
            for row in rows
        ):
            reasons.append(
                "Rows matched the question, but none contained all required fields: "
                + ", ".join(required_fields)
            )
            base_status = "partial"

    if rows and not any(_has_stable_reference(row) for row in rows):
        reasons.append(
            "Rows matched, but no stable finding/evidence reference was present."
        )
        base_status = "partial"

    if spec is not None and spec.sub_requirements:
        coverage = sub_requirement_coverage(spec, rows)
        satisfied = [item for item in coverage if item["satisfied"]]
        if satisfied and len(satisfied) < len(coverage):
            base_status = "partial"
            missing = [item["label"] for item in coverage if not item["satisfied"]]
            reasons.append(
                "Composite answer partially met; unmet sub-requirements: "
                + ", ".join(missing)
            )
        elif not satisfied:
            base_status = "partial"
            reasons.append(
                "No declarative sub-requirement was fully satisfied by the available rows."
            )

    if base_status not in _valid_structured_statuses():
        base_status = "answered"
    return base_status, reasons


def explicit_all_timestamps_request(question_text: str) -> bool:
    """Whether the question asks for the complete timestamp field group."""
    text = strip_section_instructions(question_text)
    return bool(
        re.search(
            r"\b(?:all|every)\s+(?:(?:of\s+the)\s+)?"
            r"(?:(?:available|observed|recorded|known)\s+)?"
            r"time[\s-]?stamps?\b",
            text,
            flags=re.IGNORECASE,
        )
        or re.search(r"(?:すべて|全て|全)(?:の)?タイムスタンプ", text)
    )


def question_timestamp_coverage(
    db: CaseDB,
    question_text: str,
    contract: dict[str, Any],
    records: dict[str, dict[str, Any]],
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """Return declared timestamp fields and fields absent from each evidence row.

    The field group comes from the canonical artifact table's declared TIMESTAMP
    columns, limited to its typed observation catalog. Model-selected requirements
    do not redefine an explicit request for all timestamps.
    """
    if not explicit_all_timestamps_request(question_text):
        return (), {}

    def unresolved(reason: str) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
        return (), {evidence_id: (reason,) for evidence_id in records} or {
            "__coverage__": (reason,)
        }

    requirements = contract.get("requirements")
    families = {
        str(item.get("family") or "").strip().casefold()
        for item in requirements or []
        if isinstance(item, dict)
    }
    if len(families) != 1 or "" in families:
        return unresolved("artifact family is unresolved")
    family = next(iter(families))
    table = canonical_record_table(family)
    catalog = observation_catalog().get(family)
    if not table or not catalog:
        return unresolved("declared timestamp fields are unavailable")
    rows = db.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'main' AND table_name = ? "
        "AND UPPER(data_type) LIKE '%TIMESTAMP%' ORDER BY ordinal_position",
        [table],
    ).fetchall()
    catalog_fields = set(catalog["fields"])
    fields = tuple(str(row[0]) for row in rows if str(row[0]) in catalog_fields)
    json_fields = {
        str(row[0])
        for row in db.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'main' AND table_name = ? "
            "AND UPPER(data_type) = 'JSON'",
            [table],
        ).fetchall()
        if str(row[0]) in catalog_fields
    }
    from forensia.knowledge.catalog import load_schema_hints

    declaration = load_schema_hints().get(table, {})
    declared_arrays = declaration.get("timestamp_array_fields")
    if json_fields and not isinstance(declared_arrays, list):
        return unresolved("timestamp array fields are not classified")
    if declared_arrays is not None and (
        not isinstance(declared_arrays, list)
        or any(
            not isinstance(field_name, str) or field_name not in json_fields
            for field_name in declared_arrays
        )
    ):
        return unresolved(
            "timestamp array declaration does not match the artifact schema"
        )
    fields += tuple(field_name for field_name in declared_arrays or [])
    timestamp_arrays = set(declared_arrays or [])
    if not fields:
        return unresolved("declared timestamp fields are unavailable")

    def field_has_value(record: dict[str, Any], field_name: str) -> bool:
        value = record.get(field_name)
        if field_name in timestamp_arrays:
            return bool(
                isinstance(value, (list, tuple))
                and value
                and all(item is not None and str(item).strip() for item in value)
            )
        return _has_value(record, field_name)

    missing = {
        evidence_id: tuple(
            field_name
            for field_name in fields
            if not field_has_value(record, field_name)
        )
        for evidence_id, record in records.items()
    }
    return fields, {
        evidence_id: values for evidence_id, values in missing.items() if values
    }
