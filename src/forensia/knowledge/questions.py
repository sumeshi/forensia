from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from forensia.knowledge.resources import schema_dir

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None  # type: ignore[assignment,misc]

import yaml

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


def is_valid_structured_status(status: str) -> bool:
    return normalize_structured_status(status) in _valid_structured_statuses()


def _schema_dir() -> Path:
    # knowledge/ is a sibling of the packaged rulepacks/ data directory.
    return schema_dir()


def _clean_text(value: Any) -> str:
    text = str(value or "").casefold()
    text = text.replace("_", " ").replace("-", " ")
    return " ".join(re.split(r"\s+", text)).strip()


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    text = str(value or "").strip()
    return (text,) if text else ()


def _coerce_dict_list(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, dict))


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

    When a timezone name is provided and hour qualifiers are present, the returned
    hour values are converted to UTC so that SQL filters match the UTC timestamps
    stored in the database. Also returns a ``timezone_note`` key explaining the basis.

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
    text = str(question_text or "")

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

    # Convert hour qualifiers to UTC when timezone is known
    if hour_from and hour_to and tz_name and tz_name != "UTC" and ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
            # Use a reference date (today) to get the UTC offset
            ref_date = datetime.now(UTC).date()
            from_local = datetime(
                ref_date.year,
                ref_date.month,
                ref_date.day,
                int(hour_from.split(":")[0]),
                int(hour_from.split(":")[1]),
                tzinfo=tz,
            )
            to_local = datetime(
                ref_date.year,
                ref_date.month,
                ref_date.day,
                int(hour_to.split(":")[0]),
                int(hour_to.split(":")[1]),
                tzinfo=tz,
            )
            from_utc = from_local.astimezone(UTC)
            to_utc = to_local.astimezone(UTC)
            hour_from = f"{from_utc.hour:02d}:{from_utc.minute:02d}"
            hour_to = f"{to_utc.hour:02d}:{to_utc.minute:02d}"
            result["timezone_note"] = (
                f"Time-of-day filter applied in UTC (converted from {tz_name} local time)"
            )
            result["basis"] = tz_name
        except ValueError, OSError, KeyError:
            result["timezone_note"] = (
                f"Time-of-day filter applied in UTC (timezone {tz_name} could not be resolved)"
            )
            result["basis"] = "UTC"
    elif hour_from and hour_to:
        result["timezone_note"] = "Time-of-day filter applied in UTC (timezone unknown)"
        result["basis"] = "UTC"
    else:
        result["basis"] = tz_name if tz_name else "UTC"

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
        if value is not None and str(value).strip():
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
                is_path = value_field.casefold() in {
                    "file_path",
                    "file_name",
                    "path",
                }
                if is_path:
                    value_ok = any(
                        token and token in row_value for token in allowed_values
                    )
                else:
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
                    str(k): [str(v) for v in vs]
                    for k, vs in require_value.items()
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
        rules.get("required_fields") or spec.required_fields
        if spec is not None
        else ()
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
            missing = [
                item["label"] for item in coverage if not item["satisfied"]
            ]
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
