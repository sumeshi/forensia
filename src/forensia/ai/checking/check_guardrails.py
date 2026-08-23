"""Deterministic guardrails: verdict consistency and benign context."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from forensia.ai.checking.check_normalize import (
    _collect_observed_evidence_ids,
    _filter_evidence_references,
    _has_zero_evidence,
    _normalize_finding_updates,
    _normalize_verdict,
    _parse_timestamp,
    filter_memory_updates,
    validate_extracted_findings,
)
from forensia.ai.prompts.prompt_investigation import (
    _load_benign_context_rules,
)
from forensia.knowledge.catalog import (
    event_context_eligible,
    event_context_from_row,
    load_event_id_hints,
)


def _context_qualified_rows(
    confirm_when: dict[str, Any], rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Exclude rows whose provider/channel cannot support a constrained ID."""

    raw_ids = confirm_when.get("co_observed_event_ids") or []
    constrained: set[int] = set()
    for value in raw_ids:
        try:
            event_id = int(value)
        except (TypeError, ValueError):
            continue
        hint = load_event_id_hints().get(event_id) or {}
        if hint.get("channels") or hint.get("providers"):
            constrained.add(event_id)
    if not constrained:
        return rows
    declared: dict[int, set[tuple[str | None, str | None]]] = {}
    for item in confirm_when.get("event_contexts") or []:
        if not isinstance(item, dict):
            continue
        try:
            event_id = int(item.get("event_id"))
        except (TypeError, ValueError):
            continue
        declared.setdefault(event_id, set()).add(
            (
                str(item.get("channel") or "").strip() or None,
                str(item.get("provider") or "").strip() or None,
            )
        )
    qualified: list[dict[str, Any]] = []
    for row in rows:
        try:
            event_id = int(row.get("event_id"))
        except (TypeError, ValueError):
            qualified.append(row)
            continue
        if event_id not in constrained:
            qualified.append(row)
            continue
        channel, provider = event_context_from_row(row)
        if not event_context_eligible(event_id, channel=channel, provider=provider):
            continue
        allowed = declared.get(event_id)
        if allowed and (channel, provider) not in allowed:
            continue
        qualified.append(row)
    return qualified


@dataclass(frozen=True, slots=True)
class VerdictTransitionRule:
    """Declare one deterministic verdict transition and its audit note."""

    name: str
    source_verdicts: frozenset[str]
    target_verdict: str
    applies: Callable[[Mapping[str, Any]], bool]
    note: Callable[[Mapping[str, Any]], str] | None = None

    def evaluate(
        self, verdict: str, context: Mapping[str, Any]
    ) -> tuple[str, str | None]:
        """Return the transitioned verdict and optional note when applicable."""
        if verdict not in self.source_verdicts or not self.applies(context):
            return verdict, None
        return self.target_verdict, self.note(context) if self.note else None


PAYLOAD_VERDICT_RULES = (
    VerdictTransitionRule(
        name="zero-evidence-positive-verdict",
        source_verdicts=frozenset({"confirmed", "newlead"}),
        target_verdict="inconclusive",
        applies=lambda context: bool(context.get("zero_evidence")),
    ),
    VerdictTransitionRule(
        name="fallback-evidence-confirmation-cap",
        source_verdicts=frozenset({"confirmed"}),
        target_verdict="newlead",
        applies=lambda context: bool(context.get("fallback_info")),
        note=lambda context: (
            "downgraded from confirmed to newlead: rows from fallback search "
            f"({(context.get('fallback_info') or {}).get('phase', 'unknown')})"
        ),
    ),
)


def _apply_verdict_transition_rules(
    verdict: str, context: Mapping[str, Any]
) -> tuple[str, list[str]]:
    """Apply transition rules in declared order and collect audit notes."""
    notes: list[str] = []
    for rule in PAYLOAD_VERDICT_RULES:
        verdict, note = rule.evaluate(verdict, context)
        if note:
            notes.append(note)
    return verdict, notes


def annotate_benign_context(
    rows: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> dict[int, list[str]]:
    """Map row_index to matching benign-context rule IDs for each row.

    Each rule must have: id, when.column, when.regex. Returns empty dict when
    no rows match any rule.
    """
    result: dict[int, list[str]] = {}
    for i, row in enumerate(rows):
        matched: list[str] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            when = rule.get("when")
            if not isinstance(when, dict):
                continue
            column = when.get("column")
            regex = when.get("regex")
            if not column or not regex:
                continue
            value = row.get(column)
            if value is None:
                continue
            try:
                if re.search(regex, str(value)):
                    matched.append(str(rule.get("id", "unknown")))
            except re.error:
                continue
        if matched:
            result[i] = matched
    return result


def _co_observation_satisfied(
    confirm_when: dict, rows: list[dict[str, Any]]
) -> tuple[bool, str]:
    """Check if co-observed event IDs satisfy correlation constraints.

    Supports `same_host`, `same_entities`, `within_minutes`, `min_count`, and
    `co_observed_event_ids`.
    Returns (satisfied, reason_string).
    """
    rows = _context_qualified_rows(confirm_when, rows)
    co_ids = confirm_when.get("co_observed_event_ids") or []
    required_ids: set[int] = set()
    for eid in co_ids:
        try:
            required_ids.add(int(eid))
        except TypeError, ValueError:
            continue
    if not required_ids:
        return (True, "no co_observed_event_ids to verify")

    same_host = bool(confirm_when.get("same_host", False))
    within_minutes: int | None = confirm_when.get("within_minutes")
    same_entities = [
        str(value).strip()
        for value in (confirm_when.get("same_entities") or [])
        if str(value).strip()
    ]
    min_count = confirm_when.get("min_count", 1)
    if not isinstance(min_count, int) or isinstance(min_count, bool) or min_count < 1:
        return (False, "min_count must be a positive integer")

    # Simple presence check when no correlation constraints
    if not same_host and not same_entities and within_minutes is None and min_count == 1:
        observed_ids: set[int] = set()
        for row in rows:
            eid = row.get("event_id")
            if eid is not None:
                try:
                    observed_ids.add(int(eid))
                except TypeError, ValueError:
                    pass
        if required_ids.issubset(observed_ids):
            return (
                True,
                f"all co_observed_event_ids {sorted(required_ids)} present in rows",
            )
        return (
            False,
            f"not all co_observed_event_ids found: missing {sorted(required_ids - observed_ids)}",
        )

    grouping_fields = (["computer"] if same_host else []) + same_entities
    grouping_fields = list(dict.fromkeys(grouping_fields))
    if grouping_fields:
        host_groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            values = [row.get(field) for field in grouping_fields]
            if all(value is not None and str(value).strip() for value in values):
                key = "|".join(
                    f"{field}={value}" for field, value in zip(grouping_fields, values)
                )
                host_groups.setdefault(key, []).append(row)
        if not host_groups:
            return (
                False,
                f"correlation fields missing from rows: {grouping_fields}",
            )
    else:
        host_groups = {"_all": rows}

    for host, host_rows in host_groups.items():
        host_event_ids: set[int] = set()
        for row in host_rows:
            eid = row.get("event_id")
            if eid is not None:
                try:
                    host_event_ids.add(int(eid))
                except TypeError, ValueError:
                    pass

        if not required_ids.issubset(host_event_ids):
            continue

        relevant_row_count = 0
        for row in host_rows:
            try:
                if int(row.get("event_id")) in required_ids:
                    relevant_row_count += 1
            except (TypeError, ValueError):
                continue
        if within_minutes is None and relevant_row_count < min_count:
            continue

        if within_minutes is not None:
            # Sliding window: find ANY window of within_minutes that contains
            # every required event ID. A global min/max span check would fail
            # whenever the result set spans days even though a valid co-observed
            # pair exists somewhere inside it.
            events: list[tuple[float, int]] = []
            for row in host_rows:
                eid = row.get("event_id")
                if eid is not None:
                    try:
                        eid_int = int(eid)
                        if eid_int in required_ids:
                            ts = _parse_timestamp(row.get("timestamp"))
                            if ts is not None:
                                events.append((ts, eid_int))
                    except TypeError, ValueError:
                        pass

            if not events:
                continue

            events.sort()
            window_seconds = within_minutes * 60
            window_counts: Counter[int] = Counter()
            left = 0
            found = False
            for right in range(len(events)):
                window_counts[events[right][1]] += 1
                while events[right][0] - events[left][0] > window_seconds:
                    window_counts[events[left][1]] -= 1
                    if window_counts[events[left][1]] == 0:
                        del window_counts[events[left][1]]
                    left += 1
                if required_ids.issubset(window_counts.keys()) and sum(
                    window_counts.values()
                ) >= min_count:
                    found = True
                    break
            if found:
                host_label = f" in group={host}" if grouping_fields else ""
                return (
                    True,
                    f"co-observed event_ids {sorted(required_ids)} within {within_minutes}min with min_count={min_count}{host_label}",
                )
        else:
            host_label = f" in group={host}" if grouping_fields else ""
            return (
                True,
                f"co-observed event_ids {sorted(required_ids)} present with min_count={min_count}{host_label}",
            )

    parts = [f"co-observation not satisfied: required={sorted(required_ids)}"]
    if same_host:
        parts.append("same_host=True")
    if same_entities:
        parts.append(f"same_entities={same_entities}")
    if within_minutes is not None:
        parts.append(f"within_{within_minutes}min")
    if min_count > 1:
        parts.append(f"min_count={min_count}")
    return (False, "; ".join(parts))


def verify_verdict_consistency(
    verdict: str,
    rationale: str,
    hypothesis,
    result_summary: dict[str, Any],
) -> tuple[str, str | None]:
    """Veto confirmed verdicts when cited event IDs don't match observed rows.

    Returns (adjusted_verdict, veto_reason_or_None).
    """
    if verdict != "confirmed":
        return verdict, None

    # -- Check 1: event_id claim vs observed event_ids --
    claimed_event_ids: set[int] = set()
    if hypothesis and hasattr(hypothesis, "confirm_when") and hypothesis.confirm_when:
        co_ids = hypothesis.confirm_when.get("co_observed_event_ids") or []
        for eid in co_ids:
            try:
                claimed_event_ids.add(int(eid))
            except TypeError, ValueError:
                pass
    # Bare numbers in the rationale are usually counts, years, or row totals,
    # not event-id claims. Treat a number as a claimed event id only when it is
    # framed by "event ..." wording, or when it is a 4-5 digit number that
    # exists in the declared event-id vocabulary (event_ids.yaml).
    from forensia.ai.prompts.prompt_context import _load_event_id_hints

    rationale_lower = rationale.lower()
    framed = {
        int(m) for m in re.findall(r"event[^0-9]{0,8}(\d{2,5})\b", rationale_lower)
    }
    bare = {int(m) for m in re.findall(r"\b(\d{4,5})\b", rationale_lower)}
    known_event_ids = set(_load_event_id_hints().keys())
    if known_event_ids:
        rationale_eids = (framed | bare) & known_event_ids
    else:
        rationale_eids = framed
    claimed_event_ids.update(rationale_eids)

    observed_event_ids: set[int] = set()
    sample_rows = result_summary.get("sample_rows") or []
    authoritative_ids: set[int] = set()
    for eid in result_summary.get("event_id_set") or []:
        try:
            authoritative_ids.add(int(eid))
        except TypeError, ValueError:
            pass
    source_event_ids = authoritative_ids
    if hypothesis and sample_rows and hasattr(hypothesis, "confirm_when"):
        confirm_when = hypothesis.confirm_when or {}
        constrained_ids = {
            int(value)
            for value in confirm_when.get("co_observed_event_ids") or []
            if str(value).strip().isdigit()
            and (
                load_event_id_hints().get(int(value), {}).get("channels")
                or load_event_id_hints().get(int(value), {}).get("providers")
            )
        }
        if constrained_ids:
            qualified_rows = _context_qualified_rows(confirm_when, sample_rows)
            qualified_constrained = {
                int(row.get("event_id"))
                for row in qualified_rows
                if str(row.get("event_id") or "").strip().isdigit()
                and int(row.get("event_id")) in constrained_ids
            }
            source_event_ids = (
                (authoritative_ids - constrained_ids) | qualified_constrained
            )
    observed_event_ids.update(source_event_ids)

    missing_ids = claimed_event_ids - observed_event_ids
    if missing_ids:
        sorted_missing = sorted(missing_ids)
        return (
            "inconclusive",
            f"verdict cited event_ids {sorted_missing} not present in result rows",
        )

    # -- Check 2: required_entities columns are non-NULL in sample rows --
    if (
        hypothesis
        and hasattr(hypothesis, "required_entities")
        and hypothesis.required_entities
    ):
        sample_rows = result_summary.get("sample_rows") or []
        if sample_rows:
            all_null = True
            for col in hypothesis.required_entities:
                for row in sample_rows:
                    val = row.get(col)
                    if val not in (
                        None,
                        "",
                        "-",
                        "n/a",
                        "na",
                        "none",
                        "null",
                        "unknown",
                    ):
                        all_null = False
                        break
                if not all_null:
                    break
            if all_null:
                return (
                    "inconclusive",
                    f"required_entities columns {hypothesis.required_entities} are NULL/absent in all sample rows",
                )

    # -- Check 3: co-observation correlation constraints (same_host / within_minutes) --
    if hypothesis and hasattr(hypothesis, "confirm_when") and hypothesis.confirm_when:
        cw = hypothesis.confirm_when
        if isinstance(cw, dict) and (cw.get("same_host") or cw.get("within_minutes")):
            sample_rows = result_summary.get("sample_rows") or []
            satisfied, veto_reason = _co_observation_satisfied(cw, sample_rows)
            if not satisfied:
                return ("inconclusive", veto_reason)

    # -- Check 4: Benign context gate --
    # Only rules matching the columns the hypothesis actually reasons about
    # (required_entities) count toward the downgrade: a machine-account
    # subject_user is the normal shape of a human interactive logon and must
    # not veto a hypothesis whose required entities are target_user/computer.
    sample_rows = result_summary.get("sample_rows") or []
    if sample_rows:
        benign_rules = _load_benign_context_rules()
        required_entities = (
            set(getattr(hypothesis, "required_entities", None) or [])
            if hypothesis
            else set()
        )
        if required_entities:
            benign_rules = [
                rule
                for rule in benign_rules
                if isinstance(rule, dict)
                and isinstance(rule.get("when"), dict)
                and rule["when"].get("column") in required_entities
            ]
        if benign_rules:
            benign_annotations = annotate_benign_context(sample_rows, benign_rules)
            if benign_annotations and len(benign_annotations) == len(sample_rows):
                all_rule_ids: set[str] = set()
                for ids in benign_annotations.values():
                    all_rule_ids.update(ids)
                return (
                    "inconclusive",
                    f"all supporting rows match benign-context rules: {sorted(all_rule_ids)}",
                )

    return verdict, None


def guardrail_check_payload(
    parsed: dict[str, Any],
    finding_candidates: list[dict[str, Any]],
    result_summary: dict[str, Any],
    fallback_info: dict | None = None,
) -> dict[str, Any]:
    """Apply safety guardrails to the raw LLM check response.

    Forces inconclusive on zero-evidence confirmed/newlead. Filters finding_updates
    to allowed IDs and enforces verdict-constrained delta signs.
    Caps fallback-sourced verdicts to newlead.
    """
    verdict = _normalize_verdict(parsed.get("verdict"))
    observed_evidence_ids = _collect_observed_evidence_ids(result_summary)
    zero_evidence = _has_zero_evidence(result_summary, observed_evidence_ids)
    verdict, transition_notes = _apply_verdict_transition_rules(
        verdict,
        {"zero_evidence": zero_evidence, "fallback_info": fallback_info},
    )
    if transition_notes:
        existing_notes = str(parsed.get("notes") or "").strip()
        parsed["notes"] = "; ".join(
            part for part in (existing_notes, *transition_notes) if part
        )

    allowed_finding_ids = {
        str(item.get("finding_id") or "").strip()
        for item in finding_candidates
        if isinstance(item, dict) and str(item.get("finding_id") or "").strip()
    }

    return {
        "query_id": parsed.get("query_id"),
        "verdict": verdict,
        "finding_updates": _normalize_finding_updates(
            parsed.get("finding_updates"),
            allowed_finding_ids=allowed_finding_ids,
            verdict=verdict,
            zero_evidence=zero_evidence,
        ),
        "suspicious_evidence": _filter_evidence_references(
            parsed.get("suspicious_evidence"),
            observed_evidence_ids,
        ),
        "new_hypotheses": parsed.get("new_hypotheses"),
        "memory_updates": filter_memory_updates(
            parsed.get("memory_updates"),
            observed_evidence_ids,
            sample_rows=result_summary.get("sample_rows"),
        ),
        "report_text": parsed.get("report_text") or "",
        "extracted_findings": validate_extracted_findings(
            parsed.get("extracted_findings"),
            observed_evidence_ids,
        ),
    }
