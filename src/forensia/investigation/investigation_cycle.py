"""Investigation cycle: broad planning, hypothesis selection, cycle body."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from forensia.context.case_profile import (
    CaseEvidenceProfile,
)
from forensia.context.investigation_candidates import build_investigation_candidates
from forensia.core.case import Case
from forensia.core.control import InvestigationStopped
from forensia.core.log import log as _log
from forensia.core.progress_event import progress_event
from forensia.core.session import Hypothesis, LLMBudgetExceededError, SessionState
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import canonical_record_table, routed_family
from forensia.investigation.hypotheses.hypothesis_manager import (
    MAX_ACTIVE_HYPOTHESES,
    _guess_related_sections,
    admit_new_hypothesis,
    merge_active_hypotheses,
    qualify_event_contexts,
)
from forensia.investigation.hypotheses.hypothesis_runner import (
    _investigate_one_hypothesis,
)
from forensia.investigation.hypotheses.seeding import (
    _scan_report_keypoints,
)
from forensia.investigation.investigation_session import (
    Ctx,
    _call_with_outage_recovery,
    _save_step,
)
from forensia.investigation.planner import (
    _compute_uncovered_keypoints,
    discover_gap_evidence,
)
from forensia.investigation.prompts import (
    _has_observed_value,
    build_gap_identifier_messages,
    build_hypothesis_drafter_messages,
)
from forensia.investigation.report_gap import (
    report_cycle_progress,
)
from forensia.investigation.selection import (
    select_focus_hypotheses,
)
from forensia.investigation.work_judgment import (
    judge_work,
    work_progress_fingerprint,
    work_progress_snapshot,
)
from forensia.investigation.work_state import pause_hypothesis_work
from forensia.knowledge.questions import (
    gap_operational_reason,
    question_contract_match_reason,
)
from forensia.knowledge.rules.loader import _get_rule_cache
from forensia.llm import json_response
from forensia.llm.llm_client import (
    LLMRequestTimeoutError,
    LLMServerUnavailableError,
    LLMStructuredOutputError,
)
from forensia.llm.telemetry import get_active_telemetry, telemetry_scope
from forensia.report.answers.keypoint_catalog import (
    REPORT_KEYPOINTS,
    investigation_keypoint_names,
)

_BROAD_DRAFT_MAX_TOKENS = 4096


def _observed_keypoints_from_findings(
    snapshot: list[dict[str, Any]], limit: int = 20
) -> list[str]:
    """Format findings as stable labels for broad-planning context."""
    keypoints: list[str] = []
    for item in snapshot[:limit]:
        title = str(item.get("title") or "").strip()
        finding_id = str(item.get("finding_id") or "").strip()
        if not title:
            continue
        keypoints.append(f"{finding_id}: {title}" if finding_id else title)
    return keypoints


@dataclass(slots=True)
class _BroadPlanContext:
    state: SessionState
    db: CaseDB
    session_id: str
    base_url: str
    model: str
    plan_cycle: int
    observed_keypoints: list[dict[str, Any]]
    observed_keypoint_labels: list[str]
    emit_fn: Callable[..., None] | None
    llm_status_fn: Callable[[str], None]
    progress_callback: Callable[[dict[str, Any]], None] | None
    case_profile: CaseEvidenceProfile | None
    case_policy: Any | None = None


def _parse_hypothesis_from_drafter(
    parsed: dict[str, Any],
    *,
    allowed_rule_ids: set[str],
    observation_only: bool = False,
) -> tuple[Hypothesis | None, str | None]:
    """Parse drafter LLM output into a Hypothesis object.

    The drafter returns ``{"hypothesis": {"description": "...", "required_entities": [...], "source_rule_ids": [...], "confirm_when": {...}, "refute_when": {...}}}``.
    Constrains source rules to the host-supplied matched candidates and assigns
    a placeholder id that ``merge_active_hypotheses`` will replace.
    """
    hyp_raw = parsed.get("hypothesis")
    if not isinstance(hyp_raw, dict):
        return None, "hypothesis-object-missing"
    hyp_raw = dict(hyp_raw)
    if observation_only:
        from forensia.knowledge.coverage import canonical_observation_claim

        if "description" in hyp_raw:
            return None, "observation-description-not-allowed"
        claim = canonical_observation_claim(
            {"support_conditions": hyp_raw.get("confirm_when")}
        )
        if not claim:
            return None, "invalid-observation-condition"
        hyp_raw["description"] = claim
    hyp_raw.setdefault("id", "draft")
    hyp_raw.setdefault("source_rule_ids", [])
    supplied_rule_ids = hyp_raw.get("source_rule_ids") or []
    if not isinstance(supplied_rule_ids, list):
        supplied_rule_ids = []
    unobserved_rule_ids = {
        str(rule_id)
        for rule_id in supplied_rule_ids
        if str(rule_id) not in allowed_rule_ids
    }
    if unobserved_rule_ids:
        _log(
            "PLAN",
            f"drafter source_rule_ids outside matched candidates ignored: {sorted(unobserved_rule_ids)}",
        )
    hyp_raw["source_rule_ids"] = [
        str(rule_id)
        for rule_id in supplied_rule_ids
        if str(rule_id) in allowed_rule_ids
    ]
    try:
        return Hypothesis.model_validate(hyp_raw), None
    except Exception as exc:
        reason = f"hypothesis schema validation: {str(exc).splitlines()[0][:160]}"
        _log(
            "PLAN",
            f"drafter output dropped ({reason})",
        )
        return None, reason


def _broad_plan_observed_labels(observed_keypoints: list[dict[str, Any]]) -> list[str]:
    return [
        f"{item['keypoint']} (rows={item['row_count']})" for item in observed_keypoints
    ]


async def _identify_broad_plan_gaps(
    ctx: _BroadPlanContext, *, max_gap_areas: int
) -> list[dict[str, Any]]:
    observed_kp_strs = (
        ctx.observed_keypoint_labels
        or _observed_keypoints_from_findings(ctx.state.findings_snapshot)
    )
    uncovered_keypoints = _compute_uncovered_keypoints(
        observed_kp_strs,
        ctx.state.active_hypotheses,
        ctx.state.resolved_hypotheses,
    )
    if not uncovered_keypoints or max_gap_areas <= 0:
        return []
    gap_input_fingerprint = _fingerprint(
        {
            "observed": observed_kp_strs,
            "uncovered": uncovered_keypoints,
            "policy": _policy_fingerprint(ctx),
        }
    )
    prior_gap_attempts = ctx.db.execute(
        "SELECT input_json, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-gap-selection'"
    ).fetchall()
    matching_gap_attempts: list[tuple[str | None, dict[str, Any]]] = []
    for input_json, output_json in prior_gap_attempts:
        try:
            saved_input = json.loads(input_json)
            saved_output = json.loads(output_json)
        except TypeError, json.JSONDecodeError:
            continue
        if saved_input.get("input_fingerprint") == gap_input_fingerprint:
            matching_gap_attempts.append((saved_output.get("status"), saved_output))
    completed = next(
        (
            output
            for status, output in reversed(matching_gap_attempts)
            if status == "completed"
        ),
        None,
    )
    if completed is not None:
        saved_areas = completed.get("gap_areas")
        return (
            list(saved_areas)[: min(4, max_gap_areas)]
            if isinstance(saved_areas, list)
            else []
        )
    if matching_gap_attempts:
        return []
    gap_step_suffix = gap_input_fingerprint[:16]

    def save_gap_attempt(status: str, **details: Any) -> None:
        _save_step(
            db=ctx.db,
            session_id=ctx.session_id,
            iteration=ctx.plan_cycle,
            phase="plan-broad-gap-selection",
            hypothesis_id=None,
            input_json={
                "input_fingerprint": gap_input_fingerprint,
                "observed_keypoints": observed_kp_strs[:20],
                "uncovered_keypoints": uncovered_keypoints,
                "policy_fingerprint": _policy_fingerprint(ctx),
            },
            output_json={"status": status, **details},
            suffix=gap_step_suffix,
        )

    save_gap_attempt("attempting")
    active_hypotheses_slim = [
        {"id": h.id, "description": h.description, "verdict": h.verdict}
        for h in ctx.state.active_hypotheses[:10]
    ]
    gap_msgs, gap_schema = build_gap_identifier_messages(
        observed_keypoints=ctx.observed_keypoints,
        uncovered_keypoints=uncovered_keypoints,
        active_hypotheses_slim=active_hypotheses_slim,
        case_profile=ctx.case_profile,
        case_policy=ctx.case_policy,
        db=ctx.db,
        session_id=ctx.session_id,
    )
    try:
        gap_parsed = await _call_with_outage_recovery(
            json_response.request_llm_json,
            base_url=ctx.base_url,
            model=ctx.model,
            _outage_progress_callback=ctx.progress_callback,
            messages=gap_msgs,
            json_schema=gap_schema,
            telemetry_phase="plan-broad-gap",
            status_callback=ctx.llm_status_fn,
        )
    except BaseException as exc:
        save_gap_attempt(
            "budget_exhausted"
            if isinstance(exc, LLMBudgetExceededError)
            else "interrupted"
            if isinstance(exc, InvestigationStopped)
            else "failed"
            if isinstance(exc, Exception)
            else "interrupted",
            error_type=type(exc).__name__,
            reason=str(exc)[:300],
        )
        raise
    raw_gap_areas = gap_parsed.get("gap_areas", [])
    gap_areas = raw_gap_areas if isinstance(raw_gap_areas, list) else []

    valid_gap_areas = [
        gap
        for gap in gap_areas
        if isinstance(gap, dict) and gap.get("keypoint_id") in REPORT_KEYPOINTS
    ]
    if len(valid_gap_areas) < len(gap_areas):
        _log(
            "PLAN",
            f"gap_identifier invented {len(gap_areas) - len(valid_gap_areas)} non-existent keypoint names, dropped",
        )
    gap_areas = valid_gap_areas

    max_gap_areas = min(4, max_gap_areas)
    if len(gap_areas) > max_gap_areas:
        gap_areas = gap_areas[:max_gap_areas]
    save_gap_attempt("completed", gap_areas=gap_areas)
    return gap_areas


def _rules_for_candidate(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rule_cache = _get_rule_cache()
    rules = []
    for rule_id in candidate.get("rule_ids") or []:
        rule = rule_cache.get(str(rule_id))
        if rule is not None:
            rules.append(rule.model_dump())
    return rules


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _policy_fingerprint(ctx: _BroadPlanContext) -> str:
    policy = ctx.case_policy
    return str(
        getattr(policy, "content_sha256", None)
        or _fingerprint(getattr(policy, "body", ""))
    )


def _candidate_linked_work(
    candidate: dict[str, Any],
    db: CaseDB,
    prior_attempts: dict[str, list[dict[str, Any]]],
    *,
    additional_ids: set[str] | None = None,
) -> list[dict[str, str | None]]:
    candidate_ref = str(candidate.get("candidate_ref") or "")
    hypothesis_ids = {
        str(attempt.get("admitted_hypothesis_id"))
        for attempt in prior_attempts.get(candidate_ref, [])
        if attempt.get("status") == "admitted" and attempt.get("admitted_hypothesis_id")
    }
    hypothesis_ids.update(additional_ids or set())
    from forensia.core.verification import VerificationSpec

    work = []
    for hypothesis_id in sorted(hypothesis_ids):
        row = db.execute(
            "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
            [hypothesis_id],
        ).fetchone()
        work.append(
            {
                "hypothesis_id": hypothesis_id,
                "spec_fingerprint": (
                    _fingerprint(
                        VerificationSpec.model_validate_json(row[0]).model_dump(
                            mode="json"
                        )
                    )
                    if row and row[0]
                    else None
                ),
            }
        )
    return work


def _candidate_input_fingerprint(
    candidate: dict[str, Any],
    ctx: _BroadPlanContext,
    linked_work: list[dict[str, str | None]],
) -> str:
    return _fingerprint(
        {
            "candidate_fingerprint": candidate.get("candidate_fingerprint"),
            "policy_fingerprint": _policy_fingerprint(ctx),
            "linked_work": linked_work,
        }
    )


def _prior_candidate_attempts(db: CaseDB) -> dict[str, list[dict[str, Any]]]:
    attempts: dict[str, list[dict[str, Any]]] = {}
    rows = db.execute(
        "SELECT input_json, output_json FROM trace.investigation_steps "
        "WHERE phase = 'plan-broad-candidate' ORDER BY created_at, step_id"
    ).fetchall()
    for input_json, output_json in rows:
        try:
            input_payload = json.loads(input_json)
            output_payload = json.loads(output_json)
        except TypeError, json.JSONDecodeError:
            continue
        candidate_ref = str(input_payload.get("candidate_ref") or "")
        if not candidate_ref:
            continue
        attempts.setdefault(candidate_ref, []).append(
            {
                **input_payload,
                "status": output_payload.get("status"),
                "settled_input_fingerprint": output_payload.get(
                    "settled_input_fingerprint"
                ),
                "admitted_hypothesis_id": output_payload.get("admitted_hypothesis_id"),
                "reason": output_payload.get("reason"),
                "correction_calls_used": int(
                    output_payload.get("correction_calls_used") or 0
                ),
                "draft_calls_used": int(output_payload.get("draft_calls_used") or 0),
                "draft": output_payload.get("draft"),
            }
        )
    return attempts


def _remaining_broad_plan_calls(db: CaseDB, session_id: str, cap: int) -> int:
    telemetry = get_active_telemetry()
    limit = int(getattr(telemetry, "max_logical_calls", 0) or 0)
    if not limit:
        return cap
    used = int(
        db.execute(
            "SELECT COUNT(*) FROM trace.llm_logical_calls WHERE session_id = ?",
            [session_id],
        ).fetchone()[0]
        or 0
    )
    return min(cap, max(0, limit - used))


def _select_candidate_drafts(
    ctx: _BroadPlanContext, limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prior = _prior_candidate_attempts(ctx.db)
    # Eligibility must not issue SQL while the candidate result is being read.
    linked_work_by_candidate = {
        ref: _candidate_linked_work({"candidate_ref": ref}, ctx.db, prior)
        for ref in prior
    }
    eligible_inputs: dict[str, dict[str, Any]] = {}
    exhausted_count = 0
    already_linked_count = 0
    examined_count = 0

    def eligible(metadata: dict[str, Any]) -> bool:
        nonlocal exhausted_count, already_linked_count, examined_count
        examined_count += 1
        candidate_ref = str(metadata.get("candidate_ref") or "")
        fingerprint = str(metadata.get("candidate_fingerprint") or "")
        if not candidate_ref or not fingerprint:
            return False
        linked_work = linked_work_by_candidate.get(candidate_ref, [])
        input_fingerprint = _candidate_input_fingerprint(metadata, ctx, linked_work)
        candidate_attempts = [
            attempt
            for attempt in prior.get(candidate_ref, [])
            if attempt.get("candidate_fingerprint") == fingerprint
        ]
        if any(
            attempt.get("status") == "admitted"
            and attempt.get("settled_input_fingerprint") == input_fingerprint
            for attempt in candidate_attempts
        ):
            already_linked_count += 1
            return False
        same_input_attempts = [
            attempt
            for attempt in candidate_attempts
            if attempt.get("input_fingerprint") == input_fingerprint
            and attempt.get("status")
            in {
                "attempting",
                "interrupted",
                "correcting",
                "failed",
                "budget_exhausted",
                "invalid_draft",
                "admission_rejected",
                "feasibility_rejected",
                "question_contract_rejected",
                "generation_failed",
                "merge_missing",
                "unresolved_observation",
            }
        ]
        prior_draft_calls = sum(
            int(attempt.get("draft_calls_used") or 0) for attempt in same_input_attempts
        )
        if prior_draft_calls >= 1 or any(
            attempt.get("status") == "unresolved_observation"
            for attempt in same_input_attempts
        ):
            exhausted_count += 1
            return False
        if len(eligible_inputs) < max(0, limit):
            eligible_inputs[fingerprint] = {
                "input_fingerprint": input_fingerprint,
                "attempt_number": len(same_input_attempts) + 1,
                "linked_work": linked_work,
            }
        return True

    projection = build_investigation_candidates(
        ctx.db,
        limit=max(0, min(20, limit)),
        eligible=eligible,
    )
    counts = dict(projection.get("counts") or {})
    selected = []
    for candidate in projection.get("candidates") or []:
        fingerprint = str(candidate.get("candidate_fingerprint") or "")
        selected.append(
            {
                "candidate": candidate,
                **eligible_inputs.get(fingerprint, {}),
                "prior_attempts": prior,
            }
        )
    counts.update(
        {
            "draft_selected_count": len(selected),
            "attempt_exhausted_count": exhausted_count,
            "already_linked_count": already_linked_count,
            "unexamined_candidate_count": max(
                0, counts.get("candidate_count", 0) - examined_count
            ),
            "draft_cap_omitted_count": (
                max(0, counts["eligible_candidate_count"] - len(selected))
                if counts.get("eligibility_complete")
                and counts.get("eligible_candidate_count") is not None
                else None
            ),
        }
    )
    return selected, counts


async def _call_broad_drafter(
    ctx: _BroadPlanContext,
    gap: dict[str, Any],
    *,
    candidate: dict[str, Any] | None,
    draft_index: int,
    correction_budget: list[int],
    logical_call_id: str | None,
    attempt_ordinal: list[int],
) -> tuple[Hypothesis | None, str | None]:
    available_rules = _rules_for_candidate(candidate) if candidate else []
    allowed_rule_ids = {
        str(rule_id) for rule_id in (candidate or {}).get("rule_ids") or []
    }
    h_msgs, h_schema = build_hypothesis_drafter_messages(
        gap,
        available_rules,
        case_profile=ctx.case_profile,
        case_policy=ctx.case_policy,
        db=ctx.db,
        session_id=ctx.session_id,
        observed_candidate=candidate,
    )
    h_parsed = await _call_with_outage_recovery(
        json_response.request_llm_json,
        base_url=ctx.base_url,
        model=ctx.model,
        _outage_progress_callback=ctx.progress_callback,
        messages=h_msgs,
        json_schema=h_schema,
        telemetry_phase="plan-broad-draft",
        max_tokens=_BROAD_DRAFT_MAX_TOKENS,
        status_callback=ctx.llm_status_fn,
        correction_budget=correction_budget,
        logical_call_id=logical_call_id,
        attempt_ordinal=attempt_ordinal,
    )
    hypothesis, rejection_reason = _parse_hypothesis_from_drafter(
        h_parsed,
        allowed_rule_ids=allowed_rule_ids,
        observation_only="description"
        not in h_schema["properties"]["hypothesis"]["properties"],
    )
    if hypothesis:
        observation = hypothesis.verification_spec.support_conditions.get("observation")
        if candidate and isinstance(observation, dict):
            from forensia.investigation.verification.assessment import (
                _observation_utc_datetime,
                _observation_value_matches,
            )
            from forensia.knowledge.coverage import (
                canonical_observation_claim,
                observation_claim_scope_error,
            )

            scope_error = observation_claim_scope_error(
                hypothesis.description, hypothesis.verification_spec
            )
            if scope_error:
                return None, scope_error

            rows = candidate.get("evidence") or []
            field, expected = observation["field"], observation["value"]
            # A timestamp copied from a different field is a drafting error,
            # not a reason to search for an unrelated record with that value.
            if (
                observation["operator"] == "equals"
                and _observation_utc_datetime(expected) is not None
                and not any(
                    _observation_value_matches(row.get(field), "equals", expected)
                    for row in rows
                )
            ):
                actual_fields = sorted(
                    {
                        key
                        for row in rows
                        for key, value in row.items()
                        if key != field
                        and _observation_value_matches(value, "equals", expected)
                    }
                )
                if actual_fields:
                    return (
                        None,
                        f"observation-field-value-mismatch: value belongs to {', '.join(actual_fields)}, not {field}",
                    )
            targets = sorted(
                {
                    str(row.get("evidence_id") or row.get("artifact_id"))
                    for row in rows
                    if row.get("evidence_id") or row.get("artifact_id")
                }
            )
            if not targets:
                return None, "observation-target-missing"
            observation["evidence_ids"] = targets
            refute_observation = hypothesis.verification_spec.refute_conditions.get(
                "observation"
            )
            if isinstance(refute_observation, dict):
                if refute_observation.get("family") != observation["family"]:
                    return None, "observation-refute-target-family-mismatch"
                refute_observation["evidence_ids"] = targets
            hypothesis.description = canonical_observation_claim(
                hypothesis.verification_spec
            )
        keypoint_id = gap.get("keypoint_id", "")
        if (
            keypoint_id
            and "observation" not in hypothesis.verification_spec.support_conditions
        ):
            hypothesis.target_keypoint_id = keypoint_id
        hypothesis.id = f"draft-{ctx.plan_cycle}-{draft_index}"
    return hypothesis, rejection_reason


def _attach_explicit_gap_source(
    hypothesis: Hypothesis, gap: dict[str, Any], db: CaseDB
) -> None:
    """Carry an explicit report question's exact Gap identity into its draft."""
    gap_id = str(gap.get("gap_id") or "").strip()
    if not gap_id:
        return
    row = db.execute(
        "SELECT block_heading FROM report_gaps WHERE gap_id = ?", [gap_id]
    ).fetchone()
    if row and str(row[0] or "").strip():
        hypothesis.source_gap_id = gap_id


def _unobserved_requested_values(
    candidate: dict[str, Any],
) -> list[str]:
    contract = candidate.get("request_contract") or {}
    evidence = [row for row in candidate.get("evidence") or [] if isinstance(row, dict)]
    observed_requirements = []
    missing = []
    for requirement in contract.get("requirements") or []:
        if (
            not isinstance(requirement, dict)
            or requirement.get("kind") != "observed_value"
        ):
            continue
        field = str(requirement.get("field") or "")
        family = str(requirement.get("family") or "").strip().lower()
        if not field or not family:
            continue
        observed_requirements.append((family, field))
        source = canonical_record_table(family)
        if not any(
            routed_family(str(row.get("evidence_id") or "")) == family
            and row.get("_source") == source
            and _has_observed_value(row.get(field))
            for row in evidence
        ):
            missing.append((family, field))
    if any(requirement not in missing for requirement in observed_requirements):
        return []
    return sorted({field for _family, field in missing})


async def _draft_and_admit_candidate(
    ctx: _BroadPlanContext, selected: dict[str, Any], draft_index: int
) -> tuple[Hypothesis | None, dict[str, Any]]:
    candidate = selected["candidate"]
    candidate_ref = str(candidate["candidate_ref"])
    candidate_fingerprint = str(candidate["candidate_fingerprint"])
    input_fingerprint = str(selected["input_fingerprint"])
    attempt_number = int(selected["attempt_number"])
    prior_attempts = selected["prior_attempts"]
    linked_work_before = selected.get("linked_work") or _candidate_linked_work(
        candidate, ctx.db, prior_attempts
    )
    input_payload = {
        "candidate_ref": candidate_ref,
        "gap_id": (selected.get("gap") or {}).get("gap_id"),
        "question": (selected.get("gap") or {}).get("description"),
        "candidate_fingerprint": candidate_fingerprint,
        "input_fingerprint": input_fingerprint,
        "policy_fingerprint": _policy_fingerprint(ctx),
        "linked_work": linked_work_before,
        "selection_reason": (
            "existing uncovered keypoint"
            if candidate.get("gap_keypoint_id")
            else "current observed match; eligible for bounded draft attempt"
        ),
        "rule_ids": candidate.get("rule_ids", [])[:20],
        "evidence_ids": candidate.get("evidence_ids", [])[:3],
        "scope": candidate.get("scope", {}),
    }
    step_suffix = f"{candidate_ref}-{input_fingerprint[:10]}-{attempt_number}"
    prior_correction_calls = sum(
        int(attempt.get("correction_calls_used") or 0)
        for attempt in prior_attempts.get(candidate_ref, [])
        if attempt.get("candidate_fingerprint") == candidate_fingerprint
        and attempt.get("input_fingerprint") == input_fingerprint
    )
    prior_draft_calls = sum(
        int(attempt.get("draft_calls_used") or 0)
        for attempt in prior_attempts.get(candidate_ref, [])
        if attempt.get("candidate_fingerprint") == candidate_fingerprint
        and attempt.get("input_fingerprint") == input_fingerprint
    )
    draft_calls_used = prior_draft_calls + 1
    correction_budget = [max(0, 1 - prior_correction_calls)]
    attempt_ordinal = [0]
    telemetry = get_active_telemetry()
    logical_call_id = (
        telemetry.begin_logical_call(phase="plan-broad-draft", iteration=ctx.plan_cycle)
        if telemetry is not None
        else None
    )
    logical_status = "failed"

    def save_outcome(output: dict[str, Any]) -> None:
        _save_step(
            db=ctx.db,
            session_id=ctx.session_id,
            iteration=ctx.plan_cycle,
            phase="plan-broad-candidate",
            hypothesis_id=None,
            input_json=input_payload,
            output_json=output,
            suffix=step_suffix,
        )
        gap_id = (selected.get("gap") or {}).get("gap_id")
        if gap_id and (output.get("reason") or output.get("error_type")):
            reason = (
                "investigation_attempt_failed"
                if output.get("error_type")
                else output["reason"]
            )
            ctx.db.execute(
                "UPDATE report_gaps SET coverage_reason = ?, updated_at = now() WHERE gap_id = ?",
                [reason, gap_id],
            )

    save_outcome(
        {
            "status": "attempting",
            "attempt_number": attempt_number,
            "correction_calls_used": prior_correction_calls,
            "draft_calls_used": draft_calls_used,
        }
    )
    gap = dict(
        selected.get("gap")
        or {
            "candidate_ref": candidate_ref,
            "title": candidate.get("title"),
            "summary": candidate.get("summary"),
            "scope": candidate.get("scope", {}),
        }
    )
    discovery: dict[str, Any] | None = None
    try:
        prompt_candidate = selected.get("prompt_candidate") or candidate
        if gap.get("block_heading"):
            discovery = await _call_with_outage_recovery(
                discover_gap_evidence,
                question=str(gap["description"]),
                db=ctx.db,
                base_url=ctx.base_url,
                model=ctx.model,
                case_policy=ctx.case_policy,
                status_callback=ctx.llm_status_fn,
                correction_budget=correction_budget,
                _outage_progress_callback=ctx.progress_callback,
            )
            if discovery["status"] in {"invalid", "empty"} and correction_budget[0] > 0:
                discovery["discovery_step_id"] = (
                    f"{ctx.session_id}-{ctx.plan_cycle:02d}-plan-gap-discovery-"
                    f"{step_suffix}-rejected"
                )
                _save_step(
                    db=ctx.db,
                    session_id=ctx.session_id,
                    iteration=ctx.plan_cycle,
                    phase="plan-gap-discovery",
                    hypothesis_id=None,
                    input_json={
                        "gap_id": gap["gap_id"],
                        "question": gap["description"],
                    },
                    output_json=discovery,
                    suffix=step_suffix + "-rejected",
                )
                retry_feedback = discovery
                if discovery["status"] == "empty":
                    retry_feedback = {
                        key: discovery[key]
                        for key in (
                            "status",
                            "reason",
                            "sql",
                            "proposed_sql",
                            "row_count",
                            "truncated",
                            "contract_validated",
                            "request_contract",
                        )
                        if key in discovery
                    }
                correction_budget[0] -= 1
                discovery = await _call_with_outage_recovery(
                    discover_gap_evidence,
                    question=str(gap["description"]),
                    db=ctx.db,
                    base_url=ctx.base_url,
                    model=ctx.model,
                    case_policy=ctx.case_policy,
                    status_callback=ctx.llm_status_fn,
                    correction_budget=correction_budget,
                    feedback=retry_feedback,
                    _outage_progress_callback=ctx.progress_callback,
                )
            discovery["discovery_step_id"] = (
                f"{ctx.session_id}-{ctx.plan_cycle:02d}-plan-gap-discovery-{step_suffix}"
            )
            _save_step(
                db=ctx.db,
                session_id=ctx.session_id,
                iteration=ctx.plan_cycle,
                phase="plan-gap-discovery",
                hypothesis_id=None,
                input_json={"gap_id": gap["gap_id"], "question": gap["description"]},
                output_json=discovery,
                suffix=step_suffix,
            )
            if discovery["status"] != "completed":
                outcome = {
                    "candidate_ref": candidate_ref,
                    "status": "discovery_failed",
                    "reason": discovery["reason"],
                    "draft_calls_used": draft_calls_used,
                    "attempt_number": attempt_number,
                    "correction_calls_used": prior_correction_calls
                    + 1
                    - correction_budget[0],
                }
                save_outcome(outcome)
                logical_status = "success"
                return None, outcome
            prompt_candidate = discovery["candidate"]
            prompt_candidate["candidate_ref"] = candidate_ref
            prompt_candidate["discovery_step_id"] = discovery["discovery_step_id"]
        missing_observations = _unobserved_requested_values(prompt_candidate)
        if missing_observations:
            outcome = {
                "candidate_ref": candidate_ref,
                "status": "unresolved_observation",
                "reason": (
                    "requested_observation_unavailable: "
                    + ", ".join(missing_observations)
                ),
                "draft_calls_used": prior_draft_calls,
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
            }
            save_outcome(outcome)
            logical_status = "success"
            return None, outcome
        hypothesis, rejection_reason = await _call_broad_drafter(
            ctx,
            gap,
            candidate=prompt_candidate,
            draft_index=draft_index,
            correction_budget=correction_budget,
            logical_call_id=logical_call_id,
            attempt_ordinal=attempt_ordinal,
        )
        logical_status = "success"

        def judge_draft(
            value: Hypothesis | None, parse_error: str | None
        ) -> tuple[bool, str, str]:
            if value is None:
                return False, parse_error or "invalid-draft", "invalid_draft"
            if gap.get("block_heading"):
                reason = question_contract_match_reason(
                    prompt_candidate.get("request_contract"),
                    value.verification_spec,
                    observation_records={
                        str(row.get("evidence_id")): row
                        for row in prompt_candidate.get("evidence", [])
                        if isinstance(row, dict) and row.get("evidence_id")
                    },
                )
                if reason:
                    return False, reason, "question_contract_rejected"
                support = value.verification_spec.support_conditions
                observation = (
                    support.get("observation") if isinstance(support, dict) else None
                )
                candidate_ids = {
                    str(evidence_id)
                    for evidence_id in prompt_candidate.get("evidence_ids", [])
                    if evidence_id
                }
                observation_ids = (
                    observation.get("evidence_ids")
                    if isinstance(observation, dict)
                    else None
                )
                observed_ids = {
                    str(evidence_id)
                    for evidence_id in observation_ids or []
                    if evidence_id
                }
                if (
                    not observed_ids
                    or not candidate_ids
                    or not observed_ids.issubset(candidate_ids)
                ):
                    return (
                        False,
                        "question_observation_evidence_mismatch",
                        "question_contract_rejected",
                    )
            _attach_explicit_gap_source(value, gap, ctx.db)
            qualify_event_contexts(value, ctx.db)
            support = value.verification_spec.support_conditions
            if isinstance(support, dict):
                from forensia.knowledge.coverage import verification_feasibility_error

                infeasible = verification_feasibility_error(
                    ctx.db, support, value.required_entities
                )
                if infeasible:
                    return (
                        False,
                        f"{infeasible[0]}: {infeasible[1]}",
                        "feasibility_rejected",
                    )
            accepted, reason = admit_new_hypothesis(value, ctx.state)
            return accepted, reason, "admission_rejected"

        accepted, reason, rejection_status = judge_draft(hypothesis, rejection_reason)
        if not accepted and correction_budget[0] > 0:
            proposal = (
                hypothesis.model_dump(mode="json") if hypothesis is not None else None
            )
            correction_budget[0] -= 1
            draft_calls_used += 1
            feedback = {
                "rejection_reason": reason,
                "prior_proposal": proposal,
                "instruction": "Correct the rejected proposal while preserving its intended scope; do not broaden or replace it with a narrower causal claim.",
            }
            save_outcome(
                {
                    "status": "correcting",
                    "reason": reason,
                    "draft": proposal,
                    "attempt_number": attempt_number,
                    "correction_calls_used": prior_correction_calls + 1,
                    "draft_calls_used": draft_calls_used,
                }
            )
            correction_gap = {**gap, "draft_feedback": feedback}
            hypothesis, rejection_reason = await _call_broad_drafter(
                ctx,
                correction_gap,
                candidate=prompt_candidate,
                draft_index=draft_index,
                correction_budget=correction_budget,
                logical_call_id=logical_call_id,
                attempt_ordinal=attempt_ordinal,
            )
            accepted, reason, rejection_status = judge_draft(
                hypothesis, rejection_reason
            )
        if not accepted:
            status = rejection_status
            save_outcome(
                {
                    "status": status,
                    "reason": reason,
                    "draft": (
                        hypothesis.model_dump(mode="json")
                        if hypothesis is not None
                        else None
                    ),
                    "attempt_number": attempt_number,
                    "correction_calls_used": (
                        prior_correction_calls + 1 - correction_budget[0]
                    ),
                    "draft_calls_used": draft_calls_used,
                }
            )
            if ctx.emit_fn:
                ctx.emit_fn(
                    "investigate/admit",
                    "Broad-plan hypothesis draft was rejected",
                    iteration=ctx.plan_cycle,
                    kind="hypothesis.admission_skipped",
                    status="skipped",
                    severity="warning",
                    reason=str(reason).split(":", 1)[0],
                    candidate_ref=candidate_ref,
                )
            return hypothesis, {
                "candidate_ref": candidate_ref,
                "status": status,
                "reason": reason,
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
                "draft_calls_used": draft_calls_used,
            }

        aliases: dict[str, str] = {}
        ctx.state.active_hypotheses = merge_active_hypotheses(
            db=ctx.db,
            current=ctx.state.active_hypotheses,
            updates=[hypothesis],
            resolved=ctx.state.resolved_hypotheses,
            session_id=ctx.session_id,
            origin="broad_plan",
            alias_map_out=aliases,
        )
        admitted_id = aliases.get(hypothesis.id)
        merged = next(
            (
                item
                for item in [
                    *ctx.state.active_hypotheses,
                    *ctx.state.resolved_hypotheses,
                ]
                if item.id == admitted_id
            ),
            None,
        )
        if merged is None:
            save_outcome(
                {
                    "status": "merge_missing",
                    "reason": "canonical merge did not return an admitted hypothesis ID",
                    "draft_hypothesis_id": hypothesis.id,
                    "attempt_number": attempt_number,
                    "correction_calls_used": prior_correction_calls
                    + 1
                    - correction_budget[0],
                    "draft_calls_used": draft_calls_used,
                }
            )
            return hypothesis, {
                "candidate_ref": candidate_ref,
                "status": "merge_missing",
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
                "draft_calls_used": draft_calls_used,
            }
        linked_work = _candidate_linked_work(
            candidate, ctx.db, prior_attempts, additional_ids={merged.id}
        )
        settled_fingerprint = _candidate_input_fingerprint(candidate, ctx, linked_work)
        save_outcome(
            {
                "status": "admitted",
                "reason": "question_has_unverified_candidate"
                if gap.get("gap_id")
                else "candidate_admitted",
                "draft_hypothesis_id": hypothesis.id,
                "admitted_hypothesis_id": merged.id,
                "admitted_spec_fingerprint": _fingerprint(
                    merged.verification_spec.model_dump(mode="json")
                ),
                "discovery_step_id": (discovery or {}).get("discovery_step_id"),
                "contract_id": (discovery or {}).get("contract_id"),
                "settled_input_fingerprint": settled_fingerprint,
                "linked_work": linked_work,
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
                "draft_calls_used": draft_calls_used,
            }
        )
        if ctx.emit_fn:
            ctx.emit_fn(
                "investigate/admit",
                f"Admitted hypothesis {merged.id} from broad-plan candidate",
                iteration=ctx.plan_cycle,
                kind="hypothesis.admitted",
                status="completed",
                severity="success",
                reason="broad_plan_candidate_admitted",
                hypothesis_id=merged.id,
                candidate_ref=candidate_ref,
            )
        return hypothesis, {
            "candidate_ref": candidate_ref,
            "status": "admitted",
            "draft_hypothesis_id": hypothesis.id,
            "admitted_hypothesis_id": merged.id,
            "attempt_number": attempt_number,
            "correction_calls_used": prior_correction_calls + 1 - correction_budget[0],
            "draft_calls_used": draft_calls_used,
        }
    except (LLMStructuredOutputError, LLMRequestTimeoutError) as exc:
        if exc.error_code not in {
            "generated_output_parse_failed",
            "llm_request_timeout",
        }:
            logical_status = "failed"
            save_outcome(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error_code": exc.error_code,
                    "reason": str(exc)[:300],
                    "attempt_number": attempt_number,
                    "correction_calls_used": prior_correction_calls
                    + 1
                    - correction_budget[0],
                    "draft_calls_used": draft_calls_used,
                }
            )
            raise
        reason = f"{exc.error_code}: {str(exc)[:300]}"
        save_outcome(
            {
                "status": "generation_failed",
                "error_type": type(exc).__name__,
                "error_code": exc.error_code,
                "reason": reason,
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
                "draft_calls_used": draft_calls_used,
            }
        )
        logical_status = "failed"
        return None, {
            "candidate_ref": candidate_ref,
            "status": "generation_failed",
            "reason": reason,
            "attempt_number": attempt_number,
            "correction_calls_used": prior_correction_calls + 1 - correction_budget[0],
            "draft_calls_used": draft_calls_used,
        }
    except BaseException as exc:
        logical_status = (
            "discarded" if isinstance(exc, InvestigationStopped) else "failed"
        )
        save_outcome(
            {
                "status": (
                    "budget_exhausted"
                    if isinstance(exc, LLMBudgetExceededError)
                    else "failed"
                    if isinstance(exc, Exception)
                    else "interrupted"
                ),
                "error_type": type(exc).__name__,
                "reason": str(exc)[:300],
                "attempt_number": attempt_number,
                "correction_calls_used": prior_correction_calls
                + 1
                - correction_budget[0],
                "draft_calls_used": draft_calls_used,
            }
        )
        raise
    finally:
        if telemetry is not None and logical_call_id is not None:
            telemetry.close_logical_call(
                logical_call_id=logical_call_id, status=logical_status
            )


def _select_gap_drafts(
    ctx: _BroadPlanContext, gaps: list[dict[str, Any]], limit: int
) -> tuple[list[dict[str, Any]], int]:
    if limit <= 0:
        return [], 0

    from forensia.investigation.hypotheses.execution import _evidence_scope_fingerprint

    prior = _prior_candidate_attempts(ctx.db)
    evidence_revision = _evidence_scope_fingerprint(ctx.db, "SELECT 1")
    selected: list[dict[str, Any]] = []
    exhausted = 0
    for gap in gaps:
        keypoint_id = str(gap.get("keypoint_id") or "").strip()
        gap_id = str(gap.get("gap_id") or "").strip()
        candidate_ref = str(gap.get("candidate_ref") or "").strip()
        identity = gap_id or keypoint_id
        if not identity:
            continue
        candidate_ref = candidate_ref or "gap-" + identity
        candidate = {
            "candidate_ref": candidate_ref,
            "candidate_fingerprint": _fingerprint(
                {
                    "gap_id": gap_id or None,
                    "keypoint_id": keypoint_id,
                    "section_key": gap.get("section_key"),
                    "description": gap.get("description"),
                    "task_id": gap.get("task_id"),
                    "origin": gap.get("origin"),
                    "evidence_revision": evidence_revision,
                    "observed_keypoints": ctx.observed_keypoint_labels,
                }
            ),
            "gap_keypoint_id": keypoint_id or None,
            "rule_ids": [],
            "evidence_ids": [],
            "scope": {},
            "title": str(gap.get("description") or keypoint_id or gap_id)[:200],
            "summary": str(
                gap_operational_reason(ctx.db, gap_id)
                or gap.get("coverage_reason")
                or gap.get("why_uncovered")
                or "Existing case gap without a current Finding candidate."
            )[:500],
        }
        linked_work = _candidate_linked_work(candidate, ctx.db, prior)
        input_fingerprint = _candidate_input_fingerprint(candidate, ctx, linked_work)
        attempts = [
            attempt
            for attempt in prior.get(candidate_ref, [])
            if attempt.get("candidate_fingerprint")
            == candidate["candidate_fingerprint"]
            and attempt.get("input_fingerprint") == input_fingerprint
            and attempt.get("status")
            in {
                "attempting",
                "interrupted",
                "correcting",
                "failed",
                "budget_exhausted",
                "invalid_draft",
                "admission_rejected",
                "feasibility_rejected",
                "question_contract_rejected",
                "merge_missing",
                "discovery_failed",
                "generation_failed",
                "unresolved_observation",
            }
        ]
        if any(
            attempt.get("status") == "admitted"
            and attempt.get("settled_input_fingerprint") == input_fingerprint
            for attempt in prior.get(candidate_ref, [])
        ):
            continue
        if sum(
            int(attempt.get("draft_calls_used") or 0) for attempt in attempts
        ) >= 1 or any(
            attempt.get("status") == "unresolved_observation" for attempt in attempts
        ):
            exhausted += 1
            continue
        selected.append(
            {
                "candidate": candidate,
                "prompt_candidate": None,
                "input_fingerprint": input_fingerprint,
                "attempt_number": len(attempts) + 1,
                "gap": gap,
                "prior_attempts": prior,
                "linked_work": linked_work,
            }
        )
        if len(selected) >= limit:
            break
    return selected, exhausted


def _persisted_gap_drafts(ctx: _BroadPlanContext) -> list[dict[str, Any]]:
    """Project existing unlinked Gap/Task work into the bounded draft pool."""
    rows = ctx.db.execute(
        "SELECT g.gap_id, g.section_key, g.description, g.kind, g.status, "
        "g.task_id, g.coverage_reason, g.origin, g.block_heading "
        "FROM report_gaps g "
        "LEFT JOIN investigation_tasks t ON t.task_id = g.task_id "
        "WHERE g.status IN ('open', 'in_progress', 'needs_review') "
        "AND g.hypothesis_id IS NULL "
        "AND (g.task_id IS NULL OR t.status IN ('open', 'in_progress')) "
        "ORDER BY CASE WHEN COALESCE(g.block_heading, '') <> '' THEN 0 ELSE 1 END, "
        "CASE g.origin WHEN 'configuration' THEN 0 ELSE 1 END, "
        "g.created_at, g.gap_id"
    ).fetchall()
    return [
        {
            "candidate_ref": f"gap-{row[0]}",
            "gap_id": str(row[0]),
            "keypoint_id": "",
            "section_key": str(row[1] or ""),
            "description": str(row[2] or ""),
            "kind": str(row[3] or ""),
            "status": str(row[4] or ""),
            "task_id": str(row[5] or ""),
            "coverage_reason": (
                gap_operational_reason(ctx.db, str(row[0])) or str(row[6] or "")
            ),
            "origin": str(row[7] or ""),
            "block_heading": str(row[8] or ""),
            "why_uncovered": (
                gap_operational_reason(ctx.db, str(row[0])) or str(row[6] or "")
            ),
        }
        for row in rows
    ]


def _save_broad_plan_results(
    ctx: _BroadPlanContext,
    plan_input: dict[str, Any],
    gap_areas: list[dict[str, Any]],
    drafted_hypotheses: list[Hypothesis],
    candidate_summary: dict[str, Any],
    candidate_outcomes: list[dict[str, Any]],
    *,
    status: str = "completed",
    terminal_error: dict[str, Any] | None = None,
) -> None:
    output = {
        "status": status,
        "gap_areas": gap_areas,
        "hypotheses": [h.model_dump() for h in drafted_hypotheses],
        "candidate_summary": candidate_summary,
        "candidate_outcomes": candidate_outcomes,
    }
    if terminal_error:
        output["terminal_error"] = terminal_error
    _save_step(
        db=ctx.db,
        session_id=ctx.session_id,
        iteration=ctx.plan_cycle,
        phase="plan-broad",
        hypothesis_id=None,
        input_json=plan_input,
        output_json=output,
    )


def _emit_broad_plan_result(
    ctx: _BroadPlanContext,
    drafted_hypotheses: list[Hypothesis],
    stop_flag: bool,
    candidate_summary: dict[str, Any],
) -> None:
    candidate_count = int(candidate_summary.get("candidate_count", 0))
    omitted_count = candidate_summary.get("draft_cap_omitted_count", 0)
    unassessed_count = (
        candidate_summary.get("unexamined_candidate_count", 0) + omitted_count
        if omitted_count is not None
        else "unknown"
    )
    _log(
        "PLAN",
        f"+{len(drafted_hypotheses)} draft(s), candidates={candidate_count}, "
        f"unassessed={unassessed_count}, active={len(ctx.state.active_hypotheses)}, "
        f"stop={stop_flag}",
    )
    if ctx.emit_fn:
        ctx.emit_fn(
            "investigate/plan",
            f"[plan] drafts={len(drafted_hypotheses)} candidates={candidate_count} "
            f"unassessed={unassessed_count} active={len(ctx.state.active_hypotheses)}",
            iteration=ctx.plan_cycle,
            kind="investigation.plan.completed",
            status="completed",
            severity="success",
            reason="no_remaining_candidates" if stop_flag else "planning_complete",
        )


async def _run_broad_plan_step(
    state: SessionState,
    db: CaseDB,
    session_id: str,
    base_url: str,
    model: str,
    plan_cycle: int,
    observed_keypoints: list[dict[str, Any]],
    emit_fn: Callable[..., None] | None,
    llm_status_fn: Callable[[str], None],
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    case_profile: CaseEvidenceProfile | None = None,
    case_policy: Any | None = None,
) -> bool:
    """Plan from observed candidates, or fall back to uncovered keypoints."""
    import httpx

    observed_keypoint_labels = _broad_plan_observed_labels(observed_keypoints)
    plan_input = state.model_dump()
    ctx = _BroadPlanContext(
        state=state,
        db=db,
        session_id=session_id,
        base_url=base_url,
        model=model,
        plan_cycle=plan_cycle,
        observed_keypoints=observed_keypoints,
        observed_keypoint_labels=observed_keypoint_labels,
        emit_fn=emit_fn,
        llm_status_fn=llm_status_fn,
        progress_callback=progress_callback,
        case_profile=case_profile,
        case_policy=case_policy,
    )
    gap_areas: list[dict[str, Any]] = []
    drafted_hypotheses: list[Hypothesis] = []
    candidate_outcomes: list[dict[str, Any]] = []
    candidate_summary: dict[str, Any] = {}

    def save_terminal_plan(exc: BaseException) -> None:
        _save_broad_plan_results(
            ctx,
            plan_input,
            gap_areas,
            drafted_hypotheses,
            candidate_summary,
            candidate_outcomes,
            status=(
                "budget_exhausted"
                if isinstance(exc, LLMBudgetExceededError)
                else "interrupted"
                if isinstance(exc, InvestigationStopped)
                or not isinstance(exc, Exception)
                else "failed"
            ),
            terminal_error={
                "error_type": type(exc).__name__,
                "reason": str(exc)[:300],
                **(
                    {"error_code": exc.error_code}
                    if isinstance(exc, LLMStructuredOutputError)
                    else {}
                ),
            },
        )

    try:
        available_slots = max(0, MAX_ACTIVE_HYPOTHESES - len(state.active_hypotheses))
        call_allowance = _remaining_broad_plan_calls(
            db, session_id, cap=min(4, available_slots)
        )
        gap_identification_error: str | None = None
        persisted_gaps = _persisted_gap_drafts(ctx) if available_slots else []
        gap_limit = min(
            4 if any(g.get("block_heading") for g in persisted_gaps) else 1,
            available_slots,
            call_allowance,
        )
        gap_selected, exhausted_gaps = _select_gap_drafts(
            ctx, persisted_gaps, gap_limit
        )
        if call_allowance >= 2 and available_slots and not gap_selected:
            try:
                gap_areas = await _identify_broad_plan_gaps(ctx, max_gap_areas=4)
            except LLMBudgetExceededError:
                raise
            except LLMServerUnavailableError:
                raise
            except LLMStructuredOutputError as exc:
                if exc.error_code != "generated_output_parse_failed":
                    raise
                gap_identification_error = (
                    f"generated_output_parse_failed: {str(exc)[:240]}"
                )
                gap_areas = []
            except RuntimeError as exc:
                gap_identification_error = str(exc)[:240]
                gap_areas = []
                _log(
                    "PLAN",
                    f"gap identification failed; continuing with persisted work and findings: {gap_identification_error}",
                    level="warning",
                )
        gap_areas = [*persisted_gaps, *gap_areas]
        if available_slots and not gap_selected:
            remaining_calls = _remaining_broad_plan_calls(
                db, session_id, cap=min(4, available_slots)
            )
            gap_selected, exhausted_gaps = _select_gap_drafts(
                ctx,
                gap_areas,
                limit=min(
                    gap_limit,
                    remaining_calls,
                ),
            )
        remaining_calls = _remaining_broad_plan_calls(
            db, session_id, cap=min(4, available_slots)
        )
        candidate_selected, candidate_summary = _select_candidate_drafts(
            ctx,
            limit=max(
                0,
                min(
                    4 - len(gap_selected),
                    available_slots - len(gap_selected),
                    remaining_calls,
                ),
            ),
        )
        selected = [*gap_selected, *candidate_selected]
        candidate_summary.update(
            {
                "available_hypothesis_slots": available_slots,
                "remaining_call_allowance": call_allowance,
                "gap_areas_returned": len(gap_areas),
                "persisted_gap_count": len(persisted_gaps),
                "gap_drafts_selected": len(gap_selected),
                "gap_identification_error": gap_identification_error,
                "gap_attempt_exhausted_count": exhausted_gaps,
                "gap_draft_unassessed_count": max(
                    0, len(gap_areas) - len(gap_selected) - exhausted_gaps
                ),
                "selected_gap_keypoints": [
                    item.get("candidate", {}).get("gap_keypoint_id")
                    for item in gap_selected
                ],
            }
        )
        _save_broad_plan_results(
            ctx,
            plan_input,
            gap_areas,
            drafted_hypotheses,
            candidate_summary,
            candidate_outcomes,
            status="running",
        )
        for draft_index, selection in enumerate(selected, start=1):
            hypothesis, outcome = await _draft_and_admit_candidate(
                ctx, selection, draft_index
            )
            candidate_outcomes.append(outcome)
            if hypothesis is not None:
                drafted_hypotheses.append(hypothesis)

        candidate_summary["drafted_count"] = len(drafted_hypotheses)
        candidate_summary["admitted_count"] = sum(
            outcome.get("status") == "admitted" for outcome in candidate_outcomes
        )
        candidate_summary["rejected_count"] = sum(
            outcome.get("status")
            in {"admission_rejected", "feasibility_rejected", "invalid_draft"}
            for outcome in candidate_outcomes
        )
        observed_labels = observed_keypoint_labels or _observed_keypoints_from_findings(
            state.findings_snapshot
        )
        uncovered_count = len(
            _compute_uncovered_keypoints(
                observed_labels,
                state.active_hypotheses,
                state.resolved_hypotheses,
            )
        )
        candidate_summary["uncovered_keypoint_count"] = uncovered_count
        if available_slots == 0:
            candidate_summary["stop_reason"] = "active_hypothesis_cap"
        elif call_allowance == 0 and (
            candidate_summary.get("candidate_count", 0) or uncovered_count
        ):
            candidate_summary["stop_reason"] = "llm_budget_exhausted"
        elif candidate_summary.get("attempt_exhausted_count", 0):
            candidate_summary["stop_reason"] = "candidate_retry_exhausted"
        elif candidate_summary.get("draft_cap_omitted_count", 0):
            candidate_summary["stop_reason"] = "candidate_draft_cap"
        stop_flag = (
            int(candidate_summary.get("candidate_count", 0)) == 0
            and not gap_areas
            and not selected
            and uncovered_count == 0
            and available_slots > 0
            and call_allowance > 0
        )
        _save_broad_plan_results(
            ctx,
            plan_input,
            gap_areas,
            drafted_hypotheses,
            candidate_summary,
            candidate_outcomes,
        )
        _emit_broad_plan_result(ctx, drafted_hypotheses, stop_flag, candidate_summary)
        return stop_flag
    except InvestigationStopped as exc:
        save_terminal_plan(exc)
        raise
    except LLMStructuredOutputError as exc:
        save_terminal_plan(exc)
        raise
    except httpx.HTTPStatusError as exc:
        save_terminal_plan(exc)
        if exc.response.status_code >= 500:
            raise
        err_msg = f"LLM failed: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn(
                "investigate/plan",
                err_msg,
                iteration=plan_cycle,
                kind="investigation.plan_failed",
                status="failed",
                severity="error",
                reason="http_status_error",
            )
        return False
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        save_terminal_plan(exc)
        err_msg = f"LLM server error: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        raise
    except LLMRequestTimeoutError as exc:
        save_terminal_plan(exc)
        err_msg = f"LLM request timed out; broad planning skipped: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn(
                "investigate/plan",
                err_msg,
                iteration=plan_cycle,
                kind="investigation.plan_failed",
                status="failed",
                severity="error",
                reason="llm_request_timeout",
            )
        return False
    except (LLMServerUnavailableError, LLMBudgetExceededError) as exc:
        save_terminal_plan(exc)
        raise
    except Exception as exc:
        save_terminal_plan(exc)
        err_msg = f"Planning failed: {exc}"
        _log("PLAN_BROAD", err_msg, level="error")
        if emit_fn:
            emit_fn(
                "investigate/plan",
                err_msg,
                iteration=plan_cycle,
                kind="investigation.plan_failed",
                status="failed",
                severity="error",
                reason="planning_error",
            )
        return False
    except BaseException as exc:
        save_terminal_plan(exc)
        raise


async def _run_cycle_body(
    *,
    state: SessionState,
    ctx: Ctx,
    db: CaseDB,
    case: Case,
    session_id: str,
    base_url: str,
    model: str,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    max_queries_per_hypothesis: int,
    plan_cycle: int,
    max_iter: int,
    report_only: bool,
    case_profile: CaseEvidenceProfile | None = None,
) -> tuple[bool, list[str]]:
    """Run one plan cycle: broad plan + hypothesis loop.

    Returns (broad_plan_stop, focus_sections).
    """

    def _emit(
        stage: str,
        summary: str,
        *,
        iteration: int | None = None,
        kind: str,
        status: str = "running",
        severity: str = "info",
        reason: str | None = None,
        **extras: Any,
    ) -> None:
        if not progress_callback:
            return
        refs = {
            key: value
            for key, value in {
                "hypothesis_id": extras.get("hypothesis_id")
                or state.focus_hypothesis_id,
                "query_id": extras.get("query_id"),
                "reasoning_entry_id": extras.get("reasoning_entry_id"),
                "step_id": extras.get("step_id"),
            }.items()
            if value
        }
        progress_callback(
            progress_event(
                kind,
                status,
                severity=severity,
                reason=reason,
                stage=stage,
                iteration=state.iteration if iteration is None else iteration,
                summary=summary,
                session_id=session_id,
                refs=refs,
                **{
                    key: value
                    for key, value in extras.items()
                    if key
                    in {
                        "candidate_ref",
                        "score",
                        "leading_factor",
                        "draft_count",
                        "candidate_count",
                        "unassessed_count",
                        "error_type",
                    }
                },
            )
        )

    def llm_status(message: str) -> None:
        _log("LLM", message)
        _emit(
            "investigate/llm",
            message,
            iteration=state.iteration,
            kind="llm.request_status",
            reason="provider_status_update",
        )

    broad_plan_stop = False
    focus_sections: list[str] = []
    observed_keypoints = _scan_report_keypoints(case, db)
    _save_step(
        db=db,
        session_id=session_id,
        iteration=plan_cycle,
        phase="plan-keypoint-scan",
        hypothesis_id=None,
        input_json={
            "keypoints": sorted(REPORT_KEYPOINTS.keys()),
            "investigation_eligible_keypoints": list(investigation_keypoint_names()),
        },
        output_json={"observed_keypoints": observed_keypoints},
    )

    if not report_only:
        active_ids = [hypothesis.id for hypothesis in state.active_hypotheses]
        judgments = judge_work(
            db, active_ids, selection_gate=True, session_id=session_id
        )
        for hypothesis in list(state.active_hypotheses):
            judgment = judgments.get(hypothesis.id)
            if judgment is None or judgment.runnable:
                continue
            exhausted = next(
                (
                    blocker
                    for blocker in judgment.blockers
                    if blocker.code
                    in {
                        "work_exhausted",
                        "planner_exhausted",
                        "no_eligible_capability",
                        "retry_budget",
                        "inconclusive_limit",
                    }
                ),
                None,
            )
            if exhausted is not None:
                pause_hypothesis_work(db, hypothesis, exhausted.code)
                state.active_hypotheses.remove(hypothesis)
                state.resolved_hypotheses.append(hypothesis)
                _emit(
                    "investigate/plan",
                    f"paused {hypothesis.id}: {exhausted.code}",
                    kind="hypothesis.work_paused",
                    status="stopped",
                    severity="warning",
                    reason=exhausted.code,
                    hypothesis_id=hypothesis.id,
                )
        runnable_ids = sorted(
            hypothesis_id
            for hypothesis_id, judgment in judgments.items()
            if judgment.runnable
        )
        if runnable_ids:
            _save_step(
                db=db,
                session_id=session_id,
                iteration=plan_cycle,
                phase="plan-broad",
                hypothesis_id=None,
                input_json={"runnable_existing_hypothesis_ids": runnable_ids},
                output_json={
                    "status": "skipped",
                    "reason": "existing_runnable_work",
                    "runnable_existing_hypothesis_ids": runnable_ids,
                },
            )
        else:
            broad_plan_stop = await _call_with_outage_recovery(
                _run_broad_plan_step,
                base_url=base_url,
                model=model,
                _outage_progress_callback=progress_callback,
                state=state,
                db=db,
                session_id=session_id,
                plan_cycle=plan_cycle,
                observed_keypoints=observed_keypoints,
                emit_fn=_emit,
                llm_status_fn=llm_status,
                case_profile=case_profile,
                case_policy=ctx.forensia_policy,
            )
        remaining_cycles = max(1, max_iter - plan_cycle + 1)
        focus_max = max(
            2, (len(state.active_hypotheses) + remaining_cycles - 1) // remaining_cycles
        )
        selection_results = select_focus_hypotheses(
            db,
            limit=focus_max,
            findings_snapshot=state.findings_snapshot,
            session_id=session_id,
            iteration=plan_cycle,
        )
        active_by_id = {hyp.id: hyp for hyp in state.active_hypotheses}
        focus_hypotheses = [
            active_by_id[result.hypothesis_id]
            for result in selection_results
            if result.eligible and result.hypothesis_id in active_by_id
        ]
        for result in selection_results:
            leading_factor = max(
                result.components, key=lambda item: item.weighted, default=None
            )
            reason = (
                result.block_reason
                if not result.eligible
                else leading_factor.name
                if leading_factor
                else "eligible"
            )
            _emit(
                "investigate/select",
                (
                    f"hypothesis {result.hypothesis_id} selected for focus "
                    f"(score={result.total_score:.1f}; "
                    f"factor={leading_factor.name if leading_factor else 'eligible'})"
                    if result.eligible
                    else f"hypothesis {result.hypothesis_id} not selected: {reason}"
                ),
                iteration=plan_cycle,
                kind="hypothesis.selected"
                if result.eligible
                else "hypothesis.selection_skipped",
                status="completed" if result.eligible else "skipped",
                severity="info" if result.eligible else "warning",
                reason="selected_by_priority_score" if result.eligible else reason,
                hypothesis_id=result.hypothesis_id,
                score=result.total_score,
                leading_factor=(
                    {
                        "name": leading_factor.name,
                        "reason": leading_factor.reason,
                    }
                    if leading_factor
                    else None
                ),
            )
        for hypothesis in focus_hypotheses:
            if ctx.interrupted:
                break
            state.focus_hypothesis_id = hypothesis.id
            state.focus_depth = 0
            focus_sections = _guess_related_sections(hypothesis.description)
            _log("HYPOTHESIS", f"{hypothesis.id} — {hypothesis.description}")
            _emit(
                "investigate/hypothesis",
                f"[hypothesis] {hypothesis.id}: {hypothesis.description}",
                iteration=plan_cycle,
                kind="hypothesis.investigation_started",
                status="running",
                reason="focus_hypothesis_selected",
                hypothesis_id=hypothesis.id,
            )
            with telemetry_scope(hypothesis_id=hypothesis.id, iteration=plan_cycle):
                semantic_before = work_progress_snapshot(db, hypothesis.id)
                fingerprint_before = (
                    work_progress_fingerprint(semantic_before)
                    if semantic_before is not None
                    else None
                )
                state, sections = await _investigate_one_hypothesis(
                    hypothesis=hypothesis,
                    state=state,
                    ctx=ctx,
                    db=db,
                    base_url=base_url,
                    model=model,
                    plan_cycle=plan_cycle,
                    session_id=session_id,
                    max_queries_per_hypothesis=max_queries_per_hypothesis,
                    case=case,
                    query_limit=max_queries_per_hypothesis,
                    emit_fn=_emit,
                    llm_status_fn=llm_status,
                    case_profile=case_profile,
                )
            semantic_after = work_progress_snapshot(db, hypothesis.id)
            progressed = bool(
                semantic_before is not None
                and semantic_after is not None
                and report_cycle_progress(semantic_before, semantic_after)
            )
            fingerprint_after = (
                work_progress_fingerprint(semantic_after)
                if semantic_after is not None
                else None
            )
            _save_step(
                db=db,
                session_id=session_id,
                iteration=plan_cycle,
                phase="work-progress",
                hypothesis_id=hypothesis.id,
                input_json={"fingerprint_before": fingerprint_before},
                output_json={
                    "status": "completed",
                    "fingerprint": fingerprint_after,
                    "progressed": progressed,
                },
            )
    return broad_plan_stop, focus_sections
