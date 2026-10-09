"""Unified settlement gate for hypothesis resolution.

R8-01: All hypothesis settlement (confirmed/refuted/untestable) must flow
through a single ``SettlementDecision`` pure function.  Direct calls to
``resolve_hypothesis`` from heuristics are prohibited.

The settlement gate enforces:
- supporting EvidenceLink >= 1 for confirmed
- machine sufficiency == sufficient for confirmed
- required entities have concrete values (not unknown/None/-/empty/loopback)
- correlation constraints satisfied (same_host, within_minutes, logon type, etc.)
- no unresolved contradictory groups
- observation vs assessment claim separation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from forensia.ai.checking.sufficiency import (
    EvidenceLink,
    SufficiencyResult,
    derivation_root_key,
    evaluate_sufficiency,
    load_evidence_links,
)
from forensia.ai.retrieval_telemetry import RetrievalEvaluation
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.knowledge.coverage import (
    derive_required_capabilities,
    get_coverage_summary,
    relevant_coverage_states,
)

# Values that are NOT concrete entity instantiations.
_DISQUALIFIED_ENTITY_VALUES = frozenset(
    {
        "",
        "-",
        "unknown",
        "none",
        "null",
        "n/a",
        "na",
        "not applicable",
        "not established",
        "not available",
        "loopback",
        "127.0.0.1",
        "::1",
        "localhost",
        "0.0.0.0",
    }
)

# Template tokens that indicate un-interpolated placeholders.
_TEMPLATE_TOKEN_PREFIXES = ("{", "<%", "{{")


@dataclass(frozen=True, slots=True)
class SettlementInput:
    """All inputs required for a settlement decision.

    Constructed by the runner before calling ``settle_hypothesis``.
    """

    hypothesis: Hypothesis
    checker_verdict: str  # raw LLM verdict from check phase
    check_summary: str
    sample_rows: list[dict[str, Any]] | None = None
    co_observed_event_ids: list[int] | None = None
    co_observation_satisfied: bool = False
    co_observation_reason: str = ""
    same_host: bool = False
    within_minutes: int | None = None
    is_benign_auth: bool = False
    has_rule_refute_when_zero_rows: bool = False
    consecutive_zero_row_inconclusive: int = 0
    consecutive_same_missing: int = 0
    unavailable_missing_event_ids: list[int] | None = None
    # Scope-wise absence judgment computed by the runner from the latest
    # zero-row RetrievalEvaluation and the Coverage states of the hypothesis'
    # required capabilities.  A rule-declared zero_rows refutation is only
    # admissible when the absence itself is observable; "unknown" or
    # "unavailable" keeps the hypothesis untestable instead of refuted.
    absence_scope: Literal["observable", "unknown", "unavailable"] = "unknown"
    absence_note: str = ""
    # The runner computes and persists the authoritative machine assessment
    # before settlement.  Reuse that exact snapshot so settlement cannot
    # reinterpret the same evidence with a different capability policy.
    sufficiency_result: SufficiencyResult | None = None


@dataclass(slots=True)
class SettlementDecision:
    """The output of the unified settlement gate.

    This is a pure function result — no side effects.
    """

    verdict: str  # confirmed, refuted, untestable, inconclusive, newlead
    reason: str
    allowed: bool = True  # False means the transition is blocked
    # Detailed gate results for auditing
    gates_passed: list[str] = field(default_factory=list)
    gates_failed: list[str] = field(default_factory=list)
    # Sufficiency assessment (populated when settlement proceeds)
    sufficiency_status: str | None = None
    sufficiency_score: float | None = None


def _is_concrete_entity(value: str | None) -> bool:
    """Return True if the value is a concrete entity instantiation."""
    if value is None:
        return False
    normalized = str(value).strip().lower()
    if normalized in _DISQUALIFIED_ENTITY_VALUES:
        return False
    # Template tokens like {target_user}, <%var%>
    for prefix in _TEMPLATE_TOKEN_PREFIXES:
        if normalized.startswith(prefix):
            return False
    return True


def _is_loopback_ip(value: str | None) -> bool:
    """Return True if the value is a loopback/empty IP address."""
    if value is None:
        return True
    normalized = str(value).strip().lower()
    return normalized in {
        "",
        "-",
        "127.0.0.1",
        "::1",
        "localhost",
        "0.0.0.0",
        "unknown",
    }


def _check_required_entities_concrete(
    hypothesis: Hypothesis,
    sample_rows: list[dict[str, Any]] | None,
) -> tuple[bool, str]:
    """Verify required entities have concrete values in sample rows.

    Returns (passed, reason).
    """
    required = hypothesis.required_entities
    if not required:
        return True, "no required entities declared"

    if not sample_rows:
        return False, "no sample rows to verify required entities"

    disqualified: list[str] = []
    for entity in required:
        entity_lower = entity.lower()
        # Check if any row has a concrete value for this entity
        found_concrete = False
        for row in sample_rows:
            # Direct column match
            value = row.get(entity)
            if value is not None and _is_concrete_entity(str(value)):
                # Additional check: if entity is src_ip-like, reject loopback
                if "src" in entity_lower or "source" in entity_lower:
                    if _is_loopback_ip(str(value)):
                        continue
                found_concrete = True
                break
            # Also check role-based aliases
            for col, val in row.items():
                if col.lower() == entity_lower and _is_concrete_entity(str(val)):
                    if "src" in entity_lower or "source" in entity_lower:
                        if _is_loopback_ip(str(val)):
                            continue
                    found_concrete = True
                    break
            if found_concrete:
                break
        if not found_concrete:
            disqualified.append(entity)

    if disqualified:
        return False, f"required entities without concrete values: {disqualified}"
    return True, "all required entities have concrete values"


def _check_correlation_constraints(
    si: SettlementInput,
    sample_rows: list[dict[str, Any]] | None,
) -> tuple[bool, str]:
    """Verify rule-required correlation constraints beyond same_host/within_minutes.

    Returns (passed, reason).
    """
    confirm_when = si.hypothesis.verification_spec.support_conditions
    if not confirm_when:
        return True, "no correlation constraints declared"

    # Recheck the complete condition on its qualified, field-matching rows.
    # A caller-supplied co-observation flag cannot bypass the shared predicate.
    if confirm_when.get("co_observed_event_ids"):
        from forensia.ai.checking.check_guardrails import _co_observation_satisfied

        correlated, reason = _co_observation_satisfied(confirm_when, sample_rows or [])
        if not correlated:
            return False, f"co-observation not satisfied: {reason}"

    # same_host constraint
    if confirm_when.get("same_host") and not si.same_host:
        # Re-verify with sample rows if available
        if sample_rows:
            hosts = set()
            for row in sample_rows:
                host = row.get("computer") or row.get("host")
                if host and str(host).strip():
                    hosts.add(str(host).strip())
            if len(hosts) > 1:
                return (
                    False,
                    f"same_host required but events span multiple hosts: {hosts}",
                )
        # If no sample rows, trust the co_observation check

    # Required identity values that occur in multiple event types must refer
    # to the same entity.  Merely finding concrete values somewhere in the
    # result set would otherwise correlate unrelated accounts.
    co_ids = {
        int(value)
        for value in confirm_when.get("co_observed_event_ids") or []
        if str(value).strip().isdigit()
    }
    for entity in si.hypothesis.required_entities:
        values_by_event: list[set[str]] = []
        for event_id in co_ids:
            values = {
                str(row.get(entity)).strip().casefold()
                for row in (sample_rows or [])
                if str(row.get("event_id") or "").strip() == str(event_id)
                and _is_concrete_entity(row.get(entity))
            }
            if values:
                values_by_event.append(values)
        if len(values_by_event) >= 2 and not set.intersection(*values_by_event):
            return False, f"required entity {entity!r} differs across correlated events"

    return True, "correlation constraints satisfied"


def judge_absence_scope(
    db: CaseDB,
    hypothesis: Hypothesis,
    evaluation: RetrievalEvaluation | None,
    *,
    source_families: list[str] | None = None,
) -> tuple[Literal["observable", "unknown", "unavailable"], str]:
    """Judge whether the latest retrieval can support a scope-wise absence.

    A rule-declared zero-rows refutation is admissible only when the absence
    itself is observable: the retrieval scope was valid, the emptiness was
    observable (not an unknown-coverage empty result), and the Coverage
    projection shows every required capability available over the queried
    scope.  Any other state — rejected/unknown scope, invalid or unavailable
    retrieval, partial/unknown capability coverage, or no relevant coverage
    rows — returns a non-observable scope plus a note naming the deficit, and
    the settlement gate keeps the hypothesis untestable in that case.
    """
    required_capabilities = derive_required_capabilities(
        hypothesis.verification_spec.required_capabilities,
        hypothesis.verification_spec.support_conditions,
    )
    if evaluation is None:
        return "unknown", "no retrieval evaluation for the latest attempt"
    if evaluation.scope_status != "valid":
        return "unknown", f"retrieval scope_status={evaluation.scope_status}"
    if evaluation.outcome == "unavailable":
        return "unavailable", "retrieval outcome=unavailable"
    if evaluation.outcome == "invalid":
        return "unknown", "retrieval outcome=invalid"
    if evaluation.empty_semantics != "observable":
        return (
            "unknown",
            "empty result not observable "
            f"(empty_semantics={evaluation.empty_semantics}, "
            f"coverage_status={evaluation.coverage_status})",
        )
    states = relevant_coverage_states(
        get_coverage_summary(db), required_capabilities, source_families=source_families
    )
    if states is None:
        return (
            "unknown",
            "uncovered-scope: no required capabilities declared, Coverage "
            "cannot represent the queried scope",
        )
    incomplete = {
        capability: matched
        for capability, matched in sorted(states.items())
        if any(state != "available" for state in matched)
    }
    if incomplete:
        detail = ", ".join(
            f"{capability}={','.join(matched)}"
            for capability, matched in incomplete.items()
        )
        return "unknown", f"required capability coverage not available: {detail}"
    return (
        "observable",
        "valid scope with observable emptiness; required capabilities available",
    )


def _check_no_unresolved_contradictions(
    links: list[EvidenceLink],
) -> tuple[bool, str]:
    """Verify no unresolved contradictory evidence groups.

    Returns (passed, reason).
    """
    contradictory = [
        l
        for l in links
        if l.role == "contradictory" and str(l.assessment_id or "").strip()
    ]
    if not contradictory:
        return True, "no contradictory evidence"
    # Group by derivation root; query id is acquisition history and never
    # splits or merges roots.
    groups: dict[str, list[EvidenceLink]] = {}
    for link in contradictory:
        groups.setdefault(derivation_root_key(link), []).append(link)
    return False, f"{len(groups)} unresolved contradictory groups"


def settle_hypothesis(
    db: CaseDB,
    si: SettlementInput,
    *,
    evidence_requirements: dict[str, Any] | None = None,
) -> SettlementDecision:
    """Load authoritative state and delegate to the pure decision function."""
    return decide_settlement(
        si,
        links=load_evidence_links(db, si.hypothesis.id, current_only=True),
        coverage=get_coverage_summary(db),
        evidence_requirements=evidence_requirements,
    )


def decide_settlement(
    si: SettlementInput,
    *,
    links: list[EvidenceLink],
    coverage: dict[str, dict[str, str]],
    evidence_requirements: dict[str, Any] | None = None,
) -> SettlementDecision:
    """Return a settlement decision without reading or mutating external state.

    The caller supplies an immutable snapshot of evidence links and coverage;
    persistence remains the runner's responsibility.

    Gates for confirmed:
    1. Checker verdict must be confirmed
    2. Supporting EvidenceLink ≥ 1
    3. Machine sufficiency == sufficient
    4. Required entities have concrete values
    5. Correlation constraints satisfied
    6. No unresolved contradictory groups
    7. Not benign auth only

    Gates for refuted/untestable:
    - Standard auto-refute/untestable conditions
    """
    hypothesis = si.hypothesis
    sample_rows = si.sample_rows or []

    # ── Path 1: Auto-untestable (missing event IDs unavailable) ──
    if si.unavailable_missing_event_ids:
        id_list = ", ".join(str(eid) for eid in si.unavailable_missing_event_ids)
        return SettlementDecision(
            verdict="untestable",
            reason=(
                f"Untestable: verification requires event IDs [{id_list}] "
                "which are not present in the available telemetry — "
                "absence of telemetry is not a disproof."
            ),
            gates_passed=["auto_untestable_missing_events"],
        )

    # ── Path 2: Auto-refute (3+ consecutive zero-row inconclusive) ──
    if (
        si.checker_verdict == "inconclusive"
        and si.consecutive_zero_row_inconclusive >= 3
    ):
        if si.has_rule_refute_when_zero_rows and si.absence_scope == "observable":
            return SettlementDecision(
                verdict="refuted",
                reason=(
                    "Auto-refuted: repeated 0-row inconclusive results over an "
                    "observable absence scope (valid retrieval, available "
                    "coverage), consistent with rule-declared "
                    "refute_when.zero_rows condition."
                ),
                gates_passed=["auto_refute_zero_rows"],
            )
        if si.has_rule_refute_when_zero_rows:
            return SettlementDecision(
                verdict="untestable",
                reason=(
                    "Untestable: repeated 0-row inconclusive results — "
                    "rule-declared refute_when.zero_rows is not applied "
                    "because the absence is not observable: "
                    f"{si.absence_note or 'absence scope unknown'}"
                ),
                gates_passed=["auto_untestable_zero_rows"],
            )
        return SettlementDecision(
            verdict="untestable",
            reason=(
                "Untestable: repeated 0-row inconclusive results — "
                "available telemetry does not contain the event types "
                "required to verify this hypothesis."
            ),
            gates_passed=["auto_untestable_zero_rows"],
        )

    # ── Path 3: Auto-refute (3+ consecutive same-missing) ──
    if si.consecutive_same_missing >= 3:
        if si.has_rule_refute_when_zero_rows and si.absence_scope == "observable":
            return SettlementDecision(
                verdict="refuted",
                reason=(
                    "hypothesis requires evidence not present in current dataset "
                    "(3+ consecutive same-missing check) over an observable "
                    "absence scope (valid retrieval, available coverage)"
                ),
                gates_passed=["auto_refute_same_missing"],
            )
        if si.has_rule_refute_when_zero_rows:
            return SettlementDecision(
                verdict="untestable",
                reason=(
                    "hypothesis requires evidence not present in current dataset "
                    "(3+ consecutive same-missing check) — rule-declared "
                    "refute_when.zero_rows is not applied because the absence "
                    f"is not observable: {si.absence_note or 'absence scope unknown'}"
                ),
                gates_passed=["auto_untestable_same_missing"],
            )
        return SettlementDecision(
            verdict="untestable",
            reason=(
                "Untestable: hypothesis requires evidence not present in "
                "current dataset (3+ consecutive same-missing check) — "
                "absence of telemetry is not a disproof."
            ),
            gates_passed=["auto_untestable_same_missing"],
        )

    # ── Path 4: Confirmed ──
    # Co-observation is a deterministic correlation gate, not a semantic
    # verdict.  In particular, a rule may declare a corroborating event that
    # is weaker than the primary claim (for example an account-change event
    # adjacent to a password reset).  Never use that correlation alone to
    # override a checker that explicitly found the claim inconclusive.
    is_checker_confirmed = si.checker_verdict == "confirmed"

    if is_checker_confirmed:
        gates_passed: list[str] = []
        gates_failed: list[str] = []

        # Gate 4a: Supporting EvidenceLink ≥ 1
        supporting_links = [
            l
            for l in links
            if l.role == "supporting" and str(l.assessment_id or "").strip()
        ]
        if supporting_links:
            gates_passed.append("evidence_link_exists")
        else:
            gates_failed.append("no_supporting_evidence_link")

        # Gate 4b: Machine sufficiency == sufficient
        suff_result = si.sufficiency_result
        if suff_result is None:
            # Standalone callers (for example focused settlement tests) do not
            # have a persisted runner assessment.  Even there, evaluate from
            # the hypothesis' canonical policy rather than silently dropping
            # required capabilities.
            verification_spec = hypothesis.verification_spec
            required_capabilities = derive_required_capabilities(
                verification_spec.required_capabilities,
                verification_spec.support_conditions,
            )
            suff_result = evaluate_sufficiency(
                {
                    "hypothesis_id": hypothesis.id,
                    "required_capabilities": required_capabilities,
                    "evidence_requirements": evidence_requirements or {},
                },
                links,
                coverage,
            )
        if suff_result.status == "sufficient":
            gates_passed.append("machine_sufficient")
        else:
            gates_failed.append(f"machine_sufficiency={suff_result.status}")

        # Gate 4c: Required entities have concrete values
        entities_ok, entities_reason = _check_required_entities_concrete(
            hypothesis, sample_rows
        )
        if entities_ok:
            gates_passed.append("required_entities_concrete")
        else:
            gates_failed.append(f"required_entities: {entities_reason}")

        # Gate 4d: Correlation constraints
        corr_ok, corr_reason = _check_correlation_constraints(si, sample_rows)
        if corr_ok:
            gates_passed.append("correlation_constraints")
        else:
            gates_failed.append(f"correlation: {corr_reason}")

        # Gate 4e: No unresolved contradictions
        contra_ok, contra_reason = _check_no_unresolved_contradictions(links)
        if contra_ok:
            gates_passed.append("no_contradictions")
        else:
            gates_failed.append(f"contradictions: {contra_reason}")

        # Gate 4f: Not benign auth only
        if si.is_benign_auth:
            gates_failed.append("benign_auth_only")
        else:
            gates_passed.append("not_benign_auth")

        if gates_failed:
            return SettlementDecision(
                verdict="inconclusive",
                reason=f"Confirmed blocked: {'; '.join(gates_failed)}",
                allowed=False,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                sufficiency_status=suff_result.status,
                sufficiency_score=suff_result.score,
            )

        return SettlementDecision(
            verdict="confirmed",
            reason="All settlement gates passed",
            allowed=True,
            gates_passed=gates_passed,
            gates_failed=[],
            sufficiency_status=suff_result.status,
            sufficiency_score=suff_result.score,
        )

    # An inconclusive semantic verdict remains inconclusive even when the
    # deterministic correlation constraints pass.  Still evaluate those
    # constraints so the next planning attempt can observe concrete defects
    # (for example mismatched identities or an ineligible logon type).
    if si.checker_verdict == "inconclusive":
        corr_ok, corr_reason = _check_correlation_constraints(si, sample_rows)
        if not corr_ok:
            return SettlementDecision(
                verdict="inconclusive",
                reason=f"Correlation constraints failed: {corr_reason}",
                allowed=False,
                gates_failed=[f"correlation: {corr_reason}"],
            )

    # ── Path 5: Assessed contradiction ──
    # A checker refutation is admissible only when the deterministic
    # assessment produced at least one contradictory observation group.
    if si.checker_verdict == "refuted":
        contradictory_groups = {
            derivation_root_key(l)
            for l in links
            if l.role == "contradictory" and str(l.assessment_id or "").strip()
        }
        if contradictory_groups:
            return SettlementDecision(
                verdict="refuted",
                reason="Refuted with assessed contradictory evidence group",
                gates_passed=["assessed_contradictory_group"],
            )
        return SettlementDecision(
            verdict="inconclusive",
            reason="Refuted checker verdict lacks an assessed contradictory evidence group",
            allowed=False,
            gates_failed=["no_assessed_contradictory_group"],
        )

    # An untestable checker verdict is admissible only through the explicit
    # unavailable/missing/zero-row auto paths above; never pass it through.
    if si.checker_verdict == "untestable":
        return SettlementDecision(
            verdict="inconclusive",
            reason="Untestable checker verdict lacks an approved auto-untestable condition",
            allowed=False,
            gates_failed=["no_auto_untestable_condition"],
        )

    # ── Path 6: Inconclusive / newlead — no settlement ──
    return SettlementDecision(
        verdict=si.checker_verdict or "inconclusive",
        reason="No settlement conditions met",
        allowed=False,
    )


def build_settlement_input(
    *,
    hypothesis: Hypothesis,
    checker_verdict: str,
    check_summary: str,
    sample_rows: list[dict[str, Any]] | None = None,
    co_observed_event_ids: list[int] | None = None,
    co_observation_satisfied: bool = False,
    co_observation_reason: str = "",
    same_host: bool = False,
    within_minutes: int | None = None,
    is_benign_auth: bool = False,
    has_rule_refute_when_zero_rows: bool = False,
    consecutive_zero_row_inconclusive: int = 0,
    consecutive_same_missing: int = 0,
    unavailable_missing_event_ids: list[int] | None = None,
    absence_scope: Literal["observable", "unknown", "unavailable"] = "unknown",
    absence_note: str = "",
    sufficiency_result: SufficiencyResult | None = None,
) -> SettlementInput:
    """Convenience constructor for SettlementInput."""
    return SettlementInput(
        hypothesis=hypothesis,
        checker_verdict=checker_verdict,
        check_summary=check_summary,
        sample_rows=sample_rows,
        co_observed_event_ids=co_observed_event_ids,
        co_observation_satisfied=co_observation_satisfied,
        co_observation_reason=co_observation_reason,
        same_host=same_host,
        within_minutes=within_minutes,
        is_benign_auth=is_benign_auth,
        has_rule_refute_when_zero_rows=has_rule_refute_when_zero_rows,
        consecutive_zero_row_inconclusive=consecutive_zero_row_inconclusive,
        consecutive_same_missing=consecutive_same_missing,
        unavailable_missing_event_ids=unavailable_missing_event_ids,
        absence_scope=absence_scope,
        absence_note=absence_note,
        sufficiency_result=sufficiency_result,
    )


def build_settlement_input_from_confirm_when(
    *,
    hypothesis: Hypothesis,
    checker_verdict: str,
    check_summary: str,
    sample_rows: list[dict[str, Any]] | None = None,
    has_rule_refute_when_zero_rows: bool = False,
    consecutive_zero_row_inconclusive: int = 0,
    consecutive_same_missing: int = 0,
    unavailable_missing_event_ids: list[int] | None = None,
    absence_scope: Literal["observable", "unknown", "unavailable"] = "unknown",
    absence_note: str = "",
    sufficiency_result: SufficiencyResult | None = None,
) -> SettlementInput:
    """Build SettlementInput from the hypothesis' canonical support conditions.

    This helper extracts co_observed_event_ids, same_host, within_minutes from
    the hypothesis's confirm_when dict and evaluates co-observation satisfaction.
    """
    from forensia.ai.checking.check_guardrails import _co_observation_satisfied

    confirm_when = hypothesis.verification_spec.support_conditions
    rows = sample_rows or []

    co_observed_ids: list[int] = []
    co_satisfied = False
    co_reason = ""
    same_host = False
    within_minutes = None

    if confirm_when:
        raw_ids = confirm_when.get("co_observed_event_ids") or []
        for eid in raw_ids:
            try:
                co_observed_ids.append(int(eid))
            except TypeError, ValueError:
                continue
        if co_observed_ids:
            co_satisfied, co_reason = _co_observation_satisfied(confirm_when, rows)
        same_host = bool(confirm_when.get("same_host", False))
        within_minutes = confirm_when.get("within_minutes")

    return SettlementInput(
        hypothesis=hypothesis,
        checker_verdict=checker_verdict,
        check_summary=check_summary,
        sample_rows=sample_rows,
        co_observed_event_ids=co_observed_ids or None,
        co_observation_satisfied=co_satisfied,
        co_observation_reason=co_reason,
        same_host=same_host,
        within_minutes=within_minutes,
        is_benign_auth=False,  # Caller must set separately
        has_rule_refute_when_zero_rows=has_rule_refute_when_zero_rows,
        consecutive_zero_row_inconclusive=consecutive_zero_row_inconclusive,
        consecutive_same_missing=consecutive_same_missing,
        unavailable_missing_event_ids=unavailable_missing_event_ids,
        absence_scope=absence_scope,
        absence_note=absence_note,
        sufficiency_result=sufficiency_result,
    )
