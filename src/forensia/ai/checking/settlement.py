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
from typing import Any

from forensia.ai.checking.sufficiency import (
    EvidenceLink,
    evaluate_sufficiency,
    load_evidence_links,
)
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.knowledge.coverage import get_coverage_summary

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
    confirm_when = si.hypothesis.confirm_when or {}
    if not confirm_when:
        return True, "no correlation constraints declared"

    # If co-observation was already checked and failed, that's a gate failure
    if confirm_when.get("co_observed_event_ids") and not si.co_observation_satisfied:
        return False, f"co-observation not satisfied: {si.co_observation_reason}"

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

    # within_minutes constraint
    if confirm_when.get("within_minutes") is not None and not si.within_minutes:
        # Already checked by co_observation_satisfied
        pass

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

    # Optional rule-declared per-event field constraints (for example,
    # Security 4624 must be LogonType 10 when confirming an RDP session).
    for raw_event_id, constraints in (
        confirm_when.get("event_constraints") or {}
    ).items():
        if not isinstance(constraints, dict):
            continue
        event_rows = [
            row
            for row in (sample_rows or [])
            if str(row.get("event_id") or "").strip() == str(raw_event_id)
        ]
        if not event_rows:
            return False, f"event {raw_event_id} required for field constraints"
        for field_name, expected_values in constraints.items():
            expected = {
                str(value).strip().casefold()
                for value in (
                    expected_values
                    if isinstance(expected_values, list)
                    else [expected_values]
                )
            }
            if not any(
                str(row.get(field_name) or "").strip().casefold() in expected
                for row in event_rows
            ):
                return False, (
                    f"event {raw_event_id} requires {field_name} in {sorted(expected)}"
                )

    return True, "correlation constraints satisfied"


def _check_no_unresolved_contradictions(
    links: list[EvidenceLink],
) -> tuple[bool, str]:
    """Verify no unresolved contradictory evidence groups.

    Returns (passed, reason).
    """
    contradictory = [l for l in links if l.role == "contradictory"]
    if not contradictory:
        return True, "no contradictory evidence"
    # Group by derivation
    groups: dict[str, list[EvidenceLink]] = {}
    for link in contradictory:
        key = link.derivation_group or link.evidence_id
        groups.setdefault(key, []).append(link)
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
        links=load_evidence_links(db, si.hypothesis.id),
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
    1. Checker verdict must be confirmed (or auto-confirm conditions met)
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
        if si.has_rule_refute_when_zero_rows:
            return SettlementDecision(
                verdict="refuted",
                reason=(
                    "Auto-refuted: repeated 0-row inconclusive results, "
                    "consistent with rule-declared refute_when.zero_rows condition."
                ),
                gates_passed=["auto_refute_zero_rows"],
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
        if si.has_rule_refute_when_zero_rows:
            return SettlementDecision(
                verdict="refuted",
                reason=(
                    "hypothesis requires evidence not present in current dataset "
                    "(3+ consecutive same-missing check)"
                ),
                gates_passed=["auto_refute_same_missing"],
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

    # ── Path 4: Confirmed (from checker verdict or auto-confirm) ──
    is_auto_confirm = (
        si.checker_verdict == "inconclusive"
        and si.co_observation_satisfied
        and bool(hypothesis.source_rule_ids)  # only rule-seeded
    )
    is_checker_confirmed = si.checker_verdict == "confirmed"

    if is_checker_confirmed or is_auto_confirm:
        gates_passed: list[str] = []
        gates_failed: list[str] = []

        # Gate 4a: Supporting EvidenceLink ≥ 1
        supporting_links = [l for l in links if l.role == "supporting"]
        if supporting_links:
            gates_passed.append("evidence_link_exists")
        else:
            gates_failed.append("no_supporting_evidence_link")

        # Gate 4b: Machine sufficiency == sufficient
        suff_result = evaluate_sufficiency(
            {
                "hypothesis_id": hypothesis.id,
                "required_capabilities": [],
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

        # Gate 4g: Auto-confirm only when checker was inconclusive
        # (prevents auto-confirm from overriding a refuted/untestable verdict)
        if is_auto_confirm and si.checker_verdict not in ("inconclusive",):
            gates_failed.append(
                f"auto_confirm_override_prevented: checker_verdict={si.checker_verdict}"
            )

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

    # ── Path 5: Checker verdict passed through ──
    # For refuted/untestable from the checker, allow direct settlement
    if si.checker_verdict in ("refuted", "untestable"):
        return SettlementDecision(
            verdict=si.checker_verdict,
            reason=f"Checker verdict: {si.checker_verdict}",
            gates_passed=["checker_verdict_passthrough"],
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
) -> SettlementInput:
    """Build SettlementInput by assessing co-observation from hypothesis.confirm_when.

    This helper extracts co_observed_event_ids, same_host, within_minutes from
    the hypothesis's confirm_when dict and evaluates co-observation satisfaction.
    """
    from forensia.ai.checking.check_guardrails import _co_observation_satisfied

    confirm_when = hypothesis.confirm_when or {}
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
    )
