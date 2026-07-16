"""Evidence sufficiency evaluation: policy hierarchy, role verification, LLM/machine reconciliation."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from forensia.db.database import CaseDB
from forensia.knowledge.coverage import (
    get_coverage_summary,
    infer_capabilities,
    load_evidence_sufficiency_policy,
)

logger = logging.getLogger(__name__)


@dataclass
class EvidenceLink:
    link_id: str
    hypothesis_id: str
    evidence_id: str
    finding_id: str
    query_id: str
    assessment_id: str
    role: str  # supporting, corroborating, contradictory, duplicate
    source_family: str
    source_file: str
    derivation_group: str
    strength: str


@dataclass
class SufficiencyResult:
    status: str  # sufficient, insufficient, unobservable, unknown
    score: float  # 0.0 - 1.0
    reasons: list[str]
    independent_groups: int
    families: list[str]
    contradictory_groups: int
    missing_requirements: list[str]
    human_review_required: bool


VALID_ROLES = frozenset(["supporting", "corroborating", "contradictory", "duplicate"])
VALID_STRENGTHS = frozenset(["weak", "moderate", "strong"])


def _load_sufficiency_thresholds() -> dict[str, float]:
    """Load sufficiency thresholds from YAML policy."""
    policy = load_evidence_sufficiency_policy()
    thresholds = policy.get("thresholds", {})
    return {
        "sufficient": thresholds.get("sufficient", 0.6),
        "partial": thresholds.get("partial", 0.3),
    }


def _load_scoring_weights() -> dict[str, float]:
    """Load scoring weights from YAML policy."""
    policy = load_evidence_sufficiency_policy()
    weights = policy.get("scoring_weights", {})
    return {
        "supporting_groups": weights.get("supporting_groups", 0.3),
        "family_diversity": weights.get("family_diversity", 0.2),
        "corroborating_groups": weights.get("corroborating_groups", 0.15),
        "no_contradiction": weights.get("no_contradiction", 0.15),
        "multi_family_bonus": weights.get("multi_family_bonus", 0.2),
        "contradictory_penalty_per_group": weights.get(
            "contradictory_penalty_per_group", 0.3
        ),
    }


def load_evidence_links(db: CaseDB, hypothesis_id: str) -> list[EvidenceLink]:
    """Load evidence links for a hypothesis."""
    rows = db.execute(
        "SELECT link_id, hypothesis_id, evidence_id, finding_id, query_id, "
        "assessment_id, role, source_family, source_file, derivation_group, strength "
        "FROM hypothesis_evidence WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchall()
    return [
        EvidenceLink(
            link_id=r[0],
            hypothesis_id=r[1],
            evidence_id=r[2],
            finding_id=r[3] or "",
            query_id=r[4] or "",
            assessment_id=r[5] or "",
            role=r[6] or "supporting",
            source_family=r[7] or "",
            source_file=r[8] or "",
            derivation_group=r[9] or "",
            strength=r[10] or "moderate",
        )
        for r in rows
    ]


def _group_by_derivation(links: list[EvidenceLink]) -> dict[str, list[EvidenceLink]]:
    """Group evidence links by derivation_group (same root record)."""
    groups: dict[str, list[EvidenceLink]] = {}
    for link in links:
        key = link.derivation_group or link.evidence_id
        groups.setdefault(key, []).append(link)
    return groups


def evaluate_sufficiency(
    hypothesis: dict[str, Any],
    links: list[EvidenceLink],
    coverage: dict[str, dict[str, str]],
    policy: dict[str, Any] | None = None,
) -> SufficiencyResult:
    """Evaluate evidence sufficiency for a hypothesis.

    Returns a SufficiencyResult with status, score, and detailed reasons.
    """
    if policy is None:
        policy = load_evidence_sufficiency_policy()

    common = policy.get("common_rules", {})
    default_suff = policy.get("default_sufficiency", {})

    configured_thresholds = policy.get("thresholds", {})
    configured_weights = policy.get("scoring_weights", {})
    thresholds = {
        **_load_sufficiency_thresholds(),
        **{
            key: float(value)
            for key, value in configured_thresholds.items()
            if isinstance(value, (int, float))
        },
    }
    weights = {
        **_load_scoring_weights(),
        **{
            key: float(value)
            for key, value in configured_weights.items()
            if isinstance(value, (int, float))
        },
    }
    sufficient_threshold = thresholds["sufficient"]
    partial_threshold = thresholds["partial"]

    reasons: list[str] = []
    missing: list[str] = []

    relevant_capabilities = {
        str(item) for item in hypothesis.get("required_capabilities", []) if str(item)
    }
    relevant_coverage = {
        key: value
        for key, value in coverage.items()
        if not relevant_capabilities or key.split(":", 1)[-1] in relevant_capabilities
    }

    if not links:
        unavailable = [
            cov
            for cov in relevant_coverage.values()
            if cov.get("state") in {"unavailable", "degraded"}
        ]
        if relevant_coverage and len(unavailable) == len(relevant_coverage):
            return SufficiencyResult(
                status="unobservable",
                score=0.0,
                reasons=["Required evidence capabilities are unavailable"],
                independent_groups=0,
                families=[],
                contradictory_groups=0,
                missing_requirements=sorted(relevant_capabilities),
                human_review_required=False,
            )
        return SufficiencyResult(
            status="insufficient",
            score=0.0,
            reasons=["No evidence links found"],
            independent_groups=0,
            families=[],
            contradictory_groups=0,
            missing_requirements=["at least 1 supporting evidence group"],
            human_review_required=False,
        )

    supporting = [l for l in links if l.role == "supporting"]
    corroborating = [l for l in links if l.role == "corroborating"]
    contradictory = [l for l in links if l.role == "contradictory"]

    if common.get("zero_rows_is_not_support") and not supporting and not corroborating:
        reasons.append("No supporting or corroborating evidence")

    if common.get("contradictory_evidence_must_be_addressed") and contradictory:
        reasons.append(f"{len(contradictory)} contradictory evidence entries")

    supporting_groups = _group_by_derivation(supporting)
    strong_supporting_groups = {
        key: group
        for key, group in supporting_groups.items()
        if any(link.strength in {"moderate", "strong"} for link in group)
    }
    corroborating_groups = _group_by_derivation(corroborating)
    contradictory_groups = _group_by_derivation(contradictory)

    independent_supporting = len(strong_supporting_groups)
    independent_corroborating = len(corroborating_groups)

    supporting_families = set(l.source_family for l in supporting if l.source_family)
    corroborating_families = set(
        l.source_family for l in corroborating if l.source_family
    )
    all_families = supporting_families | corroborating_families

    requirements = hypothesis.get("evidence_requirements") or {}
    min_groups = requirements.get(
        "min_independent_groups", default_suff.get("min_independent_groups", 1)
    )
    min_families = requirements.get(
        "min_distinct_families", default_suff.get("min_distinct_families", 1)
    )

    if independent_supporting < min_groups:
        missing.append(
            f"Need {min_groups} independent supporting groups, have {independent_supporting}"
        )
        reasons.append(f"Only {independent_supporting} independent supporting groups")

    if len(all_families) < min_families:
        missing.append(
            f"Need {min_families} distinct families, have {len(all_families)}"
        )
        reasons.append(f"Only {len(all_families)} distinct families: {all_families}")

    unobservable_caps = 0
    for cov in relevant_coverage.values():
        if cov.get("state") in {"unavailable", "degraded"}:
            unobservable_caps += 1

    if unobservable_caps > 0 and not supporting:
        reasons.append(
            f"{unobservable_caps} capabilities unavailable, no direct evidence"
        )

    score = 0.0
    if supporting:
        score += weights["supporting_groups"] * min(
            independent_supporting / max(min_groups, 1), 1.0
        )
        score += weights["family_diversity"] * min(
            len(all_families) / max(min_families, 1), 1.0
        )
    if corroborating:
        score += weights["corroborating_groups"] * min(
            independent_corroborating / 2.0, 1.0
        )
    if not contradictory:
        score += weights["no_contradiction"]
    if all_families and len(all_families) >= 2:
        score += weights["multi_family_bonus"]

    contradictory_penalty = (
        len(contradictory_groups) * weights["contradictory_penalty_per_group"]
    )
    score = max(0.0, score - contradictory_penalty)

    human_review = False

    if contradictory and len(contradictory_groups) > 0:
        human_review = True
        if score >= sufficient_threshold:
            status = "needs_review"
            reasons.append("Strong evidence exists but contradictions need resolution")
        else:
            status = "insufficient"
            reasons.append("Contradictory evidence weakens conclusion")
    elif score >= sufficient_threshold and independent_supporting >= min_groups:
        status = "sufficient"
        reasons.append("Meets minimum evidence requirements")
    elif score >= partial_threshold:
        status = "partial"
        reasons.append("Some supporting evidence but below threshold")
    elif unobservable_caps > 0 and not supporting:
        status = "unobservable"
        reasons.append("Key capabilities unavailable for direct observation")
    else:
        status = "insufficient"
        reasons.append("Insufficient evidence for conclusion")

    return SufficiencyResult(
        status=status,
        score=min(score, 1.0),
        reasons=reasons,
        independent_groups=independent_supporting,
        families=list(all_families),
        contradictory_groups=len(contradictory_groups),
        missing_requirements=missing,
        human_review_required=human_review,
    )


def reconcile_verdicts(
    machine_result: SufficiencyResult,
    llm_verdict: str,
) -> tuple[str, str]:
    """Reconcile machine sufficiency with LLM semantic verdict.

    Returns (final_verdict, reconciliation_reason).
    """
    m = machine_result.status
    v = llm_verdict

    if v == "confirmed" and m == "sufficient":
        return "confirmed", "Both LLM and machine agree"

    if v == "confirmed" and m != "sufficient":
        return "inconclusive", f"LLM says confirmed but machine assessment is {m}"

    if v == "refuted" and machine_result.contradictory_groups > 0:
        return "refuted", "LLM refuted with contradictory evidence support"

    if v == "refuted" and m == "unobservable":
        return "untestable", "Cannot observe to confirm or deny"

    if v == "refuted" and m in {"insufficient", "partial", "needs_review"}:
        return "inconclusive", f"LLM says refuted but machine assessment is {m}"

    if m == "sufficient" and v == "inconclusive":
        return "needs_review", "Machine sufficient but LLM inconclusive"

    return v, f"Using LLM verdict (machine={m})"


def update_claim_support_for_hypothesis(
    db: CaseDB,
    *,
    hypothesis_id: str,
    result: SufficiencyResult,
    final_verdict: str,
) -> int:
    """Project hypothesis sufficiency into Claims that cite the hypothesis."""
    if result.status == "unobservable" or final_verdict == "untestable":
        support_status = "unobservable"
    elif result.status == "sufficient" and final_verdict == "confirmed":
        support_status = "supported"
    elif result.status == "partial":
        support_status = "partially_supported"
    else:
        support_status = "needs_review"
    updated = 0
    for claim_id, raw_ids in db.execute(
        "SELECT claim_id, hypothesis_ids FROM claims"
    ).fetchall():
        ids = raw_ids
        if isinstance(ids, str):
            try:
                ids = json.loads(ids)
            except (TypeError, ValueError):
                ids = []
        if hypothesis_id not in (ids if isinstance(ids, list) else []):
            continue
        db.execute(
            "UPDATE claims SET support_status = ?, updated_at = now() "
            "WHERE claim_id = ?",
            [support_status, claim_id],
        )
        updated += 1
    return updated


def assess_and_persist_sufficiency(
    db: CaseDB,
    *,
    hypothesis_id: str,
    investigation_text: str,
    evidence_requirements: dict[str, Any] | None,
    llm_verdict: str,
) -> tuple[SufficiencyResult, str, str, list[str]]:
    """Run the authoritative machine assessment and persist its projections."""
    required_capabilities = infer_capabilities(investigation_text)
    result = evaluate_sufficiency(
        {
            "hypothesis_id": hypothesis_id,
            "required_capabilities": required_capabilities,
            "evidence_requirements": evidence_requirements or {},
        },
        load_evidence_links(db, hypothesis_id),
        get_coverage_summary(db),
    )
    final_verdict, reconciliation_reason = reconcile_verdicts(result, llm_verdict)
    if final_verdict == "needs_review":
        final_verdict = "inconclusive"
        result.human_review_required = True
    reason = "; ".join([*result.reasons, reconciliation_reason])
    db.execute(
        "UPDATE hypotheses SET sufficiency_status = ?, sufficiency_score = ?, "
        "sufficiency_reason = ?, sufficiency_policy_id = ?, "
        "human_review_required = ? WHERE hypothesis_id = ?",
        [
            result.status,
            result.score,
            reason,
            "evidence_sufficiency:v1",
            result.human_review_required,
            hypothesis_id,
        ],
    )
    update_claim_support_for_hypothesis(
        db,
        hypothesis_id=hypothesis_id,
        result=result,
        final_verdict=final_verdict,
    )
    return result, final_verdict, reason, required_capabilities


def create_hypothesis_evidence_link(
    db: CaseDB,
    *,
    hypothesis_id: str,
    evidence_id: str,
    role: str = "supporting",
    source_family: str = "",
    source_file: str = "",
    derivation_group: str = "",
    finding_id: str = "",
    query_id: str = "",
    assessment_id: str = "",
    strength: str = "moderate",
    created_session: str = "",
) -> str:
    """Create an evidence link for a hypothesis. Returns the link_id."""
    import uuid

    if role not in VALID_ROLES:
        raise ValueError(f"Invalid evidence role: {role}")
    if strength not in VALID_STRENGTHS:
        raise ValueError(f"Invalid evidence strength: {strength}")
    existing = db.execute(
        "SELECT link_id FROM hypothesis_evidence "
        "WHERE hypothesis_id = ? AND evidence_id = ? AND role = ? "
        "AND COALESCE(query_id, '') = COALESCE(?, '') LIMIT 1",
        [hypothesis_id, evidence_id, role, query_id],
    ).fetchone()
    if existing:
        return str(existing[0])
    link_id = f"EL-{uuid.uuid4().hex[:12]}"
    if not derivation_group:
        derivation_group = evidence_id
    if not source_family and evidence_id:
        prefix = evidence_id.split("-")[0] if "-" in evidence_id else ""
        source_family = prefix
    db.execute(
        """
        INSERT INTO hypothesis_evidence (
            link_id, hypothesis_id, evidence_id, finding_id, query_id,
            assessment_id, role, source_family, source_file,
            derivation_group, strength, created_session, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())
        """,
        [
            link_id,
            hypothesis_id,
            evidence_id,
            finding_id,
            query_id,
            assessment_id,
            role,
            source_family,
            source_file,
            derivation_group,
            strength,
            created_session,
        ],
    )
    return link_id


def create_evidence_links_for_query(
    db: CaseDB,
    *,
    hypothesis_id: str,
    evidence_ids: list[str],
    query_id: str = "",
    role: str = "supporting",
    created_session: str = "",
    strengths: dict[str, str] | None = None,
) -> list[str]:
    """Create evidence links for all evidence IDs from a query result."""
    link_ids = []
    for eid in evidence_ids:
        lid = create_hypothesis_evidence_link(
            db,
            hypothesis_id=hypothesis_id,
            evidence_id=eid,
            role=role,
            query_id=query_id,
            created_session=created_session,
            strength=(strengths or {}).get(eid, "moderate"),
        )
        link_ids.append(lid)
    return link_ids
