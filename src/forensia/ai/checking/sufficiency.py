"""Evidence sufficiency evaluation: policy hierarchy, role verification, LLM/machine reconciliation."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import (
    lookup_evidence_record,
    routed_family,
)
from forensia.evidence.content_identity import (
    fingerprint_from_record,
)
from forensia.knowledge.coverage import (
    derive_required_capabilities,
    get_coverage_summary,
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
    # Canonical content identity of the backing evidence row at assessment
    # time (evidence/content_identity.py).  Empty means the identity could
    # not be established when the link was written; such links are never
    # counted as current support.
    content_fingerprint: str = ""
    verification_spec_fingerprint: str = ""


def verification_spec_fingerprint(spec: Any) -> str:
    """Return a stable identity for a canonical VerificationSpec."""
    payload = spec.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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


VALID_ROLES = frozenset(
    [
        "supporting",
        "corroborating",
        "contradictory",
        "contextual",
        "unrelated",
        "duplicate",
    ]
)
VALID_STRENGTHS = frozenset(["weak", "moderate", "strong"])

# Observations that were retrieved (rows observed) but could not be turned into
# an admissible EvidenceLink — e.g. retrieval was inadequate or no evidence_id
# could be extracted.  Recorded so sufficiency can distinguish "nothing to link"
# from "rows existed but were not linkable" (the latter must NOT be reported as
# a bare "No evidence links found").
_UNLINKABLE_OBS_SQL = """
CREATE TABLE IF NOT EXISTS hypothesis_unlinkable_obs (
    hypothesis_id VARCHAR,
    query_id VARCHAR,
    reason VARCHAR,
    observed_rows INTEGER,
    created_session VARCHAR,
    created_at TIMESTAMP
)
"""


def record_unlinkable_observation(
    db: CaseDB,
    *,
    hypothesis_id: str,
    query_id: str = "",
    reason: str = "",
    observed_rows: int = 0,
    created_session: str = "",
) -> None:
    """Persist a structured reason for an observed-but-unlinkable query result."""
    db.execute(_UNLINKABLE_OBS_SQL)
    db.execute(
        "INSERT INTO hypothesis_unlinkable_obs "
        "(hypothesis_id, query_id, reason, observed_rows, created_session, created_at) "
        "VALUES (?, ?, ?, ?, ?, now())",
        [
            hypothesis_id,
            query_id or "",
            reason or "",
            int(observed_rows or 0),
            created_session or "",
        ],
    )


def load_unlinkable_observations_for_session(
    db: CaseDB, hypothesis_id: str, created_session: str | None = None
) -> list[tuple[str, int]]:
    """Return unlinkable observations, optionally bounded to one session."""
    try:
        db.execute(_UNLINKABLE_OBS_SQL)
        session_clause = ""
        params: list[str] = [hypothesis_id]
        if created_session:
            session_clause = " AND created_session = ?"
            params.append(created_session)
        rows = db.execute(
            "SELECT reason, observed_rows FROM hypothesis_unlinkable_obs "
            "WHERE hypothesis_id = ?" + session_clause,
            params,
        ).fetchall()
        return [(str(r[0] or ""), int(r[1]) if r[1] is not None else 0) for r in rows]
    except Exception:
        return []


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


def evidence_link_currentness(
    db: CaseDB, link: EvidenceLink
) -> tuple[bool, str | None]:
    """Return ``(True, None)`` when a link's judged material is verifiably current.

    Currentness is derived at read time from stored identities only; the
    hypothesis_evidence row is never mutated or deleted by this check.
    Four verifications apply:

    1. The referenced evidence row must still exist in the normalized table(s)
       routed by the evidence_id prefix (db/evidence_lookup.py).  ``mft-``
       resolves against mft_entries only — mft_timeline rows share the entry's
       evidence_id and are derived from it, so no separate timeline branch is
       needed; ``prefetch-`` already routes to both prefetch tables.
    2. When both the link and the found row carry a non-empty ``source_file``
       (the raw source SHA-256 for evtx/mft/prefetch), they must match.
    3. The link's recorded ``content_fingerprint`` must match the fingerprint
       of the row as it exists now (evidence/content_identity.py).  This
       detects an in-place content change of the same evidence_id under the
       same source identity — for example the same raw file re-normalized
       with modified rows — which the source comparison cannot see.  Registry
       rows are content-addressed (``artifact_id``) and skip the source-file
       match; their content fingerprint covers identification.
    4. The link's ``verification_spec_fingerprint`` must match the current
       canonical Spec for its Hypothesis.

    An empty stored or live fingerprint makes currentness undecidable; the
    link is conservatively excluded from current support (``requires
    re-evaluation``) and is never silently refilled. The sufficiency policy is
    re-applied on every assessment.
    """
    evidence_id = str(link.evidence_id or "").strip()
    if not evidence_id or routed_family(evidence_id) is None:
        return False, "evidence_identity_unverifiable"
    row = lookup_evidence_record(db, evidence_id)
    if row is None:
        return False, "evidence_row_missing"
    if routed_family(evidence_id) != "registry":
        link_source = str(link.source_file or "").strip()
        row_source = str(row.get("source_file") or "").strip()
        if not link_source or not row_source:
            return False, "source_identity_unverifiable"
        if link_source != row_source:
            return False, "source_file_mismatch"
    # Registry rows are content-addressed (artifact_id); every other family
    # is addressed by the raw source SHA-256.  Either way the recorded
    # content fingerprint identifies the judged material itself.
    link_fingerprint = str(link.content_fingerprint or "").strip()
    live_fingerprint = fingerprint_from_record(row)
    if not link_fingerprint or not live_fingerprint:
        return False, "content_unverifiable"
    if link_fingerprint != live_fingerprint:
        return False, "content_changed"
    spec_row = db.execute(
        "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
        [link.hypothesis_id],
    ).fetchone()
    if not spec_row or not spec_row[0]:
        return False, "verification_spec_unverifiable"
    raw_spec = spec_row[0]
    if isinstance(raw_spec, str):
        try:
            raw_spec = json.loads(raw_spec)
        except json.JSONDecodeError:
            return False, "verification_spec_unverifiable"
    try:
        from forensia.core.verification import VerificationSpec

        current_spec_fingerprint = verification_spec_fingerprint(
            VerificationSpec.model_validate(raw_spec)
        )
    except Exception:
        return False, "verification_spec_unverifiable"
    if not link.verification_spec_fingerprint:
        return False, "verification_spec_unverifiable"
    if link.verification_spec_fingerprint != current_spec_fingerprint:
        return False, "verification_spec_changed"
    return True, None


def load_evidence_links(
    db: CaseDB, hypothesis_id: str, *, current_only: bool = False
) -> list[EvidenceLink]:
    """Load evidence links for a hypothesis.

    With ``current_only=True`` links whose evidence row no longer exists or
    whose recorded source identity no longer matches the materialized row are
    excluded (see ``evidence_link_currentness``).  The excluded
    hypothesis_evidence rows themselves are historical records and are never
    deleted or mutated here.
    """
    rows = db.execute(
        "SELECT link_id, hypothesis_id, evidence_id, finding_id, query_id, "
        "assessment_id, role, source_family, source_file, derivation_group, "
        "strength, content_fingerprint, verification_spec_fingerprint "
        "FROM hypothesis_evidence WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchall()
    links = [
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
            content_fingerprint=r[11] or "",
            verification_spec_fingerprint=r[12] or "",
        )
        for r in rows
    ]
    if current_only:
        links = [link for link in links if evidence_link_currentness(db, link)[0]]
    return links


def derivation_root_key(link: EvidenceLink) -> str:
    """Return the derivation root a link belongs to (independence boundary).

    A link is part of the same derivation root as another link when the
    derivation root itself is the same, not when the acquisition attempt is:
    the query id is acquisition history and never manufactures independence.

    - An explicitly declared ``derivation_group`` names one root; links
      sharing it are never independent (same-root re-search invariant).
    - Otherwise the root is the content identity of the backing row:
      the evidence record within its source.  The same evidence fetched
      again via different queries collapses to one root and cannot become
      multiple independent groups.
    """
    declared = str(link.derivation_group or "").strip()
    if declared:
        return f"declared:{declared}"
    source = str(link.source_file or "").strip()
    return f"row:{link.evidence_id}|{source}"


def _group_by_derivation(links: list[EvidenceLink]) -> dict[str, list[EvidenceLink]]:
    """Group evidence links by derivation root (see derivation_root_key)."""
    groups: dict[str, list[EvidenceLink]] = {}
    for link in links:
        groups.setdefault(derivation_root_key(link), []).append(link)
    return groups


def _assessed_links(links: list[EvidenceLink]) -> list[EvidenceLink]:
    """Return links with an Evidence Assessment provenance identifier.

    Links written by pre-assessment versions are retained for history, but they
    are not admissible evidence for sufficiency or settlement.  Keeping this
    filter here also makes all callers use the same legacy-data boundary.
    """
    return [link for link in links if str(link.assessment_id or "").strip()]


def evaluate_sufficiency(
    hypothesis: dict[str, Any],
    links: list[EvidenceLink],
    coverage: dict[str, dict[str, str]],
    policy: dict[str, Any] | None = None,
    unlinkable_reasons: list[str] | None = None,
) -> SufficiencyResult:
    """Evaluate evidence sufficiency for a hypothesis.

    Returns a SufficiencyResult with status, score, and detailed reasons.

    ``unlinkable_reasons`` carries structured reasons for observations that were
    retrieved but could not be turned into an admissible EvidenceLink.  When
    supplied and non-empty it replaces the misleading "No evidence links found"
    verdict (which implies nothing was ever observed) with an explicit note that
    rows existed but were not linkable.
    """
    if policy is None:
        policy = load_evidence_sufficiency_policy()
    unlinkable_reasons = unlinkable_reasons or []

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

    raw_capabilities = hypothesis.get("required_capabilities")
    relevant_capabilities = {
        str(item) for item in (raw_capabilities or []) if str(item)
    }
    relevant_coverage = (
        {
            key: value
            for key, value in coverage.items()
            if key.split(":", 1)[-1] in relevant_capabilities
        }
        if raw_capabilities is not None
        else dict(coverage)
    )

    # Legacy links without an assessment_id remain loadable, but cannot
    # contribute support, contradiction, family diversity, or independence.
    links = _assessed_links(links)

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
        if unlinkable_reasons:
            return SufficiencyResult(
                status="insufficient",
                score=0.0,
                reasons=[
                    "Observations observed but not linkable: "
                    + "; ".join(unlinkable_reasons)
                ],
                independent_groups=0,
                families=[],
                contradictory_groups=0,
                missing_requirements=["at least 1 linkable supporting evidence group"],
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
            except TypeError, ValueError:
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
    evidence_requirements: dict[str, Any] | None,
    llm_verdict: str,
    verification_spec: dict[str, Any] | Any,
    session_id: str | None = None,
) -> tuple[SufficiencyResult, str, str, list[str]]:
    """Run the authoritative machine assessment and persist its projections.

    ``verification_spec`` is required: capabilities derive from the canonical
    spec only (declared list first, then its support conditions).  There is
    no text-inference fallback that would re-derive different requirements
    at a different verification stage.
    """
    spec = (
        verification_spec
        if isinstance(verification_spec, dict)
        else verification_spec.model_dump()
    )
    required_capabilities = derive_required_capabilities(
        spec.get("required_capabilities"), spec.get("support_conditions")
    )
    # Split historical from currently-usable links with the shared predicate.
    # Stale links stay in hypothesis_evidence; they only stop counting here.
    current_links: list[EvidenceLink] = []
    stale_counts: dict[str, int] = {}
    for link in load_evidence_links(db, hypothesis_id):
        is_current, stale_reason = evidence_link_currentness(db, link)
        if is_current:
            current_links.append(link)
        else:
            stale_counts[stale_reason or "unverifiable"] = (
                stale_counts.get(stale_reason or "unverifiable", 0) + 1
            )
    result = evaluate_sufficiency(
        {
            "hypothesis_id": hypothesis_id,
            "required_capabilities": required_capabilities,
            "evidence_requirements": evidence_requirements or {},
        },
        current_links,
        get_coverage_summary(db),
        unlinkable_reasons=[
            reason
            for reason, _ in load_unlinkable_observations_for_session(
                db, hypothesis_id, session_id
            )
        ],
    )
    if stale_counts:
        # Deterministic wording (sufficiency_reason is not hashed anywhere).
        result.reasons.append(
            "historical/non-current evidence links excluded from current "
            "support: "
            + ", ".join(
                f"{reason}={count}" for reason, count in sorted(stale_counts.items())
            )
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
    # Capture the source and canonical content identity from normalized
    # Evidence at admission (new observation, not a read-time backfill of
    # history). Content-addressed Registry IDs need only existence.
    record = lookup_evidence_record(db, evidence_id)
    content_fingerprint = fingerprint_from_record(record)
    spec_row = db.execute(
        "SELECT verification_spec FROM hypotheses WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchone()
    raw_spec = spec_row[0] if spec_row else None
    if isinstance(raw_spec, str):
        raw_spec = json.loads(raw_spec)
    from forensia.core.verification import VerificationSpec

    if not isinstance(raw_spec, dict):
        raise ValueError(
            f"hypothesis {hypothesis_id} has no canonical VerificationSpec; "
            "cannot record an evidence judgment without its verification contract"
        )
    spec_fingerprint = verification_spec_fingerprint(
        VerificationSpec.model_validate(raw_spec)
    )
    if record is not None and not source_file and routed_family(evidence_id) != "registry":
        source_file = str(record.get("source_file") or "").strip()
    # A link records one judgment of one materialized content version. Keep
    # previous judgments intact even when the same query is retried.
    if not derivation_group:
        derivation_group = evidence_id
    existing = db.execute(
        "SELECT link_id FROM hypothesis_evidence "
        "WHERE hypothesis_id = ? AND evidence_id = ? AND role = ? "
        "AND COALESCE(query_id, '') = COALESCE(?, '') "
        "AND COALESCE(source_file, '') = ? "
        "AND COALESCE(content_fingerprint, '') = ? "
        "AND COALESCE(verification_spec_fingerprint, '') = ? "
        "AND COALESCE(assessment_id, '') = ? "
        "AND COALESCE(derivation_group, '') = ? LIMIT 1",
        [
            hypothesis_id, evidence_id, role, query_id, source_file,
            content_fingerprint, spec_fingerprint, assessment_id, derivation_group,
        ],
    ).fetchone()
    if existing:
        return str(existing[0])
    link_id = f"EL-{uuid.uuid4().hex[:12]}"
    if not source_family and evidence_id:
        prefix = evidence_id.split("-")[0] if "-" in evidence_id else ""
        source_family = prefix
    db.execute(
        """
        INSERT INTO hypothesis_evidence (
            link_id, hypothesis_id, evidence_id, finding_id, query_id,
            assessment_id, role, source_family, source_file,
            derivation_group, content_fingerprint, verification_spec_fingerprint,
            strength,
            created_session, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())
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
            content_fingerprint,
            spec_fingerprint,
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
    assessment_id: str = "",
    derivation_group: str = "",
    finding_ids_by_evidence: dict[str, str] | None = None,
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
            finding_id=(finding_ids_by_evidence or {}).get(eid, ""),
            strength=(strengths or {}).get(eid, "moderate"),
            assessment_id=assessment_id,
            derivation_group=derivation_group,
        )
        link_ids.append(lid)
    return link_ids
