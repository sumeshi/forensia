"""Invalidate existing domain dependents when normalized evidence is replaced or changed."""

from __future__ import annotations

import json

from forensia.db.database import CaseDB
from forensia.evidence.content_identity import (
    bulk_evidence_content_fingerprints,
)

_SOURCE_TABLES: dict[str, tuple[tuple[str, str], ...]] = {
    "evtx": (("evtx_events", "evidence_id"),),
    "mft": (
        ("mft_entries", "evidence_id"),
        ("mft_timeline", "evidence_id"),
    ),
    "prefetch": (
        ("prefetch_executions", "evidence_id"),
        ("prefetch_timeline", "evidence_id"),
    ),
    "registry": (("registry_artifacts", "artifact_id"),),
}


def _json_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except TypeError, ValueError:
            return []
    return [str(item) for item in value] if isinstance(value, list) else []


def _referenced_dependent_ids(db: CaseDB) -> set[str]:
    """IDs whose dependents live in hypotheses, claims, sections, facts, timeline."""
    referenced = {
        str(row[0])
        for row in db.execute(
            "SELECT evidence_id FROM hypothesis_evidence "
            "WHERE evidence_id IS NOT NULL "
            "UNION SELECT evidence_id FROM section_evidence "
            "WHERE evidence_id IS NOT NULL"
        ).fetchall()
        if row[0]
    }
    for (raw_ids,) in db.execute("SELECT evidence_ids FROM claims").fetchall():
        referenced.update(_json_string_list(raw_ids))
    for (raw_ids,) in db.execute("SELECT evidence_ids FROM section_facts").fetchall():
        referenced.update(_json_string_list(raw_ids))
    referenced.update(
        str(row[0])
        for row in db.execute(
            "SELECT evidence_id FROM case_timeline WHERE evidence_id IS NOT NULL"
        ).fetchall()
        if row[0]
    )
    return referenced


def _materialized_ids(db: CaseDB, source_kind: str, referenced: set[str]) -> set[str]:
    tables = _SOURCE_TABLES.get(source_kind, ())
    if not tables or not referenced:
        return set()
    ordered_ids = tuple(sorted(referenced))
    placeholders = ", ".join("?" for _ in ordered_ids)
    materialized: set[str] = set()
    for table, id_column in tables:
        materialized.update(
            str(row[0])
            for row in db.execute(
                f"SELECT {id_column} FROM {table} "
                f"WHERE {id_column} IN ({placeholders})",
                ordered_ids,
            ).fetchall()
            if row[0]
        )
    return materialized


def fetch_referenced_evidence_ids(db: CaseDB, source_kind: str) -> set[str]:
    """Return materialized IDs that currently have durable dependents.

    Replacement invalidation only needs IDs referenced by hypotheses, claims,
    report sections, reusable section facts, or the case timeline. Avoid
    snapshotting large evidence tables such as MFT; only referenced IDs are
    surveyed.
    """
    referenced = _referenced_dependent_ids(db)
    if not referenced:
        return set()
    return _materialized_ids(db, source_kind, referenced)


def fetch_referenced_evidence_fingerprints(
    db: CaseDB, source_kind: str
) -> tuple[set[str], dict[str, str]]:
    """Return (materialized IDs, ID -> content fingerprint) for the survey.

    Used by callers that must distinguish removed materialized IDs from IDs
    whose backing content changed under the same identity.  Fingerprints use
    the shared canonicalization in ``evidence/content_identity.py`` so they
    agree with the fingerprint a hypothesis evidence link records at
    assessment time.
    """
    referenced = _referenced_dependent_ids(db)
    if not referenced:
        return set(), {}
    materialized = _materialized_ids(db, source_kind, referenced)
    if not materialized:
        return set(), {}
    fingerprints = bulk_evidence_content_fingerprints(db, materialized)
    return materialized, fingerprints


def invalidate_removed_evidence(
    db: CaseDB,
    evidence_ids: set[str],
    *,
    reason: str = "Assessed evidence was removed by source replacement",
) -> None:
    """Move dependents of removed or content-changed evidence to review.

    Dependents are assessed hypothesis links (their hypotheses reopen as
    active with sufficiency marked needs_review), claims, and report sections
    referenced directly or via ``section_facts.source_section``.
    ``case_timeline`` rows are historical
    records of a regeneratable projection with no mutable stale state, so they
    are only kept as-is; the timeline memory projection re-validates evidence
    presence on regeneration.  Link history is never deleted; the supplied
    reason is recorded on the affected hypotheses.
    """
    if not evidence_ids:
        return

    placeholders = ", ".join("?" for _ in evidence_ids)
    ordered_ids = tuple(sorted(evidence_ids))
    linked_hypotheses = {
        str(row[0])
        for row in db.execute(
            f"SELECT DISTINCT hypothesis_id FROM hypothesis_evidence "
            f"WHERE evidence_id IN ({placeholders}) "
            "AND COALESCE(assessment_id, '') != '' "
            "AND role IN ('supporting', 'corroborating', 'contradictory')",
            ordered_ids,
        ).fetchall()
        if row[0]
    }

    affected_claims: set[str] = set()
    affected_sections = {
        str(row[0])
        for row in db.execute(
            f"SELECT DISTINCT section_key FROM section_evidence "
            f"WHERE evidence_id IN ({placeholders})",
            ordered_ids,
        ).fetchall()
        if row[0]
    }
    for claim_id, section_key, raw_hypotheses, raw_evidence in db.execute(
        "SELECT claim_id, section_key, hypothesis_ids, evidence_ids FROM claims"
    ).fetchall():
        claim_hypotheses = set(_json_string_list(raw_hypotheses))
        claim_evidence = set(_json_string_list(raw_evidence))
        if (claim_evidence & evidence_ids) or (claim_hypotheses & linked_hypotheses):
            affected_claims.add(str(claim_id))
            if section_key:
                affected_sections.add(str(section_key))
    for raw_ids, source_section in db.execute(
        "SELECT evidence_ids, source_section FROM section_facts"
    ).fetchall():
        if source_section and set(_json_string_list(raw_ids)) & evidence_ids:
            affected_sections.add(str(source_section))

    with db.transaction():
        if linked_hypotheses:
            hypothesis_placeholders = ", ".join("?" for _ in linked_hypotheses)
            db.execute(
                f"""
                UPDATE hypotheses
                SET status = 'active',
                    verdict = NULL,
                    resolved_session = NULL,
                    sufficiency_status = 'needs_review',
                    sufficiency_reason = ?,
                    human_review_required = TRUE,
                    selection_count = 0,
                    last_selected_at = NULL,
                    next_eligible_at = NULL,
                    blocked_reason = NULL,
                    updated_at = now()
                WHERE hypothesis_id IN ({hypothesis_placeholders})
                """,
                (reason, *sorted(linked_hypotheses)),
            )
        if affected_claims:
            claim_placeholders = ", ".join("?" for _ in affected_claims)
            db.execute(
                f"UPDATE claims SET support_status = 'needs_review', updated_at = now() "
                f"WHERE claim_id IN ({claim_placeholders})",
                tuple(sorted(affected_claims)),
            )
        if affected_sections:
            section_placeholders = ", ".join("?" for _ in affected_sections)
            db.execute(
                f"UPDATE report_sections SET stale = TRUE "
                f"WHERE section_key IN ({section_placeholders})",
                tuple(sorted(affected_sections)),
            )
