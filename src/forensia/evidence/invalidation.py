"""Invalidate existing domain dependents when normalized evidence is replaced."""

from __future__ import annotations

import json

from forensia.db.database import CaseDB

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


def fetch_referenced_evidence_ids(db: CaseDB, source_kind: str) -> set[str]:
    """Return materialized IDs that currently have durable dependents.

    Replacement invalidation only needs IDs referenced by hypotheses, claims,
    or report sections. Avoid snapshotting large evidence tables such as MFT.
    """
    tables = _SOURCE_TABLES.get(source_kind, ())
    if not tables:
        return set()
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
    if not referenced:
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


def invalidate_removed_evidence(db: CaseDB, evidence_ids: set[str]) -> None:
    """Move dependents of removed evidence to review without deleting history."""
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

    with db.transaction():
        if linked_hypotheses:
            hypothesis_placeholders = ", ".join("?" for _ in linked_hypotheses)
            db.execute(
                f"""
                UPDATE hypotheses
                SET status = 'needs_review',
                    verdict = NULL,
                    resolved_session = NULL,
                    sufficiency_status = 'needs_review',
                    sufficiency_reason = 'Assessed evidence was removed by source replacement',
                    human_review_required = TRUE,
                    updated_at = now()
                WHERE hypothesis_id IN ({hypothesis_placeholders})
                """,
                tuple(sorted(linked_hypotheses)),
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
