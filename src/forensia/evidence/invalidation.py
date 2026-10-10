"""Invalidate existing domain dependents when normalized evidence is replaced or changed."""

from __future__ import annotations

import json
from collections.abc import Collection

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

_SOURCE_FILE_TABLES: dict[str, tuple[str, ...]] = {
    "evtx": ("evtx_events",),
    "mft": ("mft_timeline", "mft_entries"),
    "prefetch": ("prefetch_timeline", "prefetch_executions"),
}


def find_replaced_source_ids(
    db: CaseDB, source_keys: Collection[str] | None
) -> dict[str, dict[str, str]]:
    """Map each superseded source hash to its exact current replacement hash."""
    keys = tuple(dict.fromkeys(str(key) for key in (source_keys or ()) if key))
    if source_keys is None:
        new_sources = db.execute(
            "SELECT sha256, path, source_kind FROM ("
            "SELECT sha256, path, source_kind, "
            "row_number() OVER (PARTITION BY path, source_kind "
            "ORDER BY ingested_at DESC NULLS LAST, sha256 DESC) AS current_rank "
            "FROM ingested_files) WHERE current_rank = 1"
        ).fetchall()
    elif keys:
        placeholders = ", ".join("?" for _ in keys)
        new_sources = db.execute(
            f"SELECT sha256, path, source_kind FROM ingested_files "
            f"WHERE sha256 IN ({placeholders})",
            keys,
        ).fetchall()
    else:
        return {}
    grouped: dict[tuple[str, str], list[str]] = {}
    for source_id, path, family in new_sources:
        if not source_id or not path or family not in _SOURCE_FILE_TABLES:
            continue
        grouped.setdefault((str(family), str(path)), []).append(str(source_id))
    if not grouped:
        return {}

    replacements: dict[str, dict[str, str]] = {}
    for (family, path), selected_sources in grouped.items():
        if source_keys is None:
            # The normalizer is rebuilding all registered inputs. The latest
            # ingested hash is the active version; older same-path hashes are
            # replacement candidates, never peers that can replace one another.
            current = db.execute(
                "SELECT sha256 FROM ingested_files WHERE path = ? AND source_kind = ? "
                "ORDER BY ingested_at DESC NULLS LAST, sha256 DESC LIMIT 1",
                (path, family),
            ).fetchone()
            current_id = str(current[0]) if current else ""
        else:
            selected_placeholders = ", ".join("?" for _ in selected_sources)
            current = db.execute(
                f"SELECT sha256 FROM ingested_files WHERE path = ? "
                f"AND source_kind = ? AND sha256 IN ({selected_placeholders}) "
                "ORDER BY ingested_at DESC NULLS LAST, sha256 DESC LIMIT 1",
                (path, family, *selected_sources),
            ).fetchone()
            current_id = str(current[0]) if current else ""
        if not current_id:
            continue
        old_rows = db.execute(
            "SELECT sha256 FROM ingested_files "
            "WHERE path = ? AND source_kind = ? AND sha256 != ?",
            (path, family, current_id),
        ).fetchall()
        for (old_id,) in old_rows:
            if old_id:
                replacements.setdefault(family, {})[str(old_id)] = current_id
    return replacements


def retire_replaced_sources(
    db: CaseDB, replacements: dict[str, dict[str, str]]
) -> None:
    """Invalidate and remove superseded source rows after replacement normalized."""
    for family, old_to_new in replacements.items():
        tables = _SOURCE_FILE_TABLES.get(family)
        if not tables or not old_to_new:
            continue
        eligible_sources: set[str] = set()
        for old_id, new_id in old_to_new.items():
            old_row = db.execute(
                "SELECT path FROM ingested_files WHERE sha256 = ? AND source_kind = ?",
                (old_id, family),
            ).fetchone()
            if not old_row or not old_row[0]:
                continue
            replacement = db.execute(
                "SELECT 1 FROM ingested_files AS current "
                "JOIN evidence_sources AS status ON status.source_id = current.sha256 "
                "WHERE current.path = ? AND current.source_kind = ? "
                "AND current.sha256 = ? AND status.artifact_family = ? "
                "AND status.ingest_status IN ('normalized', 'empty') LIMIT 1",
                (old_row[0], family, new_id, family),
            ).fetchone()
            if replacement:
                eligible_sources.add(old_id)
        if not eligible_sources:
            continue
        ordered_sources = tuple(sorted(eligible_sources))
        source_placeholders = ", ".join("?" for _ in ordered_sources)
        evidence_ids: set[str] = set()
        for table in tables:
            evidence_ids.update(
                str(row[0])
                for row in db.execute(
                    f"SELECT DISTINCT evidence_id FROM {table} "
                    f"WHERE source_file IN ({source_placeholders}) "
                    "AND evidence_id IS NOT NULL",
                    ordered_sources,
                ).fetchall()
                if row[0]
            )
        referenced = fetch_referenced_evidence_ids(db, family) & evidence_ids
        with db.transaction():
            if referenced:
                _invalidate_removed_evidence_in_transaction(db, referenced)
            for table in tables:
                db.execute(
                    f"DELETE FROM {table} WHERE source_file IN ({source_placeholders})",
                    ordered_sources,
                )
            if evidence_ids:
                evidence_placeholders = ", ".join("?" for _ in evidence_ids)
                db.execute(
                    f"DELETE FROM case_timeline WHERE evidence_id IN ({evidence_placeholders})",
                    tuple(sorted(evidence_ids)),
                )
            db.execute(
                f"DELETE FROM evidence_sources WHERE source_id IN ({source_placeholders})",
                ordered_sources,
            )
            db.execute(
                f"DELETE FROM ingested_files WHERE sha256 IN ({source_placeholders})",
                ordered_sources,
            )


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
    """Invalidate evidence dependents atomically in the case database."""
    if not evidence_ids:
        return
    with db.transaction():
        _invalidate_removed_evidence_in_transaction(db, evidence_ids, reason=reason)


def _invalidate_removed_evidence_in_transaction(
    db: CaseDB,
    evidence_ids: set[str],
    *,
    reason: str = "Assessed evidence was removed by source replacement",
) -> None:
    """Move dependents of removed or content-changed evidence to review.

    Dependents are assessed hypothesis links (their hypotheses reopen as
    active with sufficiency marked needs_review), claims, and report sections
    referenced directly or via ``section_facts.source_section``.
    ``case_timeline`` rows are historical records of a regeneratable
    projection with no mutable stale state, so they are only kept as-is. Link
    history is never deleted; the supplied reason is recorded on the affected
    hypotheses.
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
