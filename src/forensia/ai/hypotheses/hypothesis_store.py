"""Hypothesis persistence: load, upsert, reasoning rows, memory render."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from forensia.ai.hypotheses.hypothesis_model import (
    _clean_confirm_when,
)
from forensia.core.session import Hypothesis, SessionState
from forensia.core.verification import normalize_verification_spec
from forensia.db.database import CaseDB
from forensia.db.query import fetch_records


def _recent_reasoning_rows(
    db: CaseDB, hypothesis_id: str, limit: int = 10
) -> list[dict[str, Any]]:
    """Fetch the most recent reasoning entries for a given hypothesis."""
    return fetch_records(
        db,
        """
        SELECT phase, verdict, query_id, body, created_at
        FROM hypothesis_reasoning
        WHERE hypothesis_id = ?
        ORDER BY created_at DESC, entry_id DESC
        LIMIT ?
        """,
        (hypothesis_id, limit),
    )


def _render_hypothesis_memory(db: CaseDB | None, hypothesis: Hypothesis) -> str:
    """Render a hypothesis as a Markdown memory block with status, verdict, and recent reasoning."""
    lines = [
        f"# Hypothesis {hypothesis.id}",
        "",
        "## Status",
        f"- {hypothesis.status}",
        "",
        "## Verdict",
        f"- {hypothesis.verdict or 'pending'}",
        "",
        "## Description",
        hypothesis.description,
        "",
        "## Summary",
        hypothesis.summary or "-",
    ]
    if db is not None:
        reasoning_rows = _recent_reasoning_rows(db, hypothesis.id)
        if reasoning_rows:
            lines.extend(["", "## Reasoning"])
            for row in reasoning_rows:
                phase = str(row.get("phase") or "")
                verdict = str(row.get("verdict") or "-")
                query_id = str(row.get("query_id") or "-")
                body = " ".join(str(row.get("body") or "").split())[:240]
                lines.append(
                    f"- [{phase}] verdict={verdict} query={query_id} :: {body}"
                )
    return "\n".join(lines) + "\n"


def _next_hypothesis_id(db: CaseDB) -> str:
    """Generate the next sequential hypothesis ID in H-NNN format."""
    row = db.execute(
        """
        SELECT COALESCE(MAX(CAST(regexp_extract(hypothesis_id, '^H-(\\d+)$', 1) AS INTEGER)), 0)
        FROM hypotheses
        WHERE regexp_matches(hypothesis_id, '^H-(\\d+)$')
        """,
    ).fetchone()
    next_num = int(row[0] or 0) + 1 if row else 1
    return f"H-{next_num:03d}"


def _row_to_hypothesis(row: dict[str, Any]) -> Hypothesis:
    """Convert a database result row into a Hypothesis object, parsing JSON fields."""
    verdict = row.get("verdict")
    source_rule_ids = row.get("source_rule_ids")
    required_entities = row.get("required_entities")
    confirm_when = row.get("confirm_when")
    refute_when = row.get("refute_when")
    evidence_requirements = row.get("evidence_requirements")
    verification_spec = row.get("verification_spec")
    if isinstance(source_rule_ids, str):
        try:
            import json

            source_rule_ids = json.loads(source_rule_ids)
        except Exception:
            source_rule_ids = []
    if not isinstance(source_rule_ids, list):
        source_rule_ids = []
    if isinstance(required_entities, str):
        try:
            import json

            required_entities = json.loads(required_entities)
        except Exception:
            required_entities = []
    if not isinstance(required_entities, list):
        required_entities = []
    if isinstance(confirm_when, str):
        try:
            import json

            confirm_when = json.loads(confirm_when)
        except Exception:
            confirm_when = None
    if isinstance(refute_when, str):
        try:
            refute_when = json.loads(refute_when)
        except Exception:
            refute_when = None
    if isinstance(evidence_requirements, str):
        try:
            evidence_requirements = json.loads(evidence_requirements)
        except Exception:
            evidence_requirements = None
    if isinstance(verification_spec, str):
        try:
            verification_spec = json.loads(verification_spec)
        except Exception:
            verification_spec = None
    normalized = normalize_verification_spec(
        confirm_when=confirm_when,
        refute_when=refute_when,
        evidence_requirements=evidence_requirements,
        required_entities=required_entities,
        verification_spec=verification_spec,
    )
    projections = normalized.legacy_fields()
    return Hypothesis(
        id=str(row.get("hypothesis_id") or ""),
        description=str(row.get("description") or ""),
        status=str(row.get("status") or "active"),
        verdict=str(verdict) if verdict else None,
        summary=str(row.get("summary") or ""),
        source_rule_ids=[str(item) for item in source_rule_ids if item],
        source_decl_id=row.get("source_decl_id"),
        source_gap_id=row.get("source_gap_id"),
        required_entities=[str(item) for item in required_entities if item],
        confirm_when=projections["confirm_when"],
        refute_when=projections["refute_when"],
        evidence_requirements=projections["evidence_requirements"],
        verification_spec=normalized,
        target_keypoint_id=row.get("target_keypoint_id"),
    )


def load_persisted_hypotheses(db: CaseDB) -> tuple[list[Hypothesis], list[Hypothesis]]:
    """Load all hypotheses from the database, partitioned into active and resolved."""
    rows = fetch_records(
        db,
        """
        SELECT hypothesis_id, description, status, verdict, summary, source_rule_ids,
               source_decl_id, required_entities, confirm_when, refute_when,
               evidence_requirements, verification_spec, source_gap_id, target_keypoint_id
        FROM hypotheses
        ORDER BY created_at, hypothesis_id
        """,
    )
    active: list[Hypothesis] = []
    resolved: list[Hypothesis] = []
    terminal_work_ids = {
        str(row[0])
        for row in db.execute(
            "SELECT hypothesis_id FROM investigation_tasks "
            "WHERE owner_phase = 'termination' AND status = 'open' "
            "AND hypothesis_id IS NOT NULL"
        ).fetchall()
    }
    for row in rows:
        hypothesis = _row_to_hypothesis(row)
        if hypothesis.status == "active" or (
            hypothesis.status == "needs_review"
            and hypothesis.id not in terminal_work_ids
        ):
            active.append(hypothesis)
        else:
            resolved.append(hypothesis)
    return active, resolved


def _upsert_hypothesis(
    db: CaseDB,
    hypothesis: Hypothesis,
    origin: str,
    session_id: str,
    resolved_session: str | None = None,
) -> None:
    """Insert or update a hypothesis row, preserving original creation metadata on conflict."""
    from forensia.core.verdicts import assert_valid_verdict

    if hypothesis.verdict is not None:
        assert_valid_verdict(hypothesis.verdict, "hypothesis_verdict")
    now = datetime.now(UTC).replace(tzinfo=None)
    existing = db.execute(
        """
        SELECT origin, created_session, created_at, resolved_session
        FROM hypotheses
        WHERE hypothesis_id = ?
        """,
        (hypothesis.id,),
    ).fetchone()
    created_origin = origin
    created_session = session_id
    created_at = now
    prior_resolved_session = resolved_session
    if existing is not None:
        created_origin = str(existing[0] or origin)
        created_session = str(existing[1] or session_id)
        created_at = existing[2] or now
        if prior_resolved_session is None:
            prior_resolved_session = existing[3]

    clean_confirm_when = _clean_confirm_when(hypothesis.confirm_when, db)
    if hypothesis.verification_spec is not None:
        # Preserve canonical fields introduced by the normalized model while
        # applying the existing admission sanitization to its compatibility
        # projection.  This keeps one source of truth without dropping
        # capability/scope metadata on every legacy write path.
        normalized = hypothesis.verification_spec.model_copy(deep=True)
        normalized.support_conditions = clean_confirm_when or {}
        if hypothesis.refute_when is not None:
            normalized.refute_conditions = dict(hypothesis.refute_when)
        if hypothesis.evidence_requirements is not None:
            normalized.evidence_requirements = dict(hypothesis.evidence_requirements)
        normalized.required_entities = list(hypothesis.required_entities)
    else:
        normalized = normalize_verification_spec(
            confirm_when=clean_confirm_when,
            refute_when=hypothesis.refute_when,
            evidence_requirements=hypothesis.evidence_requirements,
            required_entities=hypothesis.required_entities,
        )
    projections = normalized.legacy_fields()

    db.execute(
        """
        INSERT INTO hypotheses (
            hypothesis_id, description, status, verdict, summary, origin,
            created_session, resolved_session, created_at, updated_at, source_rule_ids,
            source_decl_id, required_entities, confirm_when, refute_when,
            evidence_requirements, verification_spec, source_gap_id, target_keypoint_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (hypothesis_id) DO UPDATE SET
            description = excluded.description,
            status = excluded.status,
            verdict = excluded.verdict,
            summary = excluded.summary,
            origin = excluded.origin,
            created_session = excluded.created_session,
            resolved_session = excluded.resolved_session,
            created_at = excluded.created_at,
            updated_at = excluded.updated_at,
            source_rule_ids = excluded.source_rule_ids,
            source_decl_id = excluded.source_decl_id,
            required_entities = excluded.required_entities,
            confirm_when = excluded.confirm_when,
            refute_when = excluded.refute_when,
            evidence_requirements = excluded.evidence_requirements,
            verification_spec = excluded.verification_spec,
            source_gap_id = COALESCE(excluded.source_gap_id, hypotheses.source_gap_id),
            target_keypoint_id = COALESCE(excluded.target_keypoint_id, hypotheses.target_keypoint_id)
        """,
        (
            hypothesis.id,
            hypothesis.description,
            hypothesis.status,
            hypothesis.verdict,
            hypothesis.summary,
            created_origin,
            created_session,
            prior_resolved_session,
            created_at,
            now,
            json.dumps(hypothesis.source_rule_ids, ensure_ascii=False),
            hypothesis.source_decl_id,
            json.dumps(hypothesis.required_entities, ensure_ascii=False),
            json.dumps(projections["confirm_when"], ensure_ascii=False)
            if projections["confirm_when"]
            else None,
            json.dumps(projections["refute_when"], ensure_ascii=False)
            if projections["refute_when"]
            else None,
            json.dumps(projections["evidence_requirements"], ensure_ascii=False)
            if projections["evidence_requirements"]
            else None,
            json.dumps(normalized.model_dump(mode="json"), ensure_ascii=False),
            hypothesis.source_gap_id,
            hypothesis.target_keypoint_id,
        ),
    )


def _all_hypotheses(state: SessionState) -> list[Hypothesis]:
    return [*state.active_hypotheses, *state.resolved_hypotheses]
