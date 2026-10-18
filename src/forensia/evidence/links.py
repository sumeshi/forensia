"""Current evidence links shared by investigation and report projections."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from forensia.core.verification import VerificationSpec
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record, routed_family
from forensia.evidence.content_identity import fingerprint_from_record


@dataclass
class EvidenceLink:
    link_id: str
    hypothesis_id: str
    evidence_id: str
    finding_id: str
    query_id: str
    assessment_id: str
    role: str
    source_family: str
    source_file: str
    derivation_group: str
    strength: str
    content_fingerprint: str = ""
    verification_spec_fingerprint: str = ""
    assessment_reason: str = ""
    matched_conditions: tuple[str, ...] = ()


def verification_spec_fingerprint(spec: Any) -> str:
    """Return a stable identity for a canonical VerificationSpec."""
    payload = spec.model_dump(mode="json")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def evidence_link_currentness(
    db: CaseDB, link: EvidenceLink
) -> tuple[bool, str | None]:
    """Return whether the evidence and judgment recorded by a link are current."""
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
    """Load historical links, optionally filtering with the shared currentness rule."""
    rows = db.execute(
        "SELECT link_id, hypothesis_id, evidence_id, finding_id, query_id, "
        "assessment_id, role, source_family, source_file, derivation_group, "
        "strength, content_fingerprint, verification_spec_fingerprint, "
        "assessment_reason, matched_conditions "
        "FROM hypothesis_evidence WHERE hypothesis_id = ?",
        [hypothesis_id],
    ).fetchall()
    links = []
    for row in rows:
        matched: tuple[str, ...] = ()
        if isinstance(row[14], str) and row[14].strip():
            try:
                parsed = json.loads(row[14])
                if isinstance(parsed, list):
                    matched = tuple(str(key) for key in parsed if key)
            except json.JSONDecodeError:
                pass
        links.append(
            EvidenceLink(
                link_id=row[0],
                hypothesis_id=row[1],
                evidence_id=row[2],
                finding_id=row[3] or "",
                query_id=row[4] or "",
                assessment_id=row[5] or "",
                role=row[6] or "supporting",
                source_family=row[7] or "",
                source_file=row[8] or "",
                derivation_group=row[9] or "",
                strength=row[10] or "moderate",
                content_fingerprint=row[11] or "",
                verification_spec_fingerprint=row[12] or "",
                assessment_reason=row[13] or "",
                matched_conditions=matched,
            )
        )
    if current_only:
        links = [link for link in links if evidence_link_currentness(db, link)[0]]
    return links
