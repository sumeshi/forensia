"""Content identification for normalized evidence rows (R03/T04).

Hypothesis evidence links record a compact content fingerprint of the
backing evidence row at assessment time.  Read-time currentness
(``ai/checking/sufficiency.evidence_link_currentness``) compares the stored
fingerprint with the row as it exists now, so an in-place content change of
the same evidence_id under the same source identity is detected instead of
silently refilling stale support.

Top-level administrative keys are excluded from the canonicalized content so
an idempotent re-normalization of unchanged source material cannot
invalidate existing judgments.  Everything else in the row — including the
parsed ``raw_json`` — is judged material and is fingerprinted.

An empty fingerprint ("") means the content identity could not be
established (row missing, or the id resolves nowhere the lookup rules route
to); callers must treat it conservatively as not-current, never as current.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import fetch_evidence_records

# Values that change between normalization runs without any change to the
# normalized content: insert/ingest timestamps and the lookup's own
# provenance marker.
_VOLATILE_CONTENT_KEYS = frozenset(
    {"_source", "created_at", "updated_at", "ingested_at"}
)

_FINGERPRINT_PREFIX = "cf-"


def fingerprint_from_record(record: dict[str, Any] | None) -> str:
    """Return the content fingerprint of one looked-up evidence record.

    Returns "" when the record is missing.  The canonical form is the full
    record (projections plus parsed ``raw`` document) with the volatile keys
    removed at the top level, serialized deterministically. A similarly
    named field inside raw evidence is forensic content, not metadata.
    """
    if record is None:
        return ""
    canonical = json.dumps(
        {key: value for key, value in record.items() if key not in _VOLATILE_CONTENT_KEYS},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return _FINGERPRINT_PREFIX + digest[:20]


def bulk_evidence_content_fingerprints(
    db: CaseDB, evidence_ids: Iterable[str]
) -> dict[str, str]:
    """Fingerprint many evidence ids at once using the same per-id lookup."""
    ids = sorted({str(eid) for eid in evidence_ids if eid})
    if not ids:
        return {}
    records = fetch_evidence_records(db, ids)
    return {
        eid: fingerprint_from_record(record) for eid, record in records.items()
    }
