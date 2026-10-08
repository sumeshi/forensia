"""L8 reproduction: does a deleted evidence row still count as support?

Builds a temp Case DB with an EVTX row and a supporting hypothesis_evidence
link carrying an assessment_id, then deletes the EVTX row (source replacement /
removal) and runs the loaders + evaluate_sufficiency.

- B0 (rev 242ca6a): the raw loader returned the stale link and sufficiency said
  "sufficient" — `load_evidence_links` never checked the evidence row (recorded
  in docs/round-b0-baseline.md §4).
- M0 (T04): `load_evidence_links(current_only=True)` drops links whose evidence
  row no longer exists (or whose source_file changed), so sufficiency degrades
  while the historical link row stays intact in `hypothesis_evidence`.
  The unconstrained loader (current_only=False) still returns the raw history.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from forensia.ai.checking.sufficiency import (
    create_hypothesis_evidence_link,
    evaluate_sufficiency,
    load_evidence_links,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB

EVIDENCE_ID = "evtx-4624-a"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(Path(tmpdir) / "case")
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO evtx_events (evidence_id, source_file, event_id) "
                "VALUES (?, 'sample.evtx', 4624)",
                [EVIDENCE_ID],
            )
            create_hypothesis_evidence_link(
                db,
                hypothesis_id="H-001",
                evidence_id=EVIDENCE_ID,
                role="supporting",
                source_family="evtx",
                source_file="sample.evtx",
                strength="moderate",
                query_id="Q-001",
                assessment_id="EA-test-0001",
            )
            db.execute("DELETE FROM evtx_events WHERE evidence_id = ?", [EVIDENCE_ID])
            surviving_rows = db.execute(
                "SELECT COUNT(*) FROM evtx_events WHERE evidence_id = ?",
                [EVIDENCE_ID],
            ).fetchone()[0]
            historical_links = load_evidence_links(db, "H-001")
            current_links = load_evidence_links(db, "H-001", current_only=True)
            result = evaluate_sufficiency(
                {"required_capabilities": ["logon_events"], "evidence_requirements": {}},
                current_links,
                {"evtx:logon_events": {"state": "full"}},
            )
            print(
                json.dumps(
                    {
                        "evidence_rows_after_delete": int(surviving_rows),
                        "links_loaded_raw_loader": len(historical_links),
                        "links_loaded_current_only": len(current_links),
                        "sufficiency_status": result.status,
                        "independent_groups": result.independent_groups,
                        "score": round(result.score, 4),
                    },
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    main()
