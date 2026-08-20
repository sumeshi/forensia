from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.artifacts import NormalizeResult
from forensia.evidence.normalize import normalize_all
from forensia.report.sections.section_store import _claim_support_status


class SourceInvalidationTests(unittest.TestCase):
    def _seed_dependents(self, db: CaseDB, evidence_id: str = "evtx-old") -> None:
        db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file) VALUES (?, 'source')",
            [evidence_id],
        )
        db.execute(
            """
            INSERT INTO hypotheses (
                hypothesis_id, status, verdict, sufficiency_status,
                human_review_required, updated_at
            ) VALUES ('H-1', 'confirmed', 'confirmed', 'sufficient', false, now())
            """
        )
        db.execute(
            """
            INSERT INTO hypothesis_evidence (
                link_id, hypothesis_id, evidence_id, role, assessment_id
            ) VALUES ('L-1', 'H-1', ?, 'supporting', 'assessment-1')
            """,
            [evidence_id],
        )
        db.execute(
            """
            INSERT INTO claims (
                claim_id, section_key, claim_text, hypothesis_ids, evidence_ids,
                support_status, created_at, updated_at
            ) VALUES ('C-1', 'section-1', 'claim', ?, ?, 'supported', now(), now())
            """,
            [json.dumps(["H-1"]), json.dumps([evidence_id])],
        )
        db.execute(
            """
            INSERT INTO report_sections (
                section_key, title, body, status, update_count, stale
            ) VALUES ('section-1', 'Section', 'body', 'draft', 1, false)
            """
        )
        db.execute(
            """
            INSERT INTO section_evidence (
                section_key, block_heading, evidence_id, role, source_query, created_at
            ) VALUES ('section-1', 'Block', ?, 'support', 'q1', now())
            """,
            [evidence_id],
        )

    def test_replacement_invalidates_dependents_without_deleting_link_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._seed_dependents(db)

                class UnchangedAdapter:
                    name = "evtx"

                    def normalize(self, case, db, source_keys=None):
                        del case, db, source_keys
                        return NormalizeResult(source_kind="evtx", rows=1)

                with patch(
                    "forensia.evidence.normalize.get_artifact_adapters",
                    return_value=(UnchangedAdapter(),),
                ):
                    normalize_all(case, db)
                self.assertEqual(
                    ("confirmed", "sufficient"),
                    db.execute(
                        "SELECT status, sufficiency_status FROM hypotheses "
                        "WHERE hypothesis_id = 'H-1'"
                    ).fetchone(),
                )

                class ReplacementAdapter:
                    name = "evtx"

                    def normalize(self, case, db, source_keys=None):
                        del case, source_keys
                        db.execute(
                            "DELETE FROM evtx_events WHERE evidence_id = 'evtx-old'"
                        )
                        db.execute(
                            "INSERT INTO evtx_events (evidence_id, source_file) "
                            "VALUES ('evtx-new', 'source')"
                        )
                        return NormalizeResult(source_kind="evtx", rows=1)

                with patch(
                    "forensia.evidence.normalize.get_artifact_adapters",
                    return_value=(ReplacementAdapter(),),
                ):
                    normalize_all(case, db)

                hypothesis = db.execute(
                    "SELECT status, verdict, sufficiency_status, human_review_required "
                    "FROM hypotheses WHERE hypothesis_id = 'H-1'"
                ).fetchone()
                claim = db.execute(
                    "SELECT support_status FROM claims WHERE claim_id = 'C-1'"
                ).fetchone()
                section = db.execute(
                    "SELECT stale FROM report_sections WHERE section_key = 'section-1'"
                ).fetchone()
                links = db.execute(
                    "SELECT evidence_id, role FROM hypothesis_evidence WHERE link_id = 'L-1'"
                ).fetchone()

            self.assertEqual(("needs_review", None, "needs_review", True), hypothesis)
            self.assertEqual(("needs_review",), claim)
            self.assertEqual((True,), section)
            self.assertEqual(("evtx-old", "supporting"), links)

    def test_claim_support_lookup_recognizes_registry_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO registry_artifacts (
                        artifact_id, dataset_id, source_ids, plugin, raw_json, created_at
                    ) VALUES ('registry-artifact-1', 'dataset-1', '[]', 'plugin', '{}', now())
                    """
                )
                self.assertEqual(
                    "supported",
                    _claim_support_status(db, ["registry-artifact-1"], [], []),
                )


if __name__ == "__main__":
    unittest.main()
