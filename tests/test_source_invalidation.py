from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.ai.investigation.selection import select_focus_hypotheses
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
                human_review_required, verification_spec, selection_count,
                blocked_reason, next_eligible_at, updated_at
            ) VALUES ('H-1', 'confirmed', 'confirmed', 'sufficient', false,
                      '{"spec_version":"1"}', 8, 'old attempt blocked',
                      now() + INTERVAL 1 DAY, now())
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

            self.assertEqual(("active", None, "needs_review", True), hypothesis)
            with CaseDB(case) as db:
                self.assertEqual(
                    [row.hypothesis_id for row in select_focus_hypotheses(db, limit=1)],
                    ["H-1"],
                )
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

    def test_removed_evidence_stales_section_facts_dependents(self) -> None:
        """section_facts and case_timeline references are part of the invalidation survey."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._seed_dependents(db)
                db.execute(
                    """
                    INSERT INTO section_facts (
                        fact_id, fact_type, fact_value, evidence_ids,
                        source_query, source_section, confidence,
                        created_at, updated_at
                    ) VALUES (
                        'fact-1', 'fact_type', '"v"', ?, 'q1', 'section-2',
                        0.8, now(), now()
                    )
                    """,
                    [json.dumps(["evtx-old"])],
                )
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, status, update_count, stale
                    ) VALUES ('section-2', 'Other', 'body', 'draft', 1, false)
                    """
                )
                db.execute(
                    """
                    INSERT INTO case_timeline (
                        entry_id, timestamp, source, ref_id, host, summary, evidence_id
                    ) VALUES ('t-1', now(), 'evtx', 'r1', 'host', 'summary', 'evtx-old')
                    """
                )

                class ReplacementAdapter:
                    name = "evtx"

                    def normalize(self, case, db, source_keys=None):
                        del case, source_keys
                        db.execute(
                            "DELETE FROM evtx_events WHERE evidence_id = 'evtx-old'"
                        )
                        return NormalizeResult(source_kind="evtx", rows=0)

                with patch(
                    "forensia.evidence.normalize.get_artifact_adapters",
                    return_value=(ReplacementAdapter(),),
                ):
                    normalize_all(case, db)

                self.assertEqual(
                    (True,),
                    db.execute(
                        "SELECT stale FROM report_sections "
                        "WHERE section_key = 'section-2'"
                    ).fetchone(),
                )
                # History is kept: facts and timeline rows are not deleted.
                self.assertEqual(
                    (1,), db.execute("SELECT COUNT(*) FROM section_facts").fetchone()
                )
                self.assertEqual(
                    (1,),
                    db.execute(
                        "SELECT COUNT(*) FROM case_timeline "
                        "WHERE evidence_id = 'evtx-old'"
                    ).fetchone(),
                )

    def test_content_change_under_same_source_invalidates_dependents(self) -> None:
        """R03: same evidence_id under the same source with changed content.

        The dependent survey fingerprints the referenced rows; an in-place
        content change moves dependents to review without deleting link
        history, exactly like the removal path.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._seed_dependents(db)

                class ContentChangeAdapter:
                    name = "evtx"

                    def normalize(self, case, db, source_keys=None):
                        del case, source_keys
                        db.execute(
                            "UPDATE evtx_events SET message = 'rewritten by re-ingest' "
                            "WHERE evidence_id = 'evtx-old'"
                        )
                        return NormalizeResult(source_kind="evtx", rows=1)

                with patch(
                    "forensia.evidence.normalize.get_artifact_adapters",
                    return_value=(ContentChangeAdapter(),),
                ):
                    normalize_all(case, db)

                hypothesis = db.execute(
                    "SELECT status, verdict, sufficiency_status, "
                    "human_review_required, sufficiency_reason "
                    "FROM hypotheses WHERE hypothesis_id = 'H-1'"
                ).fetchone()
                claim = db.execute(
                    "SELECT support_status FROM claims WHERE claim_id = 'C-1'"
                ).fetchone()
                links = db.execute(
                    "SELECT evidence_id FROM hypothesis_evidence WHERE link_id = 'L-1'"
                ).fetchone()

            self.assertEqual(("active", None, "needs_review", True), hypothesis[:4])
            self.assertIn("content changed under the same source", hypothesis[4])
            self.assertEqual(("needs_review",), claim)
            # Link history is kept, not re-pointed.
            self.assertEqual(("evtx-old",), links)

    def test_unchanged_content_keeps_dependents_current(self) -> None:
        """Re-running normalization without content change invalidates nothing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            with CaseDB(case) as db:
                self._seed_dependents(db)

                class UnchangedAdapter:
                    name = "evtx"

                    def normalize(self, case, db, source_keys=None):
                        del case, source_keys
                        db.execute(
                            "DELETE FROM evtx_events WHERE evidence_id = 'evtx-old'"
                        )
                        db.execute(
                            "INSERT INTO evtx_events (evidence_id, source_file) "
                            "VALUES ('evtx-old', 'source')"
                        )
                        return NormalizeResult(source_kind="evtx", rows=1)

                with patch(
                    "forensia.evidence.normalize.get_artifact_adapters",
                    return_value=(UnchangedAdapter(),),
                ):
                    normalize_all(case, db)

                hypothesis = db.execute(
                    "SELECT status, sufficiency_status FROM hypotheses "
                    "WHERE hypothesis_id = 'H-1'"
                ).fetchone()
                claim = db.execute(
                    "SELECT support_status FROM claims WHERE claim_id = 'C-1'"
                ).fetchone()

            self.assertEqual(("confirmed", "sufficient"), hypothesis)
            self.assertEqual(("supported",), claim)


if __name__ == "__main__":
    unittest.main()
