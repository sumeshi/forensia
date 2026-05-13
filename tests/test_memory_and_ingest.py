from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.ai.investigator import _apply_memory_updates
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all


class MemoryAndIngestTests(unittest.TestCase):
    def test_legacy_newlead_verdicts_are_migrated_on_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES ('H-1', 'legacy verdict', 'active', 'newlead', '', 'broad_plan', 'S-1', NULL, now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO ai_reviews (
                        review_id, finding_id, verdict, report_text, missing_checks,
                        confidence_adjustment, notes, raw_response, created_at
                    ) VALUES ('R-1', 'F-1', 'newlead', '', '[]', 0.0, '', '{}', now())
                    """
                )

            legacy_verdict = "new" + "_finding"
            with CaseDB(case) as db:
                db.execute("UPDATE hypotheses SET verdict = ?", (legacy_verdict,))
                db.execute("UPDATE ai_reviews SET verdict = ?", (legacy_verdict,))

            with CaseDB(case) as db:
                hypothesis_verdict = db.execute(
                    "SELECT verdict FROM hypotheses WHERE hypothesis_id = 'H-1'"
                ).fetchone()[0]
                review_verdict = db.execute(
                    "SELECT verdict FROM ai_reviews WHERE review_id = 'R-1'"
                ).fetchone()[0]

            self.assertEqual("newlead", hypothesis_verdict)
            self.assertEqual("newlead", review_verdict)

    def test_structured_memory_updates_and_compaction_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "256"}):
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "memory_updates": {
                        "overview_append": "overview note",
                        "confirmed_facts": [{"text": "fact one", "evidence_ids": ["ev-1"]}],
                        "timeline_anchors": [{"timestamp": "2026-05-12T10:00:00", "description": "anchor", "evidence_ids": ["ev-2"]}],
                        "open_questions": [{"question": "need more logs", "kind": "internal_db_check"}],
                        "narrative": ["initial storyline"],
                        "refuted_hypotheses": [{"hypothesis_id": "H-old", "description": "old theory", "reason": "timestamps do not line up"}],
                        "important_entities": [{"entity_type": "src_ip", "name": "10.0.0.5", "notes": "reused across failed logons"}],
                    }
                },
                db=None,
            )

            self.assertIn("fact one", memory.confirmed_facts_path.read_text(encoding="utf-8"))
            self.assertIn("anchor", memory.timeline_anchors_path.read_text(encoding="utf-8"))
            self.assertIn("need more logs", memory.open_questions_path.read_text(encoding="utf-8"))
            self.assertIn("initial storyline", memory.narrative_path.read_text(encoding="utf-8"))
            self.assertIn("old theory", memory.refuted_hypotheses_path.read_text(encoding="utf-8"))
            self.assertIn("10.0.0.5", memory.important_entities_path.read_text(encoding="utf-8"))

            memory.update_overview("# Overview\n\n" + ("x" * 4096))
            confirmed_before = memory.confirmed_facts_path.read_text(encoding="utf-8")
            timeline_before = memory.timeline_anchors_path.read_text(encoding="utf-8")
            refuted_before = memory.refuted_hypotheses_path.read_text(encoding="utf-8")
            entities_before = memory.important_entities_path.read_text(encoding="utf-8")
            for index in range(20):
                memory.append_open_question(f"question-{index}", "internal_db_check")

            overview_text = memory.overview_path.read_text(encoding="utf-8")
            open_questions_text = memory.open_questions_path.read_text(encoding="utf-8")

            self.assertIn("# Compacted Memory", overview_text)
            self.assertEqual(confirmed_before, memory.confirmed_facts_path.read_text(encoding="utf-8"))
            self.assertEqual(timeline_before, memory.timeline_anchors_path.read_text(encoding="utf-8"))
            self.assertEqual(refuted_before, memory.refuted_hypotheses_path.read_text(encoding="utf-8"))
            self.assertEqual(entities_before, memory.important_entities_path.read_text(encoding="utf-8"))
            self.assertNotIn("question-0", open_questions_text)
            self.assertIn("question-19", open_questions_text)

    def test_hypothesis_memory_contains_reasoning_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H-1', 'S-1', 1, 'check', 'confirmed', 'Q-1', 'Reasoning body', now())
                    """
                )
                _apply_memory_updates(
                    memory=memory,
                    active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="sum")],
                    resolved_hypotheses=[],
                    check_output={"memory_updates": {}},
                    db=db,
                )

            hyp_path = next(memory.hypotheses_dir.glob("h-1-*.md"))
            text = hyp_path.read_text(encoding="utf-8")
            self.assertIn("## Reasoning", text)
            self.assertIn("Reasoning body", text)

    def test_ingest_all_is_incremental_and_force_reingests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            for name, content in (
                ("a.evtx", "alpha"),
                ("b.evtx", "bravo"),
                ("MFT", "charlie"),
            ):
                (input_dir / name).write_text(content, encoding="utf-8")

            def fake_ingest(case_obj: Case, source_path: str | Path, source_sha: str | None = None, progress_callback=None):
                suffix = Path(source_path).suffix.lower()
                output = case_obj.raw_dir / f"{(source_sha or 'x')[:12]}{suffix or '.jsonl'}"
                output.write_text("{}", encoding="utf-8")
                return output

            with patch("forensia.ingest.evtx.ingest_evtx_file", side_effect=fake_ingest), patch(
                "forensia.ingest.mft.ingest_mft_file",
                side_effect=fake_ingest,
            ):
                first = ingest_all(case, input_dir)
                second = ingest_all(case, input_dir)
                (input_dir / "c.evtx").write_text("delta", encoding="utf-8")
                third = ingest_all(case, input_dir)
                forced = ingest_all(case, input_dir, force=True)

            with CaseDB(case) as db:
                ingested_count = db.execute("SELECT COUNT(*) FROM ingested_files").fetchone()[0]

            self.assertEqual(3, first["new_files"])
            self.assertEqual(0, first["skipped_files"])
            self.assertEqual(0, second["new_files"])
            self.assertEqual(3, second["skipped_files"])
            self.assertEqual(1, third["new_files"])
            self.assertEqual(4, forced["new_files"])
            self.assertEqual(4, ingested_count)


if __name__ == "__main__":
    unittest.main()
