from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.ai.investigator import _apply_memory_updates
from forensia import cli as cli_module
from forensia.cli import _progress_pusher, _reset_case_tables
from forensia.config import clear_llm_settings_cache, get_llm_settings
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all


class MemoryAndIngestTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_llm_settings_cache()

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
                db.execute("DELETE FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'")

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
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "memory_updates": {
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

            confirmed_text = memory.confirmed_facts_path.read_text(encoding="utf-8")
            self.assertIn("[fact-001]", confirmed_text)
            self.assertNotIn("- fact one [evidence: ev-1]", confirmed_text)
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertIn("fact one", (memory.details_dir / "fact-001.md").read_text(encoding="utf-8"))
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

    def test_confirmed_fact_duplicates_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("same fact", ["ev-1"])
            memory.append_confirmed_fact("same fact", ["ev-1"])

            lines = [line for line in memory.confirmed_facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicates_with_dash_prefixed_body_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])
            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])

            lines = [line for line in memory.confirmed_facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicate_check_uses_hash_cache_before_detail_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.append_confirmed_fact("fact one", ["ev-1"])

            with patch.object(Path, "glob", side_effect=AssertionError("glob should not be called")):
                memory.append_confirmed_fact("fact one", ["ev-1"])

    def test_next_fact_detail_id_uses_details_dir_not_compacted_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.confirmed_facts_path.write_text("# Confirmed Facts\n\n- [fact-001] compacted\n", encoding="utf-8")
            (memory.details_dir / "fact-042.md").write_text("# fact-042\n\nbody\n", encoding="utf-8")

            self.assertEqual("fact-043", memory._next_fact_detail_id())

    def test_confirmed_facts_are_not_compacted_when_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "128"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            original = "# Confirmed Facts\n\n" + ("x" * 512) + "\n"
            memory.confirmed_facts_path.write_text(original, encoding="utf-8")

            changed = memory.compact_if_oversized(memory.confirmed_facts_path)

            self.assertFalse(changed)
            self.assertEqual(original, memory.confirmed_facts_path.read_text(encoding="utf-8"))

    def test_timeline_anchors_archive_old_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            for index in range(101):
                memory.append_timeline_anchor(
                    f"2026-05-12T10:{index:02d}:00",
                    f"anchor-{index}",
                    [f"ev-{index:03d}"],
                )

            timeline_text = memory.timeline_anchors_path.read_text(encoding="utf-8")
            timeline_lines = [line for line in timeline_text.splitlines() if line.startswith("- ")]
            archive_text = (memory.details_dir / "timeline_archive.md").read_text(encoding="utf-8")

            self.assertEqual(80, len(timeline_lines))
            self.assertIn("anchor-0", archive_text)
            self.assertNotIn("anchor-0", timeline_text)

    def test_narrative_is_compacted_via_llm_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.narrative_path.write_text("# Narrative\n\n" + ("x" * 512), encoding="utf-8")

            with patch("forensia.core.memory.chat_completion", return_value="compressed narrative") as mock_chat:
                changed = memory.compact_narrative_if_needed("http://localhost:1234", "test-model")

            self.assertTrue(changed)
            self.assertEqual("compressed narrative\n", memory.narrative_path.read_text(encoding="utf-8"))
            messages = mock_chat.call_args.kwargs["messages"]
            self.assertIn("Compress the following investigation narrative", messages[0]["content"])
            self.assertIn("Write the compressed narrative in ja.", messages[0]["content"])

    def test_narrative_compaction_prompt_stays_english_for_english_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(
            os.environ,
            {"LLM_MEMORY_MAX_BYTES": "64", "LLM_OUTPUT_LANGUAGE": "en"},
        ):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.narrative_path.write_text("# Narrative\n\n" + ("x" * 512), encoding="utf-8")

            with patch("forensia.core.memory.chat_completion", return_value="compressed narrative") as mock_chat:
                memory.compact_narrative_if_needed("http://localhost:1234", "test-model")

            messages = mock_chat.call_args.kwargs["messages"]
            self.assertIn("Write the compressed narrative in en.", messages[0]["content"])
            self.assertNotRegex(messages[0]["content"], r"[ぁ-んァ-ン一-龥]")

    def test_narrative_compaction_failure_keeps_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            original = "# Narrative\n\n" + ("x" * 512)
            memory.narrative_path.write_text(original, encoding="utf-8")

            with patch("forensia.core.memory.chat_completion", side_effect=RuntimeError("timeout")):
                changed = memory.compact_narrative_if_needed("http://localhost:1234", "test-model")

            self.assertFalse(changed)
            self.assertEqual(original, memory.narrative_path.read_text(encoding="utf-8"))

    def test_get_llm_settings_cache_can_be_cleared(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "ja"}):
            clear_llm_settings_cache()
            first = get_llm_settings()
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            second_before_clear = get_llm_settings()
            clear_llm_settings_cache()
            second_after_clear = get_llm_settings()

        self.assertEqual("ja", first["output_language"])
        self.assertEqual("ja", second_before_clear["output_language"])
        self.assertEqual("en", second_after_clear["output_language"])

    def test_schema_backfill_migration_runs_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                applied_count = db.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'"
                ).fetchone()[0]
            with CaseDB(case) as db:
                applied_count_reopen = db.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'"
                ).fetchone()[0]

            self.assertEqual(1, applied_count)
            self.assertEqual(1, applied_count_reopen)

    def test_schema_creates_indexes_for_lookup_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                names = {
                    row[0]
                    for row in db.execute(
                        """
                        SELECT index_name
                        FROM duckdb_indexes()
                        WHERE index_name IN (
                            'findings_by_id',
                            'findings_by_status_confidence',
                            'evtx_events_by_evidence_id',
                            'mft_entries_by_evidence_id',
                            'investigation_steps_by_session_hypothesis',
                            'ai_reviews_by_finding'
                        )
                        """
                    ).fetchall()
                }

            self.assertEqual(
                {
                    "findings_by_id",
                    "findings_by_status_confidence",
                    "evtx_events_by_evidence_id",
                    "mft_entries_by_evidence_id",
                    "investigation_steps_by_session_hypothesis",
                    "ai_reviews_by_finding",
                },
                names,
            )

    def test_progress_pusher_writes_progress_snapshot_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db, patch("forensia.cli.write_progress_snapshot") as mock_progress, patch(
                "forensia.cli.write_api_snapshots"
            ) as mock_full:
                push = _progress_pusher(
                    db,
                    {
                        "stage": "investigate",
                        "status": "running",
                        "iteration": 0,
                        "summary": "start",
                        "recent_logs": [],
                    },
                )
                push("tick", stage="investigate")

            mock_progress.assert_called_once()
            mock_full.assert_not_called()

    def test_reset_case_tables_clears_ingested_files_claims_and_hypothesis_reasoning(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO ingested_files (sha256, path, source_kind, size, ingested_at)
                    VALUES ('sha-1', '/tmp/a.evtx', 'evtx', 10, now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO claims (
                        claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
                        support_status, created_at, updated_at
                    ) VALUES ('C-1', '1_overview', 'claim', '[]', '[]', '[]', 'supported', now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H-1', 'S-1', 1, 'check', 'confirmed', 'Q-1', 'body', now())
                    """
                )

                _reset_case_tables(db)

                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM ingested_files").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM claims").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM hypothesis_reasoning").fetchone()[0])

    def test_run_renders_report_once_via_render_written_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "a.evtx").write_text("alpha", encoding="utf-8")
            output_dir = Path(tmpdir) / "case"

            with patch("forensia.cli.ingest_all", return_value={"new_files": 1, "skipped_files": 0, "evtx_files": 1, "mft_files": 0}), patch(
                "forensia.cli.normalize_all",
                return_value={"evtx_rows": 1, "mft_entries": 0, "mft_timeline_rows": 0},
            ), patch("forensia.cli.resolve_llm_config", return_value=(None, None)), patch("forensia.cli.load_rules_from_dir", return_value=[]), patch(
                "forensia.cli.render_written_report",
                return_value=(output_dir / "reports" / "report.md", output_dir / "reports" / "report.html"),
            ) as mock_render_written, patch("forensia.cli.render_html_report") as mock_render_html, patch(
                "forensia.cli.write_api_snapshots"
            ):
                cli_module.run(
                    input_dir=str(input_dir),
                    out=str(output_dir),
                    profile="windows-basic",
                    llm_base_url=None,
                    model=None,
                )

            mock_render_written.assert_called_once()
            mock_render_html.assert_not_called()

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
