from __future__ import annotations

import asyncio
import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from forensia.ai.checker import CheckResult, summarize_query_result
from forensia.ai.investigator import _apply_memory_updates, _sync_keypoint_cards
from forensia.artifacts import MftArtifactAdapter, PrefetchArtifactAdapter
from forensia import cli as cli_module
from forensia.cli import _progress_pusher, _reset_case_tables
from forensia.config import clear_llm_settings_cache, get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all
from forensia.normalize.evtx import normalize_evtx
from forensia.normalize.mft import normalize_mft
from forensia.normalize import normalize_all


class MemoryAndIngestTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_llm_settings_cache()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def test_summarize_query_result_includes_head_tail_and_distinct_counts(self) -> None:
        rows = [
            {
                "evidence_id": f"ev-{index}",
                "target_user": "alice" if index < 6 else "bob",
                "computer": "host1" if index % 2 == 0 else "host2",
                "src_ip": f"10.0.0.{(index % 3) + 1}",
                "event_id": 4624 if index < 6 else 4634,
                "timestamp": f"2026-05-16 00:{index:02d}:00",
            }
            for index in range(12)
        ]

        summary = summarize_query_result(rows)

        self.assertEqual(12, summary["row_count"])
        self.assertEqual(rows[:5], summary["head_rows"])
        self.assertEqual(rows[-5:], summary["tail_rows"])
        self.assertEqual(rows[:5] + rows[-5:], summary["sample_rows"])
        self.assertEqual(2, summary["distinct_counts"]["target_user"])
        self.assertEqual(2, summary["distinct_counts"]["computer"])
        self.assertEqual(3, summary["distinct_counts"]["src_ip"])
        self.assertEqual(2, summary["distinct_counts"]["event_id"])

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
                        "facts": [{"text": "fact one", "evidence_ids": ["ev-1"]}],
                        "timeline": [{"timestamp": "2026-05-12T10:00:00", "description": "anchor", "evidence_ids": ["ev-2"]}],
                        "tasks": [{"text": "need more logs", "kind": "internal_db_check"}],
                        "overview": ["initial storyline"],
                        "refuted_hypotheses": [{"hypothesis_id": "H-old", "description": "old theory", "reason": "timestamps do not line up"}],
                        "entities": [{"entity_type": "src_ip", "name": "10.0.0.5", "role": "source_ip", "notes": "reused across failed logons"}],
                    }
                },
                db=None,
            )

            confirmed_text = memory.facts_path.read_text(encoding="utf-8")
            self.assertIn("[fact-001]", confirmed_text)
            self.assertNotIn("- fact one [evidence: ev-1]", confirmed_text)
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertIn("fact one", (memory.details_dir / "fact-001.md").read_text(encoding="utf-8"))
            self.assertIn("anchor", memory.timeline_path.read_text(encoding="utf-8"))
            self.assertIn("need more logs", memory.tasks_memory_path.read_text(encoding="utf-8"))
            self.assertIn("initial storyline", memory.overview_path.read_text(encoding="utf-8"))
            self.assertIn("old theory", memory.refuted_hypotheses_path.read_text(encoding="utf-8"))
            self.assertTrue((memory.entities_ip_dir / "10.0.0.5.md").exists())
            self.assertIn("10.0.0.5", (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"))
            self.assertIn("role: source_ip", (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"))

            memory.update_overview("# Overview\n\n" + ("x" * 4096))
            confirmed_before = memory.facts_path.read_text(encoding="utf-8")
            timeline_before = memory.timeline_path.read_text(encoding="utf-8")
            refuted_before = memory.refuted_hypotheses_path.read_text(encoding="utf-8")
            entities_before = (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8")
            for index in range(20):
                memory.append_task(f"question-{index}", "internal_db_check")

            tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")

            self.assertTrue(memory.overview_path.stat().st_size > memory.max_bytes)
            self.assertEqual(confirmed_before, memory.facts_path.read_text(encoding="utf-8"))
            self.assertEqual(timeline_before, memory.timeline_path.read_text(encoding="utf-8"))
            self.assertEqual(refuted_before, memory.refuted_hypotheses_path.read_text(encoding="utf-8"))
            self.assertEqual(entities_before, (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"))
            self.assertNotIn("question-0", tasks_text)
            self.assertIn("question-19", tasks_text)

    def test_confirmed_fact_duplicates_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("same fact", ["ev-1"])
            memory.append_confirmed_fact("same fact", ["ev-1"])

            lines = [line for line in memory.facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicates_with_dash_prefixed_body_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])
            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])

            lines = [line for line in memory.facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicates_with_reordered_evidence_ids_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("same fact", ["ev-2", "ev-1"])
            memory.append_confirmed_fact("same fact", ["ev-1", "ev-2"])

            lines = [line for line in memory.facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))
            detail = (memory.details_dir / "fact-001.md").read_text(encoding="utf-8")
            self.assertIn("- ev-1", detail)
            self.assertIn("- ev-2", detail)

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
            memory.facts_path.write_text("# Facts\n\n- [fact-001] compacted\n", encoding="utf-8")
            (memory.details_dir / "fact-042.md").write_text("# fact-042\n\nbody\n", encoding="utf-8")
            memory = MemoryManager(case)

            self.assertEqual(43, memory._next_fact_id)

    def test_alloc_fact_detail_id_does_not_glob_each_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            with patch.object(Path, "glob", side_effect=AssertionError("glob should not be called")):
                self.assertEqual("fact-001", memory._alloc_fact_detail_id())
                self.assertEqual("fact-002", memory._alloc_fact_detail_id())

    def test_memory_init_scans_fact_details_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.memory_dir / "details").mkdir(parents=True, exist_ok=True)
            (case.memory_dir / "details" / "fact-042.md").write_text("# fact-042\n\nbody\n", encoding="utf-8")
            original_glob = Path.glob
            fact_glob_calls = 0

            def counting_glob(path: Path, pattern: str):
                nonlocal fact_glob_calls
                if path == case.memory_dir / "details" and pattern == "fact-*.md":
                    fact_glob_calls += 1
                return original_glob(path, pattern)

            with patch.object(Path, "glob", autospec=True, side_effect=counting_glob):
                memory = MemoryManager(case)

            self.assertEqual(1, fact_glob_calls)
            self.assertEqual(43, memory._next_fact_id)

    def test_parse_fact_detail_restores_multiline_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            detail_lines = [
                "# fact-001",
                "",
                "first line",
                "second line",
                "",
                "## Evidence",
                "- ev-1",
            ]

            parsed = memory._parse_fact_detail(detail_lines)

            self.assertEqual(("first line\nsecond line", ["ev-1"]), parsed)

    def test_multiline_fact_hashes_restore_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.append_confirmed_fact("first line\nsecond line", ["ev-2", "ev-1"])

            reopened = MemoryManager(case)
            reopened.append_confirmed_fact("first line\nsecond line", ["ev-1", "ev-2"])

            lines = [line for line in reopened.facts_path.read_text(encoding="utf-8").splitlines() if line.startswith("- ")]
            self.assertEqual(1, len(lines))

    def test_facts_are_not_compacted_when_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "128"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            original = "# Facts\n\n" + ("x" * 512) + "\n"
            memory.facts_path.write_text(original, encoding="utf-8")

            changed = memory.compact_if_oversized(memory.facts_path)

            self.assertFalse(changed)
            self.assertEqual(original, memory.facts_path.read_text(encoding="utf-8"))

    def test_timeline_archive_old_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            for index in range(101):
                memory.append_timeline_anchor(
                    f"2026-05-12T10:{index:02d}:00",
                    f"anchor-{index}",
                    [f"ev-{index:03d}"],
                )

            timeline_text = memory.timeline_path.read_text(encoding="utf-8")
            timeline_lines = [line for line in timeline_text.splitlines() if line.startswith("- ")]
            archive_text = (memory.archive_dir / "timeline_archive.md").read_text(encoding="utf-8")

            self.assertEqual(80, len(timeline_lines))
            self.assertIn("anchor-0", archive_text)
            self.assertNotIn("anchor-0", timeline_text)

    def test_llm_compaction_targets_include_hypotheses_and_entities_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.upsert_hypothesis("H-1", "desc", "# Hypothesis H-1\n")
            memory.upsert_entity("user", "alice", "# Entity alice\n")
            memory.upsert_entity("host", "srv-1", "# Entity srv-1\n")
            memory.upsert_entity("ip", "10.0.0.5", "# Entity 10.0.0.5\n")

            targets = memory._llm_compaction_targets()

            self.assertEqual(
                [
                    memory.hypotheses_dir / "H-1.md",
                    memory.entities_user_dir / "alice.md",
                    memory.entities_host_dir / "srv-1.md",
                    memory.entities_ip_dir / "10.0.0.5.md",
                ],
                targets,
            )
            self.assertNotIn(memory.suspicious_path, targets)

    def test_suspicious_table_is_compacted_without_breaking_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "256"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            header = "# Suspicious Evidence\n\n| evidence_id | reason | confidence |\n|---|---|---|\n"
            rows = "\n".join(f"| ev-{index:03d} | reason-{index} | 0.5 |" for index in range(100))
            memory.suspicious_path.write_text(header + rows + "\n", encoding="utf-8")

            changed = memory.compact_if_oversized(memory.suspicious_path)

            self.assertTrue(changed)
            content = memory.suspicious_path.read_text(encoding="utf-8")
            self.assertIn("| evidence_id | reason | confidence |", content)
            self.assertIn("|---|---|---|", content)
            self.assertLessEqual(memory.suspicious_path.stat().st_size, memory.max_bytes)

    def test_overview_is_compacted_via_llm_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.overview_path.write_text("# Overview\n\n" + ("x" * 512), encoding="utf-8")

            with patch("forensia.core.memory._llm_call", return_value="compressed overview") as mock_chat:
                changed = memory.compact_overview_if_needed(self._llm_base_url(), "test-model")

            self.assertTrue(changed)
            self.assertEqual("compressed overview\n", memory.overview_path.read_text(encoding="utf-8"))
            messages = mock_chat.call_args.kwargs["messages"]
            self.assertIn("Compress the following investigation overview", messages[0]["content"])
            self.assertIn("Write the compressed overview in ja.", messages[0]["content"])

    def test_overview_default_template_uses_new_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            overview = memory.load_overview()

            self.assertIn("## Case Scope", overview)
            self.assertIn("## Key Findings", overview)
            self.assertIn("## Investigation Policy", overview)
            self.assertNotIn("## Confirmed Hosts", overview)
            self.assertNotIn("## Confirmed Timeline", overview)
            self.assertNotIn("## Active Hypotheses", overview)

    def test_overview_compaction_prompt_stays_english_for_english_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(
            os.environ,
            {"LLM_MEMORY_MAX_BYTES": "64", "LLM_OUTPUT_LANGUAGE": "en"},
        ):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.overview_path.write_text("# Overview\n\n" + ("x" * 512), encoding="utf-8")

            with patch("forensia.core.memory._llm_call", return_value="compressed overview") as mock_chat:
                memory.compact_overview_if_needed(self._llm_base_url(), "test-model")

            messages = mock_chat.call_args.kwargs["messages"]
            self.assertIn("Write the compressed overview in en.", messages[0]["content"])
            self.assertNotRegex(messages[0]["content"], r"[ぁ-んァ-ン一-龥]")

    def test_overview_compaction_failure_keeps_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            original = "# Overview\n\n" + ("x" * 512)
            memory.overview_path.write_text(original, encoding="utf-8")

            with patch("forensia.core.memory._llm_call", side_effect=RuntimeError("timeout")):
                changed = memory.compact_overview_if_needed(self._llm_base_url(), "test-model")

            self.assertFalse(changed)
            self.assertEqual(original, memory.overview_path.read_text(encoding="utf-8"))

    def test_stale_keypoint_cards_are_deleted_when_snapshot_shrinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            large_snapshot = [
                {
                    "finding_id": f"F-{index}",
                    "title": f"title-{index}",
                    "severity": "medium",
                    "confidence": 0.5,
                    "summary": f"summary-{index}",
                    "evidence": [{"evidence_id": f"ev-{index}"}],
                }
                for index in range(1, 4)
            ]
            small_snapshot = large_snapshot[:1]

            _sync_keypoint_cards(memory, large_snapshot)
            self.assertTrue((memory.keypoints_dir / "KP-0003.md").exists())

            _sync_keypoint_cards(memory, small_snapshot)

            self.assertTrue((memory.keypoints_dir / "KP-0001.md").exists())
            self.assertFalse((memory.keypoints_dir / "KP-0002.md").exists())
            self.assertFalse((memory.keypoints_dir / "KP-0003.md").exists())

    def test_hypothesis_memory_is_llm_compacted_when_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "96"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Overview\n\n" + ("x" * 512))
            memory.upsert_hypothesis("H-1", "oversized", "# Hypothesis H-1\n\n" + ("y" * 512))

            with patch("forensia.core.memory._llm_call", return_value="# Hypothesis H-1\n\n- compacted") as mock_chat:
                changed = memory.compact_oversized_with_llm(self._llm_base_url(), "test-model")

            self.assertEqual([str(memory.hypotheses_dir / "H-1.md")], changed)
            self.assertEqual("# Overview\n\n" + ("x" * 512), memory.overview_path.read_text(encoding="utf-8"))
            self.assertEqual("# Hypothesis H-1\n\n- compacted\n", (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8"))
            mock_chat.assert_called_once()

    def test_entity_memory_is_llm_compacted_when_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "96"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.upsert_entity("ip", "10.0.0.5", "# ip: 10.0.0.5\n\n" + ("z" * 512))

            with patch("forensia.core.memory._llm_call", return_value="- compacted entity") as mock_chat:
                changed = memory.compact_oversized_with_llm(self._llm_base_url(), "test-model")

            self.assertEqual([str(memory.entities_ip_dir / "10.0.0.5.md")], changed)
            self.assertEqual(
                "# ip: 10.0.0.5\n\n- compacted entity\n",
                (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"),
            )
            mock_chat.assert_called_once()

    def test_hypothesis_memory_path_depends_only_on_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.upsert_hypothesis("H-1", "first-description", "# Hypothesis H-1\n\nfirst\n")
            memory.upsert_hypothesis("H-1", "second-description", "# Hypothesis H-1\n\nsecond\n")

            hyp_path = memory.hypotheses_dir / "H-1.md"
            self.assertTrue(hyp_path.exists())
            self.assertEqual("# Hypothesis H-1\n\nsecond\n", hyp_path.read_text(encoding="utf-8"))
            self.assertEqual([hyp_path], sorted(memory.hypotheses_dir.glob("*.md")))

    def test_hypothesis_upsert_removes_legacy_slug_named_file_for_same_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            legacy_path = memory.hypotheses_dir / "h-1-old-description.md"
            legacy_path.write_text("# Hypothesis H-1\n\nlegacy\n", encoding="utf-8")

            memory.upsert_hypothesis("H-1", "new-description", "# Hypothesis H-1\n\ncurrent\n")

            self.assertFalse(legacy_path.exists())
            self.assertEqual(
                "# Hypothesis H-1\n\ncurrent\n",
                (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8"),
            )

    def test_oversized_memory_llm_compaction_failure_keeps_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            original = "# Overview\n\n" + ("x" * 512)
            memory.update_overview(original)

            with patch("forensia.core.memory._llm_call", side_effect=RuntimeError("timeout")):
                changed = memory.compact_oversized_with_llm(self._llm_base_url(), "test-model")

            self.assertEqual([], changed)
            self.assertEqual(original, memory.overview_path.read_text(encoding="utf-8"))

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

    def test_reset_case_tables_clears_derived_report_and_ingest_tables(self) -> None:
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
                    INSERT INTO prefetch_timeline (
                        timeline_id, evidence_id, executable_name, prefetch_hash, exec_time, exec_index, source_file, tags
                    ) VALUES ('PT-1', 'prefetch-tool-abc123', 'tool.exe', 'abc123', now(), 0, 'TOOL.EXE.pf', '[]')
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_facts (
                        fact_id, fact_type, fact_key, fact_value, evidence_ids, source_query,
                        source_section, confidence, created_at, updated_at
                    ) VALUES ('SF-1', 'universal_question', 'host_identity', '{}', '[]', 'structured:host_identity', '1_overview', 0.9, now(), now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_evidence (
                        section_key, block_heading, evidence_id, role, source_query, created_at
                    ) VALUES ('1_overview', 'Scope', 'evtx-security-000000000001', 'supporting', 'overview_hosts', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO query_cache (sql_hash, sql_text, result_json, executed_at)
                    VALUES ('hash-1', 'SELECT 1', '[{"x":1}]', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_runs (run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at)
                    VALUES ('SR-1', '1_overview', 'Scope', 1, 'query', '{}', 'sufficient', now())
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_questions (
                        question_id, section_key, block_heading, question_text, question_type,
                        answer_spec, intent, confidence, matched_rule, required_evidence,
                        status, created_at, updated_at
                    ) VALUES ('SQ-1', '1_overview', 'Scope', 'question', 'host_identity',
                              'host_identity', 'List hosts', 1.0, 'host_identity', '{}', 'resolved', now(), now())
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
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM prefetch_timeline").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM section_facts").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM section_evidence").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM query_cache").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM section_runs").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM section_questions").fetchone()[0])
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM hypothesis_reasoning").fetchone()[0])

    def test_run_renders_report_once_via_render_written_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "a.evtx").write_text("alpha", encoding="utf-8")
            output_dir = Path(tmpdir) / "case"

            with patch(
                "forensia.cli.ingest_all",
                return_value={
                    "new_files": 1,
                    "skipped_files": 0,
                    "evtx_files": 1,
                    "mft_files": 0,
                    "prefetch_files": 0,
                },
            ), patch(
                "forensia.cli.normalize_all",
                return_value={
                    "evtx_rows": 1,
                    "mft_entries": 0,
                    "mft_timeline_rows": 0,
                    "prefetch_executions": 0,
                },
            ), patch("forensia.cli.resolve_llm_config", return_value=(None, None)), patch("forensia.cli.load_rules_from_dir", return_value=[]), patch(
                "forensia.cli.render_written_report",
                return_value=(output_dir / "reports" / "report.md", output_dir / "reports" / "report.html"),
            ) as mock_render_written, patch("forensia.cli.render_html_report") as mock_render_html, patch(
                "forensia.cli.write_api_snapshots"
            ):
                cli_module.investigate(
                    case_dir=str(output_dir),
                    input_dir=str(input_dir),
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

            hyp_path = memory.hypotheses_dir / "H-1.md"
            text = hyp_path.read_text(encoding="utf-8")
            self.assertIn("## Reasoning", text)
            self.assertIn("Reasoning body", text)

    def test_resolved_hypothesis_memory_skips_reasoning_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db, patch("forensia.ai.hypothesis_manager._recent_reasoning_rows") as mock_reasoning:
                mock_reasoning.return_value = [{"phase": "check", "verdict": "confirmed", "query_id": "Q-1", "body": "body"}]
                _apply_memory_updates(
                    memory=memory,
                    active_hypotheses=[Hypothesis(id="H-1", description="active desc", status="active", summary="sum")],
                    resolved_hypotheses=[Hypothesis(id="H-2", description="resolved desc", status="confirmed", summary="done")],
                    check_output={"memory_updates": {}},
                    db=db,
                )

            mock_reasoning.assert_called_once_with(db, "H-1")
            active_text = (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8")
            resolved_text = (memory.hypotheses_dir / "H-2.md").read_text(encoding="utf-8")
            self.assertIn("## Reasoning", active_text)
            self.assertNotIn("## Reasoning", resolved_text)

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
                return output, None

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

    def test_ingest_all_counts_prefetch_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "APP.EXE-12345678.pf").write_text("prefetch", encoding="utf-8")

            def fake_ingest(case_obj: Case, source_path: str | Path, source_sha: str | None = None, progress_callback=None):
                output = case_obj.raw_dir / f"prefetch-entries-{(source_sha or 'x')[:12]}.jsonl"
                output.write_text("{}", encoding="utf-8")
                return output, None

            with patch("forensia.ingest.prefetch.ingest_prefetch_file", side_effect=fake_ingest):
                counts = ingest_all(case, input_dir)

            self.assertEqual(1, counts["new_files"])
            self.assertEqual(1, counts["prefetch_files"])
            self.assertEqual(0, counts["evtx_files"])
            self.assertEqual(0, counts["mft_files"])

    def test_prefetch_adapter_only_claims_pf_files(self) -> None:
        adapter = PrefetchArtifactAdapter()
        prefetch_dir = Path("/tmp/Prefetch")

        self.assertTrue(adapter.can_handle(prefetch_dir / "APP.EXE-12345678.pf"))
        self.assertFalse(adapter.can_handle(prefetch_dir))

    def test_mft_adapter_accepts_names_containing_mft(self) -> None:
        adapter = MftArtifactAdapter()

        self.assertTrue(adapter.can_handle(Path("/tmp/$MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT")))
        self.assertTrue(adapter.can_handle(Path("/tmp/MFT_C")))
        self.assertTrue(adapter.can_handle(Path("/tmp/exported_mft.bin")))

    def test_normalize_all_includes_prefetch_execution_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db, patch("forensia.normalize.evtx.normalize_evtx", return_value=0), patch(
                "forensia.normalize.mft.normalize_mft",
                return_value=(0, 0),
            ), patch("forensia.normalize.prefetch.normalize_prefetch", return_value=(3, 0)):
                counts = normalize_all(case, db)

            self.assertEqual(3, counts["prefetch_executions"])
            self.assertEqual(0, counts["prefetch_timeline"])
            self.assertEqual(0, counts["evtx_rows"])
            self.assertEqual(0, counts["mft_entries"])

    def test_normalize_evtx_ignores_prefetch_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / "prefetch-test.jsonl").write_text(
                json.dumps(
                    {
                        "source_type": "prefetch",
                        "source_file": "sample/Prefetch/APP.EXE-12345678.pf",
                        "name": "APP.EXE",
                        "evidence_id": "prefetch-app-1234",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            with CaseDB(case) as db:
                inserted = normalize_evtx(case, db)
                row_count = db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]

            self.assertEqual(0, inserted)
            self.assertEqual(0, row_count)

    def test_normalize_mft_uses_sql_projection_for_entries_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            record = {
                "header": {
                    "flags": "EntryFlags(ALLOCATED)",
                    "record_number": 42,
                    "is_directory": False,
                },
                "attributes": {
                    "StandardInformation": {
                        "data": {
                            "created": "2015-03-25T11:08:36.956950Z",
                            "modified": "2015-03-25T11:08:36.956950Z",
                            "mft_modified": "2015-03-25T11:08:36.956950Z",
                            "accessed": "2015-03-25T11:08:36.956950Z",
                        }
                    },
                    "FileName": {
                        "data": {
                            "created": "2015-03-25T11:08:36.956950Z",
                            "modified": "2015-03-25T11:08:36.956950Z",
                            "mft_modified": "2015-03-25T11:08:36.956950Z",
                            "accessed": "2015-03-25T11:08:36.956950Z",
                            "name": "example.txt",
                            "path": "C:\\Users\\informant\\Desktop\\example.txt",
                        }
                    },
                },
                "source_type": "mft",
                "source_file": "sample/cfreds/MFT_C",
                "evidence_id": "mft-000000000042-00",
            }
            (case.raw_dir / "mft-entries-test.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")

            with CaseDB(case) as db:
                entries, timeline = normalize_mft(case, db)
                entry = db.execute(
                    "SELECT record_number, file_name, extension, is_directory, is_deleted FROM mft_entries"
                ).fetchone()

            self.assertEqual(1, entries)
            self.assertEqual(0, timeline)
            self.assertEqual((42, "example.txt", "txt", False, False), entry)

    def test_cli_add_and_run_surface_prefetch_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(Path(tmpdir) / "case-add")
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir(parents=True, exist_ok=True)
            runner = CliRunner()

            with patch(
                "forensia.cli.ingest_all",
                return_value={
                    "new_files": 1,
                    "skipped_files": 0,
                    "evtx_files": 0,
                    "mft_files": 0,
                    "prefetch_files": 1,
                },
            ):
                add_result = runner.invoke(cli_module.app, ["add", str(case.path), str(input_dir)])

            self.assertEqual(0, add_result.exit_code, add_result.output)
            self.assertIn("prefetch=1", add_result.output)

            output_dir = Path(tmpdir) / "case-run"
            with patch(
                "forensia.cli.ingest_all",
                return_value={
                    "new_files": 1,
                    "skipped_files": 0,
                    "evtx_files": 0,
                    "mft_files": 0,
                    "prefetch_files": 1,
                },
            ), patch(
                "forensia.cli.normalize_all",
                return_value={
                    "evtx_rows": 0,
                    "mft_entries": 0,
                    "mft_timeline_rows": 0,
                    "prefetch_executions": 2,
                },
            ), patch("forensia.cli.resolve_llm_config", return_value=(None, None)), patch(
                "forensia.cli.load_rules_from_dir",
                return_value=[],
            ), patch(
                "forensia.cli.render_written_report",
                return_value=(output_dir / "reports" / "report.md", output_dir / "reports" / "report.html"),
            ), patch("forensia.cli.write_api_snapshots"):
                run_result = runner.invoke(cli_module.app, ["investigate", str(output_dir), str(input_dir)])

            self.assertEqual(0, run_result.exit_code, run_result.output)
            self.assertIn("prefetch_files=1", run_result.output)
            self.assertIn("prefetch_executions=2", run_result.output)


    # ─── R2-10 tests ───────────────────────────────────────────────────────────

    def test_r2_10_overview_writes_only_on_state_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Investigation Overview\n\n## Key Findings\n- none\n")
            overview_before = memory.load_overview()

            # 5 inconclusive checks → overview unchanged
            for i in range(5):
                _apply_memory_updates(
                    memory=memory,
                    active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                    resolved_hypotheses=[],
                    check_output={
                        "verdict": "inconclusive",
                        "memory_updates": {
                            "overview": [f"inconclusive check {i}"],
                            "facts": [{"text": f"fact {i}", "evidence_ids": ["ev-1"]}],
                        },
                    },
                    db=None,
                )
            self.assertEqual(overview_before, memory.load_overview(),
                             "overview should not grow after 5 inconclusive checks")

            # 1 confirmed → overview grows
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "confirmed",
                    "memory_updates": {
                        "overview": ["confirmed finding"],
                        "facts": [{"text": "confirmed fact", "evidence_ids": ["ev-2"]}],
                    },
                },
                db=None,
            )
            self.assertIn("confirmed finding", memory.load_overview(),
                          "overview should grow after confirmed verdict")

    def test_r2_10_new_nonobserved_entity_triggers_overview(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Investigation Overview\n\n## Key Findings\n- none\n")

            # Inconclusive but with a new entity (role ≠ observed_user)
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "inconclusive",
                    "memory_updates": {
                        "overview": ["new entity discovered"],
                        "entities": [{"entity_type": "src_ip", "name": "10.0.0.99", "role": "source_ip", "notes": "new"}],
                    },
                },
                db=None,
            )
            self.assertIn("new entity discovered", memory.load_overview(),
                          "new entity with role ≠ observed_user triggers overview")

    def test_r2_10_first_artifact_family_triggers_overview(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Investigation Overview\n\n## Key Findings\n- none\n")

            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "inconclusive",
                    "memory_updates": {
                        "overview": ["mft evidence found"],
                        "facts": [{"text": "mft activity", "evidence_ids": ["mft-000001"]}],
                    },
                },
                db=None,
            )
            self.assertIn("mft evidence found", memory.load_overview(),
                          "first artifact family triggers overview")

    def test_r2_10_fact_truncation_at_word_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            long_words = ["word"] * 50  # 250 chars, well over 160
            long_body = " ".join(long_words)
            memory.append_confirmed_fact(long_body, ["ev-1"])
            detail_id = "fact-001"
            self.assertTrue((memory.details_dir / f"{detail_id}.md").exists())
            detail_content = (memory.details_dir / f"{detail_id}.md").read_text(encoding="utf-8")
            self.assertIn(long_body, detail_content,
                          "detail file has full body")

            facts_text = memory.facts_path.read_text(encoding="utf-8")
            line_with_preview = [l for l in facts_text.splitlines() if l.startswith("- [fact-001]")][0]
            self.assertIn("[fact-001]", line_with_preview,
                          "fact line references detail link")
            # Extract preview text between [fact-001] and metadata brackets
            after_link = line_with_preview.split("[fact-001] ", 1)[-1]
            if " [" in after_link:
                preview = after_link.split(" [")[0]
            else:
                preview = after_link
            if "…" in preview:
                self.assertLessEqual(len(preview.replace("…", "")), 160,
                                     "truncated text ≤ 160 chars")
                self.assertFalse(preview.endswith(" "),
                                 "no trailing space")
                self.assertFalse(preview.endswith("… "),
                                 "no space before …")
            else:
                self.assertLessEqual(len(preview), 160,
                                     "untruncated preview ≤ 160 chars")

    def test_r2_10_fact_truncation_never_mid_word(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Body where char 160 falls mid-word
            body = "a " + "supercalifragilisticexpialidocious " * 5 + "zzz trailing"
            memory.append_confirmed_fact(body, ["ev-1"])
            facts_text = memory.facts_path.read_text(encoding="utf-8")
            line_with_preview = [l for l in facts_text.splitlines() if l.startswith("- [fact-001]")][0]
            after_link = line_with_preview.split("[fact-001] ", 1)[-1]
            if " [" in after_link:
                preview = after_link.split(" [")[0]
            else:
                preview = after_link

            if "…" in preview:
                chars_before = preview.split("…")[0]
                # Check that truncation is at a word boundary: the character in
                # the original 160-char prefix at position len(chars_before) must
                # be a space (or boundary). We use rfind(" ") so it's always a space.
                original_prefix = body[:160]
                if chars_before:
                    self.assertEqual(
                        original_prefix[len(chars_before)], " ",
                        "truncation should occur at a space word boundary",
                    )

    def test_r2_10_task_jaccard_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Add first task
            memory.append_task("Investigate the context of logon events on host", "human_decision")
            # Near-paraphrase (≥0.6 Jaccard) → should be deduped
            memory.append_task("Investigate the context of logon events on host machine", "human_decision")
            # Different task → should be added
            memory.append_task("Check network connections from suspicious IP", "human_decision")
            # Identical to the third → deduped (exact match via existing logic)
            memory.append_task("Check network connections from suspicious IP", "human_decision")

            tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
            task_lines = [l for l in tasks_text.splitlines() if l.startswith("- [human_decision]")]
            self.assertEqual(2, len(task_lines),
                             "only 2 unique tasks after dedup (2 paraphrased → 1, + 1 unique)")

    def test_r2_10_task_human_decision_cap_at_10(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Add 11 distinct human_decision tasks (different enough for Jaccard < 0.6)
            distinct_tasks = [
                "review dns logs for external beaconing",
                "check scheduled tasks for persistence",
                "examine prefetch for unknown executables",
                "correlate 4625 logon failures by source ip",
                "extract process parents from 4688 events",
                "audit service installs around compromise time",
                "scan mft for recently modified system files",
                "check registry run keys for autoruns",
                "inspect 5140 share access for admin shares",
                "review 4648 explicit credential use patterns",
                "correlate 4697 service install with network activity",
            ]
            for task in distinct_tasks:
                memory.append_task(task, "human_decision")

            tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
            task_lines = [l for l in tasks_text.splitlines() if l.startswith("- [human_decision]")]
            self.assertLessEqual(len(task_lines), 10,
                                 "at most 10 human_decision tasks")
            task_texts = [l.split("] ", 1)[-1] for l in task_lines]
            self.assertNotIn(distinct_tasks[0], task_texts,
                             "oldest human_decision task evicted")

    def test_r2_10_inconclusive_without_transition_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Investigation Overview\n\n## Key Findings\n- none\n")
            overview_before = memory.load_overview()

            # Inconclusive with no new entities, no new families
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[Hypothesis(id="H-1", description="desc", status="active", summary="")],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "inconclusive",
                    "memory_updates": {
                        "overview": ["boring inconclusive detail"],
                        "facts": [{"text": "some fact", "evidence_ids": ["ev-1"]}],
                    },
                },
                db=None,
            )
            self.assertEqual(overview_before, memory.load_overview(),
                             "plain inconclusive without transition writes nothing to overview")


if __name__ == "__main__":
    unittest.main()
