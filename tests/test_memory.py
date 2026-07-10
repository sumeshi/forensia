from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forensia.ai.checking.check_normalize import summarize_query_result
from forensia.ai.investigation_session import _sync_keypoint_cards
from forensia.ai.memory_sync import _apply_memory_updates
from forensia.config import (
    get_llm_settings,
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB


class MemoryTests(unittest.TestCase):
    """MemoryManager core: facts, dedup, compaction, overview, timeline archive."""

    def tearDown(self) -> None:
        reload_settings()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def test_summarize_query_result_includes_head_tail_and_distinct_counts(
        self,
    ) -> None:
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
                db.execute(
                    "DELETE FROM schema_migrations WHERE migration_key = 'legacy_schema_backfill'"
                )

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
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "256"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[
                    Hypothesis(
                        id="H-1", description="desc", status="active", summary=""
                    )
                ],
                resolved_hypotheses=[],
                check_output={
                    "memory_updates": {
                        "facts": [{"text": "fact one", "evidence_ids": ["ev-1"]}],
                        "timeline": [
                            {
                                "timestamp": "2026-05-12T10:00:00",
                                "description": "anchor",
                                "evidence_ids": ["ev-2"],
                            }
                        ],
                        "tasks": [
                            {"text": "need more logs", "kind": "internal_db_check"}
                        ],
                        "overview": ["initial storyline"],
                        "refuted_hypotheses": [
                            {
                                "hypothesis_id": "H-old",
                                "description": "old theory",
                                "reason": "timestamps do not line up",
                            }
                        ],
                        "entities": [
                            {
                                "entity_type": "src_ip",
                                "name": "10.0.0.5",
                                "role": "source_ip",
                                "notes": "reused across failed logons",
                            }
                        ],
                    }
                },
                db=None,
            )

            confirmed_text = memory.facts_path.read_text(encoding="utf-8")
            self.assertIn("[fact-001]", confirmed_text)
            self.assertNotIn("- fact one [evidence: ev-1]", confirmed_text)
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertIn(
                "fact one",
                (memory.details_dir / "fact-001.md").read_text(encoding="utf-8"),
            )
            self.assertIn("anchor", memory.timeline_path.read_text(encoding="utf-8"))
            self.assertIn(
                "need more logs", memory.tasks_memory_path.read_text(encoding="utf-8")
            )
            self.assertIn(
                "initial storyline", memory.overview_path.read_text(encoding="utf-8")
            )
            self.assertIn(
                "old theory", memory.refuted_hypotheses_path.read_text(encoding="utf-8")
            )
            self.assertTrue((memory.entities_ip_dir / "10.0.0.5.md").exists())
            self.assertIn(
                "10.0.0.5",
                (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"),
            )
            self.assertIn(
                "role: source_ip",
                (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"),
            )

            memory.update_overview("# Overview\n\n" + ("x" * 4096))
            confirmed_before = memory.facts_path.read_text(encoding="utf-8")
            timeline_before = memory.timeline_path.read_text(encoding="utf-8")
            refuted_before = memory.refuted_hypotheses_path.read_text(encoding="utf-8")
            entities_before = (memory.entities_ip_dir / "10.0.0.5.md").read_text(
                encoding="utf-8"
            )
            for index in range(20):
                memory.append_task(f"question-{index}", "internal_db_check")

            tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")

            self.assertTrue(memory.overview_path.stat().st_size > memory.max_bytes)
            self.assertEqual(
                confirmed_before, memory.facts_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                timeline_before, memory.timeline_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                refuted_before,
                memory.refuted_hypotheses_path.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                entities_before,
                (memory.entities_ip_dir / "10.0.0.5.md").read_text(encoding="utf-8"),
            )
            self.assertNotIn("question-0", tasks_text)
            self.assertIn("question-19", tasks_text)

    def test_confirmed_fact_duplicates_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("same fact", ["ev-1"])
            memory.append_confirmed_fact("same fact", ["ev-1"])

            lines = [
                line
                for line in memory.facts_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("- ")
            ]
            self.assertEqual(1, len(lines))
            self.assertTrue((memory.details_dir / "fact-001.md").exists())
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicates_with_dash_prefixed_body_are_skipped(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])
            memory.append_confirmed_fact("- suspicious dash-prefixed fact", ["ev-1"])

            lines = [
                line
                for line in memory.facts_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("- ")
            ]
            self.assertEqual(1, len(lines))
            self.assertFalse((memory.details_dir / "fact-002.md").exists())

    def test_confirmed_fact_duplicates_with_reordered_evidence_ids_are_skipped(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            memory.append_confirmed_fact("same fact", ["ev-2", "ev-1"])
            memory.append_confirmed_fact("same fact", ["ev-1", "ev-2"])

            lines = [
                line
                for line in memory.facts_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("- ")
            ]
            self.assertEqual(1, len(lines))
            detail = (memory.details_dir / "fact-001.md").read_text(encoding="utf-8")
            self.assertIn("- ev-1", detail)
            self.assertIn("- ev-2", detail)

    def test_confirmed_fact_duplicate_check_uses_hash_cache_before_detail_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.append_confirmed_fact("fact one", ["ev-1"])

            with patch.object(
                Path, "glob", side_effect=AssertionError("glob should not be called")
            ):
                memory.append_confirmed_fact("fact one", ["ev-1"])

    def test_next_fact_detail_id_uses_details_dir_not_compacted_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.facts_path.write_text(
                "# Facts\n\n- [fact-001] compacted\n", encoding="utf-8"
            )
            (memory.details_dir / "fact-042.md").write_text(
                "# fact-042\n\nbody\n", encoding="utf-8"
            )
            memory = MemoryManager(case)

            self.assertEqual(43, memory._next_fact_id)

    def test_alloc_fact_detail_id_does_not_glob_each_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            with patch.object(
                Path, "glob", side_effect=AssertionError("glob should not be called")
            ):
                self.assertEqual("fact-001", memory._alloc_fact_detail_id())
                self.assertEqual("fact-002", memory._alloc_fact_detail_id())

    def test_memory_init_scans_fact_details_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.memory_dir / "details").mkdir(parents=True, exist_ok=True)
            (case.memory_dir / "details" / "fact-042.md").write_text(
                "# fact-042\n\nbody\n", encoding="utf-8"
            )
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

            lines = [
                line
                for line in reopened.facts_path.read_text(encoding="utf-8").splitlines()
                if line.startswith("- ")
            ]
            self.assertEqual(1, len(lines))

    def test_facts_are_not_compacted_when_oversized(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "128"}),
        ):
            reload_settings()
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
            timeline_lines = [
                line for line in timeline_text.splitlines() if line.startswith("- ")
            ]
            archive_text = (memory.archive_dir / "timeline_archive.md").read_text(
                encoding="utf-8"
            )

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
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "256"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            header = "# Suspicious Evidence\n\n| evidence_id | reason | confidence |\n|---|---|---|\n"
            rows = "\n".join(
                f"| ev-{index:03d} | reason-{index} | 0.5 |" for index in range(100)
            )
            memory.suspicious_path.write_text(header + rows + "\n", encoding="utf-8")

            changed = memory.compact_if_oversized(memory.suspicious_path)

            self.assertTrue(changed)
            content = memory.suspicious_path.read_text(encoding="utf-8")
            self.assertIn("| evidence_id | reason | confidence |", content)
            self.assertIn("|---|---|---|", content)
            self.assertLessEqual(
                memory.suspicious_path.stat().st_size, memory.max_bytes
            )

    def test_overview_is_compacted_via_llm_summary(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            mock_chat = Mock(return_value="compressed overview")
            memory = MemoryManager(case, summarize=mock_chat)
            memory.overview_path.write_text(
                "# Overview\n\n" + ("x" * 512), encoding="utf-8"
            )

            changed = memory.compact_overview_if_needed(
                self._llm_base_url(), "test-model"
            )

            self.assertTrue(changed)
            self.assertEqual(
                "compressed overview\n",
                memory.overview_path.read_text(encoding="utf-8"),
            )
            messages = mock_chat.call_args[0][0]
            self.assertIn(
                "Compress the following investigation overview", messages[0]["content"]
            )
            self.assertIn(
                "Write the compressed overview in ja.", messages[0]["content"]
            )

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
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(
                os.environ,
                {"LLM_MEMORY_MAX_BYTES": "64", "LLM_OUTPUT_LANGUAGE": "en"},
            ),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            mock_chat = Mock(return_value="compressed overview")
            memory = MemoryManager(case, summarize=mock_chat)
            memory.overview_path.write_text(
                "# Overview\n\n" + ("x" * 512), encoding="utf-8"
            )

            memory.compact_overview_if_needed(self._llm_base_url(), "test-model")

            messages = mock_chat.call_args[0][0]
            self.assertIn(
                "Write the compressed overview in en.", messages[0]["content"]
            )

    def test_overview_compaction_failure_keeps_existing_file(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(
                case, summarize=Mock(side_effect=RuntimeError("timeout"))
            )
            original = "# Overview\n\n" + ("x" * 512)
            memory.overview_path.write_text(original, encoding="utf-8")

            changed = memory.compact_overview_if_needed(
                self._llm_base_url(), "test-model"
            )

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
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "96"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            mock_chat = Mock(return_value="# Hypothesis H-1\n\n- compacted")
            memory = MemoryManager(case, summarize=mock_chat)
            memory.update_overview("# Overview\n\n" + ("x" * 512))
            memory.upsert_hypothesis(
                "H-1", "oversized", "# Hypothesis H-1\n\n" + ("y" * 512)
            )

            changed = memory.compact_oversized_with_llm(
                self._llm_base_url(), "test-model"
            )

            self.assertEqual([str(memory.hypotheses_dir / "H-1.md")], changed)
            self.assertEqual(
                "# Overview\n\n" + ("x" * 512),
                memory.overview_path.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                "# Hypothesis H-1\n\n- compacted\n",
                (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8"),
            )
            mock_chat.assert_called_once()

    def test_entity_memory_is_llm_compacted_when_oversized(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "96"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            mock_chat = Mock(return_value="- compacted entity")
            memory = MemoryManager(case, summarize=mock_chat)
            memory.upsert_entity("ip", "10.0.0.5", "# ip: 10.0.0.5\n\n" + ("z" * 512))

            changed = memory.compact_oversized_with_llm(
                self._llm_base_url(), "test-model"
            )

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

            memory.upsert_hypothesis(
                "H-1", "first-description", "# Hypothesis H-1\n\nfirst\n"
            )
            memory.upsert_hypothesis(
                "H-1", "second-description", "# Hypothesis H-1\n\nsecond\n"
            )

            hyp_path = memory.hypotheses_dir / "H-1.md"
            self.assertTrue(hyp_path.exists())
            self.assertEqual(
                "# Hypothesis H-1\n\nsecond\n", hyp_path.read_text(encoding="utf-8")
            )
            self.assertEqual([hyp_path], sorted(memory.hypotheses_dir.glob("*.md")))

    def test_hypothesis_upsert_removes_legacy_slug_named_file_for_same_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            legacy_path = memory.hypotheses_dir / "h-1-old-description.md"
            legacy_path.write_text("# Hypothesis H-1\n\nlegacy\n", encoding="utf-8")

            memory.upsert_hypothesis(
                "H-1", "new-description", "# Hypothesis H-1\n\ncurrent\n"
            )

            self.assertFalse(legacy_path.exists())
            self.assertEqual(
                "# Hypothesis H-1\n\ncurrent\n",
                (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8"),
            )

    def test_oversized_memory_llm_compaction_failure_keeps_existing_file(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "64"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(
                case, summarize=Mock(side_effect=RuntimeError("timeout"))
            )
            original = "# Overview\n\n" + ("x" * 512)
            memory.update_overview(original)

            changed = memory.compact_oversized_with_llm(
                self._llm_base_url(), "test-model"
            )

            self.assertEqual([], changed)
            self.assertEqual(original, memory.overview_path.read_text(encoding="utf-8"))

    def test_get_llm_settings_cache_can_be_cleared(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "ja"}):
            reload_settings()
            first = get_llm_settings()
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            second_before_clear = get_llm_settings()
            reload_settings()
            second_after_clear = get_llm_settings()

        self.assertEqual("ja", first["output_language"])
        self.assertEqual("ja", second_before_clear["output_language"])
        self.assertEqual("en", second_after_clear["output_language"])


if __name__ == "__main__":
    unittest.main()
