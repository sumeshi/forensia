from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from forensia.ai.checking.check_normalize import summarize_query_result
from forensia.ai.investigation import investigation_session
from forensia.ai.investigation.investigation_session import sync_keypoint_cards
from forensia.ai.investigation.memory_sync import apply_memory_updates
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "256"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            apply_memory_updates(
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "128"}),
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "256"}),
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
            patch.dict(
                os.environ,
                {"FORENSIA_MEMORY_MAX_BYTES": "64", "FORENSIA_OUTPUT_LANGUAGE": "ja"},
            ),
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
                {"FORENSIA_MEMORY_MAX_BYTES": "64", "FORENSIA_OUTPUT_LANGUAGE": "en"},
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "64"}),
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

            sync_keypoint_cards(memory, large_snapshot)
            self.assertTrue((memory.keypoints_dir / "KP-0003.md").exists())

            sync_keypoint_cards(memory, small_snapshot)

            self.assertTrue((memory.keypoints_dir / "KP-0001.md").exists())
            self.assertFalse((memory.keypoints_dir / "KP-0002.md").exists())
            self.assertFalse((memory.keypoints_dir / "KP-0003.md").exists())

    def test_finding_snapshot_round_robins_semantic_themes(self) -> None:
        candidates = [
            {
                "finding_id": finding_id,
                "rule_id": theme,
                "title": finding_id,
                "summary": finding_id,
                "confidence": confidence,
                "evidence": [{"evidence_id": f"ev-{finding_id}"}],
            }
            for finding_id, theme, confidence in (
                ("A-1", "theme-a", 0.99),
                ("A-2", "theme-a", 0.98),
                ("A-3", "theme-a", 0.97),
                ("B-1", "theme-b", 0.70),
                ("C-1", "theme-c", 0.60),
            )
        ]
        with (
            patch.object(
                investigation_session, "_findings_snapshot", return_value=candidates
            ),
            patch.object(
                investigation_session,
                "classify_finding_theme",
                side_effect=lambda item: item["rule_id"],
            ),
        ):
            snapshot = investigation_session._finding_snapshot(Mock(), limit=3)

        self.assertEqual(["A-1", "B-1", "C-1"], [x["finding_id"] for x in snapshot])
        self.assertEqual(3, snapshot[0]["theme_count"])
        self.assertEqual(["A-1", "A-2", "A-3"], snapshot[0]["theme_finding_ids"])

    def test_hypothesis_memory_is_llm_compacted_when_oversized(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "96"}),
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "96"}),
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
            patch.dict(os.environ, {"FORENSIA_MEMORY_MAX_BYTES": "64"}),
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
        with patch.dict(os.environ, {"FORENSIA_OUTPUT_LANGUAGE": "ja"}):
            reload_settings()
            first = get_llm_settings()
        with patch.dict(os.environ, {"FORENSIA_OUTPUT_LANGUAGE": "en"}):
            second_before_clear = get_llm_settings()
            reload_settings()
            second_after_clear = get_llm_settings()

        self.assertEqual("ja", first["output_language"])
        self.assertEqual("ja", second_before_clear["output_language"])
        self.assertEqual("en", second_after_clear["output_language"])


class TokenizeTests(unittest.TestCase):
    """Unit tests for MemoryManager._tokenize."""

    def test_basic_split(self):
        result = MemoryManager._tokenize("User logged in at 2pm")
        self.assertIn("user", result)
        self.assertIn("logged", result)
        self.assertIn("2pm", result)

    def test_casefold(self):
        result = MemoryManager._tokenize("Alice BOB charlie")
        self.assertEqual(result, {"alice", "bob", "charlie"})

    def test_single_char_excluded(self):
        result = MemoryManager._tokenize("a is the X")
        self.assertNotIn("a", result)
        self.assertIn("is", result)
        self.assertIn("the", result)


class FileMatchesRelevanceTests(unittest.TestCase):
    """Unit tests for MemoryManager._file_matches_relevance."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Create a simple file with known content
        ent_dir = self.tmpdir / "entities" / "user"
        ent_dir.mkdir(parents=True)
        (ent_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n\n- Active directory account for alice\n",
            encoding="utf-8",
        )
        (ent_dir / "BOB_JONES.md").write_text(
            "# Bob Jones\n\n- Service account for bob\n",
            encoding="utf-8",
        )
        self.rel_path_alice = "entities/user/ALICE_SMITH.md"
        self.rel_path_bob = "entities/user/BOB_JONES.md"

    def test_filename_match(self):
        terms = {"alice"}
        self.assertTrue(
            MemoryManager._file_matches_relevance(
                self.rel_path_alice, self.tmpdir, terms
            )
        )

    def test_filename_no_match(self):
        terms = {"alice"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(self.rel_path_bob, self.tmpdir, terms)
        )

    def test_content_match(self):
        # "service" is in Bob's content, not filename
        terms = {"service"}
        self.assertTrue(
            MemoryManager._file_matches_relevance(self.rel_path_bob, self.tmpdir, terms)
        )

    def test_content_no_match(self):
        terms = {"firewall"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(
                self.rel_path_alice, self.tmpdir, terms
            )
        )

    def test_nonexistent_file(self):
        terms = {"alice"}
        self.assertFalse(
            MemoryManager._file_matches_relevance(
                "entities/user/NOPE.md", self.tmpdir, terms
            )
        )


class BuildRelevanceTermsTests(unittest.TestCase):
    """Unit tests for MemoryManager.build_relevance_terms_from_hypothesis."""

    def test_none_hypothesis(self):
        self.assertEqual(
            MemoryManager.build_relevance_terms_from_hypothesis(None), set()
        )

    def test_extracts_description_tokens(self):
        hyp = SimpleNamespace(
            description="Compromised user alice via phishing",
            required_entities=[],
        )
        terms = MemoryManager.build_relevance_terms_from_hypothesis(hyp)
        self.assertIn("compromised", terms)
        self.assertIn("alice", terms)
        self.assertIn("phishing", terms)

    def test_extracts_required_entities(self):
        hyp = SimpleNamespace(
            description="Investigate lateral movement",
            required_entities=["alice-smith", "file-server-01"],
        )
        terms = MemoryManager.build_relevance_terms_from_hypothesis(hyp)
        self.assertIn("alice", terms)
        self.assertIn("smith", terms)
        self.assertIn("file", terms)
        self.assertIn("server", terms)


class InvestigationContextFilesRelevanceTests(unittest.TestCase):
    """Integration tests for investigation_context_files with relevance filtering."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.mm = MemoryManager(self.case)

        # Create 10 entity files: 2 related to "alice", 8 unrelated
        ent_dir = self.mm.entities_dir
        ent_user_dir = ent_dir / "user"
        ent_user_dir.mkdir(parents=True, exist_ok=True)
        ent_host_dir = ent_dir / "host"
        ent_host_dir.mkdir(parents=True, exist_ok=True)
        ent_ip_dir = ent_dir / "ip"
        ent_ip_dir.mkdir(parents=True, exist_ok=True)

        # 2 related to alice
        (ent_user_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n- User account alice-smith [confirmed]\n",
            encoding="utf-8",
        )
        (ent_host_dir / "WORKSTATION-ALICE.md").write_text(
            "# WORKSTATION-ALICE\n- Host used by alice-smith\n",
            encoding="utf-8",
        )
        # 8 unrelated
        for name in [
            "BOB_JONES",
            "CHARLIE_BROWN",
            "DAVE_WILSON",
            "EVE_ADAMS",
            "FRANK_MILLER",
            "GRACE_HOPPER",
            "HELEN_PARK",
            "IVAN_PETROV",
        ]:
            subdir = (
                ent_user_dir if name in ("BOB_JONES", "CHARLIE_BROWN") else ent_ip_dir
            )
            subdir.mkdir(parents=True, exist_ok=True)
            (subdir / f"{name}.md").write_text(
                f"# {name}\n- Some unrelated entity\n", encoding="utf-8"
            )

        # Create 2 keypoint files: 1 related, 1 unrelated
        kp_dir = self.mm.keypoints_dir
        kp_dir.mkdir(parents=True, exist_ok=True)
        (kp_dir / "KP-ALICE-MOVEMENT.md").write_text(
            "# KP Alice Movement\n- Alice moved laterally from workstation\n",
            encoding="utf-8",
        )
        (kp_dir / "KP-BOB-LOGIN.md").write_text(
            "# KP Bob Login\n- Bob logged in at 9am\n",
            encoding="utf-8",
        )

    def test_no_relevance_returns_all_entities(self):
        """Without relevance_terms, all entity files are included."""
        files = self.mm.investigation_context_files(
            include_overview=False,
            include_archive=False,
            include_keypoints=False,
            include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 10)

    def test_empty_relevance_returns_all_entities(self):
        """Empty relevance_terms should include all entity files (backward compat)."""
        files = self.mm.investigation_context_files(
            relevance_terms=set(),
            include_overview=False,
            include_archive=False,
            include_keypoints=False,
            include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 10)

    def test_relevance_filters_entities(self):
        """With alice-related terms, only 2 entity files should be returned."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False,
            include_archive=False,
            include_keypoints=False,
            include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        self.assertEqual(len(entity_files), 2)
        names = {Path(f).stem for f in entity_files}
        self.assertIn("ALICE_SMITH", names)
        self.assertIn("WORKSTATION-ALICE", names)

    def test_relevance_filters_keypoints(self):
        """With alice-related terms, only the alice keypoint should be returned."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False,
            include_archive=False,
            include_entities=False,
            include_scratch=False,
        )
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(kp_files), 1)
        self.assertIn("ALICE", Path(kp_files[0]).stem)

    def test_relevance_filters_both_entities_and_keypoints(self):
        """Combined filtering of entities and keypoints."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False,
            include_archive=False,
            include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(entity_files), 2)
        self.assertEqual(len(kp_files), 1)

    def test_overview_files_not_filtered(self):
        """Overview/archive/scratch files are never filtered by relevance_terms."""
        terms = {"alice"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_entities=False,
            include_keypoints=False,
        )
        # overview.md, facts.md, timeline.md, tasks.md should always be present
        self.assertIn("overview.md", files)
        self.assertIn("facts.md", files)

    def test_core_memory_survives_when_overview_is_excluded(self):
        files = self.mm.investigation_context_files(
            include_overview=False,
            include_entities=False,
            include_keypoints=False,
            include_scratch=False,
            include_archive=False,
        )
        self.assertNotIn("overview.md", files)
        self.assertIn("facts.md", files)
        self.assertIn("timeline.md", files)
        self.assertIn("tasks.md", files)

    def test_memory_index_lists_paths_without_loading_bodies(self):
        index = self.mm.build_memory_index(relevance_terms={"alice"})
        self.assertIn('<MEMORY_INDEX scope="global">', index)
        self.assertIn("entities/user/ALICE_SMITH.md", index)
        self.assertLess(
            index.find("entities/user/ALICE_SMITH.md"),
            index.find("entities/user/BOB_JONES.md"),
        )

    def test_memory_index_is_hierarchical_and_hypothesis_scoped(self):
        for hypothesis_id in ("H-A", "H-B"):
            scratch = self.mm.scratch_dir / hypothesis_id
            scratch.mkdir(parents=True, exist_ok=True)
            (scratch / "tasks.md").write_text(
                f"# {hypothesis_id} private work\n", encoding="utf-8"
            )
            (self.mm.hypotheses_dir / f"{hypothesis_id}.md").write_text(
                f"# {hypothesis_id}\n", encoding="utf-8"
            )

        index = self.mm.build_memory_index("H-A", relevance_terms={"alice"})

        self.assertIn('<MEMORY_INDEX scope="H-A">', index)
        self.assertIn("<CATEGORIES>", index)
        self.assertIn("- entities: 10", index)
        self.assertIn("hypotheses/H-A.md", index)
        self.assertIn("scratch/H-A/tasks.md", index)
        self.assertNotIn("H-B", index)

    def test_scoped_context_loads_only_current_hypothesis_scratch(self):
        for scope in ("global", "H-A", "H-B"):
            scratch = self.mm.scratch_dir / scope
            scratch.mkdir(parents=True, exist_ok=True)
            (scratch / "notes.md").write_text(f"# {scope}\n", encoding="utf-8")

        files = self.mm.investigation_context_files(
            "H-A",
            include_overview=False,
            include_core=False,
            include_archive=False,
            include_entities=False,
            include_keypoints=False,
        )

        self.assertEqual(["scratch/H-A/notes.md"], files)

    def test_scoped_read_more_rejects_other_hypothesis_and_archive(self):
        allowed, rejected = self.mm.filter_paths_for_scope(
            [
                "facts.md",
                "entities/user/ALICE_SMITH.md",
                "scratch/H-A/tasks.md",
                "hypotheses/H-A.md",
                "scratch/H-B/tasks.md",
                "hypotheses/H-B.md",
                "archive/refuted.md",
                "../secrets.md",
            ],
            "H-A",
        )

        self.assertEqual(
            [
                "facts.md",
                "entities/user/ALICE_SMITH.md",
                "scratch/H-A/tasks.md",
                "hypotheses/H-A.md",
            ],
            allowed,
        )
        self.assertEqual(4, len(rejected))

    def test_no_matching_terms_returns_empty_entities(self):
        """If relevance_terms don't match anything, entity/keypoint lists are empty."""
        terms = {"zzzznonexistent"}
        files = self.mm.investigation_context_files(
            relevance_terms=terms,
            include_overview=False,
            include_archive=False,
            include_scratch=False,
        )
        entity_files = [f for f in files if f.startswith("entities/")]
        kp_files = [f for f in files if f.startswith("keypoints/")]
        self.assertEqual(len(entity_files), 0)
        self.assertEqual(len(kp_files), 0)


class LoadInvestigationContextRelevanceTests(unittest.TestCase):
    """Integration test for load_investigation_context passing relevance_terms."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.case = Case.init(self.tmpdir)
        self.mm = MemoryManager(self.case)

        ent_user_dir = self.mm.entities_dir / "user"
        ent_user_dir.mkdir(parents=True, exist_ok=True)
        (ent_user_dir / "ALICE_SMITH.md").write_text(
            "# Alice Smith\n- User account alice-smith\n",
            encoding="utf-8",
        )
        (ent_user_dir / "BOB_JONES.md").write_text(
            "# Bob Jones\n- Unrelated entity bob-jones\n",
            encoding="utf-8",
        )

    def test_load_investigation_context_filters(self):
        """load_investigation_context should pass relevance_terms through."""
        context = self.mm.load_investigation_context(
            relevance_terms={"alice"},
            include_overview=False,
            include_archive=False,
            include_keypoints=False,
            include_scratch=False,
            max_bytes=100_000,
        )
        # Should contain alice file but not bob file
        self.assertIn("alice-smith", context.lower())
        self.assertNotIn("bob-jones", context.lower())


def test_ctx_refresh_caches_forwards_relevance_terms() -> None:
    """The investigator's preloaded contexts must carry relevance filtering.

    Why: ctx.memory_plan / ctx.memory_check are handed to the planner and
    checker as their default context, which SKIPS the lazy-load fallbacks
    where relevance filtering also lives. If the preload does not filter,
    relevance filtering is inert for the whole main investigation loop.
    """
    from unittest.mock import MagicMock

    from forensia.ai.investigation.investigation_session import (
        Ctx,
        ctx_refresh_caches,
    )
    from forensia.core.memory import MemoryManager
    from forensia.core.session import Hypothesis

    memory = MagicMock()
    memory.max_bytes = 16384
    memory.load_compact_context.return_value = ""
    memory.load_investigation_context.return_value = ""
    memory.build_relevance_terms_from_hypothesis.side_effect = (
        MemoryManager.build_relevance_terms_from_hypothesis
    )

    hypothesis = Hypothesis(
        id="H-001",
        description="credential reuse by informant",
        required_entities=["target_user"],
    )
    ctx_refresh_caches(Ctx(), memory, "http://localhost", "m", hypothesis=hypothesis)

    calls = memory.load_investigation_context.call_args_list
    assert len(calls) == 2  # memory_plan and memory_check
    for call in calls:
        terms = call.kwargs.get("relevance_terms")
        assert terms, "preloaded context must be relevance-filtered"
        assert "informant" in terms
        assert call.args[0] == "H-001" or call.kwargs.get("hypothesis_id") == "H-001"


class FuzzyDedupTests(unittest.TestCase):
    """Verify that _append_markdown_entry suppresses near-duplicates via jaccard_similarity."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_exact_duplicate_skipped(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line = "- User logged in [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line))
        # Exact same line should be skipped
        self.assertFalse(mm._append_markdown_entry(path, heading, line))

    def test_near_duplicate_same_evidence_skipped(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Same fact, slightly different wording, same evidence → suppressed
        self.assertFalse(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_near_duplicate_different_evidence_appended(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-002]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Same fact, different evidence → must be kept
        self.assertTrue(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_different_fact_appended(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- Server crashed at midnight [confirmed | evidence: E-003]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Completely different fact → must be appended
        self.assertTrue(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_fuzzy_dedup_disabled_by_default(self):
        mm = self._make_manager()
        path = mm.facts_path
        heading = "# Facts"
        line1 = "- User logged in at 2pm [confirmed | evidence: E-001]"
        line2 = "- The user logged in at 2pm [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        # Without fuzzy_dedup, near-duplicates pass through (existing behavior)
        self.assertTrue(mm._append_markdown_entry(path, heading, line2))

    def test_timeline_near_duplicate_skipped(self):
        mm = self._make_manager()
        path = mm.timeline_path
        heading = "# Timeline"
        line1 = "- 2026-01-01 12:00: User logged in [confirmed | evidence: E-001]"
        line2 = "- 2026-01-01 12:00: The user logged in [confirmed | evidence: E-001]"
        self.assertTrue(mm._append_markdown_entry(path, heading, line1))
        self.assertFalse(
            mm._append_markdown_entry(path, heading, line2, fuzzy_dedup=True)
        )

    def test_extract_line_text(self):
        line = "- [fact-001] User logged in [confirmed | evidence: E-001]"
        self.assertEqual(MemoryManager._extract_line_text(line), "User logged in")

    def test_extract_evidence_ids(self):
        line = "- User logged in [confirmed | evidence: E-001, E-002]"
        self.assertEqual(MemoryManager._extract_evidence_ids(line), ["E-001", "E-002"])

    def test_extract_evidence_ids_none(self):
        line = "- User logged in [confirmed]"
        self.assertEqual(MemoryManager._extract_evidence_ids(line), [])


class AppendConfirmedFactFuzzyDedupTests(unittest.TestCase):
    """Integration tests for append_confirmed_fact with fuzzy dedup."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_same_fact_different_words_skipped(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        # Same fact, slightly reworded → suppressed
        mm.append_confirmed_fact("The user logged in at 2pm", ["E-001"])
        content = mm.facts_path.read_text()
        # Should contain only one fact entry
        self.assertEqual(content.count("[fact-"), 1)

    def test_same_fact_different_evidence_kept(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        mm.append_confirmed_fact("User logged in at 2pm", ["E-002"])
        content = mm.facts_path.read_text()
        # Different evidence → both kept
        self.assertEqual(content.count("[fact-"), 2)

    def test_different_fact_kept(self):
        mm = self._make_manager()
        mm.append_confirmed_fact("User logged in at 2pm", ["E-001"])
        mm.append_confirmed_fact("Server crashed at midnight", ["E-003"])
        content = mm.facts_path.read_text()
        self.assertEqual(content.count("[fact-"), 2)


class AppendTimelineFuzzyDedupTests(unittest.TestCase):
    """Integration tests for append_timeline_anchor with fuzzy dedup."""

    def _make_manager(self) -> MemoryManager:
        tmpdir = tempfile.mkdtemp()
        case = Case.init(tmpdir)
        return MemoryManager(case)

    def test_same_event_different_words_skipped(self):
        mm = self._make_manager()
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-001"])
        mm.append_timeline_anchor("2026-01-01 12:00", "The user logged in", ["E-001"])
        content = mm.timeline_path.read_text()
        self.assertEqual(content.count("- 2026-01-01"), 1)

    def test_same_event_different_evidence_kept(self):
        mm = self._make_manager()
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-001"])
        mm.append_timeline_anchor("2026-01-01 12:00", "User logged in", ["E-002"])
        content = mm.timeline_path.read_text()
        self.assertEqual(content.count("- 2026-01-01"), 2)


if __name__ == "__main__":
    unittest.main()
