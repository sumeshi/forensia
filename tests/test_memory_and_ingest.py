from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.ai.checker import CheckResult
from forensia.ai.investigator import _apply_memory_updates, _sync_keypoint_cards
from forensia import cli as cli_module
from forensia.cli import _progress_pusher, _reset_case_tables
from forensia.config import clear_llm_settings_cache, get_llm_settings, resolve_llm_config
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.ingest import ingest_all


class MemoryAndIngestTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_llm_settings_cache()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

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
                        "entities": [{"entity_type": "src_ip", "name": "10.0.0.5", "notes": "reused across failed logons"}],
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

            with patch("forensia.core.memory.chat_completion", return_value="compressed overview") as mock_chat:
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

            with patch("forensia.core.memory.chat_completion", return_value="compressed overview") as mock_chat:
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

            with patch("forensia.core.memory.chat_completion", side_effect=RuntimeError("timeout")):
                changed = memory.compact_overview_if_needed(self._llm_base_url(), "test-model")

            self.assertFalse(changed)
            self.assertEqual(original, memory.overview_path.read_text(encoding="utf-8"))

    def test_keypoint_cards_are_created_from_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence,
                        status, tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (
                        'F-1', 'rule-1', 'Suspicious logon', 'summary', 'high', 0.9,
                        'accepted', '[]', '[]', '[{"evidence_id":"ev-1"}]', '', '[]', now()
                    )
                    """
                )
                with patch("forensia.ai.investigator._seed_findings", return_value=1), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    from forensia.ai.investigator import investigate

                    investigate(
                        case=case,
                        db=db,
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=1,
                        no_progress_limit=1,
                        report_every_n_cycles=999,
                    )

            keypoint = case.memory_dir / "keypoints" / "KP-0001.md"
            self.assertTrue(keypoint.exists())
            text = keypoint.read_text(encoding="utf-8")
            self.assertIn("finding_id: F-1", text)
            self.assertIn("title: Suspicious logon", text)
            self.assertIn("- ev-1", text)

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

    def test_investigation_deletes_stale_hypothesis_cards_after_init_style_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            stale_path = memory.hypotheses_dir / "H-stale.md"
            stale_path.write_text("# Hypothesis H-stale\n\nold\n", encoding="utf-8")

            with CaseDB(case) as db, patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                "forensia.ai.investigator.render_written_report",
                return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
            ):
                from forensia.ai.investigator import investigate

                investigate(
                    case=case,
                    db=db,
                    base_url=self._llm_base_url(),
                    model="test-model",
                    max_iter=1,
                    no_progress_limit=1,
                    report_every_n_cycles=999,
                )

            self.assertFalse(stale_path.exists())

    def test_investigation_keeps_active_and_resolved_hypothesis_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            stale_path = memory.hypotheses_dir / "H-stale.md"
            stale_path.write_text("# Hypothesis H-stale\n\nold\n", encoding="utf-8")

            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES
                        ('H-1', 'active hypothesis', 'active', NULL, 'active summary', 'broad_plan', 'S-1', NULL, now(), now()),
                        ('H-2', 'resolved hypothesis', 'confirmed', 'confirmed', 'resolved summary', 'check_new', 'S-1', 'S-1', now(), now())
                    """
                )
                memory.upsert_hypothesis("H-1", "active", "# Hypothesis H-1\n\nactive\n")
                memory.upsert_hypothesis("H-2", "resolved", "# Hypothesis H-2\n\nresolved\n")

                with patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    from forensia.ai.investigator import investigate

                    investigate(
                        case=case,
                        db=db,
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=1,
                        no_progress_limit=1,
                        report_every_n_cycles=999,
                    )

            self.assertTrue((memory.hypotheses_dir / "H-1.md").exists())
            self.assertTrue((memory.hypotheses_dir / "H-2.md").exists())
            self.assertFalse(stale_path.exists())

    def test_investigation_marks_session_failed_when_llm_runtime_error_escapes_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db, patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                "forensia.ai.investigator.broad_plan_investigation",
                side_effect=RuntimeError("llm failed"),
            ):
                from forensia.ai.investigator import investigate

                with self.assertRaisesRegex(RuntimeError, "llm failed"):
                    investigate(
                        case=case,
                        db=db,
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=1,
                        no_progress_limit=1,
                        report_every_n_cycles=999,
                    )

                status, finished_at = db.execute(
                    """
                    SELECT status, finished_at
                    FROM investigation_sessions
                    ORDER BY started_at DESC, session_id DESC
                    LIMIT 1
                    """
                ).fetchone()

            self.assertEqual("failed", status)
            self.assertIsNotNone(finished_at)

    def test_investigation_applies_guarded_memory_updates_not_raw_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            planned_query = PlannedQuery(
                query_id="Q-1",
                hypothesis_id="H-1",
                purpose="purpose",
                sql="SELECT evidence_id FROM findings",
            )
            guarded_result = CheckResult(
                query_id="Q-1",
                verdict="inconclusive",
                finding_updates=[],
                suspicious_evidence=[],
                new_hypotheses=[],
                memory_updates={"facts": [], "timeline": [], "tasks": []},
                report_text="guarded",
                new_leads=0,
                progress=False,
                raw_response={
                    "memory_updates": {
                        "facts": [{"text": "bad fact", "evidence_ids": ["ev-bad"]}],
                        "timeline": [
                            {
                                "timestamp": "2026-05-12T10:00:00",
                                "description": "bad timeline",
                                "evidence_ids": ["ev-bad"],
                            }
                        ],
                    },
                    "suspicious_evidence": [{"evidence_id": "ev-bad", "reason": "bad", "confidence": 0.9}],
                },
            )

            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES ('H-1', 'active hypothesis', 'active', NULL, '', 'broad_plan', 'S-1', NULL, now(), now())
                    """
                )
                with patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                    "forensia.ai.investigator.broad_plan_investigation",
                    return_value=type("BroadPlanStub", (), {"hypotheses": [], "stop": False, "raw_response": {}})(),
                ), patch(
                    "forensia.ai.investigator.plan_hypothesis_query",
                    return_value=type(
                        "HypothesisPlanStub",
                        (),
                        {"hypothesis": None, "query": planned_query, "needs_more": False, "raw_response": {}},
                    )(),
                ), patch(
                    "forensia.ai.investigator.fetch_records",
                    return_value=[{"evidence_id": "ev-good"}],
                ), patch(
                    "forensia.ai.investigator.check_query_result",
                    return_value=guarded_result,
                ), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    from forensia.ai.investigator import investigate

                    investigate(
                        case=case,
                        db=db,
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=1,
                        no_progress_limit=1,
                        max_queries_per_hypothesis=1,
                        report_every_n_cycles=999,
                    )

            facts_text = (case.memory_dir / "facts.md").read_text(encoding="utf-8") if (case.memory_dir / "facts.md").exists() else ""
            timeline_text = (case.memory_dir / "timeline.md").read_text(encoding="utf-8") if (case.memory_dir / "timeline.md").exists() else ""
            suspicious_text = (
                (case.memory_dir / "evidence" / "suspicious.md").read_text(encoding="utf-8")
                if (case.memory_dir / "evidence" / "suspicious.md").exists()
                else ""
            )

            self.assertNotIn("bad fact", facts_text)
            self.assertNotIn("bad timeline", timeline_text)
            self.assertNotIn("ev-bad", suspicious_text)

    def test_investigation_initializes_overview_with_new_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db, patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                "forensia.ai.investigator.render_written_report",
                return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
            ):
                from forensia.ai.investigator import investigate

                investigate(
                    case=case,
                    db=db,
                    base_url=self._llm_base_url(),
                    model="test-model",
                    max_iter=1,
                    no_progress_limit=1,
                    report_every_n_cycles=999,
                )

            overview = (case.memory_dir / "overview.md").read_text(encoding="utf-8")
            self.assertIn("## Case Scope", overview)
            self.assertIn("## Key Findings", overview)
            self.assertIn("## Investigation Policy", overview)
            self.assertNotIn("## Confirmed Hosts", overview)

    def test_overview_cache_is_bounded_on_session_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "128"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Overview\n\n" + ("x" * 512))
            with CaseDB(case) as db, patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                "forensia.ai.investigator.render_written_report",
                return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
            ), patch.object(MemoryManager, "load_compact_context", autospec=True, wraps=MemoryManager.load_compact_context) as mock_compact:
                from forensia.ai.investigator import investigate

                investigate(
                    case=case,
                    db=db,
                    base_url=self._llm_base_url(),
                    model="test-model",
                    max_iter=1,
                    no_progress_limit=1,
                    report_every_n_cycles=999,
                )

            overview_calls = [
                call for call in mock_compact.call_args_list
                if len(call.args) >= 2 and call.args[1] == ["overview.md"] and call.kwargs.get("max_bytes") == memory.max_bytes
            ]
            self.assertTrue(overview_calls)

    def test_hypothesis_memory_is_llm_compacted_when_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "96"}):
            clear_llm_settings_cache()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Overview\n\n" + ("x" * 512))
            memory.upsert_hypothesis("H-1", "oversized", "# Hypothesis H-1\n\n" + ("y" * 512))

            with patch("forensia.core.memory.chat_completion", return_value="# Hypothesis H-1\n\n- compacted") as mock_chat:
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

            with patch("forensia.core.memory.chat_completion", return_value="- compacted entity") as mock_chat:
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

            with patch("forensia.core.memory.chat_completion", side_effect=RuntimeError("timeout")):
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
