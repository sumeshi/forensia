from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.memory_sync import _apply_memory_updates
from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis
from forensia.db.database import CaseDB


class MemorySyncTests(unittest.TestCase):
    """Investigation → memory sync: hypothesis/entity files, overview write routing."""

    def tearDown(self) -> None:
        reload_settings()

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

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
                    active_hypotheses=[
                        Hypothesis(
                            id="H-1", description="desc", status="active", summary="sum"
                        )
                    ],
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
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.hypotheses.hypothesis_store._recent_reasoning_rows"
                ) as mock_reasoning,
            ):
                mock_reasoning.return_value = [
                    {
                        "phase": "check",
                        "verdict": "confirmed",
                        "query_id": "Q-1",
                        "body": "body",
                    }
                ]
                _apply_memory_updates(
                    memory=memory,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-1",
                            description="active desc",
                            status="active",
                            summary="sum",
                        )
                    ],
                    resolved_hypotheses=[
                        Hypothesis(
                            id="H-2",
                            description="resolved desc",
                            status="confirmed",
                            summary="done",
                        )
                    ],
                    check_output={"memory_updates": {}},
                    db=db,
                )

            mock_reasoning.assert_called_once_with(db, "H-1")
            active_text = (memory.hypotheses_dir / "H-1.md").read_text(encoding="utf-8")
            resolved_text = (memory.hypotheses_dir / "H-2.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("## Reasoning", active_text)
            self.assertNotIn("## Reasoning", resolved_text)


    def test_r2_10_overview_writes_only_on_state_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n## Key Findings\n- none\n"
            )
            overview_before = memory.load_overview()

            # 5 inconclusive checks → overview unchanged
            for i in range(5):
                _apply_memory_updates(
                    memory=memory,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-1", description="desc", status="active", summary=""
                        )
                    ],
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
            self.assertEqual(
                overview_before,
                memory.load_overview(),
                "overview should not grow after 5 inconclusive checks",
            )

            # 1 confirmed → overview grows
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[
                    Hypothesis(
                        id="H-1", description="desc", status="active", summary=""
                    )
                ],
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
            self.assertIn(
                "confirmed finding",
                memory.load_overview(),
                "overview should grow after confirmed verdict",
            )

    def test_r2_10_new_nonobserved_entity_triggers_overview(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n## Key Findings\n- none\n"
            )

            # Inconclusive but with a new entity (role ≠ observed_user)
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[
                    Hypothesis(
                        id="H-1", description="desc", status="active", summary=""
                    )
                ],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "inconclusive",
                    "memory_updates": {
                        "overview": ["new entity discovered"],
                        "entities": [
                            {
                                "entity_type": "src_ip",
                                "name": "10.0.0.99",
                                "role": "source_ip",
                                "notes": "new",
                            }
                        ],
                    },
                },
                db=None,
            )
            self.assertIn(
                "new entity discovered",
                memory.load_overview(),
                "new entity with role ≠ observed_user triggers overview",
            )

    def test_r2_10_first_artifact_family_triggers_overview(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n## Key Findings\n- none\n"
            )

            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[
                    Hypothesis(
                        id="H-1", description="desc", status="active", summary=""
                    )
                ],
                resolved_hypotheses=[],
                check_output={
                    "verdict": "inconclusive",
                    "memory_updates": {
                        "overview": ["mft evidence found"],
                        "facts": [
                            {"text": "mft activity", "evidence_ids": ["mft-000001"]}
                        ],
                    },
                },
                db=None,
            )
            self.assertIn(
                "mft evidence found",
                memory.load_overview(),
                "first artifact family triggers overview",
            )

    def test_r2_10_fact_truncation_at_word_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            long_words = ["word"] * 50  # 250 chars, well over 160
            long_body = " ".join(long_words)
            memory.append_confirmed_fact(long_body, ["ev-1"])
            detail_id = "fact-001"
            self.assertTrue((memory.details_dir / f"{detail_id}.md").exists())
            detail_content = (memory.details_dir / f"{detail_id}.md").read_text(
                encoding="utf-8"
            )
            self.assertIn(long_body, detail_content, "detail file has full body")

            facts_text = memory.facts_path.read_text(encoding="utf-8")
            line_with_preview = [
                l for l in facts_text.splitlines() if l.startswith("- [fact-001]")
            ][0]
            self.assertIn(
                "[fact-001]", line_with_preview, "fact line references detail link"
            )
            # Extract preview text between [fact-001] and metadata brackets
            after_link = line_with_preview.split("[fact-001] ", 1)[-1]
            if " [" in after_link:
                preview = after_link.split(" [")[0]
            else:
                preview = after_link
            if "…" in preview:
                self.assertLessEqual(
                    len(preview.replace("…", "")), 160, "truncated text ≤ 160 chars"
                )
                self.assertFalse(preview.endswith(" "), "no trailing space")
                self.assertFalse(preview.endswith("… "), "no space before …")
            else:
                self.assertLessEqual(
                    len(preview), 160, "untruncated preview ≤ 160 chars"
                )

    def test_r2_10_fact_truncation_never_mid_word(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Body where char 160 falls mid-word
            body = "a " + "supercalifragilisticexpialidocious " * 5 + "zzz trailing"
            memory.append_confirmed_fact(body, ["ev-1"])
            facts_text = memory.facts_path.read_text(encoding="utf-8")
            line_with_preview = [
                l for l in facts_text.splitlines() if l.startswith("- [fact-001]")
            ][0]
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
                        original_prefix[len(chars_before)],
                        " ",
                        "truncation should occur at a space word boundary",
                    )

    def test_r2_10_task_jaccard_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Add first task
            memory.append_task(
                "Investigate the context of logon events on host", "human_decision"
            )
            # Near-paraphrase (≥0.6 Jaccard) → should be deduped
            memory.append_task(
                "Investigate the context of logon events on host machine",
                "human_decision",
            )
            # Different task → should be added
            memory.append_task(
                "Check network connections from suspicious IP", "human_decision"
            )
            # Identical to the third → deduped (exact match via existing logic)
            memory.append_task(
                "Check network connections from suspicious IP", "human_decision"
            )

            tasks_text = memory.tasks_memory_path.read_text(encoding="utf-8")
            task_lines = [
                l for l in tasks_text.splitlines() if l.startswith("- [human_decision]")
            ]
            self.assertEqual(
                2,
                len(task_lines),
                "only 2 unique tasks after dedup (2 paraphrased → 1, + 1 unique)",
            )

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
            task_lines = [
                l for l in tasks_text.splitlines() if l.startswith("- [human_decision]")
            ]
            self.assertLessEqual(len(task_lines), 10, "at most 10 human_decision tasks")
            task_texts = [l.split("] ", 1)[-1] for l in task_lines]
            self.assertNotIn(
                distinct_tasks[0], task_texts, "oldest human_decision task evicted"
            )

    def test_append_overview_routes_to_key_findings_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n"
                "## Case Scope\n- none\n\n"
                "## Key Findings\n- none\n\n"
                "## Investigation Policy\n- preserve evidence fidelity\n\n"
                "## Active Tasks\n- none\n"
            )

            memory.append_overview("Key finding: suspicious logon from 10.0.0.5")
            memory.append_overview("Finding: anomalous service install detected")

            overview = memory.load_overview()
            self.assertIn("Key finding: suspicious logon from 10.0.0.5", overview)
            self.assertIn("Finding: anomalous service install detected", overview)

            # Key Findings section should have no -none placeholder
            kf_section = overview.split("## Key Findings", 1)[1]
            if "\n## " in kf_section:
                kf_section = kf_section.split("\n## ", 1)[0]
            self.assertNotIn("- none", kf_section)

            # Verify content is under ## Key Findings, not appended at end
            kf_idx = overview.index("## Key Findings")
            scope_idx = overview.index("## Case Scope")
            policy_idx = overview.index("## Investigation Policy")
            assert "## Active Tasks" in overview
            finding1_idx = overview.index("Key finding: suspicious logon from 10.0.0.5")
            finding2_idx = overview.index("Finding: anomalous service install detected")
            self.assertGreater(finding1_idx, kf_idx)
            self.assertGreater(finding2_idx, kf_idx)
            self.assertLess(finding1_idx, policy_idx)
            self.assertLess(finding2_idx, policy_idx)
            self.assertLess(scope_idx, kf_idx)

    def test_append_overview_task_routes_to_active_tasks_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n"
                "## Key Findings\n- none\n\n"
                "## Active Tasks\n- none\n"
            )

            memory.append_overview("Task: correlate 4625 logon failures by source ip")
            memory.append_overview("Investigate network connections from 10.0.0.5")

            overview = memory.load_overview()
            self.assertIn("Task: correlate 4625 logon failures by source ip", overview)
            self.assertIn("Investigate network connections from 10.0.0.5", overview)

            # Active Tasks section should have no -none placeholder
            if "## Active Tasks" in overview:
                at_section = overview.split("## Active Tasks", 1)[1]
                if "\n## " in at_section:
                    at_section = at_section.split("\n## ", 1)[0]
                self.assertNotIn("- none", at_section)

            # Content should be under ## Active Tasks, not under ## Key Findings
            tasks_idx = overview.index("## Active Tasks")
            kf_idx = overview.index("## Key Findings")
            task_idx = overview.index(
                "Task: correlate 4625 logon failures by source ip"
            )
            inv_idx = overview.index("Investigate network connections from 10.0.0.5")
            self.assertGreater(task_idx, tasks_idx)
            self.assertGreater(inv_idx, tasks_idx)
            self.assertGreater(task_idx, kf_idx)
            self.assertGreater(inv_idx, kf_idx)

    def test_append_overview_generic_fact_defaults_to_key_findings(self) -> None:
        """Facts with no routing keyword (the dominant check-output shape, e.g.
        'A password reset occurred on host X') must land under Key Findings,
        not pile up after the template — that pile-up was the R5 symptom."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n"
                "## Key Findings\n- none\n\n"
                "## Active Tasks\n- none\n"
            )

            memory.append_overview("A password reset occurred on 'informant-PC'")

            overview = memory.load_overview()
            kf_idx = overview.index("## Key Findings")
            tasks_idx = overview.index("## Active Tasks")
            fact_idx = overview.index("A password reset occurred on 'informant-PC'")
            self.assertGreater(fact_idx, kf_idx)
            self.assertLess(fact_idx, tasks_idx)

    def test_append_overview_falls_back_to_end_when_heading_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview("# Investigation Overview\n\n## Notes\n- existing\n")

            memory.append_overview("Some generic prose without a Key Findings heading")

            overview = memory.load_overview()
            notes_idx = overview.index("## Notes")
            prose_idx = overview.index(
                "Some generic prose without a Key Findings heading"
            )
            self.assertGreater(prose_idx, notes_idx)

    def test_append_overview_clears_seed_placeholder_in_active_tasks(self) -> None:
        """The initial-overview seed line (Awaiting initial
        investigation) is a placeholder and must vanish once a real task lands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n"
                "## Key Findings\n- none\n\n"
                "## Active Tasks\n- Awaiting initial investigation\n"
            )

            memory.append_overview(
                "Verify logon type distribution for host informant-PC"
            )

            overview = memory.load_overview()
            self.assertNotIn("Awaiting initial investigation", overview)
            self.assertIn(
                "Verify logon type distribution for host informant-PC", overview
            )
            tasks_idx = overview.index("## Active Tasks")
            task_idx = overview.index("Verify logon type distribution")
            self.assertGreater(task_idx, tasks_idx)

    def test_append_overview_routes_to_case_scope_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n"
                "## Case Scope\n- none\n\n"
                "## Key Findings\n- none\n"
            )

            memory.append_overview("Scope includes hosts SRV-01, SRV-02")

            overview = memory.load_overview()
            self.assertIn("Scope includes hosts SRV-01, SRV-02", overview)

            # Case Scope section should have no -none, Key Findings should still have it
            scope_section = overview.split("## Key Findings")[0]
            self.assertNotIn("- none", scope_section)

            scope_idx = overview.index("## Case Scope")
            content_idx = overview.index("Scope includes hosts SRV-01, SRV-02")
            kf_idx = overview.index("## Key Findings")
            self.assertGreater(content_idx, scope_idx)
            self.assertLess(content_idx, kf_idx)

    def test_r2_10_inconclusive_without_transition_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.update_overview(
                "# Investigation Overview\n\n## Key Findings\n- none\n"
            )
            overview_before = memory.load_overview()

            # Inconclusive with no new entities, no new families
            _apply_memory_updates(
                memory=memory,
                active_hypotheses=[
                    Hypothesis(
                        id="H-1", description="desc", status="active", summary=""
                    )
                ],
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
            self.assertEqual(
                overview_before,
                memory.load_overview(),
                "plain inconclusive without transition writes nothing to overview",
            )

    def test_priority_trimming_keeps_p0_over_p3(self) -> None:
        """With a tiny budget, overview and facts (P0) survive while scratch (P3) is removed."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "300"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Create files at each priority level
            memory.overview_path.write_text(
                "# Overview\n\n- key finding 1\n- key finding 2\n- key finding 3\n",
                encoding="utf-8",
            )
            memory.facts_path.write_text(
                "# Facts\n\n- confirmed fact A\n- confirmed fact B\n",
                encoding="utf-8",
            )
            memory.timeline_path.write_text(
                "# Timeline\n\n- 2026-05-12: event alpha\n- 2026-05-13: event beta\n",
                encoding="utf-8",
            )
            memory.tasks_memory_path.write_text(
                "# Tasks\n\n- [internal_db_check] check logs\n",
                encoding="utf-8",
            )
            # P2 entity
            entity_dir = memory.entities_ip_dir / "10-0-0-5.md"
            entity_dir.parent.mkdir(parents=True, exist_ok=True)
            entity_dir.write_text(
                "# 10.0.0.5\n\n- suspicious IP\n- role: source\n",
                encoding="utf-8",
            )
            # P2 keypoint
            kp_dir = memory.keypoints_dir / "KP-001.md"
            kp_dir.parent.mkdir(parents=True, exist_ok=True)
            kp_dir.write_text(
                "# KP-001\n\n- important keypoint\n",
                encoding="utf-8",
            )
            # P3 scratch
            scratch_dir = memory.scratch_global_dir
            scratch_dir.mkdir(parents=True, exist_ok=True)
            (scratch_dir / "scratch_notes.md").write_text(
                "# Scratch Notes\n\n- scratch item 1\n- scratch item 2\n- scratch item 3\n",
                encoding="utf-8",
            )

            files = memory.investigation_context_files()
            result = memory.load_compact_context(files, max_bytes=300)

            # P0 files must survive — overview and facts content should be present
            self.assertIn("key finding", result, "P0 overview must survive budget pressure")
            self.assertIn("confirmed fact", result, "P0 facts must survive budget pressure")
            # P3 scratch should be removed first
            self.assertNotIn("scratch item", result, "P3 scratch should be removed")

    def test_file_priority_assignment(self) -> None:
        """Verify _file_priority assigns correct levels to file paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            self.assertEqual(memory._file_priority("overview.md"), memory.PRIORITY_P0)
            self.assertEqual(memory._file_priority("facts.md"), memory.PRIORITY_P0)
            self.assertEqual(memory._file_priority("timeline.md"), memory.PRIORITY_P1)
            self.assertEqual(memory._file_priority("tasks.md"), memory.PRIORITY_P1)
            self.assertEqual(memory._file_priority("archive/refuted.md"), memory.PRIORITY_P1)
            self.assertEqual(memory._file_priority("archive/resolved_gaps.md"), memory.PRIORITY_P1)
            self.assertEqual(memory._file_priority("entities/user/alice.md"), memory.PRIORITY_P2)
            self.assertEqual(memory._file_priority("entities/ip/10-0-0-5.md"), memory.PRIORITY_P2)
            self.assertEqual(memory._file_priority("keypoints/KP-001.md"), memory.PRIORITY_P2)
            self.assertEqual(memory._file_priority("scratch/global/notes.md"), memory.PRIORITY_P3)
            self.assertEqual(memory._file_priority("scratch/H-001/scratch.md"), memory.PRIORITY_P3)

    def test_p0_never_fully_removed_under_extreme_budget(self) -> None:
        """Even with a near-zero budget, P0 files keep at least _P0_MIN_LINES lines."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "1"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Write multi-line P0 content
            overview_lines = [f"- overview item {i}" for i in range(20)]
            memory.overview_path.write_text(
                "# Overview\n\n" + "\n".join(overview_lines) + "\n",
                encoding="utf-8",
            )
            facts_lines = [f"- fact item {i}" for i in range(20)]
            memory.facts_path.write_text(
                "# Facts\n\n" + "\n".join(facts_lines) + "\n",
                encoding="utf-8",
            )

            files = ["overview.md", "facts.md"]
            result = memory.load_compact_context(files, max_bytes=1)

            # Overview and facts must NOT be fully removed
            self.assertIn("# Overview", result)
            self.assertIn("# Facts", result)
            # Must keep at least _P0_MIN_LINES from each
            overview_section = result.split("# Facts")[0]
            self.assertGreaterEqual(
                len([l for l in overview_section.splitlines() if l.strip()]),
                memory._P0_MIN_LINES - 1,  # heading counts as a line
            )

    def test_tail_trimming_preserves_head(self) -> None:
        """When files are truncated, the HEAD (first lines) of P0 files are always kept."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"LLM_MEMORY_MAX_BYTES": "400"}),
        ):
            reload_settings()
            case = Case.init(tmpdir)
            memory = MemoryManager(case)

            # Overview is large enough that even after dropping P3/P1 files,
            # overview alone exceeds budget — so it gets TRUNCATED (not removed).
            overview_lines = [f"- overview item {i}" for i in range(20)]
            memory.overview_path.write_text(
                "# Overview\n\n" + "\n".join(overview_lines) + "\n",
                encoding="utf-8",
            )
            # Small facts (P0) to survive
            memory.facts_path.write_text(
                "# Facts\n\n- confirmed fact alpha\n",
                encoding="utf-8",
            )
            # Large timeline (P1) — will be removed entirely before P0 trimming
            timeline_lines = [f"- 2026-05-{i:02d}: event {i}" for i in range(1, 21)]
            memory.timeline_path.write_text(
                "# Timeline\n\n" + "\n".join(timeline_lines) + "\n",
                encoding="utf-8",
            )
            # Scratch (P3) — removed first
            scratch_dir = memory.scratch_global_dir
            scratch_dir.mkdir(parents=True, exist_ok=True)
            scratch_lines = [f"- scratch entry {i}" for i in range(15)]
            (scratch_dir / "bulk.md").write_text(
                "# Bulk\n\n" + "\n".join(scratch_lines) + "\n",
                encoding="utf-8",
            )

            files = ["overview.md", "facts.md", "timeline.md", "scratch/global/bulk.md"]
            result = memory.load_compact_context(files, max_bytes=400)

            # Head of overview must be preserved (first items)
            self.assertIn("overview item 0", result)
            self.assertIn("overview item 1", result)
            # Later items may be trimmed away
            # Facts must survive
            self.assertIn("confirmed fact alpha", result)
            # P3 scratch must be removed
            self.assertNotIn("scratch entry", result)
            # Timeline should be removed (over budget even after scratch)
            self.assertNotIn("event 1", result)


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
