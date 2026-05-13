from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
import yaml

from forensia.ai.investigator import (
    _append_hypothesis_reasoning,
    _classify_gap_kind,
    _gap_hypothesis_id,
    _inject_gap_hypotheses,
    _load_persisted_hypotheses,
    _report_cycle_progress,
    investigate,
)
from forensia.ai.planner import BroadPlanResult, HypothesisPlanResult
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.report.writer import fill_section


class PersistenceTests(unittest.TestCase):
    def test_append_hypothesis_reasoning_is_idempotent_per_query_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                first = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                second = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                count = db.execute("SELECT COUNT(*) FROM hypothesis_reasoning WHERE hypothesis_id = 'H-1'").fetchone()[0]

            self.assertEqual(first, second)
            self.assertEqual(1, count)

    def test_load_persisted_hypotheses_restores_resolved_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "H-1",
                        "suspicious lateral movement confirmed",
                        "confirmed",
                        "confirmed",
                        "resolved in prior session",
                        "broad_plan",
                        "session-old",
                        "session-old",
                        now,
                        now,
                    ),
                )
                active, resolved = _load_persisted_hypotheses(db)

            self.assertEqual(0, len(active))
            self.assertEqual(1, len(resolved))
            self.assertEqual("H-1", resolved[0].id)
            self.assertEqual("confirmed", resolved[0].status)

    def test_fill_section_upserts_report_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path("src/forensia/report_template/1_overview.md")
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n本文\n\n【調査不足: FEC を確認できなかったため】",
                ):
                    body = fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": []},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test",
                    )
                row = db.execute(
                    "SELECT section_key, title, body, confidence, status, update_count, gaps FROM report_sections WHERE section_key = ?",
                    ("1_overview",),
                ).fetchone()

            self.assertIn("【調査不足:", body)
            self.assertIsNotNone(row)
            self.assertEqual("1_overview", row[0])
            self.assertGreater(len(row[2]), 0)
            self.assertLess(float(row[3]), 1.0)
            self.assertEqual("draft", row[4])
            self.assertEqual(1, int(row[5]))

    def test_investigate_report_only_refreshes_all_sections_and_emits_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            events: list[dict[str, object]] = []
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# Section\n\n本文\n\n【調査不足: 追加確認が必要】",
                ), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    result = investigate(
                        case=case,
                        db=db,
                        base_url="http://localhost:1234",
                        model="test-model",
                        max_iter=1,
                        report_only=True,
                        progress_callback=events.append,
                    )

                section_count = db.execute("SELECT COUNT(*) FROM report_sections").fetchone()[0]
                rows = db.execute(
                    "SELECT section_key, confidence, status, update_count, gaps FROM report_sections ORDER BY section_key"
                ).fetchall()

            self.assertEqual("completed", result["status"])
            self.assertEqual(8, section_count)
            self.assertEqual(8, len(rows))
            self.assertIn("investigate/report-section", [str(event["stage"]) for event in events])
            self.assertIn("investigate/report-section-done", [str(event["stage"]) for event in events])
            self.assertIn("investigate/report-cycle-done", [str(event["stage"]) for event in events])
            self.assertEqual(8, len(result["report_sections"]["items"]))
            self.assertTrue(all(float(confidence) < 1.0 for _, confidence, _, _, _ in rows))
            self.assertTrue(all(status_name == "draft" for _, _, status_name, _, _ in rows))
            self.assertTrue(all(int(update_count) == 1 for _, _, _, update_count, _ in rows))

    def test_fill_section_promotes_stable_and_report_completion_marks_ai_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path("src/forensia/report_template/1_overview.md")
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n本文のみ",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": []},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test",
                    )
                db.execute("UPDATE report_sections SET status = 'ai_exhausted' WHERE section_key = '1_overview'")
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n本文のみ",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": []},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test-2",
                    )
                row = db.execute(
                    "SELECT status, update_count, confidence FROM report_sections WHERE section_key = '1_overview'"
                ).fetchone()

            self.assertEqual("ai_exhausted", row[0])
            self.assertEqual(2, int(row[1]))
            self.assertGreaterEqual(float(row[2]), 0.9)

    def test_finalize_section_creates_claim_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path("src/forensia/report_template/1_overview.md")
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n侵害の兆候が見られた。\n\n追加確認が必要。",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": []},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test",
                    )
                claim_count = db.execute("SELECT COUNT(*) FROM claims WHERE section_key = '1_overview'").fetchone()[0]

            self.assertGreaterEqual(int(claim_count), 1)

    def test_report_fill_writes_supported_claim_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path("src/forensia/report_template/1_overview.md")
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("F-1", "rule", "Title", "Summary", "high", 0.9, "accepted", "[]", "[]", '[{"evidence_id":"ev-1","timestamp":"2026-05-13T10:00:00"}]', "", "[]", now),
                )
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("ev-1", "a.evtx", "Security", 4624, 1, now, "host1", "", "", "", "", "", "", "", "", "", "{}", "[]", "info"),
                )
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n侵害の兆候が見られた。",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": [{"finding_id": "F-1"}]},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test",
                    )
                claim_status = db.execute("SELECT support_status FROM claims WHERE section_key = '1_overview'").fetchone()[0]

            self.assertEqual("supported", claim_status)

    def test_report_only_cycle_writes_shared_report_brief(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# Section\n\n本文",
                ), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    investigate(
                        case=case,
                        db=db,
                        base_url="http://localhost:1234",
                        model="test-model",
                        max_iter=1,
                        report_only=True,
                    )

            self.assertTrue((case.reports_dir / "report_brief.json").exists())

    def test_report_cycle_progress_can_be_true_from_gap_reduction_alone(self) -> None:
        self.assertTrue(
            _report_cycle_progress(
                {"total_gaps": 3, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )
        self.assertFalse(
            _report_cycle_progress(
                {"total_gaps": 2, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )

    def test_gap_hypotheses_are_injected_once_for_new_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(db, state, ["foo bar"], session_id="session-test")
                duplicate = _inject_gap_hypotheses(db, state, ["foo bar"], session_id="session-test")
                rows = db.execute(
                    "SELECT hypothesis_id, origin, status, description FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()

            self.assertEqual(1, added)
            self.assertEqual(0, duplicate)
            self.assertEqual(1, len(state.active_hypotheses))
            self.assertEqual(_gap_hypothesis_id("foo bar"), state.active_hypotheses[0].id)
            self.assertEqual([(_gap_hypothesis_id("foo bar"), "report_gap", "active", "foo bar")], rows)

    def test_external_or_human_gaps_do_not_become_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(
                    db,
                    state,
                    ["この src_ip の所有組織を確認", "利用者へのヒアリングが必要"],
                    session_id="session-test",
                    memory=memory,
                )
                row_count = db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]

            self.assertEqual("external_lookup", _classify_gap_kind("この src_ip の所有組織を確認"))
            self.assertEqual("human_decision", _classify_gap_kind("利用者へのヒアリングが必要"))
            self.assertEqual(0, added)
            self.assertEqual(0, row_count)
            self.assertIn("所有組織", memory.open_questions_path.read_text(encoding="utf-8"))

    def test_investigate_reinjects_gap_hypothesis_on_second_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_root = case.path / "report_template_custom"
            template_root.mkdir(parents=True, exist_ok=True)
            (template_root / "1_overview.md").write_text(
                "---\nsection: 1_overview\ntitle: Overview\nevidence_queries: []\n---\n# Overview\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                with patch(
                    "forensia.ai.investigator._seed_findings",
                    return_value=0,
                ), patch(
                    "forensia.ai.investigator.broad_plan_investigation",
                    return_value=BroadPlanResult(
                        read_more=[],
                        hypotheses=[],
                        stop=False,
                        stop_reason=None,
                        raw_response={},
                    ),
                ), patch(
                    "forensia.ai.investigator.plan_hypothesis_query",
                    return_value=HypothesisPlanResult(
                        read_more=[],
                        hypothesis=None,
                        query=None,
                        needs_more=False,
                        stop_reason=None,
                        raw_response={},
                    ),
                ), patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# Overview\n\n本文\n\n【調査不足: foo bar】",
                ), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    result = investigate(
                        case=case,
                        db=db,
                        base_url="http://localhost:1234",
                        model="test-model",
                        max_iter=2,
                        no_progress_limit=5,
                        max_queries_per_hypothesis=1,
                        template_root=template_root,
                    )

            hypotheses = result["hypotheses"]
            gap_id = _gap_hypothesis_id("foo bar")
            active_gap = next((item for item in hypotheses if item["id"] == gap_id), None)
            self.assertIsNotNone(active_gap)
            self.assertEqual("active", active_gap["status"])

    def test_case_init_creates_allowlist_stub_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            initial = case.allowlist_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(initial)
            self.assertIn("rules", parsed)
            case.allowlist_path.write_text("rules:\n  - rule_id: custom\n", encoding="utf-8")
            Case.init(tmpdir)
            preserved = case.allowlist_path.read_text(encoding="utf-8")
            self.assertEqual("rules:\n  - rule_id: custom\n", preserved)

    def test_investigate_writes_ai_logs_per_llm_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# Section\n\n本文",
                ), patch(
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    result = investigate(
                        case=case,
                        db=db,
                        base_url="http://localhost:1234",
                        model="test-model",
                        max_iter=1,
                        report_only=True,
                    )
            session_dir = case.ai_logs_dir / result["session_id"]
            self.assertTrue(session_dir.exists())
            self.assertGreaterEqual(len(list(session_dir.glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
