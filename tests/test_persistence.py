from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from forensia.ai.investigator import (
    _gap_hypothesis_id,
    _inject_gap_hypotheses,
    _load_persisted_hypotheses,
    _report_cycle_progress,
    investigate,
)
from forensia.ai.planner import BroadPlanResult, HypothesisPlanResult
from forensia.core.case import Case
from forensia.core.session import SessionState
from forensia.db.database import CaseDB
from forensia.report.writer import fill_section


class PersistenceTests(unittest.TestCase):
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

    def test_fill_section_promotes_stable_and_report_completion_marks_approved(self) -> None:
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
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test",
                    )
                db.execute("UPDATE report_sections SET status = 'approved' WHERE section_key = '1_overview'")
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# 調査概要\n\n本文のみ",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        base_url="http://localhost:1234",
                        model="test-model",
                        session_id="session-test-2",
                    )
                row = db.execute(
                    "SELECT status, update_count, confidence FROM report_sections WHERE section_key = '1_overview'"
                ).fetchone()

            self.assertEqual("approved", row[0])
            self.assertEqual(2, int(row[1]))
            self.assertGreaterEqual(float(row[2]), 0.9)

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


if __name__ == "__main__":
    unittest.main()
