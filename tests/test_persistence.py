from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
import yaml
from typer.testing import CliRunner

from forensia import cli as cli_module
from forensia.ai.checker import _insert_investigation_finding
from forensia.ai.investigator import (
    _append_hypothesis_reasoning,
    _final_summary,
    investigate,
)
from forensia.ai.planner import BroadPlanResult, HypothesisPlanResult
from forensia.ai.report_gap import (
    _classify_gap_kind,
    _gap_hypothesis_id,
    _inject_gap_hypotheses,
    _report_cycle_progress,
)
from forensia.ai.hypothesis_manager import _load_persisted_hypotheses
from forensia.config import clear_llm_settings_cache, resolve_llm_config
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.report.writer import _build_report_brief, _extract_claim_texts, _section_confidence, collect_gaps, fill_section
from forensia.report_templates import export_packaged_report_templates


class PersistenceTests(unittest.TestCase):
    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def test_collect_gaps_supports_english_and_japanese_placeholders(self) -> None:
        self.assertEqual(
            ["no logon data"],
            collect_gaps({"sec": "[INSUFFICIENT EVIDENCE: no logon data]"}),
        )
        self.assertEqual(
            ["ログオン記録なし"],
            collect_gaps({"sec": "【調査不足: ログオン記録なし】"}),
        )

    def test_collect_gaps_preserves_order_while_deduplicating(self) -> None:
        self.assertEqual(
            ["gap one", "gap two"],
            collect_gaps(
                {
                    "a": "[INSUFFICIENT EVIDENCE: gap one]\n[INSUFFICIENT EVIDENCE: gap two]",
                    "b": "[INSUFFICIENT EVIDENCE: gap one]",
                }
            ),
        )

    def test_section_confidence_and_claim_extraction_respect_english_gap_placeholder(self) -> None:
        self.assertEqual(1.0, _section_confidence("no gaps here"))
        self.assertLess(_section_confidence("[INSUFFICIENT EVIDENCE: x]"), 1.0)
        self.assertEqual([], _extract_claim_texts("[INSUFFICIENT EVIDENCE: missing evidence]"))

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
                        base_url=self._llm_base_url(),
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
                        base_url=self._llm_base_url(),
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
                        base_url=self._llm_base_url(),
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
                        base_url=self._llm_base_url(),
                        model="test-model",
                        session_id="session-test-2",
                    )
                row = db.execute(
                    "SELECT status, update_count, confidence FROM report_sections WHERE section_key = '1_overview'"
                ).fetchone()

            self.assertEqual("ai_exhausted", row[0])
            self.assertEqual(2, int(row[1]))
            self.assertGreaterEqual(float(row[2]), 0.9)

    def test_human_reviewed_section_is_not_overwritten_by_fill_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = Path("src/forensia/report_template/1_overview.md")
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
                    ) VALUES ('1_overview', 'Overview', '# Locked\n\nHuman text', 1.0, 'human_reviewed', 1, '[]', 'session-1', now())
                    """
                )
                with patch(
                    "forensia.report.writer.chat_completion",
                    return_value="# Investigation Overview\n\nAI rewrite",
                ):
                    fill_section(
                        case=case,
                        db=db,
                        template_path=template_path,
                        context_sections={},
                        report_brief={"top_findings": []},
                        base_url=self._llm_base_url(),
                        model="test-model",
                        session_id="session-test",
                    )
                row = db.execute(
                    "SELECT body, status, update_count FROM report_sections WHERE section_key = '1_overview'"
                ).fetchone()

            self.assertEqual("# Locked\n\nHuman text", row[0])
            self.assertEqual("human_reviewed", row[1])
            self.assertEqual(1, int(row[2]))

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
                        base_url=self._llm_base_url(),
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
                        base_url=self._llm_base_url(),
                        model="test-model",
                        session_id="session-test",
                    )
                claim_status = db.execute("SELECT support_status FROM claims WHERE section_key = '1_overview'").fetchone()[0]

            self.assertEqual("supported", claim_status)

    def test_build_report_brief_trims_excerpt_in_sql(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("1_overview", "Overview", "x" * 800, 0.9, "draft", 1, "[]", "S-1", now),
                )
                brief = _build_report_brief(db)

            self.assertEqual(1, len(brief["prior_sections"]))
            self.assertLessEqual(len(brief["prior_sections"][0]["excerpt"]), 400)

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
                        base_url=self._llm_base_url(),
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
            self.assertIn("所有組織", memory.tasks_memory_path.read_text(encoding="utf-8"))

    def test_gap_classification_supports_english_external_and_human_keywords(self) -> None:
        for phrase in (
            "Need ip reputation check for this address",
            "Perform geo lookup for the source IP",
            "This requires external internet confirmation",
        ):
            self.assertEqual("external_lookup", _classify_gap_kind(phrase))
        for phrase in (
            "Need manager approval before concluding",
            "Confirm with the business owner",
            "Check whether this action was authorized by policy",
        ):
            self.assertEqual("human_decision", _classify_gap_kind(phrase))

    def test_final_summary_fallback_follows_output_language(self) -> None:
        with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            self.assertEqual(
                "No additional progress was made during this investigation.",
                _final_summary(SessionState(session_id="S-1")),
            )
            clear_llm_settings_cache()

    def test_investigation_finding_title_prefix_follows_output_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            planned_query = PlannedQuery(query_id="Q-1", hypothesis_id="H-1", purpose="host triage", sql="SELECT 1")
            with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "ja"}):
                clear_llm_settings_cache()
                with CaseDB(case) as db:
                    finding_id = _insert_investigation_finding(
                        case=case,
                        db=db,
                        session_id="S-1",
                        iteration=1,
                        planned_query=planned_query,
                        hypothesis=None,
                        result_summary={"sample_rows": []},
                        report_text="body",
                    )
                    title = db.execute("SELECT title FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()[0]
            self.assertEqual("調査: host triage", title)
            clear_llm_settings_cache()

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
                        base_url=self._llm_base_url(),
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

    def test_broad_plan_only_new_hypotheses_do_not_reset_no_progress_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            generated = {"count": 0}

            def fake_broad_plan(*args, **kwargs):
                generated["count"] += 1
                index = generated["count"]
                return BroadPlanResult(
                    read_more=[],
                    hypotheses=[Hypothesis(id=f"H-{index}", description=f"hypothesis {index}", status="active", summary="")],
                    stop=False,
                    stop_reason=None,
                    raw_response={},
                )

            with CaseDB(case) as db:
                with patch("forensia.ai.investigator._seed_findings", return_value=0), patch(
                    "forensia.ai.investigator.broad_plan_investigation",
                    side_effect=fake_broad_plan,
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
                    "forensia.ai.investigator.render_written_report",
                    return_value=(case.reports_dir / "report.md", case.reports_dir / "report.html"),
                ):
                    result = investigate(
                        case=case,
                        db=db,
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=5,
                        no_progress_limit=2,
                        report_every_n_cycles=999,
                    )
                    iterations = db.execute(
                        "SELECT iterations FROM investigation_sessions WHERE session_id = ?",
                        (result["session_id"],),
                    ).fetchone()[0]

            self.assertEqual("completed", result["status"])
            self.assertEqual(2, int(iterations))

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

    def test_case_init_seeds_report_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            self.assertTrue((case.report_template_dir / "1_overview.md").exists())
            self.assertTrue((case.report_template_dir / "8_recommendations.md").exists())

    def test_export_packaged_report_templates_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir)
            self.assertGreaterEqual(len(written), 8)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_templates_export_command_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(cli_module.app, ["templates-export", tmpdir])
            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_investigate_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "custom-templates"
            export_packaged_report_templates(template_dir)
            runner = CliRunner()
            captured: dict[str, object] = {}

            def fake_investigate_loop(*args, **kwargs):
                captured["template_root"] = kwargs.get("template_root")
                return {
                    "session_id": "session-test",
                    "status": "completed",
                    "iteration": 1,
                    "summary": "done",
                    "hypotheses": [],
                    "report_sections": {"items": []},
                }

            with patch("forensia.cli.investigate_loop", side_effect=fake_investigate_loop):
                result = runner.invoke(
                    cli_module.app,
                    [
                        "investigate",
                        str(case.path),
                        "--llm-base-url",
                        "http://127.0.0.1:1234",
                        "--model",
                        "test-model",
                        "--template-dir",
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])

    def test_investigate_command_rejects_empty_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            empty_dir = Path(tmpdir) / "empty-templates"
            empty_dir.mkdir()
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "investigate",
                    str(case.path),
                    "--llm-base-url",
                    "http://127.0.0.1:1234",
                    "--model",
                    "test-model",
                    "--template-dir",
                    str(empty_dir),
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("[0-9]*_*.md", result.output)

    def test_run_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            template_dir = Path(tmpdir) / "custom-templates"
            export_packaged_report_templates(template_dir)
            runner = CliRunner()
            captured: dict[str, object] = {}

            def fake_investigate_loop(*args, **kwargs):
                captured["template_root"] = kwargs.get("template_root")
                return {
                    "session_id": "session-test",
                    "status": "completed",
                    "iteration": 1,
                    "summary": "done",
                    "hypotheses": [],
                    "report_sections": {"items": []},
                }

            with patch("forensia.cli.ingest_all", return_value={"new_files": 0, "skipped_files": 0, "evtx_files": 0, "mft_files": 0}), patch(
                "forensia.cli.normalize_all",
                return_value={"evtx_rows": 0, "mft_entries": 0, "mft_timeline_rows": 0},
            ), patch("forensia.cli.load_rules_from_dir", return_value=[]), patch(
                "forensia.cli.investigate_loop",
                side_effect=fake_investigate_loop,
            ), patch(
                "forensia.cli.render_written_report",
                return_value=(output_dir / "reports" / "report.md", output_dir / "reports" / "report.html"),
            ):
                result = runner.invoke(
                    cli_module.app,
                    [
                        "run",
                        str(input_dir),
                        "--out",
                        str(output_dir),
                        "--llm-base-url",
                        "http://127.0.0.1:1234",
                        "--model",
                        "test-model",
                        "--template-dir",
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])

    def test_run_command_rejects_unknown_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "run",
                    str(input_dir),
                    "--out",
                    str(output_dir),
                    "--profile",
                    "does-not-exist",
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("Available profiles", result.output)

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
                        base_url=self._llm_base_url(),
                        model="test-model",
                        max_iter=1,
                        report_only=True,
                    )
            session_dir = case.ai_logs_dir / result["session_id"]
            self.assertTrue(session_dir.exists())
            self.assertGreaterEqual(len(list(session_dir.glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
