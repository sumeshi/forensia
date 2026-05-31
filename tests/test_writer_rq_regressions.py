from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from forensia.core.case import Case
from forensia.ai.section_agent import (
    _fallback_narrative_body,
    _is_effectively_empty_body,
    _question_routing_answer_spec,
    run_section_block_agent,
)
from forensia.config import clear_llm_settings_cache
from forensia.db.database import CaseDB
from forensia.report.writer import (
    _GateCtx,
    _assemble_section_body,
    _check_recommendations_strength,
    build_structured_answer,
    _check_citation_token_no_finding_id,
    _check_hedge_no_citation,
    _render_structured_answer_markdown,
    _resolve_evidence_results,
    _validate_body_evidence_ids,
)


class WriterRQRegressionTests(unittest.TestCase):
    def test_status_only_narration_gets_deterministic_fallback(self) -> None:
        self.assertTrue(_is_effectively_empty_body("**Status:** answered"))
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Executive Summary",
                status="partial",
                collected_results=[
                    {
                        "kind": "rows",
                        "keypoint": "raw_sql",
                        "row_count": 2,
                        "evidence_ids": ["evtx-security-000000000122"],
                        "sample_rows": [
                            {
                                "timestamp": "2015-03-22T14:34:28",
                                "event_id": 4624,
                                "computer": "informant-PC",
                                "target_user": "informant",
                                "evidence_id": "evtx-security-000000000122",
                            }
                        ],
                    }
                ],
                flat_evidence=[
                    {
                        "timestamp": "2015-03-22T14:34:28",
                        "event_id": 4624,
                        "computer": "informant-PC",
                        "target_user": "informant",
                        "evidence_id": "evtx-security-000000000122",
                    }
                ],
                actual_query_count=1,
                actual_query_row_counts=[2],
            )
            clear_llm_settings_cache()

        self.assertIn("**Status:** partial", body)
        self.assertIn("evtx-security-000000000122", body)
        self.assertGreater(len(body), 120)

    def test_not_found_fallback_does_not_emit_block_skipped_marker(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Network Activity",
                status="not_found",
                collected_results=[
                    {"kind": "rows", "keypoint": "evtx_network_connections", "row_count": 0, "sample_rows": []}
                ],
                flat_evidence=[],
                actual_query_count=1,
                actual_query_row_counts=[0],
            )
            clear_llm_settings_cache()

        self.assertIn("returned no matching rows", body)
        self.assertNotIn("Block skipped", body)

    def test_assemble_section_body_preserves_template_preamble(self) -> None:
        body = _assemble_section_body("# Investigation Overview", ["## Executive Summary\n\nBody"])
        self.assertTrue(body.startswith("# Investigation Overview\n\n## Executive Summary"))

    def test_recommendation_strength_accepts_japanese_verification_wording(self) -> None:
        ctx = _GateCtx(
            section_key="5_recommendations",
            title="Recommendations",
            evidence_results=[],
            db=None,
            behaviors=("require_recommendations_strength",),
        )
        note, cap = _check_recommendations_strength(
            "追加の相関確認を行い、根拠が揃った後に封じ込めを判断する。",
            ctx,
        )
        self.assertIsNone(note)
        self.assertIsNone(cap)

    def test_question_routing_resolves_specific_shutdown_and_logon_specs(self) -> None:
        self.assertEqual("last_shutdown_event", _question_routing_answer_spec("Last recorded shutdown time", ""))
        self.assertEqual("last_human_logon", _question_routing_answer_spec("Last logged-on user", ""))
        self.assertEqual("daily_session_activity", _question_routing_answer_spec("Startup, shutdown, logon, and logoff history", ""))

    def test_missing_reason_string_renders_as_one_bullet(self) -> None:
        markdown = _render_structured_answer_markdown(
            {
                "id": "Q-TEST",
                "status": "answered",
                "answer": [{"value": "example"}],
                "missing_reason": "single reason string",
                "queries_run": ["SELECT 1"],
            },
            "Q-TEST",
        )
        section = markdown.split("### Missing Reason", 1)[1].split("### Queries Run", 1)[0]
        bullets = [line.strip() for line in section.splitlines() if line.strip().startswith("-")]
        self.assertEqual(["- single reason string"], bullets)

    def test_structured_markdown_previews_large_tables(self) -> None:
        markdown = _render_structured_answer_markdown(
            {
                "id": "Q-BIG",
                "status": "answered",
                "answer": [{"value": index, "paths": [f"path-{sub}" for sub in range(8)]} for index in range(30)],
                "missing_reason": [],
                "queries_run": ["structured:test"],
                "json_path": "structured/answers.json",
                "csv_path": "structured/Q-BIG.csv",
            },
            "Large Answer",
        )

        self.assertIn("Showing 25 of 30 rows", markdown)
        self.assertIn("... (+3 more)", markdown)
        self.assertNotIn("| 29 |", markdown)

    def test_benchmark_keypoint_sql_executes_on_minimal_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, is_deleted, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000001-01",
                        r"C:\Users\Alice\AppData\Local\Google\Drive\sync_config.db",
                        "sync_config.db",
                        False,
                        datetime.now(UTC).replace(tzinfo=None),
                    ),
                )
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, is_deleted, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000002-01",
                        r"C:\Users\Alice\Desktop\resignation_letter.docx",
                        "resignation_letter.docx",
                        False,
                        datetime.now(UTC).replace(tzinfo=None),
                    ),
                )
                results = _resolve_evidence_results(
                    case,
                    db,
                    keypoints=["structured_cloud_artifacts", "structured_resignation_files"],
                )

            keypoints = {result["keypoint"] for result in results}
            self.assertIn("structured_cloud_artifacts", keypoints)
            self.assertIn("structured_resignation_files", keypoints)
            cloud = next(result for result in results if result["keypoint"] == "structured_cloud_artifacts")
            resignation = next(result for result in results if result["keypoint"] == "structured_resignation_files")
            self.assertGreaterEqual(cloud["row_count"], 1)
            self.assertGreaterEqual(resignation["row_count"], 1)

    def test_structured_benchmark_last_logon_persists_json_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, event_id, timestamp, computer, target_user, logon_type, process_name, src_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                        "informant",
                        "2",
                        r"C:\Windows\System32\winlogon.exe",
                        "127.0.0.1",
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_human_logon",
                    answer_id="Q8",
                    section_key="6_appendix",
                    block_heading="2. Last logged-on user",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("answered", answer["status"])
            self.assertEqual(["logon_time", "computer", "user_name", "logon_type", "process_name", "src_ip", "evidence_id"], answer["columns"])
            self.assertEqual("informant", answer["answer"][0]["user_name"])
            self.assertIn("2015-03-22T14:34:28", answer["answer"][0]["logon_time"])
            self.assertTrue((case.reports_dir / "structured" / "Q8.csv").exists())
            answers = json.loads((case.reports_dir / "structured" / "answers.json").read_text(encoding="utf-8"))
            self.assertEqual("Q8", answers[0]["id"])

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-system-000000000001", 6006, datetime(2015, 3, 22, 14, 38, 16), "informant-PC"),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-security-000000000002", 4624, datetime(2015, 3, 25, 15, 31, 0), "informant-PC"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_shutdown_event",
                    answer_id="Q9",
                    section_key="6_appendix",
                    block_heading="3. Last shutdown time",
                )

            self.assertIsNotNone(answer)
            self.assertEqual(6006, answer["answer"][0]["event_id"])
            self.assertIn("2015-03-22T14:38:16", answer["answer"][0]["shutdown_time"])

    def test_question_marker_structured_block_bypasses_llm_plan_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-system-000000000001", 6006, datetime(2015, 3, 22, 14, 38, 16), "informant-PC"),
                )
                result = run_section_block_agent(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading="Last shutdown time",
                    template_body="<!-- question -->",
                    context_sections={},
                    current_section_outline=[],
                    report_brief={},
                    base_url="http://127.0.0.1:1",
                    model="unused",
                    benchmark_mode=True,
                    answer_id="Q9",
                )

            self.assertEqual("answered", result.status)
            self.assertIn("2015-03-22T14:38:16", result.body)
            self.assertTrue((case.reports_dir / "structured" / "Q9.csv").exists())

    def test_structured_benchmark_antiforensics_excludes_plain_eventlog_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    ("evtx-system-000000000001", "System", 1100, datetime(2015, 3, 25, 15, 31, 0), "informant-PC"),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    ("evtx-security-000000000002", "Security", 1102, datetime(2015, 3, 25, 15, 32, 0), "informant-PC"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="antiforensic_activity",
                    answer_id="Q45",
                    section_key="6_appendix",
                    block_heading="12. Antiforensic activity",
                )

            self.assertIsNotNone(answer)
            event_ids = {row.get("event_id") for row in answer["answer"]}
            self.assertEqual({1102}, event_ids)

    def test_structured_benchmark_antiforensics_filters_installed_noise_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Program Files/CCleaner/Lang/lang-1041.dll",
                        "lang-1041.dll",
                        datetime(2015, 3, 13, 13, 54, 32),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Windows/Prefetch/CCLEANER64.EXE-779BD542.pf",
                        "CCLEANER64.EXE-779BD542.pf",
                        datetime(2015, 3, 25, 15, 15, 50),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="antiforensic_activity",
                    answer_id="Q45",
                    section_key="6_appendix",
                    block_heading="12. Antiforensic activity",
                )

            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertEqual({"mft-000000000002-00"}, evidence_ids)

    def test_structured_benchmark_prefetch_fallback_excludes_non_pf_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Windows/Prefetch/PfSvPerfStats.bin",
                        "PfSvPerfStats.bin",
                        "bin",
                        datetime(2015, 3, 25, 15, 31, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Windows/Prefetch/WINWORD.EXE-CECBA770.pf",
                        "WINWORD.EXE-CECBA770.pf",
                        "pf",
                        datetime(2015, 3, 25, 15, 30, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="application_execution_history",
                    answer_id="Q12",
                    section_key="6_appendix",
                    block_heading="4. Application execution history",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("partial", answer["status"])
            self.assertEqual(["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]])

    def test_structured_desktop_rename_uses_recent_lnk_alias_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/pricing decision.lnk",
                        "pricing decision.lnk",
                        datetime(2015, 3, 23, 20, 26, 54),
                        datetime(2015, 3, 23, 20, 26, 54),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/(secret_project)_pricing_decision.xlsx.lnk",
                        "(secret_project)_pricing_decision.xlsx.lnk",
                        datetime(2015, 3, 23, 20, 26, 53),
                        datetime(2015, 3, 23, 20, 26, 53),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="desktop_rename_candidates",
                    answer_id="Q24",
                    section_key="6_appendix",
                    block_heading="Desktop file renames",
                )

            self.assertEqual("partial", answer["status"])
            self.assertEqual("pricing decision", answer["answer"][0]["original_name"])
            self.assertEqual("(secret_project)_pricing_decision.xlsx", answer["answer"][0]["new_name"])

    def test_citation_gate_accepts_evtx_and_mft_evidence_ids(self) -> None:
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        body = (
            "This may indicate suspicious activity supported by "
            "evtx-security-000000000001 and mft-000000000002-01."
        )
        msg, score = _check_hedge_no_citation(body, ctx)
        self.assertIsNone(msg)
        msg, score = _check_citation_token_no_finding_id(body, ctx)
        self.assertIsNone(msg)

    def test_citation_gate_flags_citation_token_without_ids(self) -> None:
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        body = "The evidence suggests an incident, but the narrative does not name a concrete citation."
        msg, score = _check_citation_token_no_finding_id(body, ctx)
        self.assertIsNotNone(msg)

    def test_prefetch_evidence_ids_validate_against_prefetch_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) VALUES (?, ?)",
                    ("prefetch-winword-exe-cecba770", "WINWORD.EXE"),
                )
                missing = _validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-winword-exe-cecba770.",
                )

            self.assertEqual([], missing)

    def test_log_integrity_keypoints_ignore_non_eventlog_104(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-diagnosis-000000000004",
                        104,
                        datetime(2015, 3, 24, 15, 21, 37),
                        "informant-PC",
                        "Microsoft-Windows-Diagnosis-Scripted/Operational",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Diagnosis-Scripted"}}}',
                    ),
                )
                db.execute(
                    """
                    INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-eventlog-000000000104",
                        104,
                        datetime(2015, 3, 24, 15, 22, 37),
                        "informant-PC",
                        "System",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Eventlog"}}}',
                    ),
                )
                results = _resolve_evidence_results(
                    case,
                    db,
                    keypoints=["timeline_log_clearing", "gaps_log_integrity_events"],
                )

            timeline = next(result for result in results if result["keypoint"] == "timeline_log_clearing")
            gaps = next(result for result in results if result["keypoint"] == "gaps_log_integrity_events")
            self.assertEqual(["evtx-eventlog-000000000104"], timeline["evidence_ids"])
            self.assertEqual(1, timeline["row_count"])
            self.assertEqual([{"event_id": 104, "count": 1}], gaps["sample_rows"])
