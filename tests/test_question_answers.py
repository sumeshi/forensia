from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime

from forensia.ai.sections.section_agent import run_section_block_agent
from forensia.ai.sections.section_answers import build_daily_session_timeline
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import load_event_class_definitions
from forensia.report.answers.answer_registry import build_structured_answer
from forensia.report.answers.keypoint_catalog import resolve_evidence_results
from forensia.report.sections.quality_gates import (
    GateContext,
    check_citation_token_no_finding_id,
    check_hedge_no_citation,
)
from forensia.report.sections.section_finalize import (
    validate_section_evidence_ids,
)
from forensia.report.sections.section_quality import validate_body_evidence_ids
from forensia.report.sections.section_store import dump_section_questions_json


class QuestionAnswerTests(unittest.TestCase):
    """Structured question/keypoint SQL answers and evidence-id validation."""

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
                results = resolve_evidence_results(
                    case,
                    db,
                    keypoints=[
                        "structured_cloud_artifacts",
                        "structured_resignation_files",
                    ],
                )

            keypoints = {result["keypoint"] for result in results}
            self.assertIn("structured_cloud_artifacts", keypoints)
            self.assertIn("structured_resignation_files", keypoints)
            cloud = next(
                result
                for result in results
                if result["keypoint"] == "structured_cloud_artifacts"
            )
            resignation = next(
                result
                for result in results
                if result["keypoint"] == "structured_resignation_files"
            )
            self.assertGreaterEqual(cloud["row_count"], 1)
            self.assertGreaterEqual(resignation["row_count"], 1)

    def test_resignation_file_timestamps_uses_question_spec_evidence_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000003-01",
                        r"C:\Users\Alice\Desktop\resignation_letter.docx",
                        "resignation_letter.docx",
                        "docx",
                        datetime(2015, 3, 25, 15, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="resignation_file_timestamps",
                    answer_id="Q28",
                    section_key="6_appendix",
                    block_heading="Resignation file timestamps",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(
                ["structured:resignation_file_timestamps:mft_topic_keyword_files"],
                answer.get("queries_run"),
            )
            self.assertEqual(
                "resignation_letter.docx",
                answer["answer"][0].get("file_name"),
            )

    def test_email_data_files_uses_question_spec_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension,
                        si_created, si_modified
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000004-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 10, 0),
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="Q-email",
                    section_key="6_appendix",
                    block_heading="Email data files",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(["structured:email_data_files:mft"], answer["queries_run"])
            self.assertEqual("mailbox.ost", answer["answer"][0].get("file_name"))

    def test_email_application_usage_uses_question_spec_catalog_label(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000005-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_application_usage",
                    answer_id="Q-email-app",
                    section_key="6_appendix",
                    block_heading="Email application",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(
                "Microsoft Outlook", answer["answer"][0].get("application_name")
            )

    def test_email_application_usage_ranks_stationery_after_mail_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for index in range(35):
                    db.execute(
                        """
                        INSERT INTO mft_entries (
                            evidence_id, file_path, file_name, extension, si_modified
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            f"mft-stationery-{index:04d}",
                            rf"C:\Users\Alice\AppData\Local\Microsoft\Windows Mail\Stationery\image-{index}.jpg",
                            f"image-{index}.jpg",
                            "jpg",
                            datetime(2015, 3, 25, 15, index % 60, 0),
                        ),
                    )
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-mailbox-priority",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 20, 12, 0, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_application_usage",
                    answer_id="Q-email-app-ranked",
                    section_key="6_appendix",
                    block_heading="Email application",
                )

            self.assertEqual(
                "mailbox.ost", answer["answer"][0]["artifact_path"].rsplit("\\", 1)[-1]
            )

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
            self.assertEqual(
                [
                    "logon_time",
                    "computer",
                    "user_name",
                    "logon_type",
                    "process_name",
                    "src_ip",
                    "evidence_id",
                ],
                answer["columns"],
            )
            self.assertEqual("informant", answer["answer"][0]["user_name"])
            self.assertIn("2015-03-22T14:34:28", answer["answer"][0]["logon_time"])
            self.assertTrue((case.reports_dir / "structured" / "Q8.csv").exists())
            answers = json.loads(
                (case.reports_dir / "structured" / "answers.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("Q8", answers[0]["id"])

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000002",
                        4624,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                    ),
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
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
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
                    question_mode=True,
                    answer_id="Q9",
                )

            self.assertEqual("answered", result.status)
            self.assertIn("2015-03-22T14:38:16", result.body)
            self.assertTrue((case.reports_dir / "structured" / "Q9.csv").exists())

    def test_section_question_resolution_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
                )
                run_section_block_agent(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading="Most recent shutdown",
                    template_body="<!-- question -->",
                    context_sections={},
                    current_section_outline=[],
                    report_brief={},
                    base_url="http://127.0.0.1:1",
                    model="unused",
                    question_mode=True,
                    answer_id="Q9",
                )
                row = db.execute(
                    """
                    SELECT answer_spec, question_type, status
                    FROM section_questions
                    WHERE section_key = '6_appendix'
                      AND block_heading = 'Most recent shutdown'
                    LIMIT 1
                    """
                ).fetchone()
                dump_section_questions_json(case, db, "6_appendix")

            self.assertIsNotNone(row)
            self.assertEqual(
                ("last_shutdown_event", "investigation_window", "resolved"), tuple(row)
            )
            debug_path = case.reports_dir / "debug" / "6_appendix_questions.json"
            self.assertTrue(debug_path.exists())
            self.assertIn("last_shutdown_event", debug_path.read_text(encoding="utf-8"))

    def test_generic_question_spec_builder_executes_yaml_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="case_event_window",
                    answer_id="Q-window",
                    section_key="1_overview",
                    block_heading="Case time range",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("answered", answer["status"])
            self.assertEqual(
                ["first_event", "last_event", "event_count"], answer["columns"]
            )
            self.assertEqual(1, answer["answer"][0]["event_count"])

    def test_structured_benchmark_antiforensics_excludes_plain_eventlog_shutdown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-system-000000000001",
                        "System",
                        1100,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-security-000000000002",
                        "Security",
                        1102,
                        datetime(2015, 3, 25, 15, 32, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-security-000000000003",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 33, 0),
                        "informant-PC",
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

            self.assertIsNotNone(answer)
            event_ids = {row.get("event_id") for row in answer["answer"]}
            self.assertEqual({1102}, event_ids)
            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertNotIn("evtx-system-000000000001", evidence_ids)
            self.assertNotIn("evtx-security-000000000003", evidence_ids)

    def test_structured_benchmark_antiforensics_filters_installed_noise_files(
        self,
    ) -> None:
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
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000003-00",
                        "Windows/System32/cipher.exe",
                        "cipher.exe",
                        datetime(2009, 7, 14, 1, 38, 59),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000004-00",
                        "Program Files/CCleaner/CCleaner64.exe",
                        "CCleaner64.exe",
                        datetime(2015, 3, 13, 11, 10, 26),
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

    def test_structured_antiforensics_uses_ioc_catalog_tool_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions "
                    "(evidence_id, executable_name, exec_count, last_exec_time) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        "prefetch-privazer-exe-0001",
                        "PrivaZer.exe",
                        1,
                        datetime(2015, 3, 25, 15, 40, 0),
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
            self.assertIn("prefetch-privazer-exe-0001", evidence_ids)

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
            self.assertEqual(
                ["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]]
            )

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

            self.assertEqual("candidate_only", answer["status"])
            self.assertEqual("pricing decision", answer["answer"][0]["original_name"])
            self.assertEqual(
                "(secret_project)_pricing_decision.xlsx",
                answer["answer"][0]["new_name"],
            )

    def test_citation_gate_accepts_evtx_and_mft_evidence_ids(self) -> None:
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        body = (
            "This may indicate suspicious activity supported by "
            "evtx-security-000000000001 and mft-000000000002-01."
        )
        msg, score = check_hedge_no_citation(body, ctx)
        self.assertIsNone(msg)
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNone(msg)

    def test_citation_gate_flags_citation_token_without_ids(self) -> None:
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        body = "The evidence suggests an incident, but the narrative does not name a concrete citation."
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNotNone(msg)

    def test_prefetch_evidence_ids_validate_against_prefetch_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) VALUES (?, ?)",
                    ("prefetch-winword-exe-cecba770", "WINWORD.EXE"),
                )
                missing = validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-winword-exe-cecba770.",
                )

            self.assertEqual([], missing)

    def test_validate_section_evidence_ids_removes_fabricated_keeps_real(self) -> None:
        """Real evidence IDs stay cited while fabricated IDs are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
                )
                body = (
                    "The real event evtx-security-000000000001 supported by evidence. "
                    "The fabricated event （evtx-security-999999999999） not in DB. "
                    "Another fabricated one (mft-999999999999-99) also not present."
                )
                cleaned, gaps = validate_section_evidence_ids(db, body)

                self.assertIn("evtx-security-000000000001", cleaned)
                self.assertNotIn("evtx-security-999999999999", cleaned)
                self.assertNotIn("security-999999999999", cleaned)
                self.assertNotIn("mft-999999999999-99", cleaned)
                self.assertNotIn("（）", cleaned)
                self.assertNotIn("()", cleaned)
                self.assertNotIn("（,", cleaned)
                self.assertTrue(
                    any("evtx-security-999999999999" in g for g in gaps),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertTrue(
                    any("mft-999999999999-99" in g for g in gaps),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertFalse(
                    any("evtx-security-000000000001" in g for g in gaps),
                    msg=f"real ID in gaps: {gaps}",
                )

    def test_validate_section_evidence_ids_keeps_valid_id_sharing_parens_with_invalid(
        self,
    ) -> None:
        """Removing invalid IDs must not remove valid IDs from the same citation group."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000122",
                        4648,
                        datetime(2015, 3, 22, 15, 57, 54),
                        "informant-PC",
                    ),
                )
                body = (
                    "Invalid first （evtx-security-999999999999, evtx-security-000000000122） here. "
                    "Invalid last (evtx-security-000000000122, evtx-bogus-999999999999) there."
                )
                cleaned, _gaps = validate_section_evidence_ids(db, body)

                self.assertIn("（evtx-security-000000000122）", cleaned)
                self.assertIn("(evtx-security-000000000122)", cleaned)
                self.assertNotIn("evtx-security-999999999999", cleaned)
                self.assertNotIn("evtx-bogus-999999999999", cleaned)


class DailySessionTimelineBuilderTests(unittest.TestCase):
    """Daily session timeline answer builder over evtx event classes."""

    def test_load_event_class_definitions(self):
        classes = load_event_class_definitions()
        self.assertIn("startup", classes)
        self.assertIn("shutdown", classes)
        self.assertIn("logon", classes)
        self.assertIn("logoff", classes)
        self.assertEqual(classes["startup"]["event_ids"], [6005, 12])
        self.assertEqual(classes["shutdown"]["event_ids"], [6006, 13, 1074])
        # 4648 (explicit credential use) is deliberately NOT in the logon
        # class: session/daily-timeline builders count logons from this class,
        # and explicit credential use is not a logon. It lives in the separate
        # explicit_credential class consumed by auth-pattern code paths.
        self.assertEqual(classes["logon"]["event_ids"], [4624])
        self.assertEqual(classes["explicit_credential"]["event_ids"], [4648])
        self.assertEqual(classes["logon"]["logon_types"], [2, 10, 11])
        self.assertEqual(classes["logoff"]["event_ids"], [4634, 4647])

    def test_builder_with_empty_db_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                rows = build_daily_session_timeline(db)
                self.assertEqual(rows, [])

    def test_builder_returns_correct_shape_over_two_days(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Day 1: 2015-03-22
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e1",
                        6005,
                        datetime(2015, 3, 22, 8, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e2",
                        4624,
                        datetime(2015, 3, 22, 8, 15, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e3",
                        4624,
                        datetime(2015, 3, 22, 9, 0, 0),
                        "HOST1",
                        "bob",
                        "10",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e4",
                        4634,
                        datetime(2015, 3, 22, 17, 0, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e5",
                        1074,
                        datetime(2015, 3, 22, 17, 30, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )

                # Day 2: 2015-03-23
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e6",
                        12,
                        datetime(2015, 3, 23, 7, 45, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e7",
                        4624,
                        datetime(2015, 3, 23, 8, 5, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e8",
                        4647,
                        datetime(2015, 3, 23, 16, 45, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e9",
                        6006,
                        datetime(2015, 3, 23, 17, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )

                rows = build_daily_session_timeline(db)

        self.assertEqual(len(rows), 2)

        day1 = rows[0]
        self.assertEqual(day1["date"], "2015-03-22")
        self.assertEqual(day1["first_startup"], "2015-03-22 08:00:00")
        self.assertEqual(day1["first_logon"], "2015-03-22 08:15:00")
        self.assertEqual(day1["last_logoff"], "2015-03-22 17:00:00")
        self.assertEqual(day1["last_shutdown"], "2015-03-22 17:30:00")
        self.assertIn("alice", day1["logon_users"])
        self.assertIn("bob", day1["logon_users"])
        self.assertEqual(day1["interactive_logon_count"], 2)

        day2 = rows[1]
        self.assertEqual(day2["date"], "2015-03-23")
        self.assertEqual(day2["first_startup"], "2015-03-23 07:45:00")
        self.assertEqual(day2["first_logon"], "2015-03-23 08:05:00")
        self.assertEqual(day2["last_logoff"], "2015-03-23 16:45:00")
        self.assertEqual(day2["last_shutdown"], "2015-03-23 17:00:00")
        self.assertIn("charlie", day2["logon_users"])
        self.assertEqual(day2["interactive_logon_count"], 1)

    def test_builder_respects_hour_qualifiers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e1",
                        6005,
                        datetime(2015, 3, 22, 9, 5, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                # This logon is outside qualifier window (before 09:00) so should be excluded
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e2",
                        4624,
                        datetime(2015, 3, 22, 8, 0, 0),
                        "HOST1",
                        "bob",
                        "2",
                    ),
                )
                # This logon is within the window (09:00-18:00)
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e3",
                        4624,
                        datetime(2015, 3, 22, 9, 0, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )

                qualifiers = {"hour_from": "09:00", "hour_to": "18:00"}
                rows = build_daily_session_timeline(db, qualifiers)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["date"], "2015-03-22")
        self.assertEqual(rows[0]["first_startup"], "2015-03-22 09:05:00")
        self.assertEqual(rows[0]["first_logon"], "2015-03-22 09:00:00")
        self.assertEqual(rows[0]["last_logoff"], "")
        self.assertEqual(rows[0]["last_shutdown"], "")
        self.assertEqual(rows[0]["interactive_logon_count"], 1)  # bob at 08:00 excluded


if __name__ == "__main__":
    unittest.main()
