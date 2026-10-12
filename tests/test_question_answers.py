from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime

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


class QuestionAnswerTests(unittest.TestCase):
    """Structured question/keypoint SQL answers and evidence-id validation."""

    def test_host_execution_keypoint_requires_event_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with CaseDB(Case.init(tmpdir)) as db:
                events = [
                    (
                        4104,
                        "Application",
                        "Microsoft-Windows-Winlogon",
                        "wrong-channel",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-Winlogon",
                        "wrong-provider",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-PowerShell",
                        "powershell-event",
                    ),
                    (
                        4104,
                        "Microsoft-Windows-PowerShell/Operational",
                        None,
                        "missing-provider",
                    ),
                    (
                        4688,
                        "Security",
                        "Microsoft-Windows-Security-Auditing",
                        "process-event",
                    ),
                ]
                for index, (event_id, channel, provider, evidence_id) in enumerate(
                    events
                ):
                    raw_json = json.dumps(
                        {"winlog": {"provider": {"name": provider}}}
                        if provider
                        else {"winlog": {}}
                    )
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, event_id, channel, timestamp, computer,
                            process_name, raw_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"evtx-{index}",
                            event_id,
                            channel,
                            datetime(2015, 3, 22, 14, index),
                            "PC-01",
                            evidence_id,
                            raw_json,
                        ),
                    )

                result = resolve_evidence_results(
                    db, keypoints=["host_execution_activity"]
                )[0]

            self.assertEqual(2, result["row_count"])
            self.assertEqual(
                {"powershell-event", "process-event"},
                {row["process_name"] for row in result["sample_rows"]},
            )

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
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-01",
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
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-01",
                        r"C:\Users\Alice\Desktop\resignation_letter.docx",
                        "resignation_letter.docx",
                        False,
                        datetime.now(UTC).replace(tzinfo=None),
                    ),
                )
                results = resolve_evidence_results(
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
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000004-01",
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
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000005-01",
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
                        evidence_id, event_id, channel, timestamp, computer, target_user,
                        logon_type, process_name, src_ip, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        4624,
                        "Security",
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                        "informant",
                        "2",
                        r"C:\Windows\System32\winlogon.exe",
                        "127.0.0.1",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
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
            answer_path = case.reports_dir / answer["json_path"]
            self.assertTrue(answer_path.exists())
            self.assertEqual(
                "Q8", json.loads(answer_path.read_text(encoding="utf-8"))["id"]
            )

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, channel, timestamp, computer, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system-000000000001",
                        6006,
                        "System",
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                        '{"winlog":{"provider":{"name":"EventLog"}}}',
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, channel, timestamp, computer, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-wrong-context",
                        6006,
                        "Application",
                        datetime(2015, 3, 24, 14, 38, 16),
                        "informant-PC",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Winlogon"}}}',
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
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

    def test_structured_benchmark_antiforensics_filters_noise_across_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?), (?, ?, ?, ?, ?)",
                    (
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
                        "Security",
                        1102,
                        datetime(2015, 3, 25, 15, 32, 0),
                        "informant-PC",
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000003",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 33, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "UPDATE evtx_events SET raw_json = ? WHERE event_id IN (1100, 1102)",
                    ('{"winlog":{"provider":{"name":"Microsoft-Windows-Eventlog"}}}',),
                )
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) VALUES (?, ?, ?, ?)",
                    (
                        "prefetch-privazer-exe-0001",
                        "PrivaZer.exe",
                        1,
                        datetime(2015, 3, 25, 15, 40, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Program Files/CCleaner/Lang/lang-1041.dll",
                        "lang-1041.dll",
                        datetime(2015, 3, 13, 13, 54, 32),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                        "Windows/Prefetch/CCLEANER64.EXE-779BD542.pf",
                        "CCLEANER64.EXE-779BD542.pf",
                        datetime(2015, 3, 25, 15, 15, 50),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000003-00",
                        "Windows/System32/cipher.exe",
                        "cipher.exe",
                        datetime(2009, 7, 14, 1, 38, 59),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000004-00",
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
            self.assertEqual(
                {
                    "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
                    "prefetch-privazer-exe-0001",
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000002",
                },
                evidence_ids,
            )
            event_ids = {
                row.get("event_id")
                for row in answer["answer"]
                if row.get("event_id") is not None
            }
            self.assertEqual({1102}, event_ids)

    def test_structured_benchmark_prefetch_fallback_excludes_non_pf_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Windows/Prefetch/PfSvPerfStats.bin",
                        "PfSvPerfStats.bin",
                        "bin",
                        datetime(2015, 3, 25, 15, 31, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
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
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/pricing decision.lnk",
                        "pricing decision.lnk",
                        datetime(2015, 3, 23, 20, 26, 54),
                        datetime(2015, 3, 23, 20, 26, 54),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-00",
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
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001 and mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000002-01."
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
                    (
                        "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-winword-exe-cecba770",
                        "WINWORD.EXE",
                    ),
                )
                missing = validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-winword-exe-cecba770.",
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
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
                )
                body = (
                    "The real event evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001 supported by evidence. "
                    "The fabricated event （evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999） not in DB. "
                    "Another fabricated one (mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99) also not present."
                )
                cleaned, gaps = validate_section_evidence_ids(db, body)

                self.assertIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
                    cleaned,
                )
                self.assertNotIn("security-999999999999", cleaned)
                self.assertNotIn(
                    "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99",
                    cleaned,
                )
                self.assertNotIn("（）", cleaned)
                self.assertNotIn("()", cleaned)
                self.assertNotIn("（,", cleaned)
                self.assertTrue(
                    any(
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999"
                        in g
                        for g in gaps
                    ),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertTrue(
                    any(
                        "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-999999999999-99"
                        in g
                        for g in gaps
                    ),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertFalse(
                    any(
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001"
                        in g
                        for g in gaps
                    ),
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
                        "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122",
                        4648,
                        datetime(2015, 3, 22, 15, 57, 54),
                        "informant-PC",
                    ),
                )
                body = (
                    "Invalid first （evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122） here. "
                    "Invalid last (evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122, evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bogus-999999999999) there."
                )
                cleaned, _gaps = validate_section_evidence_ids(db, body)

                self.assertIn(
                    "（evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122）",
                    cleaned,
                )
                self.assertIn(
                    "(evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000122)",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
                    cleaned,
                )
                self.assertNotIn(
                    "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bogus-999999999999",
                    cleaned,
                )


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
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="daily_session_timeline",
                    answer_id="daily",
                    section_key="2_timeline",
                    block_heading="Daily session timeline",
                )
                self.assertEqual(answer["answer"], [])
                self.assertEqual(answer["status"], "not_found")

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
                db.execute(
                    """
                    UPDATE evtx_events
                    SET channel = CASE WHEN event_id IN (6005, 6006, 6008, 12, 13, 1074) THEN 'System' ELSE 'Security' END,
                        raw_json = CASE
                          WHEN event_id IN (6005, 6006, 6008) THEN '{"winlog":{"provider":{"name":"EventLog"}}}'
                          WHEN event_id IN (12, 13) THEN '{"winlog":{"provider":{"name":"Microsoft-Windows-Kernel-General"}}}'
                          WHEN event_id = 1074 THEN '{"winlog":{"provider":{"name":"User32"}}}'
                          ELSE '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}'
                        END
                    WHERE event_id IN (6005, 6006, 6008, 12, 13, 4624, 4634, 4647, 1074)
                    """
                )

                rows = build_structured_answer(
                    case,
                    db,
                    answer_spec="daily_session_timeline",
                    answer_id="daily",
                    section_key="2_timeline",
                    block_heading="Daily session timeline",
                )["answer"]

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
        self.assertEqual(
            set(day1["evidence_ids"]),
            {"evtx-e1", "evtx-e2", "evtx-e3", "evtx-e4", "evtx-e5"},
        )
        self.assertEqual(len(day1["event_trace"]), 5)
        self.assertIn("UTC event_id=", day1["event_trace"][0])

        day2 = rows[1]
        self.assertEqual(day2["date"], "2015-03-23")
        self.assertEqual(day2["first_startup"], "2015-03-23 07:45:00")
        self.assertEqual(day2["first_logon"], "2015-03-23 08:05:00")
        self.assertEqual(day2["last_logoff"], "2015-03-23 16:45:00")
        self.assertEqual(day2["last_shutdown"], "2015-03-23 17:00:00")
        self.assertIn("charlie", day2["logon_users"])
        self.assertEqual(day2["interactive_logon_count"], 1)

    def test_builder_respects_body_scope_and_evidence_date_timezone(self):
        from forensia.report.report_validation import check_claim_traceability
        from forensia.report.sections.section_refresher import _block_projection

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir, source_timezone="America/New_York")
            with CaseDB(case) as db:
                times = [
                    "2015-01-22 13:30:00",
                    "2015-01-22 14:30:00",
                    "2015-03-22 12:59:59",
                    "2015-03-22 13:00:00",
                    "2015-03-22 22:00:00",
                    "2015-03-22 22:00:01",
                    "2015-03-23 13:00:00",
                    "2015-03-22 09:00:00",
                    "2015-03-23 03:00:00",
                ]
                ids = [f"evtx-{'a' * 64}-security-{i:012d}" for i in range(len(times))]
                for evidence_id, timestamp in zip(ids, times, strict=True):
                    db.execute(
                        "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type, channel, raw_json) "
                        "VALUES (?, 4624, ?, 'HOST1', 'alice', '2', 'Security', ?)",
                        [
                            evidence_id,
                            timestamp,
                            '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                        ],
                    )
                block = {
                    "heading": "System startup/shutdown and user logon/logoff",
                    "mode": "question",
                    "answer_spec": "daily_session_timeline",
                    "answer_id": "daily",
                    "template_body": "Consider only between 09:00 and 18:00 in local time, between 2015-01-22 and 2015-03-22.",
                }
                markdown, results, projection = _block_projection(
                    case, db, "timeline", block
                )
                answer = projection["answer"]
                rows = answer["answer"]
                self.assertEqual(answer["status"], "answered")
                self.assertEqual(
                    [row["date"] for row in rows], ["2015-01-22", "2015-03-22"]
                )
                self.assertEqual(rows[0]["first_logon"], "2015-01-22 14:30:00")
                self.assertEqual(rows[0]["first_logon_local"], "2015-01-22 09:30:00")
                self.assertEqual(rows[1]["first_logon"], "2015-03-22 13:00:00")
                self.assertEqual(
                    set(results[0]["evidence_ids"]), {ids[1], ids[3], ids[4]}
                )
                self.assertEqual(len(rows[1]["event_trace"]), 2)
                self.assertIn(ids[3], markdown)
                self.assertEqual(check_claim_traceability(markdown, db), [])
                exported = json.loads(
                    (case.reports_dir / "structured/daily.json").read_text()
                )
                self.assertEqual(exported["answer"], rows)

                _, _, overnight = _block_projection(
                    case,
                    db,
                    "timeline",
                    {
                        **block,
                        "template_body": "between 22:00 and 06:00 in local time, between 2015-03-22 and 2015-03-22.",
                    },
                )
                self.assertEqual(len(overnight["answer"]["answer"]), 1)
                night = overnight["answer"]["answer"][0]
                self.assertEqual(night["date"], "2015-03-22")
                self.assertEqual(set(night["evidence_ids"]), {ids[7], ids[8]})

                case.source_timezone = "UTC"
                _, _, unresolved = _block_projection(case, db, "timeline", block)
                self.assertEqual(unresolved["answer"]["status"], "partial")
                self.assertIn(
                    "local-time basis is unknown",
                    unresolved["answer"]["missing_reason"][0],
                )
                self.assertGreater(len(unresolved["answer"]["answer"]), len(rows))
                db.execute("DELETE FROM evtx_events")
                _, _, empty = _block_projection(case, db, "timeline", block)
                self.assertEqual(empty["answer"]["status"], "unobservable")
                case.source_timezone = "America/New_York"
                db.execute(
                    "INSERT INTO evtx_events (event_id, timestamp, target_user, logon_type, channel, raw_json) "
                    "VALUES (4624, '2015-03-22 13:00:00', 'alice', '2', 'Security', ?)",
                    [
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}'
                    ],
                )
                _, _, unreferenced = _block_projection(case, db, "timeline", block)
                self.assertEqual(unreferenced["answer"]["status"], "partial")
                self.assertTrue(
                    any(
                        "no stable" in reason
                        for reason in unreferenced["answer"]["missing_reason"]
                    )
                )


if __name__ == "__main__":
    unittest.main()
