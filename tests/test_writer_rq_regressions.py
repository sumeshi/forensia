from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.writer import (
    _GateCtx,
    build_structured_answer,
    _check_citation_token_no_finding_id,
    _check_hedge_no_citation,
    _render_structured_answer_markdown,
    _resolve_evidence_results,
)


class WriterRQRegressionTests(unittest.TestCase):
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
                    block_heading="2. 最終ログオンユーザー",
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
                    block_heading="3. 最終シャットダウン時刻",
                )

            self.assertIsNotNone(answer)
            self.assertEqual(6006, answer["answer"][0]["event_id"])
            self.assertIn("2015-03-22T14:38:16", answer["answer"][0]["shutdown_time"])

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
                    block_heading="12. アンチフォレンジック活動",
                )

            self.assertIsNotNone(answer)
            event_ids = {row.get("event_id") for row in answer["answer"]}
            self.assertEqual({1102}, event_ids)

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
                    block_heading="4. アプリケーション実行履歴",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("partial", answer["status"])
            self.assertEqual(["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]])

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
