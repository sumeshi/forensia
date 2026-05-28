from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.schema import CORE_SCHEMA_SQL, TRACE_SCHEMA_SQL


def _populate_smoke_case(db: CaseDB) -> None:
    """Insert minimal evidence rows for smoke testing."""
    db.conn.executemany(
        """
        INSERT INTO evtx_events (
            source_file, channel, event_id, record_id, timestamp, computer,
            user_name, target_user, subject_user, src_ip, logon_type,
            process_name, command_line, message, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            ("test.evtx", "Security", 4624, 1, "2015-03-22T08:00:00", "HOST-A",
             "user1", "user1", "SYSTEM", "192.168.1.1", 10,
             "", "", "An account was successfully logged on.",
             '{"SubjectUserName": "SYSTEM", "TargetUserName": "user1", "IpAddress": "192.168.1.1", "LogonType": "10"}'),
            ("test.evtx", "Security", 4624, 2, "2015-03-22T09:00:00", "HOST-B",
             "user2", "user2", "SYSTEM", "192.168.1.2", 3,
             "", "", "An account was successfully logged on.",
             '{"SubjectUserName": "SYSTEM", "TargetUserName": "user2", "IpAddress": "192.168.1.2", "LogonType": "3"}'),
            ("test.evtx", "Security", 4688, 3, "2015-03-22T11:00:00", "HOST-A",
             None, None, "user1", None, None,
             "powershell.exe", "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA",
             "A new process was created.",
             '{"SubjectUserName": "user1", "ProcessName": "powershell.exe", "CommandLine": "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA"}'),
            ("test.evtx", "Security", 7036, 4, "2015-03-22T10:00:00", "HOST-A",
             None, None, None, None, None,
             "svchost.exe", "", "The Service Control Manager tried to start a service.",
             '{"ServiceName": "TestService"}'),
            ("test.evtx", "Security", 4720, 5, "2015-03-22T12:00:00", "HOST-A",
             None, "new_user", "admin", None, None,
             "", "", "A user account was created.",
             '{"TargetUserName": "new_user", "SubjectUserName": "admin"}'),
        ],
    )
    db.conn.executemany(
        """
        INSERT INTO prefetch_executions (
            source_file, executable_name, exec_count, last_exec_time, raw_json
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [
            ("CHROME.EXE-ABCDEF01.pf", "CHROME.EXE", 15, "2015-03-22T08:30:00",
             '{"executable_name": "CHROME.EXE"}'),
            ("POWERSHELL.EXE-ABCDEF02.pf", "POWERSHELL.EXE", 3, "2015-03-22T11:05:00",
             '{"executable_name": "POWERSHELL.EXE"}'),
        ],
    )


@unittest.skipUnless(os.environ.get("FORENSIA_LLM_BASE_URL"), "Set FORENSIA_LLM_BASE_URL to run real LLM smoke test")
class RealLLMBenchmarkSmokeTest(unittest.TestCase):
    """Real LLM smoke test for benchmark quality regression detection.

    Requires FORENSIA_LLM_BASE_URL and FORENSIA_LLM_MODEL environment variables.
    Runs investigate() with max_llm_calls=50 on a minimal case fixture
    and asserts benchmark answer quality.
    """

    def test_real_llm_benchmark_run(self) -> None:
        base_url = os.environ["FORENSIA_LLM_BASE_URL"]
        model = os.environ.get("FORENSIA_LLM_MODEL", "gemma-4-e2b")

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for sql in CORE_SCHEMA_SQL.split(";"):
                    sql = sql.strip()
                    if sql:
                        try:
                            db.conn.execute(sql)
                        except Exception:
                            pass
                for sql in TRACE_SCHEMA_SQL.split(";"):
                    sql = sql.strip()
                    if sql:
                        try:
                            db.conn.execute(sql)
                        except Exception:
                            pass
                _populate_smoke_case(db)

            from forensia.ai.investigator import investigate
            result = investigate(
                case=case,
                base_url=base_url,
                model=model,
                max_cycles=3,
                max_llm_calls=50,
                report_every_n_cycles=3,
            )
            self.assertIn("session_id", result)
            self.assertIn("status", result)

            answers_path = case.reports_dir / "benchmark" / "answers.json"
            self.assertTrue(answers_path.exists(), "benchmark/answers.json should exist")

            try:
                answers = json.loads(answers_path.read_text(encoding="utf-8"))
            except Exception:
                self.fail("Failed to parse benchmark/answers.json")

            self.assertIsInstance(answers, list)
            self.assertGreater(len(answers), 0, "Should have at least one benchmark answer")

            statuses = [a.get("status", "") for a in answers]
            answered = sum(1 for s in statuses if s == "answered")
            self.assertGreaterEqual(
                answered,
                1,
                f"At least 1/12 benchmark questions should be answered. Statuses: {statuses}",
            )

    def test_real_llm_answers_have_valid_structure(self) -> None:
        base_url = os.environ["FORENSIA_LLM_BASE_URL"]
        model = os.environ.get("FORENSIA_LLM_MODEL", "gemma-4-e2b")

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for sql in CORE_SCHEMA_SQL.split(";"):
                    sql = sql.strip()
                    if sql:
                        try:
                            db.conn.execute(sql)
                        except Exception:
                            pass
                for sql in TRACE_SCHEMA_SQL.split(";"):
                    sql = sql.strip()
                    if sql:
                        try:
                            db.conn.execute(sql)
                        except Exception:
                            pass
                _populate_smoke_case(db)

            from forensia.ai.investigator import investigate
            result = investigate(
                case=case,
                base_url=base_url,
                model=model,
                max_cycles=3,
                max_llm_calls=50,
                report_every_n_cycles=3,
            )
            self.assertIn("session_id", result)

            from forensia.core.verdicts import valid_verdicts
            valid_statuses = set(valid_verdicts("benchmark_status"))

            answers_path = case.reports_dir / "benchmark" / "answers.json"
            if answers_path.exists():
                answers = json.loads(answers_path.read_text(encoding="utf-8"))
                for answer in answers:
                    status = answer.get("status", "")
                    self.assertIn(
                        status, valid_statuses,
                        f"Benchmark answer status '{status}' not in taxonomy: {valid_statuses}",
                    )
                    self.assertIn("id", answer, "Each answer must have an id")
