from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.schema import CORE_SCHEMA_SQL, TRACE_SCHEMA_SQL
from forensia.core.memory import EvidenceOnlyMemory, MemoryManager
from forensia.ai.section_agent import (
    _load_evidence_chains,
    run_section_block_agent,
)
from forensia.config import get_llm_settings


def _mock_llm_json(messages: list[dict], **kwargs) -> dict:
    """Return deterministic LLM responses based on message content."""
    content = ""
    if messages:
        content = str(messages[0].get("content", "")).lower()

    if "section-plan" in content:
        return {"action": "keypoint", "query": None, "planned_query": None, "enough_to_write": False}
    if "section-check" in content and ("answered" in content or "plan" in content):
        return {"verdict": "sufficient", "fact_updates": []}
    if "benchmark" in content or "question_" in content:
        return {
            "id": "benchmark-Q01",
            "status": "answered",
            "value": "Test benchmark value",
            "detail": "Test detail from mock LLM",
            "confidence": 0.9,
        }
    return {"action": "write", "enough_to_write": True}


def _populate_minimal_case(db: CaseDB) -> None:
    """Insert minimal evidence rows for benchmark testing."""
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
            ("test.evtx", "System", 7036, 3, "2015-03-22T10:00:00", "HOST-A",
             None, None, None, None, None,
             "svchost.exe", "", "The Service Control Manager tried to start a service.",
             '{"ServiceName": "TestService", "ServiceFileName": "C:\\\\test\\\\svc.exe"}'),
            ("test.evtx", "Security", 4688, 4, "2015-03-22T11:00:00", "HOST-A",
             None, None, "user1", None, None,
             "powershell.exe", "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA", "A new process was created.",
             '{"SubjectUserName": "user1", "ProcessName": "powershell.exe", "CommandLine": "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA"}'),
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


class BenchmarkE2ETests(unittest.TestCase):
    def setUp(self) -> None:
        self._patch_llm = patch(
            "forensia.ai.section_agent.request_llm_json",
            side_effect=_mock_llm_json,
        )
        self._patch_llm.start()
        self.addCleanup(self._patch_llm.stop)

    def test_evidence_chains_loaded(self) -> None:
        """Verify evidence_chain definitions are parseable from question_routing.yaml."""
        chains = _load_evidence_chains()
        self.assertGreater(len(chains), 0)
        for qtype, chain in chains.items():
            self.assertIsInstance(qtype, str)
            self.assertIsInstance(chain, list)
            for entry in chain:
                has_source = "source" in entry or "table" in entry
                self.assertTrue(has_source, f"Entry missing 'source' or 'table': {entry}")

    def test_minimal_case_db_population(self) -> None:
        """Verify minimal case data inserts correctly."""
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
                _populate_minimal_case(db)
                row = db.conn.execute("SELECT COUNT(*) AS cnt FROM evtx_events").fetchone()
                self.assertIsNotNone(row)
                self.assertGreater(row[0], 0, "No evtx_events rows inserted")

    def test_benchmark_block_agent_runs_with_mock_llm(self) -> None:
        """Run a benchmark section block agent and verify structured output."""
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
                _populate_minimal_case(db)

                memory = MemoryManager(case)
                memory.upsert_hypothesis("H-001", "test-session",
                                         "# H-001: RDP lateral movement\n\nNarrative content.")
                scratch_dir = memory.scratch_dir / "H-001"
                scratch_dir.mkdir(parents=True, exist_ok=True)
                (scratch_dir / "facts.md").write_text(
                    "# Facts\n\n- Provisional lateral movement [hypothesis: H-001 | provisional]\n",
                    encoding="utf-8",
                )

                block_req = {
                    "block_heading": "Q01: Test Question",
                    "hint": "benchmark",
                    "question_type": "q01",
                    "expected_answer_shape": {
                        "format": "text",
                        "fields": ["value", "detail"],
                        "style": "concise",
                    },
                }
                result = run_section_block_agent(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading=block_req["block_heading"],
                    template_body="",
                    context_sections={},
                    current_section_outputs={},
                    report_brief={},
                    base_url="http://test.invalid",
                    model="test-model",
                    memory=EvidenceOnlyMemory(memory),
                    max_queries_per_section=2,
                    evidence_keypoints=[],
                    benchmark_mode=True,
                )
                self.assertIsNotNone(result)
                self.assertIsInstance(result.body, str)
                self.assertGreater(len(result.body), 0)
                self.assertIn(result.status, {"error", "written", "insufficient_evidence", "not_found"})

    def test_evidence_only_memory_excludes_hypothesis_content(self) -> None:
        """Verify EvidenceOnlyMemory blocks hypothesis-derived narrative content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            memory.upsert_hypothesis("H-001", "test-session",
                                     "# H-001: RDP lateral movement to deploy service\n\n"
                                     "This is a hypothesis narrative about lateral movement.")

            scratch_dir = memory.scratch_dir / "H-001"
            scratch_dir.mkdir(parents=True, exist_ok=True)
            (scratch_dir / "facts.md").write_text(
                "# Facts\n\n- Suspected lateral movement from host A to host B [hypothesis: H-001 | provisional]\n",
                encoding="utf-8",
            )

            memory.upsert_keypoint("KP-TEST", "# KP-TEST: Suspicious remote execution\n\nTest keypoint card for remote execution.\n")
            keypoint_fact = memory.facts_path
            keypoint_fact.write_text(
                "# Facts\n\n- Validated: powershell.exe executed on HOST-A [evidence: E-001]\n",
                encoding="utf-8",
            )

            ev = EvidenceOnlyMemory(memory)
            ctx = ev.load_investigation_context(None)

            self.assertIn("KP-TEST", ctx, "EvidenceOnlyMemory should include keypoints")
            self.assertIn("Validated", ctx, "EvidenceOnlyMemory should include facts")
            self.assertNotIn("H-001", ctx, "EvidenceOnlyMemory must not contain hypothesis content")
            self.assertNotIn("lateral movement", ctx,
                             "EvidenceOnlyMemory must not contain hypothesis-derived narrative")
