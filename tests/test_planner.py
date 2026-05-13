from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.checker import _parse_new_hypotheses
from forensia.ai.planner import plan_hypothesis_query, validate_select_sql
from forensia.ai.prompts import build_broad_plan_messages, build_check_messages, build_hypothesis_plan_messages
from forensia.ai.sql_schema import ALLOWED_TABLES
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB


class _MemoryStub:
    def load_overview(self) -> str:
        return "# overview"

    def load_context(self, files: list[str]) -> str:
        return ""


class PlannerRetryTests(unittest.TestCase):
    def test_broad_plan_messages_do_not_embed_sql_framework(self) -> None:
        messages = build_broad_plan_messages(
            overview_md="# overview",
            extra_context_md="",
            iteration=1,
            findings_snapshot=[],
            active_hypotheses=[],
            resolved_hypotheses=[],
            history=[],
        )
        system = messages[0]["content"]
        self.assertNotIn("Available tables:", system)
        self.assertNotIn("event_id IN (1102, 104)", system)

    def test_hypothesis_plan_messages_list_all_allowed_tables(self) -> None:
        messages = build_hypothesis_plan_messages(
            overview_md="# overview",
            extra_context_md="",
            iteration=1,
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            hypothesis_history=[],
            query_templates=[],
        )
        system = messages[0]["content"]
        for table_name in sorted(ALLOWED_TABLES):
            self.assertIn(table_name, system)

    def test_build_check_messages_includes_structured_memory(self) -> None:
        messages = build_check_messages(
            planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            result_summary={"row_count": 1},
            overview_md="# overview",
            memory_context_md="# confirmed_facts.md\n- fact",
        )
        payload = messages[1]["content"]
        self.assertIn("# overview", payload)
        self.assertIn("confirmed_facts.md", payload)

    def test_validate_select_sql_allows_investigation_state_tables(self) -> None:
        for sql in (
            "SELECT * FROM hypotheses",
            "SELECT * FROM report_sections",
            "SELECT * FROM claims",
            "SELECT * FROM hypothesis_reasoning",
            "SELECT * FROM ingested_files",
        ):
            self.assertEqual(sql, validate_select_sql(sql))

    def test_checker_parses_new_hypotheses_leniently(self) -> None:
        hypotheses = _parse_new_hypotheses(
            [
                {
                    "id": "H-new",
                    "description": "follow this lead",
                    "status": "active",
                    "verdict": "inconclusive",
                }
            ]
        )
        self.assertEqual(1, len(hypotheses))
        self.assertIsNone(hypotheses[0].verdict)

    def test_materializes_query_template_into_sql(self) -> None:
        state = SessionState(session_id="session-template", iteration=1)
        hypothesis = Hypothesis(id="H0", description="failed logon burst")
        responses = [
            {
                "read_more": [],
                "hypothesis": {"id": "H0", "description": "failed logon burst"},
                "query": {
                    "query_id": "QT1",
                    "hypothesis_id": "H0",
                    "purpose": "failed logons by src_ip",
                    "template_id": "q_failed_logon_by_ip_window",
                    "params": {"hours": 24, "threshold": 5},
                    "sql": "",
                },
                "needs_more": True,
            }
        ]

        with patch("forensia.ai.planner.request_llm_json", side_effect=responses):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                finding_candidates=[],
                memory=_MemoryStub(),
                base_url="http://localhost:1234",
                model="test-model",
            )

        self.assertIsNotNone(result.query)
        self.assertEqual("q_failed_logon_by_ip_window", result.query.template_id)
        self.assertIn("GROUP BY src_ip", result.query.sql)

    def test_retries_once_when_sql_validation_fails(self) -> None:
        state = SessionState(session_id="session-1", iteration=1)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "hypothesis": {"id": "H1", "description": "test hypothesis"},
                "query": {
                    "query_id": "Q1",
                    "hypothesis_id": "H1",
                    "purpose": "test",
                    "sql": "SELECT * FROM nope",
                },
                "needs_more": True,
            },
            {
                "read_more": [],
                "hypothesis": {"id": "H1", "description": "test hypothesis"},
                "query": {
                    "query_id": "Q1b",
                    "hypothesis_id": "H1",
                    "purpose": "retry",
                    "sql": "SELECT * FROM findings",
                },
                "needs_more": False,
            },
        ]

        with patch("forensia.ai.planner.request_llm_json", side_effect=responses) as mock_request:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                finding_candidates=[],
                memory=_MemoryStub(),
                base_url="http://localhost:1234",
                model="test-model",
            )

        self.assertEqual(2, mock_request.call_count)
        self.assertIsNotNone(result.query)
        self.assertEqual("SELECT * FROM findings", result.query.sql)

    def test_returns_none_when_retry_is_still_invalid(self) -> None:
        state = SessionState(session_id="session-2", iteration=1)
        hypothesis = Hypothesis(id="H2", description="test hypothesis")
        responses = [
            {
                "read_more": [],
                "hypothesis": {"id": "H2", "description": "test hypothesis"},
                "query": {
                    "query_id": "Q2",
                    "hypothesis_id": "H2",
                    "purpose": "test",
                    "sql": "SELECT * FROM nope",
                },
                "needs_more": True,
            },
            {
                "read_more": [],
                "hypothesis": {"id": "H2", "description": "test hypothesis"},
                "query": {
                    "query_id": "Q2b",
                    "hypothesis_id": "H2",
                    "purpose": "retry",
                    "sql": "DELETE FROM findings",
                },
                "needs_more": True,
            },
        ]

        with patch("forensia.ai.planner.request_llm_json", side_effect=responses):
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                finding_candidates=[],
                memory=_MemoryStub(),
                base_url="http://localhost:1234",
                model="test-model",
            )

        self.assertIsNone(result.query)

    def test_route_trace_write_skips_regex_for_select(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db, patch("forensia.db.database.re.search") as mock_search:
                routed = db._route_trace_write("SELECT * FROM progress_events")
        self.assertEqual("SELECT * FROM progress_events", routed)
        mock_search.assert_not_called()


if __name__ == "__main__":
    unittest.main()
