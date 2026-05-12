from __future__ import annotations

import unittest
from unittest.mock import patch

from forensia.ai.planner import plan_hypothesis_query
from forensia.core.session import Hypothesis, SessionState


class _MemoryStub:
    def load_overview(self) -> str:
        return "# overview"

    def load_context(self, files: list[str]) -> str:
        return ""


class PlannerRetryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
