from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.checking.checker import check_query_result
from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB


class _MemoryStub:
    max_bytes = 16384

    def load_overview(self) -> str:
        return "# overview"

    def load_context(self, files: list[str]) -> str:
        return ""

    def load_compact_context(
        self, files: list[str], max_bytes: int | None = None
    ) -> str:
        return "# facts.md\n\n- fact\n\n# tasks.md\n\n- question"


def _llm_base_url() -> str:
    return resolve_llm_config()[0] or "http://test-llm.invalid"


class CheckerVerdictTests(unittest.TestCase):
    """Checker phased verdicts, demotion rules, and memory-update handling."""

    def tearDown(self) -> None:
        reload_settings()

    def test_invalid_verdict_falls_back_to_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    return_value={
                        "query_id": "Q1",
                        "verdict": "unclear",
                        "report_text": "text",
                    },
                ),
                patch(
                    "forensia.ai.checking.checker.apply_check_result", return_value=(0, False)
                ),
            ):
                result = check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[],
                    result_summary={
                        "row_count": 1,
                        "sample_rows": [],
                        "evidence_ids": [],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", result.verdict)

    def test_checker_phased_verdict_refuted(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            responses = [
                {"verdict": "refuted", "rationale": "No evidence found"},
                {
                    "memory_updates": {
                        "refuted_hypotheses": [
                            {"hypothesis_id": "H1", "reason": "No evidence"}
                        ]
                    }
                },
            ]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ),
                patch("forensia.ai.checking.checker.apply_check_result", side_effect=_capture),
            ):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[{"finding_id": "F-1"}],
                    result_summary={
                        "row_count": 1,
                        "sample_rows": [],
                        "evidence_ids": [],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("refuted", captured["result"].verdict)

    def test_checker_demotes_zero_evidence_confirmed_to_inconclusive(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            responses = [
                {"verdict": "confirmed", "rationale": "Seems confirmed"},
                {
                    "findings": [
                        {
                            "title": "Test",
                            "severity": "medium",
                            "evidence_ids": ["ev-1"],
                        }
                    ]
                },
                {"memory_updates": {}},
            ]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ),
                patch("forensia.ai.checking.checker.apply_check_result", side_effect=_capture),
            ):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[{"finding_id": "F-1"}],
                    result_summary={
                        "row_count": 0,
                        "sample_rows": [],
                        "evidence_ids": [],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", captured["result"].verdict)

    def test_checker_phased_verdict_inconclusive_memory_updates(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            responses = [
                {"verdict": "inconclusive", "rationale": "Missing src_ip"},
                {
                    "memory_updates": {
                        "facts": [{"text": "fact", "evidence_ids": ["ev-1"]}],
                        "resolved_gaps": [{"text": "gap", "evidence_ids": ["ev-2"]}],
                        "overview": ["story"],
                    }
                },
            ]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ),
                patch("forensia.ai.checking.checker.apply_check_result", side_effect=_capture),
            ):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[],
                    result_summary={
                        "row_count": 1,
                        "sample_rows": [],
                        "evidence_ids": ["ev-1"],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", captured["result"].verdict)
        self.assertEqual(
            [{"text": "fact", "evidence_ids": ["ev-1"]}],
            captured["result"].memory_updates.get("facts"),
        )

    def test_checker_phased_drops_durable_memory_updates_when_evidence_ids_empty(
        self,
    ) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            responses = [
                {"verdict": "inconclusive", "rationale": "Insufficient data"},
                {
                    "memory_updates": {
                        "facts": [{"text": "fact", "evidence_ids": ["ev-x"]}],
                        "timeline": [
                            {
                                "timestamp": "2026-05-24T01:02:03Z",
                                "description": "event",
                                "evidence_ids": ["ev-y"],
                            }
                        ],
                        "resolved_gaps": [{"text": "gap", "evidence_ids": []}],
                        "tasks": [
                            {"text": "still investigate", "kind": "internal_db_check"}
                        ],
                        "overview": ["keep storyline"],
                    }
                },
            ]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    side_effect=responses,
                ),
                patch("forensia.ai.checking.checker.apply_check_result", side_effect=_capture),
            ):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[],
                    result_summary={
                        "row_count": 1,
                        "sample_rows": [],
                        "evidence_ids": ["ev-1"],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(
            {
                "facts": [],
                "timeline": [],
                "resolved_gaps": [],
                "tasks": [{"text": "still investigate", "kind": "internal_db_check"}],
                "overview": ["keep storyline"],
            },
            captured["result"].memory_updates,
        )

    def test_checker_phased_normalizes_entity_type_and_drops_invalid_entity_updates(
        self,
    ) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.ai.llm.llm_gateway.request_llm_json",
                    return_value={
                        "query_id": "Q1",
                        "verdict": "inconclusive",
                        "memory_updates": {
                            "entities": [
                                {
                                    "entity_type": "src_ip",
                                    "name": "10.0.0.5",
                                    "role": "source_ip",
                                    "notes": "keep as ip",
                                },
                                {
                                    "entity_type": "username",
                                    "name": "alice",
                                    "role": "actor_user",
                                    "notes": "keep as user",
                                },
                                {
                                    "entity_type": "machine_account",
                                    "name": "INFORMANT-PC$",
                                    "role": "source_account",
                                    "notes": "keep as machine account",
                                },
                                {
                                    "entity_type": "service_name",
                                    "name": "-",
                                    "role": "service_name",
                                    "notes": "drop placeholder",
                                },
                                {
                                    "entity_type": "device_group",
                                    "name": "ops",
                                    "notes": "drop",
                                },
                            ]
                        },
                        "report_text": "text",
                    },
                ),
                patch("forensia.ai.checking.checker.apply_check_result", side_effect=_capture),
            ):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    planned_query=PlannedQuery(
                        query_id="Q1",
                        hypothesis_id="H1",
                        purpose="purpose",
                        sql="SELECT 1",
                    ),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[],
                    result_summary={
                        "row_count": 1,
                        "sample_rows": [],
                        "evidence_ids": ["ev-1"],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(
            {
                "entities": [
                    {
                        "entity_type": "ip",
                        "name": "10.0.0.5",
                        "role": "source_ip",
                        "notes": "keep as ip",
                    },
                    {
                        "entity_type": "user",
                        "name": "alice",
                        "role": "actor_user",
                        "notes": "keep as user",
                    },
                    {
                        "entity_type": "machine_account",
                        "name": "INFORMANT-PC$",
                        "role": "source_account",
                        "notes": "keep as machine account",
                    },
                ]
            },
            captured["result"].memory_updates,
        )


if __name__ == "__main__":
    unittest.main()
