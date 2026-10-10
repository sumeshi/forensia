from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from forensia.config import (
    reload_settings,
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, PlannedQuery
from forensia.db.database import CaseDB
from forensia.investigation.verification.checker import check_query_result


def _llm_base_url() -> str:
    return resolve_llm_config()[0] or "http://test-llm.invalid"


class CheckerVerdictTests(unittest.TestCase):
    """Checker verdicts, demotion rules, and follow-up hypotheses."""

    def tearDown(self) -> None:
        reload_settings()

    def test_invalid_verdict_falls_back_to_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.llm.json_response.request_llm_json",
                    return_value={
                        "query_id": "Q1",
                        "verdict": "unclear",
                        "report_text": "text",
                    },
                ),
                patch(
                    "forensia.investigation.verification.checker.apply_check_result",
                    return_value=(0, False),
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
            responses = [{"verdict": "refuted", "rationale": "No evidence found"}]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=responses,
                ),
                patch(
                    "forensia.investigation.verification.checker.apply_check_result",
                    side_effect=_capture,
                ),
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
            ]
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.llm.json_response.request_llm_json",
                    side_effect=responses,
                ),
                patch(
                    "forensia.investigation.verification.checker.apply_check_result",
                    side_effect=_capture,
                ),
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
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", captured["result"].verdict)

    def test_follow_up_hypotheses_come_from_verdict_call(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        response = {
            "verdict": "newlead",
            "rationale": "The result points to a separate execution path.",
            "new_hypotheses": [
                {
                    "description": "Trace the execution path",
                    "confirm_when": {"co_observed_event_ids": [4688]},
                    "refute_when": {"event_absent": True},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with (
                CaseDB(case) as db,
                patch(
                    "forensia.llm.json_response.request_llm_json",
                    return_value=response,
                ) as request,
                patch(
                    "forensia.investigation.verification.checker.apply_check_result",
                    side_effect=_capture,
                ),
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
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(1, request.call_count)
        self.assertEqual("newlead", captured["result"].verdict)
        self.assertEqual(
            ["Trace the execution path"],
            [
                hypothesis.description
                for hypothesis in captured["result"].new_hypotheses
            ],
        )
        followup = captured["result"].new_hypotheses[0]
        self.assertEqual("candidate-01", followup.id)
        self.assertEqual(
            [4688],
            followup.verification_spec.support_conditions["co_observed_event_ids"],
        )
        self.assertEqual(
            {"event_absent": True}, followup.verification_spec.refute_conditions
        )
