from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.checker import check_query_result
from forensia.ai.checker import _parse_new_hypotheses
from forensia.ai.planner import (
    _parse_hypotheses,
    _request_with_optional_context,
    plan_hypothesis_query,
    validate_select_sql,
)
from forensia.ai.prompts import (
    build_broad_plan_messages,
    build_check_messages,
    build_hypothesis_plan_messages,
    build_report_section_messages,
)
from forensia.ai.sql_schema import build_investigation_framework
from forensia.ai.sql_schema import ALLOWED_TABLES
from forensia.ai.sql_templates import _template_failed_logon_by_ip_window, coerce_list
from forensia.config import clear_llm_settings_cache, resolve_llm_config
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB


class _MemoryStub:
    max_bytes = 16384

    def load_overview(self) -> str:
        return "# overview"

    def load_context(self, files: list[str]) -> str:
        return ""

    def load_compact_context(self, files: list[str], max_bytes: int | None = None) -> str:
        return "# facts.md\n\n- fact\n\n# tasks.md\n\n- question"


def _llm_base_url() -> str:
    return resolve_llm_config()[0] or "http://test-llm.invalid"


class PlannerRetryTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_llm_settings_cache()

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
        self.assertIn("memory/details/fact-NNN.md", system)

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
        self.assertIn("memory/details/fact-NNN.md", system)

    def test_broad_plan_messages_trim_findings_payload(self) -> None:
        messages = build_broad_plan_messages(
            overview_md="# overview",
            extra_context_md="",
            iteration=1,
            findings_snapshot=[
                {
                    "finding_id": "F-1",
                    "title": "Suspicious service",
                    "severity": "high",
                    "confidence": 0.9,
                    "status": "accepted",
                    "summary": "summary",
                    "evidence": [{"raw_json": "huge"}],
                    "attack": ["T1543"],
                    "raw_json": {"x": 1},
                }
            ],
            active_hypotheses=[],
            resolved_hypotheses=[],
            history=[],
        )
        payload = messages[1]["content"]
        self.assertIn("finding_id", payload)
        self.assertIn("summary", payload)
        self.assertNotIn("raw_json", payload)
        self.assertNotIn("evidence", payload)
        self.assertNotIn("attack", payload)

    def test_broad_plan_messages_cap_resolved_hypotheses(self) -> None:
        resolved = [
            Hypothesis(id=f"H{i}", description=f"resolved {i}", status="confirmed", summary=f"summary {i}")
            for i in range(25)
        ]
        messages = build_broad_plan_messages(
            overview_md="# overview",
            extra_context_md="",
            iteration=1,
            findings_snapshot=[],
            active_hypotheses=[],
            resolved_hypotheses=resolved,
            history=[],
        )
        payload = messages[1]["content"]
        self.assertNotIn("resolved 0", payload)
        self.assertNotIn("resolved 4", payload)
        self.assertIn("resolved 5", payload)
        self.assertIn("resolved 24", payload)

    def test_build_check_messages_includes_structured_memory(self) -> None:
        messages = build_check_messages(
            planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            result_summary={"row_count": 1},
            overview_md="# overview",
            memory_context_md="# facts.md\n- fact",
        )
        payload = messages[1]["content"]
        self.assertIn("# overview", payload)
        self.assertIn("facts.md", payload)

    def test_build_check_messages_missing_checks_follow_output_language(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            messages = build_check_messages(
                planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
                hypothesis=Hypothesis(id="H1", description="desc"),
                finding_candidates=[],
                result_summary={"row_count": 1},
                overview_md="# overview",
                memory_context_md="# facts.md\n- fact",
            )
        system = messages[0]["content"]
        self.assertIn("Other host logons from the same src_ip", system)
        self.assertNotIn("src_ip からの他ホストへのログオンの有無", system)

    def test_build_check_messages_do_not_request_dead_compromised_fields(self) -> None:
        messages = build_check_messages(
            planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            result_summary={"row_count": 1},
            overview_md="# overview",
            memory_context_md="# facts.md\n- fact",
        )
        system = messages[0]["content"]
        self.assertNotIn("compromised_hosts", system)
        self.assertNotIn("compromised_users", system)

    def test_build_check_messages_define_finding_update_and_suspicious_evidence_schema(self) -> None:
        messages = build_check_messages(
            planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            result_summary={"row_count": 1},
            overview_md="# overview",
            memory_context_md="# facts.md\n- fact",
        )
        system = messages[0]["content"]
        self.assertIn("finding_id, new_status (accepted or suppressed), confidence_delta", system)
        self.assertIn("evidence_id, reason, confidence (0.0-1.0)", system)

    def test_report_section_messages_truncate_previous_sections(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "1_overview"},
            evidence_results=[],
            context_sections={"1_overview": "x" * 1200},
            template_body="# Section",
            report_brief={},
        )
        payload = messages[1]["content"]
        self.assertIn("x" * 600, payload)
        self.assertNotIn("x" * 800, payload)

    def test_report_section_messages_placeholder_follows_output_language(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            messages = build_report_section_messages(
                section_meta={"section": "1_overview"},
                evidence_results=[],
                context_sections={},
                template_body="# Section",
                report_brief={},
            )
        system = messages[0]["content"]
        self.assertIn("[INSUFFICIENT EVIDENCE: reason]", system)
        self.assertNotIn("【調査不足: 理由】", system)

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
                base_url=_llm_base_url(),
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
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertEqual(2, mock_request.call_count)
        self.assertIsNotNone(result.query)
        self.assertEqual("SELECT * FROM findings", result.query.sql)

    def test_plan_hypothesis_query_logs_debug_when_query_parse_fails(self) -> None:
        state = SessionState(session_id="session-1", iteration=1)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        response = {
            "read_more": [],
            "hypothesis": {"id": "H1", "description": "test hypothesis"},
            "query": {
                "query_id": "Q-bad",
                "hypothesis_id": "H1",
                "purpose": "broken",
                "template_id": "missing-template",
                "params": {},
                "sql": "",
            },
            "needs_more": True,
        }

        with patch("forensia.ai.planner.request_llm_json", return_value=response), self.assertLogs(
            "forensia.ai.planner", level="DEBUG"
        ) as logs:
            result = plan_hypothesis_query(
                state=state,
                hypothesis=hypothesis,
                finding_candidates=[],
                memory=_MemoryStub(),
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertIsNone(result.query)
        self.assertTrue(any("hypothesis/query parse failed" in line for line in logs.output))

    def test_parse_hypotheses_logs_debug_on_validation_failure(self) -> None:
        with self.assertLogs("forensia.ai.planner", level="DEBUG") as logs:
            hypotheses = _parse_hypotheses([{"id": "H-1"}])

        self.assertEqual([], hypotheses)
        self.assertTrue(any("hypothesis parse failed" in line for line in logs.output))

    def test_query_template_uses_dataset_max_timestamp_not_now(self) -> None:
        sql = _template_failed_logon_by_ip_window({"hours": 24, "threshold": 5})
        self.assertIn("SELECT MAX(timestamp) FROM evtx_events", sql)
        self.assertNotIn("now()", sql.lower())

    def test_coerce_list_wraps_single_dict_and_string(self) -> None:
        self.assertEqual([{"id": "H-1"}], coerce_list({"id": "H-1"}))
        self.assertEqual(["facts.md"], coerce_list("facts.md"))
        self.assertEqual([], coerce_list(""))

    def test_investigation_framework_lists_missing_columns(self) -> None:
        framework = build_investigation_framework()
        self.assertIn("investigation_steps columns: step_id, session_id, hypothesis_id, iteration, phase", framework)
        self.assertIn("ingested_files columns: sha256, path, source_kind, size, ingested_at.", framework)

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
                base_url=_llm_base_url(),
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

    def test_request_with_optional_context_starts_with_default_memory(self) -> None:
        seen: list[str] = []

        def builder(extra_context: str) -> list[dict[str, str]]:
            seen.append(extra_context)
            return [{"role": "user", "content": extra_context}]

        with patch("forensia.ai.planner.request_llm_json", return_value={"read_more": []}):
            _request_with_optional_context(
                memory=_MemoryStub(),
                messages_builder=builder,
                base_url=_llm_base_url(),
                model="test-model",
            )

        self.assertEqual(1, len(seen))
        self.assertIn("facts.md", seen[0])
        self.assertIn("tasks.md", seen[0])

    def test_request_with_optional_context_uses_compact_context_for_read_more(self) -> None:
        memory = _MemoryStub()
        with patch.object(memory, "load_compact_context", return_value="# compact extra") as mock_compact, patch(
            "forensia.ai.planner.request_llm_json",
            side_effect=[{"read_more": ["archive/refuted.md"]}, {"read_more": []}],
        ):
            _request_with_optional_context(
                memory=memory,
                messages_builder=lambda extra: [{"role": "user", "content": extra}],
                base_url=_llm_base_url(),
                model="test-model",
            )

        mock_compact.assert_any_call(["archive/refuted.md"], max_bytes=memory.max_bytes)

    def test_invalid_verdict_falls_back_to_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db, patch(
                "forensia.ai.checker.request_llm_json",
                return_value={"query_id": "Q1", "verdict": "unclear", "report_text": "text"},
            ), patch("forensia.ai.checker.apply_check_result", return_value=(0, False)):
                result = check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    iteration=1,
                    planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[],
                    result_summary={"row_count": 1, "sample_rows": [], "evidence_ids": []},
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", result.verdict)

    def test_checker_filters_finding_updates_and_refuted_constraints(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db, patch(
                "forensia.ai.checker.request_llm_json",
                return_value={
                    "query_id": "Q1",
                    "verdict": "refuted",
                    "finding_updates": [
                        {"finding_id": "F-1", "new_status": "accepted", "confidence_delta": 0.6},
                        {"finding_id": "F-2", "new_status": "suppressed", "confidence_delta": -0.4},
                    ],
                    "report_text": "text",
                },
            ), patch("forensia.ai.checker.apply_check_result", side_effect=_capture):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    iteration=1,
                    planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[{"finding_id": "F-1"}],
                    result_summary={"row_count": 1, "sample_rows": [], "evidence_ids": []},
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(
            [{"finding_id": "F-1", "new_status": "suppressed", "confidence_delta": 0.0}],
            captured["result"].finding_updates,
        )

    def test_checker_demotes_zero_evidence_confirmed_and_crushes_positive_delta(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db, patch(
                "forensia.ai.checker.request_llm_json",
                return_value={
                    "query_id": "Q1",
                    "verdict": "confirmed",
                    "finding_updates": [
                        {"finding_id": "F-1", "new_status": "accepted", "confidence_delta": 0.3},
                    ],
                    "report_text": "text",
                },
            ), patch("forensia.ai.checker.apply_check_result", side_effect=_capture):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    iteration=1,
                    planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[{"finding_id": "F-1"}],
                    result_summary={"row_count": 0, "sample_rows": [], "evidence_ids": []},
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual("inconclusive", captured["result"].verdict)
        self.assertEqual(
            [{"finding_id": "F-1", "new_status": "accepted", "confidence_delta": 0.0}],
            captured["result"].finding_updates,
        )

    def test_checker_limits_inconclusive_delta_and_filters_evidence_references(self) -> None:
        captured = {}

        def _capture(*args, **kwargs):
            captured["result"] = kwargs["check_result"]
            return (0, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db, patch(
                "forensia.ai.checker.request_llm_json",
                return_value={
                    "query_id": "Q1",
                    "verdict": "inconclusive",
                    "finding_updates": [
                        {"finding_id": "F-1", "new_status": "accepted", "confidence_delta": 0.5},
                    ],
                    "suspicious_evidence": [
                        {"evidence_id": "ev-1", "reason": "keep", "confidence": 0.9},
                        {"evidence_id": "ev-x", "reason": "drop", "confidence": 0.9},
                    ],
                    "memory_updates": {
                        "facts": [{"text": "fact", "evidence_ids": ["ev-1", "ev-x"]}],
                        "resolved_gaps": [{"text": "gap", "evidence_ids": ["ev-2", "ev-y"]}],
                        "overview": ["story"],
                    },
                    "report_text": "text",
                },
            ), patch("forensia.ai.checker.apply_check_result", side_effect=_capture):
                check_query_result(
                    case=case,
                    db=db,
                    session_id="S-1",
                    iteration=1,
                    planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
                    hypothesis=Hypothesis(id="H1", description="desc"),
                    finding_candidates=[{"finding_id": "F-1"}],
                    result_summary={
                        "row_count": 2,
                        "sample_rows": [{"evidence_id": "ev-2"}],
                        "evidence_ids": ["ev-1"],
                    },
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(
            [{"finding_id": "F-1", "new_status": "accepted", "confidence_delta": 0.02}],
            captured["result"].finding_updates,
        )
        self.assertEqual(
            [{"evidence_id": "ev-1", "reason": "keep", "confidence": 0.9}],
            captured["result"].suspicious_evidence,
        )
        self.assertEqual(
            {
                "facts": [{"text": "fact", "evidence_ids": ["ev-1"]}],
                "resolved_gaps": [{"text": "gap", "evidence_ids": ["ev-2"]}],
                "overview": ["story"],
            },
            captured["result"].memory_updates,
        )


if __name__ == "__main__":
    unittest.main()
