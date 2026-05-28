from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from forensia.ai.checker import check_query_result
from forensia.ai.checker import _parse_new_hypotheses
from forensia.ai.investigator import _query_fingerprint
from forensia.ai.section_agent import _benchmark_report_brief
from forensia.ai.planner import (
    _parse_hypotheses,
    _request_with_optional_context,
    plan_hypothesis_query,
    validate_select_sql,
)
from forensia.ai.prompts import (
    _truncate_context_sections,
    build_benchmark_section_messages,
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
from forensia.core.session import HistoryEntry, Hypothesis, PlannedQuery, SessionState
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

    def test_broad_plan_messages_cap_findings_at_20(self) -> None:
        messages = build_broad_plan_messages(
            overview_md="# overview",
            extra_context_md="",
            iteration=1,
            findings_snapshot=[
                {
                    "finding_id": f"F-{index}",
                    "title": f"title {index}",
                    "severity": "medium",
                    "confidence": 0.5,
                    "status": "accepted",
                    "summary": "summary",
                }
                for index in range(25)
            ],
            active_hypotheses=[],
            resolved_hypotheses=[],
            history=[],
            max_findings=20,
        )
        payload = messages[1]["content"]
        self.assertIn("F-19", payload)
        self.assertNotIn("F-20", payload)

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

    def test_truncate_context_sections_keeps_text_within_1500_chars(self) -> None:
        sections = {"2_timeline": "x" * 1500, "3_technical": "y" * 1501}

        trimmed = _truncate_context_sections(sections)

        self.assertEqual("x" * 1500, trimmed["2_timeline"])
        self.assertEqual("y" * 1500, trimmed["3_technical"])

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

    def test_build_check_messages_require_observed_evidence_for_durable_memory(self) -> None:
        messages = build_check_messages(
            planned_query=PlannedQuery(query_id="Q1", hypothesis_id="H1", purpose="purpose", sql="SELECT 1"),
            hypothesis=Hypothesis(id="H1", description="desc"),
            finding_candidates=[],
            result_summary={"row_count": 1},
            overview_md="# overview",
            memory_context_md="# facts.md\n- fact",
        )
        system = messages[0]["content"]
        self.assertIn("always include observed evidence_ids", system)
        self.assertIn("Do not emit speculative or unconfirmed items into memory_updates.facts", system)
        self.assertIn("If you cannot cite observed evidence_ids", system)

    def test_report_section_messages_truncate_previous_sections(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "1_overview"},
            evidence_results=[],
            context_sections={"1_overview": "x" * 1600},
            template_body="# Section",
            report_brief={},
        )
        payload = messages[1]["content"]
        self.assertIn("x" * 1500, payload)
        self.assertNotIn("x" * 1600, payload)

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

    def test_broad_plan_messages_use_system_assigned_hypothesis_ids(self) -> None:
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
        self.assertIn("<assigned by system>", system)
        self.assertNotIn('"id": "H-new"', system)

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

    def test_plan_hypothesis_query_includes_recent_db_history_on_resume(self) -> None:
        state = SessionState(session_id="session-db", iteration=2)
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        response = {"read_more": [], "query": None, "needs_more": False}

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H1', 'S-1', 1, 'check', 'inconclusive', 'Q-old', 'already tested', now())
                    """
                )
                with patch("forensia.ai.planner.request_llm_json", return_value=response) as mock_request:
                    plan_hypothesis_query(
                        state=state,
                        hypothesis=hypothesis,
                        finding_candidates=[],
                        memory=_MemoryStub(),
                        base_url=_llm_base_url(),
                        model="test-model",
                        db=db,
                    )

        payload = mock_request.call_args.kwargs["messages"][1]["content"]
        self.assertIn("Already-executed query IDs for this hypothesis: ['Q-old']", mock_request.call_args.kwargs["messages"][0]["content"])
        self.assertIn("'query_id': 'Q-old'", payload)
        self.assertIn("'body': 'already tested'", payload)

    def test_plan_hypothesis_query_dedupes_local_and_db_query_ids(self) -> None:
        state = SessionState(
            session_id="session-db",
            iteration=2,
            history=[
                HistoryEntry(
                    iteration=1,
                    query_id="Q-local",
                    hypothesis_id="H1",
                    verdict="inconclusive",
                    summary="already tested",
                    evidence_ids=[],
                )
            ],
        )
        hypothesis = Hypothesis(id="H1", description="test hypothesis")
        response = {"read_more": [], "query": None, "needs_more": False}

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, verdict, query_id, body, created_at
                    ) VALUES ('HR-1', 'H1', 'S-1', 1, 'check', 'inconclusive', 'Q-local', 'duplicate row', now())
                    """
                )
                with patch("forensia.ai.planner.request_llm_json", return_value=response) as mock_request:
                    plan_hypothesis_query(
                        state=state,
                        hypothesis=hypothesis,
                        finding_candidates=[],
                        memory=_MemoryStub(),
                        base_url=_llm_base_url(),
                        model="test-model",
                        db=db,
                    )

        system = mock_request.call_args.kwargs["messages"][0]["content"]
        user = mock_request.call_args.kwargs["messages"][1]["content"]
        self.assertEqual(1, system.count("Q-local"))
        self.assertEqual(1, user.count("'query_id': 'Q-local'"))

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
        self.assertIn("event_id = 4624 AND logon_type IN ('2','10')", framework)
        self.assertIn("4728/4732", framework)

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
                    use_phased_check=False,
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
                    use_phased_check=False,
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
                    use_phased_check=False,
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

    def test_checker_drops_durable_memory_updates_when_evidence_becomes_empty(self) -> None:
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
                        "tasks": [{"text": "still investigate", "kind": "internal_db_check"}],
                        "overview": ["keep storyline"],
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
                    finding_candidates=[],
                    result_summary={"row_count": 1, "sample_rows": [], "evidence_ids": ["ev-1"]},
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

    def test_checker_normalizes_entity_type_and_drops_invalid_entity_updates(self) -> None:
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
                    "memory_updates": {
                        "entities": [
                            {"entity_type": "src_ip", "name": "10.0.0.5", "role": "source_ip", "notes": "keep as ip"},
                            {"entity_type": "username", "name": "alice", "role": "actor_user", "notes": "keep as user"},
                            {"entity_type": "machine_account", "name": "INFORMANT-PC$", "role": "source_account", "notes": "keep as machine account"},
                            {"entity_type": "service_name", "name": "-", "role": "service_name", "notes": "drop placeholder"},
                            {"entity_type": "device_group", "name": "ops", "notes": "drop"},
                        ]
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
                    finding_candidates=[],
                    result_summary={"row_count": 1, "sample_rows": [], "evidence_ids": ["ev-1"]},
                    memory=memory,
                    base_url=_llm_base_url(),
                    model="test-model",
                )

        self.assertEqual(
            {
                "entities": [
                    {"entity_type": "ip", "name": "10.0.0.5", "role": "source_ip", "notes": "keep as ip"},
                    {"entity_type": "user", "name": "alice", "role": "actor_user", "notes": "keep as user"},
                    {"entity_type": "machine_account", "name": "INFORMANT-PC$", "role": "source_account", "notes": "keep as machine account"},
                ]
            },
            captured["result"].memory_updates,
        )

    def test_report_section_messages_include_recommendation_strength_guidance(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "5_recommendations"},
            evidence_results=[],
            context_sections={},
            template_body="# Recommended Actions",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("Match wording to confidence", system)
        self.assertIn("Recommended actions must scale with evidence strength", system)

    def test_report_section_messages_include_language_confidence_matrix_and_categories(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[],
            context_sections={},
            template_body="# Persistence and Execution",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("confidence >= 0.8", system)
        self.assertIn("confidence < 0.5", system)
        self.assertIn("Do not use 'confirmed' for findings or conclusions below 0.8 confidence", system)
        self.assertIn("GOOGLEDRIVESYNC.EXE=cloud_sync", system)
        self.assertIn("SCHTASKS.EXE=persistence_tool", system)

    def test_investigation_framework_includes_machine_account_and_category_guidance(self) -> None:
        framework = build_investigation_framework()

        self.assertIn("account names ending with '$' as machine_account", framework)
        self.assertIn("never store a machine account in source_ip", framework)
        self.assertIn("GOOGLEDRIVESYNC.EXE=cloud_sync", framework)
        self.assertIn("SCHTASKS.EXE=persistence_tool", framework)

    def test_benchmark_report_brief_strips_narrative_keys(self) -> None:
        brief = _benchmark_report_brief(
            {
                "investigation_objective": "Narrative objective",
                "top_findings": [{"finding_id": "F-1"}],
                "active_hypotheses": [{"hypothesis_id": "H-1"}],
                "confirmed_hypotheses": [{"hypothesis_id": "H-2"}],
                "evidence_inventory": {
                    "time_range": "2026-05-01 to 2026-05-02",
                    "row_counts": {"evtx_events": 12},
                    "narrative": "drop this",
                },
            }
        )

        self.assertNotIn("investigation_objective", brief)
        self.assertNotIn("top_findings", brief)
        self.assertNotIn("active_hypotheses", brief)
        self.assertEqual(
            {
                "time_range": "2026-05-01 to 2026-05-02",
                "row_counts": {"evtx_events": 12},
            },
            brief["evidence_inventory"],
        )

    def test_report_section_messages_include_event_id_guidance(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[
                {
                    "kind": "rows",
                    "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                    "head_rows": [],
                    "tail_rows": [],
                }
            ],
            context_sections={},
            template_body="# Section",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("Event ID 4720", system)
        self.assertIn("allowed_claims", system)

    def test_report_section_messages_include_strength_guidance_for_non_confirmed_sources(self) -> None:
        messages = build_report_section_messages(
            section_meta={"section": "3_technical"},
            evidence_results=[
                {
                    "kind": "rows",
                    "source_verdict": "newlead",
                    "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                }
            ],
            context_sections={},
            template_body="# Section",
            report_brief={},
        )
        system = messages[0]["content"]
        self.assertIn("source_verdict guidance", system)
        self.assertIn("avoid 'confirmed'", system)

    def test_benchmark_section_messages_request_json_only(self) -> None:
        messages = build_benchmark_section_messages(
            section_meta={"section": "6_appendix", "title": "Appendix"},
            evidence_results=[
                {
                    "kind": "rows",
                    "sample_rows": [{"evidence_id": "ev-1", "file_path": "C:/Users/Alice/file.ost"}],
                }
            ],
            template_body="## 8. メールデータファイル",
            block_heading="8. メールデータファイル",
            raw_evidence_rows=[{"summary": "file_path=C:/Users/Alice/file.ost"}],
            benchmark_id="Q8",
        )
        system = messages[0]["content"]
        self.assertIn("benchmark answer writer", system)
        self.assertIn("Output JSON only", system)
        self.assertIn('"answer"', system)
        self.assertIn("queries_run", system)

    def test_query_fingerprint_normalizes_equivalent_ast_forms(self) -> None:
        left = _query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4624 AND computer = 'HOST1'"
        )
        right = _query_fingerprint(
            "select * from evtx_events as e where computer = 'host1' and event_id in (4624)"
        )

        self.assertEqual(left, right)

    def test_query_fingerprint_changes_for_different_event_scope(self) -> None:
        left = _query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4624 AND computer = 'HOST1'"
        )
        right = _query_fingerprint(
            "SELECT * FROM evtx_events WHERE event_id = 4634 AND computer = 'HOST1'"
        )

        self.assertNotEqual(left, right)


if __name__ == "__main__":
    unittest.main()
