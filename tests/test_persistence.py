from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
import yaml
from typer.testing import CliRunner

from forensia import cli as cli_module
from forensia.ai.checker import _insert_investigation_finding
from forensia.ai.investigator import (
    _append_hypothesis_reasoning,
    _final_summary,
)
from forensia.ai.planner import HypothesisPlanResult
from forensia.ai.report_gap import (
    _classify_gap_kind,
    _gap_hypothesis_id,
    _inject_gap_hypotheses,
    _report_cycle_progress,
)
from forensia.ai.hypothesis_manager import _load_persisted_hypotheses
from forensia.ai.hypothesis_manager import _merge_active_hypotheses
from forensia.config import clear_llm_settings_cache, resolve_llm_config
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, PlannedQuery, SessionState
from forensia.db.database import CaseDB
from forensia.rules.engine import execute_event_keyword_fallback_search
from forensia.report.writer import (
    _collect_flat_evidence_rows,
    _build_report_brief,
    _default_keypoints_for_section,
    _extract_claim_texts,
    _query_top_findings,
    _quality_gate_section,
    _resolve_evidence_results,
    _sort_markdown_table_by_first_column,
    _section_confidence,
    collect_gaps,
    build_report_markdown_from_db,
    ensure_universal_question_probes,
    finalize_section,
    prepare_section_request,
)
from forensia.report_templates import export_packaged_report_templates


def _agent_plan_router(*_args, **kwargs):
    """Route section_agent.request_llm_json by which messages were sent.

    Plan messages → "write" short-circuit (no SQL).
    Check messages → "sufficient" so the loop exits cleanly.
    Used to avoid hitting a real LLM in unit tests.
    """
    messages = kwargs.get("messages")
    if messages is None and _args:
        messages = _args[0]
    system_content = ""
    if messages:
        system_content = str(messages[0].get("content", "")).lower()
    if "section-check" in system_content:
        return {"verdict": "sufficient", "fact_updates": []}
    return {"action": "write", "enough_to_write": True}


async def _async_agent_plan_router(*args, **kwargs):
    return _agent_plan_router(*args, **kwargs)


class PersistenceTests(unittest.TestCase):
    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def setUp(self) -> None:
        self._llm_json_patch = patch(
            "forensia.ai.section_agent.request_llm_json",
            side_effect=_agent_plan_router,
        )
        self._llm_json_patch.start()
        self.addCleanup(self._llm_json_patch.stop)
        # The async report-refresh path uses async_request_llm_json; mock it too
        # so async tests don't hit the real LLM.
        self._async_llm_json_patch = patch(
            "forensia.ai.section_agent.async_request_llm_json",
            side_effect=_async_agent_plan_router,
        )
        self._async_llm_json_patch.start()
        self.addCleanup(self._async_llm_json_patch.stop)

    def test_collect_gaps_supports_english_and_japanese_placeholders(self) -> None:
        self.assertEqual(
            ["no logon data"],
            collect_gaps({"sec": "[INSUFFICIENT EVIDENCE: no logon data]"}),
        )
        self.assertEqual(
            ["no logon records"],
            collect_gaps({"sec": "[INSUFFICIENT EVIDENCE: no logon records]"}),
        )

    def test_collect_gaps_preserves_order_while_deduplicating(self) -> None:
        self.assertEqual(
            ["gap one", "gap two"],
            collect_gaps(
                {
                    "a": "[INSUFFICIENT EVIDENCE: gap one]\n[INSUFFICIENT EVIDENCE: gap two]",
                    "b": "[INSUFFICIENT EVIDENCE: gap one]",
                }
            ),
        )

    def test_section_confidence_and_claim_extraction_respect_english_gap_placeholder(self) -> None:
        self.assertEqual(1.0, _section_confidence("no gaps here"))
        self.assertLess(_section_confidence("[INSUFFICIENT EVIDENCE: x]"), 1.0)
        self.assertEqual([], _extract_claim_texts("[INSUFFICIENT EVIDENCE: missing evidence]"))
        self.assertEqual(["same claim"], _extract_claim_texts("same claim\n\nsame claim"))

    def test_append_hypothesis_reasoning_is_idempotent_per_query_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                first = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                second = _append_hypothesis_reasoning(
                    db=db,
                    hypothesis_id="H-1",
                    session_id="S-1",
                    iteration=1,
                    phase="plan",
                    query_id="q-1",
                    body="look for 4625 burst",
                )
                count = db.execute("SELECT COUNT(*) FROM hypothesis_reasoning WHERE hypothesis_id = 'H-1'").fetchone()[0]

            self.assertEqual(first, second)
            self.assertEqual(1, count)

    def test_load_persisted_hypotheses_restores_resolved_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "H-1",
                        "suspicious lateral movement confirmed",
                        "confirmed",
                        "confirmed",
                        "resolved in prior session",
                        "broad_plan",
                        "session-old",
                        "session-old",
                        now,
                        now,
                    ),
                )
                active, resolved = _load_persisted_hypotheses(db)

            self.assertEqual(0, len(active))
            self.assertEqual(1, len(resolved))
            self.assertEqual("H-1", resolved[0].id)
            self.assertEqual("confirmed", resolved[0].status)

    def test_prepare_section_request_infers_section_evidence_without_template_keypoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "1_overview.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                "# Overview\n",
                encoding="utf-8",
            )
            case.memory_dir.joinpath("keypoints").mkdir(parents=True, exist_ok=True)
            case.memory_dir.joinpath("keypoints", "KP-0001.md").write_text(
                "# KP-0001\n\n- finding_id: F-1\n- title: Suspicious logon\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("ev-1", "a.evtx", "Security", 4624, 1, "host1", "", "", "", "", "", "", "", "", "", "{}", "[]", "info"),
                )
                request = prepare_section_request(case, db, template_path, {}, report_brief={})
                # Evidence resolution moved into section_agent; verify the default
                # keypoint selection + resolver directly.
                default_keypoints = _default_keypoints_for_section("1_overview")
                resolved = _resolve_evidence_results(case, db, keypoints=default_keypoints)

            self.assertEqual("1_overview", request["section_key"])
            result_names = {item["keypoint"] for item in resolved}
            self.assertIn("overview_top_findings", result_names)

    def test_prepare_section_request_infers_ioc_keypoints_from_section_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "3_technical.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                "# Technical\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        target_user, process_name, command_line, src_ip, severity
                    ) VALUES
                        ('ev-1', 'a.evtx', 'Security', 4688, 1, now(), 'host1', 'user1', 'powershell.exe', '-enc AQBkAC...', NULL, 'high'),
                        ('ev-2', 'a.evtx', 'Security', 4624, 2, now(), 'host1', 'user1', NULL, NULL, '10.0.0.1', 'info'),
                        ('ev-3', 'a.evtx', 'Security', 4624, 3, now(), 'host1', 'user2', NULL, NULL, '10.0.0.2', 'info')
                    """
                )
                prepare_section_request(case, db, template_path, {}, report_brief={})
                default_keypoints = _default_keypoints_for_section("3_technical")
                resolved = _resolve_evidence_results(case, db, keypoints=default_keypoints)

            results = {item["keypoint"]: item for item in resolved}
            self.assertIn("host_execution_activity", results)
            self.assertIn("account_logon_patterns", results)
            self.assertIn("ioc_source_ips", results)
            self.assertEqual("powershell.exe", results["host_execution_activity"]["sample_rows"][0]["process_name"])
            self.assertGreater(results["ioc_source_ips"]["row_count"], 0)

    def test_prepare_section_request_extracts_block_hints(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "6_appendix.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                (
                    "# Appendix\n\n"
                    "## 8. E-mail data files\n"
                    "<!-- question: Where is the e-mail file located? -->\n"
                    "<!-- mode: structured -->\n"
                    "<!-- answer_id: Q20 -->\n"
                    "<!-- answer_spec: email_data_files -->\n"
                    "<!-- evidence_keypoints: ioc_email_ost_files, timeline_prefetch_history -->\n"
                    "<!-- fill -->\n"
                ),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(case, db, template_path, {}, report_brief={})

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("Q20", block["answer_id"])
            self.assertEqual("email_data_files", block["answer_spec"])
            self.assertEqual("Where is the e-mail file located?", block["question"])
            self.assertEqual(["ioc_email_ost_files", "timeline_prefetch_history"], block["evidence_keypoints"])

    def test_universal_question_probes_are_explicit_and_store_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "1_overview.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text("# Overview\n\n## Evidence Scope\n<!-- fill -->\n", encoding="utf-8")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    ("evtx-security-000000000001", 4624, datetime(2015, 3, 22, 14, 34, 28), "informant-PC", "informant", "2"),
                )
                prepare_section_request(case, db, template_path, {}, report_brief={})
                initial_probe_count = db.execute(
                    "SELECT COUNT(*) FROM section_questions WHERE section_key = '__case_probe__'"
                ).fetchone()[0]
                ensure_universal_question_probes(case, db)
                probe_count = db.execute(
                    "SELECT COUNT(*) FROM section_questions WHERE section_key = '__case_probe__' AND status = 'case_probe'"
                ).fetchone()[0]
                fact = db.execute(
                    """
                    SELECT fact_value, evidence_ids
                    FROM section_facts
                    WHERE source_section = '__case_probe__'
                      AND fact_key = 'last_human_logon'
                    """
                ).fetchone()

            self.assertEqual(0, initial_probe_count)
            self.assertGreaterEqual(probe_count, 5)
            self.assertIsNotNone(fact)
            self.assertIn("informant", str(fact[0]))
            self.assertIn("evtx-security-000000000001", str(fact[1]))

    def test_question_marker_enables_structured_mode_without_explicit_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "6_appendix.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                (
                    "# Appendix\n\n"
                    "## Last shutdown\n"
                    "<!-- question -->\n"
                    "<!-- fill -->\n"
                ),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(case, db, template_path, {}, report_brief={})

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("", block["answer_spec"])

    def test_quality_gate_flags_placeholder_entities_and_non_chronological_timeline(self) -> None:
        body = (
            "| Timestamp | Host | Stage | Event | evidence_id |\n"
            "|---|---|---|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 | Login | user=None | ev-2 |\n"
            "| 2026-05-16 09:00:00 | host1 | Execution | process | ev-1 |\n"
        )

        gaps, confidence = _quality_gate_section("2_timeline", "Attack Timeline", body, [], 1.0, behaviors=("require_chronological_table",))

        self.assertTrue(any("Placeholder entity values detected" in g for g in gaps))
        self.assertTrue(any("events are not strictly chronological" in g for g in gaps))
        self.assertLess(confidence, 1.0)

    def test_collect_flat_evidence_rows_filters_sparse_rows(self) -> None:
        rows = [
            {
                "kind": "rows",
                "sample_rows": [
                    {
                        "timestamp": "2026-05-28 10:00:00",
                        "event_id": 4624,
                        "process_name": "powershell.exe",
                        "message": "NULL",
                    },
                    {
                        "timestamp": None,
                        "event_id": None,
                        "process_name": None,
                        "message": None,
                    },
                ],
            }
        ]

        flat = _collect_flat_evidence_rows(rows, min_filled_cols=0.5)
        self.assertEqual(1, len(flat))
        self.assertEqual("powershell.exe", flat[0]["process_name"])

    def test_finalize_section_flags_event_specific_disallowed_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("ev-4720", "a.evtx", "Security", 4720, 1, "host1", "", "alice", "alice", "admin", "", "", "", "", "", "{}", "[]", "info"),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body="## Account Creation\n\nThe evidence suggests privilege escalation occurred.",
                    evidence_results=[
                        {
                            "kind": "rows",
                            "sample_rows": [{"event_id": 4720, "evidence_id": "ev-4720"}],
                            "head_rows": [],
                            "tail_rows": [],
                            "evidence_ids": ["ev-4720"],
                            "finding_ids": [],
                            "hypothesis_ids": [],
                        }
                    ],
                )

            self.assertTrue(
                any("disallowed wording" in str(gap) for gap in result["gaps"]),
                msg=f"Expected event-specific claim gap in {result['gaps']}",
            )

    def test_finalize_section_flags_overstated_claims_for_non_confirmed_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("ev-1", "a.evtx", "Security", 4720, 1, "host1", "", "alice", "alice", "admin", "", "", "", "", "", "{}", "[]", "info"),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body="## Account Creation\n\nThe attack was confirmed and compromised the host.",
                    evidence_results=[
                        {
                            "kind": "rows",
                            "source_verdict": "newlead",
                            "sample_rows": [{"event_id": 4720, "evidence_id": "ev-1"}],
                            "evidence_ids": ["ev-1"],
                            "finding_ids": [],
                            "hypothesis_ids": [],
                        }
                    ],
                )

                self.assertTrue(
                    any("cautious wording" in str(gap) for gap in result["gaps"]),
                    msg=f"Expected strength gap in {result['gaps']}",
                )

    def test_execute_event_keyword_fallback_search_uses_event_id_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, source_file, channel, event_id, record_id, timestamp, computer,
                        user_name, target_user, subject_user, src_ip, logon_type, process_name,
                        command_line, service_name, message, raw_json, tags, severity
                    ) VALUES (?, ?, ?, ?, ?, now(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "ev-4720",
                        "a.evtx",
                        "Security",
                        4720,
                        1,
                        "host1",
                        "",
                        "alice",
                        "alice",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "account created for alice",
                        '{"message":"account created for alice"}',
                        "[]",
                        "info",
                    ),
                )
                rows, fallback_info = execute_event_keyword_fallback_search(
                    db, "SELECT * FROM evtx_events WHERE event_id = 4720 AND computer = 'missing'"
                )

            self.assertEqual(1, len(rows))
            self.assertEqual("keyword_in_raw_json", fallback_info["phase"])
            self.assertIn(4720, fallback_info["event_ids"])
            self.assertTrue(any("account created" in keyword for keyword in fallback_info["keywords"]))

    def test_build_report_markdown_keeps_coverage_out_of_final_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at, stale
                    ) VALUES
                        ('1_overview', 'Overview', '# Investigation Overview\n\n## Evidence Scope\n\nOriginal scope text.\n', 0.9, 'stable', 1, '[]', 's-1', now(), FALSE),
                        ('2_timeline', 'Timeline', '# Timeline\n\n**Status:** partial\n\nBody text with raw_sql reference.\n', 0.9, 'stable', 1, '[]', 's-1', now(), FALSE)
                    """
                )
                db.execute(
                    """
                    INSERT INTO section_runs (run_id, section_key, block_heading, iteration, phase, payload, verdict, created_at)
                    VALUES
                        ('run-1', '1_overview', 'Evidence Scope', 1, 'query', '{"source_kind":"keypoint","source_ref":"benchmark_ost_file","result":{"keypoint":"benchmark_ost_file","source_ref":"benchmark_ost_file","source_kind":"keypoint","kind":"rows","row_count":2}}', NULL, now()),
                        ('run-2', '2_timeline', 'Timeline', 1, 'query', '{"source_kind":"keypoint","source_ref":"benchmark_timeline_events","result":{"keypoint":"benchmark_timeline_events","source_ref":"benchmark_timeline_events","source_kind":"keypoint","kind":"rows","row_count":5}}', NULL, now()),
                        ('run-3', '2_timeline', 'Timeline', 1, 'query', '{"source_kind":"keypoint","source_ref":"empty_timeline_events","result":{"keypoint":"empty_timeline_events","source_ref":"empty_timeline_events","source_kind":"keypoint","kind":"rows","row_count":0}}', NULL, now())
                    """
                )
                coverage_rows = db.execute(
                    """
                    SELECT section_key, source_query, evidence_table, row_count, used_in_answer, queried
                    FROM section_run_coverage
                    ORDER BY section_key, source_query
                    """
                ).fetchall()
                markdown = build_report_markdown_from_db(db)

            self.assertEqual(3, len(coverage_rows))
            self.assertEqual("benchmark_ost_file", coverage_rows[0][1])
            self.assertEqual("Yes", coverage_rows[0][4])
            zero_row = next(row for row in coverage_rows if row[1] == "empty_timeline_events")
            self.assertEqual("No", zero_row[4])
            self.assertNotIn("#### Coverage Summary", markdown)
            self.assertNotIn("benchmark_ost_file", markdown)
            self.assertNotIn("#### Evidence Coverage", markdown)
            self.assertNotIn("benchmark_timeline_events", markdown)
            self.assertNotIn("**Status:** partial", markdown)
            self.assertNotIn("raw_sql", markdown)

    def test_build_report_markdown_rebuilds_non_question_sections_with_tables(self) -> None:
        """Without deterministic override, report_markdown renders from DB bodies directly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count,
                        gaps, last_filled_session, last_filled_at, stale
                    ) VALUES
                        ('1_overview', 'Investigation Overview', '# Investigation Overview\n\n## Executive Summary\n\nLLM written overview content.\n\n## Key Findings\n\nDetailed findings.', 0.8, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('2_timeline', 'Activity Timeline', '# Activity Timeline\n\n## Phase Summary\n\nTimeline narrative.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('3_technical', 'Technical Analysis', '# Technical Analysis\n\n## Systems and Accounts\n\nAccount analysis text.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE),
                        ('4_gaps', 'Investigation Gaps', '# Investigation Gaps\n\n## Evidence Gaps\n\nGap analysis.', 0.7, 'draft', 1, '[]', 'S-1', now(), FALSE)
                    """
                )

                markdown = build_report_markdown_from_db(db)

            self.assertIn("# Investigation Overview", markdown)
            self.assertIn("LLM written overview content", markdown)
            self.assertIn("# Activity Timeline", markdown)
            self.assertIn("Timeline narrative.", markdown)
            self.assertIn("# Technical Analysis", markdown)
            self.assertIn("Account analysis text.", markdown)
            self.assertIn("# Investigation Gaps", markdown)
            self.assertIn("Gap analysis.", markdown)
            self.assertNotIn("**Status:**", markdown)

    def test_build_report_markdown_adds_appendix_interpretation_to_existing_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count,
                        gaps, last_filled_session, last_filled_at, stale
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, now(), FALSE)
                    """,
                    (
                        "6_appendix",
                        "Appendix",
                        "# Appendix\n\n"
                        "## 1. Endpoint identity\n\n"
                        "**ID:** Q6\n"
                        "**Status:** answered\n\n"
                        "### Answer\n"
                        "| host_id | evidence_count | first_seen | last_seen | evidence_id |\n"
                        "| --- | --- | --- | --- | --- |\n"
                        "| informant-PC | 4453 | 2015-03-22 | 2015-03-25 | evtx-security-000000000001 |\n\n"
                        "### Queries Run\n"
                        "- structured:host_identity:evtx_distinct_hosts\n\n"
                        "### Structured Data\n"
                        "- JSON: structured/answers.json\n",
                        0.9,
                        "stable",
                        1,
                        "[]",
                        "S-1",
                    ),
                )

                markdown = build_report_markdown_from_db(db)

            self.assertIn("### Interpretation", markdown)
            self.assertIn("EVTX 上では informant-PC", markdown)
            self.assertIn("### Answer", markdown)
            self.assertNotIn("evidence_id", markdown)
            self.assertNotIn("evtx-security-000000000001", markdown)

    def test_build_report_markdown_refreshes_stale_antiforensic_appendix_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-prefetch-cleaner",
                        "Windows/Prefetch/CCLEANER64.EXE-779BD542.pf",
                        "CCLEANER64.EXE-779BD542.pf",
                        datetime(2015, 3, 25, 15, 15, 50),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-cipher-noise",
                        "Windows/System32/cipher.exe",
                        "cipher.exe",
                        datetime(2009, 7, 14, 1, 38, 59),
                    ),
                )
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count,
                        gaps, last_filled_session, last_filled_at, stale
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, now(), FALSE)
                    """,
                    (
                        "6_appendix",
                        "Appendix",
                        "# Appendix\n\n"
                        "## 12. Antiforensic activity\n\n"
                        "**ID:** Q45\n"
                        "**Status:** answered\n\n"
                        "### Answer\n"
                        "| evidence_type | file_name | file_path | evidence_id |\n"
                        "| --- | --- | --- | --- |\n"
                        "| tool_or_cleanup_artifact | cipher.exe | Windows/System32/cipher.exe | mft-cipher-noise |\n\n"
                        "### Queries Run\n"
                        "- stale\n\n"
                        "### Structured Data\n"
                        "- JSON: structured/answers.json\n",
                        0.9,
                        "stable",
                        1,
                        "[]",
                        "S-1",
                    ),
                )

                markdown = build_report_markdown_from_db(db)

            self.assertIn("CCLEANER64.EXE-779BD542.pf", markdown)
            self.assertNotIn("cipher.exe", markdown)
            self.assertNotIn("mft-cipher-noise", markdown)

    def test_finalize_section_sanitizes_raw_evidence_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                finalize_section(
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    body=(
                        "## 8. E-mail data files\n\n"
                        "#### Raw Evidence\n\n"
                        "| timestamp | process_name | message |\n"
                        "|---|---|---|\n"
                        "| 2026-05-28 10:00:00 | None | NULL |\n"
                        "\n## 9. Other\n\nSummary text.\n"
                    ),
                    evidence_results=[
                        {
                            "kind": "rows",
                            "source_verdict": "newlead",
                            "sample_rows": [{"timestamp": "2026-05-28 10:00:00", "process_name": "None"}],
                            "evidence_ids": [],
                            "finding_ids": [],
                            "hypothesis_ids": [],
                        }
                    ],
                )
                row = db.execute(
                    "SELECT body, gaps FROM report_sections WHERE section_key = ?",
                    ("6_appendix",),
                ).fetchone()

            body = str(row[0] or "")
            gaps = row[1]
            self.assertNotIn("None", body)
            self.assertNotIn("NULL", body)
            self.assertIn("Raw evidence moved to reports/evidence/6_appendix.json", body)
            self.assertIn("raw evidence rows were moved", str(gaps).lower())

    def test_finding_and_report_section_dtos_include_evidence_counts(self) -> None:
        from forensia.api.service import list_findings_dto, list_report_sections_dto

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "finding-test",
                        "rule-test",
                        "Test finding",
                        "A finding with concrete evidence.",
                        "high",
                        0.9,
                        "accepted",
                        "[]",
                        "[]",
                        json.dumps(
                            [
                                {"evidence_id": "evtx-security-000000000001"},
                                {"evidence_ids": ["prefetch-execution-000000000002"]},
                                {"evidence_id": "evtx-security-000000000001"},
                            ]
                        ),
                        "AI summary",
                        "[]",
                    ),
                )
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count,
                        gaps, last_filled_session, last_filled_at, stale
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, now(), false)
                    """,
                    ("1_overview", "Overview", "Body", 0.9, "draft", 1, "[]", "S-1"),
                )
                db.execute(
                    """
                    INSERT INTO section_evidence (section_key, block_heading, evidence_id, role, source_query, created_at)
                    VALUES
                        ('1_overview', 'A', 'evtx-security-000000000001', 'support', 'q1', now()),
                        ('1_overview', 'A', 'evtx-security-000000000001', 'support', 'q2', now()),
                        ('1_overview', 'A', 'prefetch-execution-000000000002', 'support', 'q3', now())
                    """
                )

                finding = list_findings_dto(db)[0]
                section = list_report_sections_dto(db)[0]

            self.assertEqual(
                ["evtx-security-000000000001", "prefetch-execution-000000000002"],
                finding.evidence_ids,
            )
            self.assertEqual(2, finding.evidence_count)
            self.assertEqual(
                ["evtx-security-000000000001", "prefetch-execution-000000000002"],
                section.evidence_ids,
            )
            self.assertEqual(2, section.evidence_count)

    def test_finalize_section_upserts_section_and_returns_gaps(self) -> None:
        from forensia.api.service import list_report_sections_dto

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                result = finalize_section(
                    db=db,
                    section_key="1_overview",
                    title="Overview",
                    body="## Overview\n\nOverview content here.",
                    evidence_results=[],
                )
                section = list_report_sections_dto(db)[0]

            self.assertEqual("1_overview", section.section_key)
            self.assertEqual("Overview", section.title)
            self.assertIsInstance(result, dict)
            self.assertIn("gaps", result)
            self.assertIn("confidence", result)

    def test_merge_active_hypotheses_assigns_sequential_ids_and_dedupes_description(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES
                        ('H-001', 'existing active hypothesis', 'active', NULL, '', 'broad_plan', 'S-1', NULL, now(), now(), '["rule-1"]', '["host"]', NULL),
                        ('H-002', 'resolved reference hypothesis', 'confirmed', 'confirmed', 'done', 'broad_plan', 'S-1', 'S-2', now(), now(), '["rule-2"]', '["user"]', NULL)
                    """
                )
                current = [
                    Hypothesis(id="H-001", description="existing active hypothesis", status="active", summary="", source_rule_ids=["rule-1"], required_entities=["host"]),
                ]
                updates = [
                    Hypothesis(id="H-new", description="existing active hypothesis", status="active", summary="", source_rule_ids=["rule-3"], required_entities=["computer"]),
                    Hypothesis(id="H-new-2", description="brand new hypothesis", status="active", summary="", source_rule_ids=["rule-4"], required_entities=["service"]),
                    Hypothesis(id="H-new-3", description="resolved reference hypothesis", status="active", summary="", source_rule_ids=["rule-5"], required_entities=["user"]),
                ]
                resolved = [
                    Hypothesis(id="H-002", description="resolved reference hypothesis", status="confirmed", verdict="confirmed", summary="done"),
                ]
                merged = _merge_active_hypotheses(
                    db=db,
                    current=current,
                    updates=updates,
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )
                rows = db.execute(
                    "SELECT hypothesis_id, description, status, source_rule_ids FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()

            ids = [row[0] for row in rows]
            self.assertEqual(["H-001", "H-002", "H-003"], ids)
            self.assertEqual(2, len(merged))
            self.assertEqual({"H-001", "H-003"}, {item.id for item in merged})
            self.assertIn("rule-3", str(rows[0][3]))
            self.assertEqual("H-003", rows[2][0])

    def test_merge_active_hypotheses_dedup_by_similarity_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES
                        ('H-010', 'RDP lateral movement to deploy service', 'active', NULL, '', 'broad_plan', 'S-1', NULL, now(), now(), '["rule-1"]', '["host"]', NULL)
                    """
                )
                merged = _merge_active_hypotheses(
                    db=db,
                    current=[Hypothesis(id="H-010", description="RDP lateral movement to deploy service", status="active", source_rule_ids=["rule-1"], required_entities=["host"])],
                    updates=[
                        Hypothesis(id="H-new", description="RDP lateral movement used to deploy service", status="active", source_rule_ids=["rule-2"], required_entities=["host"]),
                    ],
                    resolved=[],
                    session_id="session-test",
                    origin="broad_plan",
                )
                rows = db.execute(
                    "SELECT hypothesis_id, description, source_rule_ids FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()
                self.assertEqual(1, len(merged))
                self.assertEqual("H-010", merged[0].id)
                self.assertIn("rule-2", str(rows[0][2]))

    def test_quality_gate_flags_heading_title_mismatch(self) -> None:
        gaps, confidence = _quality_gate_section(
            "3_technical",
            "Compromised Accounts and Authentication",
            "# Indicators of Compromise\n\nBody text",
            [],
            1.0,
        )

        self.assertTrue(any("heading does not match" in gap.lower() for gap in gaps))
        self.assertLessEqual(confidence, 0.65)

    def test_quality_gate_forces_low_confidence_when_fill_placeholder_remains(self) -> None:
        gaps, confidence = _quality_gate_section(
            "1_overview",
            "Investigation Overview",
            "# Investigation Overview\n\n<!-- fill -->",
            [],
            1.0,
        )

        self.assertTrue(any("placeholder" in gap.lower() for gap in gaps))
        self.assertLessEqual(confidence, 0.3)

    def test_quality_gate_flags_recommendations_without_evidence_strength(self) -> None:
        body = (
            "## Immediate Response\n\n"
            "| Priority | Action | Justification |\n"
            "|---|---|---|\n"
            "| High | Isolate host1 now | suspicious activity observed |\n"
        )

        gaps, confidence = _quality_gate_section("5_recommendations", "Recommended Actions", body, [], 1.0, behaviors=("require_recommendations_strength",))

        self.assertTrue(any("Recommendations should state evidence strength" in g for g in gaps))
        self.assertLess(confidence, 1.0)

    def test_sort_markdown_table_by_first_column_orders_timeline_rows(self) -> None:
        body = (
            "| Timestamp | Host |\n"
            "|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 |\n"
            "| 2026-05-16 09:00:00 | host1 |\n"
        )
        sorted_body = _sort_markdown_table_by_first_column(body)
        self.assertLess(sorted_body.find("09:00:00"), sorted_body.find("10:00:00"))

    def test_export_packaged_templates_includes_appendix_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir, overwrite=True)

            self.assertTrue(any(path.name == "6_appendix.md" for path in written))
            self.assertTrue((Path(tmpdir) / "6_appendix.md").exists())

    def test_finalize_section_flags_duplicate_finding_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("F-1", "rule", "Suspicious Service", "Summary", "high", 0.9, "accepted", "[]", "[]", "[]", "", "[]", now),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Persistence and Execution",
                    body="# Persistence and Execution\n\nSuspicious Service\n\nSuspicious Service\n\nSuspicious Service",
                    evidence_results=[],
                    session_id="S-1",
                )

            self.assertTrue(any("repeated too often" in gap for gap in result["gaps"]))
            self.assertLessEqual(result["confidence"], 0.6)

    def test_finalize_section_flags_correlation_only_confirmed_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence, status,
                        tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("windows-corr-logon-then-service-0001", "windows-corr-logon-then-service", "Correlation", "Summary", "medium", 0.65, "accepted", "[]", "[]", "[]", "", "[]", now),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Persistence and Execution",
                    body="# Persistence and Execution\n\nConfirmed lateral movement based on windows-corr-logon-then-service-0001.",
                    evidence_results=[],
                    session_id="S-1",
                )

            self.assertTrue(any("Correlation-rule findings" in gap for gap in result["gaps"]))
            self.assertLessEqual(result["confidence"], 0.55)

    def test_build_report_brief_trims_excerpt_in_sql(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("1_overview", "Overview", "x" * 800, 0.9, "draft", 1, "[]", "S-1", now),
                )
                brief = _build_report_brief(db)

            self.assertEqual(1, len(brief["prior_sections"]))
            self.assertLessEqual(len(brief["prior_sections"][0]["body_excerpt"]), 400)

    def test_build_report_brief_dedupes_existing_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            now = datetime.now(UTC).replace(tzinfo=None)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO claims (
                        claim_id, section_key, claim_text, finding_ids, hypothesis_ids, evidence_ids,
                        support_status, created_at, updated_at
                    ) VALUES
                        ('c-1', '1_overview', 'same claim', '[]', '[]', '[]', 'supported', ?, ?),
                        ('c-2', '2_timeline', 'same claim', '[]', '[]', '[]', 'supported', ?, ?),
                        ('c-3', '3_technical', 'different claim', '[]', '[]', '[]', 'supported', ?, ?)
                    """,
                    (now, now, now, now, now, now),
                )
                brief = _build_report_brief(db)

            self.assertEqual(2, len(brief["existing_claims"]))

    def test_report_cycle_progress_can_be_true_from_gap_reduction_alone(self) -> None:
        self.assertTrue(
            _report_cycle_progress(
                {"total_gaps": 3, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )
        self.assertFalse(
            _report_cycle_progress(
                {"total_gaps": 2, "total_body_chars": 120},
                {"total_gaps": 2, "total_body_chars": 120},
            )
        )

    def test_gap_hypotheses_are_injected_once_for_new_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(db, state, ["foo bar"], session_id="session-test")
                duplicate = _inject_gap_hypotheses(db, state, ["foo bar"], session_id="session-test")
                rows = db.execute(
                    "SELECT hypothesis_id, origin, status, description FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()

            self.assertEqual(1, added)
            self.assertEqual(0, duplicate)
            self.assertEqual(1, len(state.active_hypotheses))
            self.assertEqual(_gap_hypothesis_id("foo bar"), state.active_hypotheses[0].id)
            self.assertEqual([(_gap_hypothesis_id("foo bar"), "report_gap", "active", "foo bar")], rows)

    def test_external_or_human_gaps_do_not_become_hypotheses(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                state = SessionState(session_id="session-test")
                added = _inject_gap_hypotheses(
                    db,
                    state,
                    ["Check src_ip ownership", "Manager interview needed"],
                    session_id="session-test",
                    memory=memory,
                )
                row_count = db.execute("SELECT COUNT(*) FROM hypotheses").fetchone()[0]

            self.assertEqual("external_lookup", _classify_gap_kind("Check src_ip ownership"))
            self.assertEqual("human_decision", _classify_gap_kind("Manager interview needed"))
            self.assertEqual(0, added)
            self.assertEqual(0, row_count)
            self.assertIn("ownership", memory.tasks_memory_path.read_text(encoding="utf-8").lower())

    def test_gap_classification_supports_english_external_and_human_keywords(self) -> None:
        for phrase in (
            "Need ip reputation check for this address",
            "Perform geo lookup for the source IP",
            "This requires external internet confirmation",
        ):
            self.assertEqual("external_lookup", _classify_gap_kind(phrase))
        for phrase in (
            "Need manager approval before concluding",
            "Confirm with the business owner",
            "Schedule a stakeholder hearing for this finding",
        ):
            self.assertEqual("human_decision", _classify_gap_kind(phrase))

    def test_final_summary_fallback_follows_output_language(self) -> None:
        with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            self.assertEqual(
                "No additional progress was made during this investigation.",
                _final_summary(SessionState(session_id="S-1")),
            )
            clear_llm_settings_cache()

    def test_investigation_finding_title_prefix_follows_output_language(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            planned_query = PlannedQuery(query_id="Q-1", hypothesis_id="H-1", purpose="host triage", sql="SELECT 1")
            with patch.dict("os.environ", {"LLM_OUTPUT_LANGUAGE": "ja"}):
                clear_llm_settings_cache()
                with CaseDB(case) as db:
                    finding_id = _insert_investigation_finding(
                        db=db,
                        session_id="S-1",
                        planned_query=planned_query,
                        result_summary={"sample_rows": []},
                        report_text="body",
                    )
                    title = db.execute("SELECT title FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()[0]
            self.assertEqual("Investigation: host triage", title)
            clear_llm_settings_cache()

    def test_case_init_creates_allowlist_stub_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            initial = case.allowlist_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(initial)
            self.assertIn("rules", parsed)
            case.allowlist_path.write_text("rules:\n  - rule_id: custom\n", encoding="utf-8")
            Case.init(tmpdir)
            preserved = case.allowlist_path.read_text(encoding="utf-8")
            self.assertEqual("rules:\n  - rule_id: custom\n", preserved)

    def test_case_init_seeds_report_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            self.assertTrue((case.report_template_dir / "1_overview.md").exists())
            self.assertTrue((case.report_template_dir / "5_recommendations.md").exists())

    def test_export_packaged_report_templates_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir)
            self.assertGreaterEqual(len(written), 6)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_templates_export_command_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(cli_module.app, ["templates-export", tmpdir])
            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_investigate_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "custom-templates"
            export_packaged_report_templates(template_dir)
            runner = CliRunner()
            captured: dict[str, object] = {}

            def fake_investigate_loop(*args, **kwargs):
                captured["template_root"] = kwargs.get("template_root")
                return {
                    "session_id": "session-test",
                    "status": "completed",
                    "iteration": 1,
                    "summary": "done",
                    "hypotheses": [],
                    "report_sections": {"items": []},
                }

            with patch("forensia.cli.investigate_loop", side_effect=fake_investigate_loop), patch(
                "forensia.cli.render_written_report",
                return_value=(case.path / "reports" / "report.md", case.path / "reports" / "report.html"),
            ):
                result = runner.invoke(
                    cli_module.app,
                    [
                        "investigate",
                        str(case.path),
                        "--llm-base-url",
                        "http://127.0.0.1:1234",
                        "--model",
                        "test-model",
                        "--template-dir",
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])

    def test_investigate_command_rejects_empty_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            empty_dir = Path(tmpdir) / "empty-templates"
            empty_dir.mkdir()
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "investigate",
                    str(case.path),
                    "--llm-base-url",
                    "http://127.0.0.1:1234",
                    "--model",
                    "test-model",
                    "--template-dir",
                    str(empty_dir),
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("[0-9]*_*.md", result.output)

    def test_run_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            template_dir = Path(tmpdir) / "custom-templates"
            export_packaged_report_templates(template_dir)
            runner = CliRunner()
            captured: dict[str, object] = {}

            def fake_investigate_loop(*args, **kwargs):
                captured["template_root"] = kwargs.get("template_root")
                return {
                    "session_id": "session-test",
                    "status": "completed",
                    "iteration": 1,
                    "summary": "done",
                    "hypotheses": [],
                    "report_sections": {"items": []},
                }

            with patch(
                "forensia.cli.ingest_all",
                return_value={"new_files": 0, "skipped_files": 0, "evtx_files": 0, "mft_files": 0, "prefetch_files": 0},
            ), patch(
                "forensia.cli.normalize_all",
                return_value={"evtx_rows": 0, "mft_entries": 0, "mft_timeline_rows": 0, "prefetch_executions": 0},
            ), patch("forensia.cli.load_rules_from_dir", return_value=[]), patch(
                "forensia.cli.investigate_loop",
                side_effect=fake_investigate_loop,
            ), patch(
                "forensia.cli.render_written_report",
                return_value=(output_dir / "reports" / "report.md", output_dir / "reports" / "report.html"),
            ):
                result = runner.invoke(
                    cli_module.app,
                    [
                        "investigate",
                        str(output_dir),
                        str(input_dir),
                        "--llm-base-url",
                        "http://127.0.0.1:1234",
                        "--model",
                        "test-model",
                        "--template-dir",
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])

    def test_run_command_rejects_unknown_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "investigate",
                    str(output_dir),
                    str(input_dir),
                    "--profile",
                    "does-not-exist",
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("Available profiles", result.output)
