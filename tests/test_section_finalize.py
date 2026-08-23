from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from forensia.config import (
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.rules.engine import execute_event_keyword_fallback_search
from forensia.report.answers.answer_registry import ensure_universal_question_probes
from forensia.report.answers.keypoint_catalog import (
    default_keypoints_for_section,
    resolve_evidence_results,
)
from forensia.report.answers.table_registry import collect_flat_evidence_rows
from forensia.report.render.markdown import sort_markdown_table_by_first_column
from forensia.report.render.writer import build_report_markdown_from_db
from forensia.report.report_brief import build_report_brief
from forensia.report.sections.quality_gates import quality_gate_section
from forensia.report.sections.section_assembly import prepare_section_request
from forensia.report.sections.section_finalize import finalize_section
from forensia.report.sections.section_store import _project_claim_provenance
from forensia.report.template_export import export_packaged_report_templates


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


class SectionFinalizeTests(unittest.TestCase):
    """Section request assembly, quality gates, finalize_section, report markdown build."""

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def setUp(self) -> None:
        # llm_gateway is the single seam for LLM JSON calls; patch here.
        llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            side_effect=_agent_plan_router,
        )
        llm_json_patch.start()
        self.addCleanup(llm_json_patch.stop)
        # The async report-refresh path uses async_request_llm_json; mock it too
        # so async tests don't hit the real LLM.
        self._async_llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.async_request_llm_json",
            side_effect=_async_agent_plan_router,
        )
        self._async_llm_json_patch.start()
        self.addCleanup(self._async_llm_json_patch.stop)

    def test_prepare_section_request_infers_section_evidence_without_template_keypoints(
        self,
    ) -> None:
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
                    (
                        "ev-1",
                        "a.evtx",
                        "Security",
                        4624,
                        1,
                        "host1",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "{}",
                        "[]",
                        "info",
                    ),
                )
                request = prepare_section_request(
                    case, db, template_path, {}, report_brief={}
                )
                # Evidence resolution moved into section_agent; verify the default
                # keypoint selection + resolver directly.
                default_keypoints = default_keypoints_for_section("1_overview")
                resolved = resolve_evidence_results(
                    case, db, keypoints=default_keypoints
                )

            self.assertEqual("1_overview", request["section_key"])
            result_names = {item["keypoint"] for item in resolved}
            self.assertIn("overview_top_findings", result_names)

    def test_prepare_section_request_infers_ioc_keypoints_from_section_name(
        self,
    ) -> None:
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
                default_keypoints = default_keypoints_for_section("3_technical")
                resolved = resolve_evidence_results(
                    case, db, keypoints=default_keypoints
                )

            results = {item["keypoint"]: item for item in resolved}
            self.assertIn("host_execution_activity", results)
            self.assertIn("account_logon_patterns", results)
            self.assertIn("ioc_source_ips", results)
            self.assertEqual(
                "powershell.exe",
                results["host_execution_activity"]["sample_rows"][0]["process_name"],
            )
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
                request = prepare_section_request(
                    case, db, template_path, {}, report_brief={}
                )

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("Q20", block["answer_id"])
            self.assertEqual("email_data_files", block["answer_spec"])
            self.assertEqual("Where is the e-mail file located?", block["question"])
            self.assertEqual(
                ["ioc_email_ost_files", "timeline_prefetch_history"],
                block["evidence_keypoints"],
            )

    def test_universal_question_probes_are_explicit_and_store_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "1_overview.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                "# Overview\n\n## Evidence Scope\n<!-- fill -->\n", encoding="utf-8"
            )
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                        "informant",
                        "2",
                    ),
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

    def test_question_marker_enables_structured_mode_without_explicit_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_path = case.path / "report_template_custom" / "6_appendix.md"
            template_path.parent.mkdir(parents=True, exist_ok=True)
            template_path.write_text(
                ("# Appendix\n\n## Last shutdown\n<!-- question -->\n<!-- fill -->\n"),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(
                    case, db, template_path, {}, report_brief={}
                )

            block = request["block_requests"][0]
            self.assertEqual("structured", block["mode"])
            self.assertEqual("", block["answer_spec"])

    def test_quality_gate_flags_placeholder_entities_and_non_chronological_timeline(
        self,
    ) -> None:
        body = (
            "| Timestamp | Host | Stage | Event | evidence_id |\n"
            "|---|---|---|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 | Login | user=None | ev-2 |\n"
            "| 2026-05-16 09:00:00 | host1 | Execution | process | ev-1 |\n"
        )

        gaps, confidence = quality_gate_section(
            "2_timeline",
            "Attack Timeline",
            body,
            [],
            1.0,
        )

        self.assertTrue(any("Placeholder entity values detected" in g for g in gaps))
        self.assertTrue(any("events are not strictly chronological" in g for g in gaps))
        self.assertLess(confidence, 1.0)

    def testcollect_flat_evidence_rows_filters_sparse_rows(self) -> None:
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

        flat = collect_flat_evidence_rows(rows, min_filled_cols=0.5)
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
                        "admin",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "{}",
                        "[]",
                        "info",
                    ),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body="## Account Creation\n\nThe evidence suggests privilege escalation occurred.",
                    evidence_results=[
                        {
                            "kind": "rows",
                            "sample_rows": [
                                {"event_id": 4720, "evidence_id": "ev-4720"}
                            ],
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

    def test_finalize_section_flags_overstated_claims_for_non_confirmed_sources(
        self,
    ) -> None:
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
                        "ev-1",
                        "a.evtx",
                        "Security",
                        4720,
                        1,
                        "host1",
                        "",
                        "alice",
                        "alice",
                        "admin",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "{}",
                        "[]",
                        "info",
                    ),
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

    def test_claims_keep_only_their_explicit_section_provenance(self) -> None:
        projected = _project_claim_provenance(
            "H-0010 is the cited hypothesis.",
            {"hypothesis_ids": ["H-001", "H-0010"]},
        )
        self.assertEqual(["H-0010"], projected["hypothesis_ids"])

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for evidence_id, event_id in (
                    ("evtx-security-000000000001", 4624),
                    ("evtx-system-000000000002", 7045),
                ):
                    db.execute(
                        """
                        INSERT INTO evtx_events (
                            evidence_id, source_file, channel, event_id, record_id,
                            timestamp, computer, raw_json, tags, severity
                        ) VALUES (?, 'source.evtx', 'Security', ?, 1, now(),
                                  'host1', '{}', '[]', 'info')
                        """,
                        (evidence_id, event_id),
                    )
                finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Technical",
                    body=(
                        "## Authentication\n\n"
                        "A logon was observed (evtx-security-000000000001).\n\n"
                        "## Service\n\n"
                        "A service was observed (evtx-system-000000000002)."
                    ),
                    evidence_results=[
                        {
                            "kind": "rows",
                            "evidence_ids": [
                                "evtx-security-000000000001",
                                "evtx-system-000000000002",
                            ],
                        }
                    ],
                )

                claims = db.execute(
                    "SELECT claim_text, evidence_ids, support_status "
                    "FROM claims ORDER BY claim_text"
                ).fetchall()

            self.assertEqual(2, len(claims))
            for claim_text, raw_ids, support_status in claims:
                evidence_ids = json.loads(raw_ids)
                self.assertEqual(1, len(evidence_ids))
                self.assertIn(evidence_ids[0], claim_text)
                self.assertEqual("supported", support_status)

    def test_finalize_section_rejects_exclusive_evtx_scope_claim(self) -> None:
        """The artifact-scope guard applies across supported report languages."""
        cases = (
            ("english", "All artifacts are EVTX.", "mft_entries", "mft-1"),
            ("japanese", "アーティファクトはすべてEVTX形式です。", "prefetch_executions", "pf-1"),
        )
        for language, body, artifact_table, artifact_id in cases:
            with self.subTest(language=language):
                with tempfile.TemporaryDirectory() as tmpdir:
                    case = Case.init(tmpdir)
                    with CaseDB(case) as db:
                        db.execute(
                            "INSERT INTO evtx_events (evidence_id, event_id) VALUES ('ev-1', 4648)"
                        )
                        db.execute(
                            f"INSERT INTO {artifact_table} (evidence_id) VALUES (?)",
                            (artifact_id,),
                        )
                        result = finalize_section(
                            db=db,
                            section_key="1_overview",
                            title="Scope",
                            body=f"## Scope\n\n{body}",
                            evidence_results=[],
                        )

                self.assertTrue(
                    any("non-EVTX" in str(gap) for gap in result["gaps"]),
                    msg=f"Expected artifact scope gap in {result['gaps']}",
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
                    db,
                    "SELECT * FROM evtx_events WHERE event_id = 4720 AND computer = 'missing'",
                )

            self.assertEqual(1, len(rows))
            self.assertEqual("keyword_in_raw_json", fallback_info["phase"])
            self.assertIn(4720, fallback_info["event_ids"])
            self.assertTrue(
                any(
                    "account created" in keyword
                    for keyword in fallback_info["keywords"]
                )
            )

    def test_build_report_markdown_keeps_coverage_out_of_final_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO report_sections (
                        section_key, title, body, confidence, status, update_count, gaps, last_filled_session, last_filled_at, stale
                    ) VALUES
                        ('1_overview', 'Overview', '# Investigation Overview\n\n## Evidence Scope\n\nOriginal scope text.\n', 0.9, 'ai_exhausted', 1, '[]', 's-1', now(), FALSE),
                        ('2_timeline', 'Timeline', '# Timeline\n\n**Status:** partial\n\nBody text with raw_sql reference.\n', 0.9, 'ai_exhausted', 1, '[]', 's-1', now(), FALSE)
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
            zero_row = next(
                row for row in coverage_rows if row[1] == "empty_timeline_events"
            )
            self.assertEqual("No", zero_row[4])
            self.assertNotIn("#### Coverage Summary", markdown)
            self.assertNotIn("benchmark_ost_file", markdown)
            self.assertNotIn("#### Evidence Coverage", markdown)
            self.assertNotIn("benchmark_timeline_events", markdown)
            self.assertNotIn("**Status:** partial", markdown)
            self.assertNotIn("raw_sql", markdown)

    def test_build_report_markdown_rebuilds_non_question_sections_with_tables(
        self,
    ) -> None:
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

    def test_build_report_markdown_adds_appendix_interpretation_to_existing_body(
        self,
    ) -> None:
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
                        "ai_exhausted",
                        1,
                        "[]",
                        "S-1",
                    ),
                )

                markdown = build_report_markdown_from_db(db)

            self.assertIn("### Interpretation", markdown)
            self.assertIn("On EVTX", markdown)
            self.assertIn("### Answer", markdown)
            self.assertNotIn("evidence_id", markdown)
            self.assertNotIn("evtx-security-000000000001", markdown)

    def test_build_report_markdown_refreshes_stale_antiforensic_appendix_block(
        self,
    ) -> None:
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
                        "ai_exhausted",
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
                            "sample_rows": [
                                {
                                    "timestamp": "2026-05-28 10:00:00",
                                    "process_name": "None",
                                }
                            ],
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
            self.assertIn(
                "Raw evidence moved to reports/evidence/6_appendix.json", body
            )
            self.assertIn("raw evidence rows were moved", str(gaps).lower())

    def test_finding_and_report_section_dtos_include_evidence_counts(self) -> None:
        from forensia.api.service import list_findings_dto
        from forensia.report.section_views import list_report_sections_dto

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
        from forensia.report.section_views import list_report_sections_dto

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

    def test_quality_gate_flags_heading_title_mismatch(self) -> None:
        gaps, confidence = quality_gate_section(
            "3_technical",
            "Compromised Accounts and Authentication",
            "# Indicators of Compromise\n\nBody text",
            [],
            1.0,
        )

        self.assertTrue(any("heading does not match" in gap.lower() for gap in gaps))
        self.assertLessEqual(confidence, 0.65)

    def test_quality_gate_forces_low_confidence_when_fill_placeholder_remains(
        self,
    ) -> None:
        gaps, confidence = quality_gate_section(
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

        gaps, confidence = quality_gate_section(
            "5_recommendations",
            "Recommended Actions",
            body,
            [],
            1.0,
        )

        self.assertTrue(
            any("Recommendations should state evidence strength" in g for g in gaps)
        )
        self.assertLess(confidence, 1.0)

    def testsort_markdown_table_by_first_column_orders_timeline_rows(self) -> None:
        body = (
            "| Timestamp | Host |\n"
            "|---|---|\n"
            "| 2026-05-16 10:00:00 | host1 |\n"
            "| 2026-05-16 09:00:00 | host1 |\n"
        )
        sorted_body = sort_markdown_table_by_first_column(body)
        self.assertLess(sorted_body.find("09:00:00"), sorted_body.find("10:00:00"))

    def test_export_packaged_templates_excludes_benchmark_appendix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir, overwrite=True)

            self.assertFalse(any(path.name == "6_appendix.md" for path in written))
            self.assertFalse((Path(tmpdir) / "6_appendix.md").exists())

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
                    (
                        "F-1",
                        "rule",
                        "Suspicious Service",
                        "Summary",
                        "high",
                        0.9,
                        "accepted",
                        "[]",
                        "[]",
                        "[]",
                        "",
                        "[]",
                        now,
                    ),
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
                    (
                        "windows-corr-logon-then-service-0001",
                        "windows-corr-logon-then-service",
                        "Correlation",
                        "Summary",
                        "medium",
                        0.65,
                        "accepted",
                        "[]",
                        "[]",
                        "[]",
                        "",
                        "[]",
                        now,
                    ),
                )
                result = finalize_section(
                    db=db,
                    section_key="3_technical",
                    title="Persistence and Execution",
                    body="# Persistence and Execution\n\nConfirmed lateral movement based on windows-corr-logon-then-service-0001.",
                    evidence_results=[],
                    session_id="S-1",
                )

            self.assertTrue(
                any("Correlation-rule findings" in gap for gap in result["gaps"])
            )
            self.assertLessEqual(result["confidence"], 0.55)

    def testbuild_report_brief_trims_excerpt_in_sql(self) -> None:
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
                    (
                        "1_overview",
                        "Overview",
                        "x" * 800,
                        0.9,
                        "draft",
                        1,
                        "[]",
                        "S-1",
                        now,
                    ),
                )
                brief = build_report_brief(db)

            self.assertEqual(1, len(brief["prior_sections"]))
            self.assertLessEqual(len(brief["prior_sections"][0]["body_excerpt"]), 400)

    def testbuild_report_brief_dedupes_existing_claims(self) -> None:
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
                brief = build_report_brief(db)

            self.assertEqual(2, len(brief["existing_claims"]))


if __name__ == "__main__":
    unittest.main()
