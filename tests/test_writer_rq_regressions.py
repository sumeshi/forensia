from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from forensia.core.case import Case
from forensia.ai.section_agent import (
    _fallback_narrative_body,
    _is_effectively_empty_body,
    _load_reusable_section_facts,
    _narrate_paragraph_with_retry,
    _question_routing_answer_spec,
    run_section_block_agent,
)
from forensia.ai.question_registry import resolve_question_spec
from forensia.config import clear_llm_settings_cache
from forensia.db.database import CaseDB
from forensia.report.writer import (
    _GateCtx,
    _assemble_section_body,
    _check_recommendations_strength,
    build_structured_answer,
    _check_citation_token_no_finding_id,
    _check_hedge_no_citation,
    _dump_section_questions_json,
    _render_structured_answer_markdown,
    _resolve_evidence_results,
    _validate_body_evidence_ids,
)


class WriterRQRegressionTests(unittest.TestCase):
    def test_status_only_narration_gets_deterministic_fallback(self) -> None:
        self.assertTrue(_is_effectively_empty_body("**Status:** answered"))
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Executive Summary",
                status="partial",
                collected_results=[
                    {
                        "kind": "rows",
                        "keypoint": "raw_sql",
                        "row_count": 2,
                        "evidence_ids": ["evtx-security-000000000122"],
                        "sample_rows": [
                            {
                                "timestamp": "2015-03-22T14:34:28",
                                "event_id": 4624,
                                "computer": "informant-PC",
                                "target_user": "informant",
                                "evidence_id": "evtx-security-000000000122",
                            }
                        ],
                    }
                ],
                flat_evidence=[
                    {
                        "timestamp": "2015-03-22T14:34:28",
                        "event_id": 4624,
                        "computer": "informant-PC",
                        "target_user": "informant",
                        "evidence_id": "evtx-security-000000000122",
                    }
                ],
                actual_query_count=1,
                actual_query_row_counts=[2],
            )
            clear_llm_settings_cache()

        self.assertIn("**Status:** partial", body)
        self.assertIn("evtx-security-000000000122", body)
        self.assertGreater(len(body), 120)

    def test_not_found_fallback_does_not_emit_block_skipped_marker(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Network Activity",
                status="not_found",
                collected_results=[
                    {"kind": "rows", "keypoint": "evtx_network_connections", "row_count": 0, "sample_rows": []}
                ],
                flat_evidence=[],
                actual_query_count=1,
                actual_query_row_counts=[0],
            )
            clear_llm_settings_cache()

        self.assertIn("returned no matching rows", body)
        self.assertNotIn("Block skipped", body)
        self.assertNotIn("evtx_network_connections", body)

    def test_reusable_section_facts_exclude_case_probe_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO section_facts (
                        fact_id, fact_type, fact_key, fact_value, evidence_ids,
                        source_query, source_section, confidence, created_at, updated_at
                    ) VALUES
                        ('sf-case', 'universal_question', 'last_human_logon', '{}', '["evtx-security-000000000001"]', 'structured:last_human_logon', '__case_probe__', 0.9, now(), now()),
                        ('sf-section', 'observation', 'section_fact', '{}', '["evtx-security-000000000002"]', 'keypoint:test', '1_overview', 0.8, now(), now())
                    """
                )
                normal = _load_reusable_section_facts(db, "1_overview")
                with_case_probe = _load_reusable_section_facts(db, "1_overview", include_case_probe=True)

            self.assertEqual(["section_fact"], [item["fact_key"] for item in normal])
            self.assertIn("last_human_logon", [item["fact_key"] for item in with_case_probe])

    def test_assemble_section_body_preserves_template_preamble(self) -> None:
        body = _assemble_section_body("# Investigation Overview", ["## Executive Summary\n\nBody"])
        self.assertTrue(body.startswith("# Investigation Overview\n\n## Executive Summary"))

    def test_recommendation_strength_accepts_japanese_verification_wording(self) -> None:
        ctx = _GateCtx(
            section_key="5_recommendations",
            title="Recommendations",
            evidence_results=[],
            db=None,
            behaviors=("require_recommendations_strength",),
        )
        note, cap = _check_recommendations_strength(
            "追加の相関確認を行い、根拠が揃った後に封じ込めを判断する。",
            ctx,
        )
        self.assertIsNone(note)
        self.assertIsNone(cap)

    def test_question_routing_resolves_specific_shutdown_and_logon_specs(self) -> None:
        self.assertEqual("last_shutdown_event", _question_routing_answer_spec("Last recorded shutdown time", ""))
        self.assertEqual("last_human_logon", _question_routing_answer_spec("Last logged-on user", ""))
        self.assertEqual("daily_session_activity", _question_routing_answer_spec("Startup, shutdown, logon, and logoff history", ""))

    def test_question_spec_registry_resolves_template_variants(self) -> None:
        samples = [
            ("Last recorded shutdown time", "", "last_shutdown_event"),
            ("Most recent shutdown", "When did the endpoint last shut down?", "last_shutdown_event"),
            ("最後のシャットダウン時刻", "", "last_shutdown_event"),
            ("Last user", "Who was the last logged-on user?", "last_human_logon"),
            ("最終ログオンユーザー", "", "last_human_logon"),
            ("Evidence Scope", "case time range and event window", "case_event_window"),
        ]
        for heading, body, expected in samples:
            spec, confidence = resolve_question_spec(block_heading=heading, template_body=body)
            self.assertIsNotNone(spec, heading)
            self.assertEqual(expected, spec.answer_spec)
            self.assertGreater(confidence, 0.0)

    def test_missing_reason_string_renders_as_one_bullet(self) -> None:
        markdown = _render_structured_answer_markdown(
            {
                "id": "Q-TEST",
                "status": "answered",
                "answer": [{"value": "example"}],
                "missing_reason": "single reason string",
                "queries_run": ["SELECT 1"],
            },
            "Q-TEST",
        )
        section = markdown.split("### Missing Reason", 1)[1].split("### Queries Run", 1)[0]
        bullets = [line.strip() for line in section.splitlines() if line.strip().startswith("-")]
        self.assertEqual(["- single reason string"], bullets)

    def test_narrate_retries_once_when_first_body_is_empty(self) -> None:
        """RPT-FU-05: narrator must get one coaching turn before we surrender to the fallback prose.

        Without the retry, every CFREDS narrative section degenerates into the deterministic
        fallback paragraph (as observed in the prior run). Pin the call sequence so a future
        refactor cannot silently delete the retry.
        """
        calls: list[list[dict[str, str]]] = []

        def fake_llm(*, messages, model, base_url, json_schema, audit_callback=None, **kwargs):
            calls.append([dict(m) for m in messages])
            if len(calls) == 1:
                return {"body": ""}
            return {"body": "A concrete narrative paragraph that cites evtx-security-000000000122."}

        base_messages = [
            {"role": "system", "content": "narrate system"},
            {"role": "user", "content": "narrate user"},
        ]
        with patch("forensia.ai.section_agent.request_llm_json", side_effect=fake_llm):
            body = _narrate_paragraph_with_retry(
                narrate_messages=base_messages,
                narrate_schema={"type": "object"},
                model="m",
                base_url="http://x",
                audit_callback=None,
                status_inner="answered",
            )
        self.assertEqual(2, len(calls), msg="retry was not invoked on empty body")
        self.assertEqual(len(base_messages) + 1, len(calls[1]))
        self.assertEqual("user", calls[1][-1]["role"])
        self.assertIn("Retry", calls[1][-1]["content"])
        self.assertIn("evtx-security-000000000122", body)

    def test_narrate_does_not_retry_when_first_body_is_substantive(self) -> None:
        """Single-call happy path must not waste a second LLM round-trip."""
        calls: list[int] = []

        def fake_llm(**kwargs):
            calls.append(1)
            return {"body": "A concrete paragraph long enough to pass the empty-body check."}

        with patch("forensia.ai.section_agent.request_llm_json", side_effect=fake_llm):
            _narrate_paragraph_with_retry(
                narrate_messages=[{"role": "system", "content": "s"}],
                narrate_schema={"type": "object"},
                model="m",
                base_url="http://x",
                audit_callback=None,
                status_inner="answered",
            )
        self.assertEqual(1, len(calls))

    def test_missing_reason_section_omitted_when_answered_and_empty(self) -> None:
        """Status=answered with no missing reason should not render `### Missing Reason\\n- none`.

        Codex's earlier fix handled `missing_reason=[]` but kept emitting the section for
        sentinel values (`["none"]`, `["該当なし"]`) that mean the same thing.
        """
        for missing in ([], ["none"], ["None"], ["該当なし"], ["なし"], ["-"], ["", "  "]):
            with self.subTest(missing=missing):
                markdown = _render_structured_answer_markdown(
                    {
                        "id": "Q-OK",
                        "status": "answered",
                        "answer": [{"value": "x"}],
                        "missing_reason": missing,
                        "queries_run": ["structured:test"],
                    },
                    "OK",
                )
                self.assertNotIn("### Missing Reason", markdown)

        partial_md = _render_structured_answer_markdown(
            {
                "id": "Q-PARTIAL",
                "status": "partial",
                "answer": [{"value": "x"}],
                "missing_reason": [],
                "queries_run": ["structured:test"],
            },
            "Partial",
        )
        self.assertIn("### Missing Reason", partial_md)

    def test_fallback_narrative_body_stays_compact(self) -> None:
        """The fallback paragraph must stay readable (under ~240 chars) and avoid keypoint name leakage.

        RPT-FU-06 / RPT-FU-07: protect against regressions where multiple sample rows were
        joined with ` / ` and exploded the paragraph past 1000 chars, or keypoint identifiers
        (`overview_top_findings=10`) leaked into the prose.
        """
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "ja"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Executive Summary",
                status="partial",
                collected_results=[
                    {
                        "kind": "rows",
                        "keypoint": "overview_top_findings",
                        "row_count": 13,
                        "evidence_ids": ["evtx-security-000000001166"],
                        "sample_rows": [
                            {"timestamp": "2015-03-25T14:45:59", "event_id": 4624, "evidence_id": "evtx-security-000000001166"},
                            {"timestamp": "2015-03-25T15:31:00", "event_id": 6006, "evidence_id": "evtx-system-000000001624"},
                            {"timestamp": "2015-03-25T15:28:47", "event_id": 4688, "evidence_id": "evtx-security-000000001200"},
                        ],
                    },
                    {
                        "kind": "rows",
                        "keypoint": "overview_hosts",
                        "row_count": 3,
                        "evidence_ids": [],
                        "sample_rows": [{"host_id": "informant-PC", "evidence_id": "evtx-security-000000000001"}],
                    },
                ],
                flat_evidence=[
                    {"timestamp": "2015-03-25T14:45:59", "event_id": 4624, "evidence_id": "evtx-security-000000001166"},
                    {"timestamp": "2015-03-25T15:31:00", "event_id": 6006, "evidence_id": "evtx-system-000000001624"},
                ],
                actual_query_count=2,
                actual_query_row_counts=[13, 3],
            )
            clear_llm_settings_cache()

        self.assertLess(len(body), 280, msg=f"fallback paragraph too long ({len(body)} chars): {body!r}")
        self.assertNotIn("overview_top_findings", body)
        self.assertNotIn("overview_hosts", body)
        self.assertNotIn("=10", body)
        self.assertNotIn("=3", body)

    def test_structured_markdown_previews_large_tables(self) -> None:
        markdown = _render_structured_answer_markdown(
            {
                "id": "Q-BIG",
                "status": "answered",
                "answer": [{"value": index, "paths": [f"path-{sub}" for sub in range(8)]} for index in range(30)],
                "missing_reason": [],
                "queries_run": ["structured:test"],
                "json_path": "structured/answers.json",
                "csv_path": "structured/Q-BIG.csv",
            },
            "Large Answer",
        )

        self.assertIn("Showing 25 of 30 rows", markdown)
        self.assertIn("### Interpretation", markdown)
        self.assertIn("構造化証拠", markdown)
        self.assertIn("... (+3 more)", markdown)
        self.assertNotIn("| 29 |", markdown)

    def test_structured_markdown_hides_evidence_id_columns(self) -> None:
        markdown = _render_structured_answer_markdown(
            {
                "id": "Q-EVIDENCE",
                "status": "answered",
                "answer": [{"name": "row", "evidence_id": "evtx-security-000000000001", "evidence_ids": ["mft-000000000001-00"], "source_file": "raw.evtx"}],
                "columns": ["name", "evidence_id", "evidence_ids", "source_file"],
                "missing_reason": [],
                "queries_run": ["structured:test"],
            },
            "Evidence preview",
        )

        self.assertIn("| name |", markdown)
        self.assertNotIn("evidence_id", markdown)
        self.assertNotIn("evtx-security-000000000001", markdown)
        self.assertNotIn("mft-000000000001-00", markdown)
        self.assertNotIn("source_file", markdown)
        self.assertNotIn("raw.evtx", markdown)

    def test_benchmark_keypoint_sql_executes_on_minimal_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, is_deleted, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000001-01",
                        r"C:\Users\Alice\AppData\Local\Google\Drive\sync_config.db",
                        "sync_config.db",
                        False,
                        datetime.now(UTC).replace(tzinfo=None),
                    ),
                )
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, is_deleted, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000002-01",
                        r"C:\Users\Alice\Desktop\resignation_letter.docx",
                        "resignation_letter.docx",
                        False,
                        datetime.now(UTC).replace(tzinfo=None),
                    ),
                )
                results = _resolve_evidence_results(
                    case,
                    db,
                    keypoints=["structured_cloud_artifacts", "structured_resignation_files"],
                )

            keypoints = {result["keypoint"] for result in results}
            self.assertIn("structured_cloud_artifacts", keypoints)
            self.assertIn("structured_resignation_files", keypoints)
            cloud = next(result for result in results if result["keypoint"] == "structured_cloud_artifacts")
            resignation = next(result for result in results if result["keypoint"] == "structured_resignation_files")
            self.assertGreaterEqual(cloud["row_count"], 1)
            self.assertGreaterEqual(resignation["row_count"], 1)

    def test_structured_benchmark_last_logon_persists_json_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (
                        evidence_id, event_id, timestamp, computer, target_user, logon_type, process_name, src_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                        "informant",
                        "2",
                        r"C:\Windows\System32\winlogon.exe",
                        "127.0.0.1",
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_human_logon",
                    answer_id="Q8",
                    section_key="6_appendix",
                    block_heading="2. Last logged-on user",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("answered", answer["status"])
            self.assertEqual(["logon_time", "computer", "user_name", "logon_type", "process_name", "src_ip", "evidence_id"], answer["columns"])
            self.assertEqual("informant", answer["answer"][0]["user_name"])
            self.assertIn("2015-03-22T14:34:28", answer["answer"][0]["logon_time"])
            self.assertTrue((case.reports_dir / "structured" / "Q8.csv").exists())
            answers = json.loads((case.reports_dir / "structured" / "answers.json").read_text(encoding="utf-8"))
            self.assertEqual("Q8", answers[0]["id"])

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-system-000000000001", 6006, datetime(2015, 3, 22, 14, 38, 16), "informant-PC"),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-security-000000000002", 4624, datetime(2015, 3, 25, 15, 31, 0), "informant-PC"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="last_shutdown_event",
                    answer_id="Q9",
                    section_key="6_appendix",
                    block_heading="3. Last shutdown time",
                )

            self.assertIsNotNone(answer)
            self.assertEqual(6006, answer["answer"][0]["event_id"])
            self.assertIn("2015-03-22T14:38:16", answer["answer"][0]["shutdown_time"])

    def test_question_marker_structured_block_bypasses_llm_plan_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-system-000000000001", 6006, datetime(2015, 3, 22, 14, 38, 16), "informant-PC"),
                )
                result = run_section_block_agent(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading="Last shutdown time",
                    template_body="<!-- question -->",
                    context_sections={},
                    current_section_outline=[],
                    report_brief={},
                    base_url="http://127.0.0.1:1",
                    model="unused",
                    benchmark_mode=True,
                    answer_id="Q9",
                )

            self.assertEqual("answered", result.status)
            self.assertIn("2015-03-22T14:38:16", result.body)
            self.assertTrue((case.reports_dir / "structured" / "Q9.csv").exists())

    def test_section_question_resolution_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-system-000000000001", 6006, datetime(2015, 3, 22, 14, 38, 16), "informant-PC"),
                )
                run_section_block_agent(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading="Most recent shutdown",
                    template_body="<!-- question -->",
                    context_sections={},
                    current_section_outline=[],
                    report_brief={},
                    base_url="http://127.0.0.1:1",
                    model="unused",
                    benchmark_mode=True,
                    answer_id="Q9",
                )
                row = db.execute(
                    """
                    SELECT answer_spec, question_type, status
                    FROM section_questions
                    WHERE section_key = '6_appendix'
                      AND block_heading = 'Most recent shutdown'
                    LIMIT 1
                    """
                ).fetchone()
                _dump_section_questions_json(case, db, "6_appendix")

            self.assertIsNotNone(row)
            self.assertEqual(("last_shutdown_event", "investigation_window", "resolved"), tuple(row))
            debug_path = case.reports_dir / "debug" / "6_appendix_questions.json"
            self.assertTrue(debug_path.exists())
            self.assertIn("last_shutdown_event", debug_path.read_text(encoding="utf-8"))

    def test_generic_question_spec_builder_executes_yaml_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    ("evtx-security-000000000001", 4624, datetime(2015, 3, 22, 14, 34, 28), "informant-PC"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="case_event_window",
                    answer_id="Q-window",
                    section_key="1_overview",
                    block_heading="Case time range",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("answered", answer["status"])
            self.assertEqual(["first_event", "last_event", "event_count"], answer["columns"])
            self.assertEqual(1, answer["answer"][0]["event_count"])

    def test_structured_benchmark_antiforensics_excludes_plain_eventlog_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    ("evtx-system-000000000001", "System", 1100, datetime(2015, 3, 25, 15, 31, 0), "informant-PC"),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    ("evtx-security-000000000002", "Security", 1102, datetime(2015, 3, 25, 15, 32, 0), "informant-PC"),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    ("evtx-security-000000000003", "Security", 1100, datetime(2015, 3, 25, 15, 33, 0), "informant-PC"),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="antiforensic_activity",
                    answer_id="Q45",
                    section_key="6_appendix",
                    block_heading="12. Antiforensic activity",
                )

            self.assertIsNotNone(answer)
            event_ids = {row.get("event_id") for row in answer["answer"]}
            self.assertEqual({1100, 1102}, event_ids)
            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertNotIn("evtx-system-000000000001", evidence_ids)

    def test_structured_benchmark_antiforensics_filters_installed_noise_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Program Files/CCleaner/Lang/lang-1041.dll",
                        "lang-1041.dll",
                        datetime(2015, 3, 13, 13, 54, 32),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Windows/Prefetch/CCLEANER64.EXE-779BD542.pf",
                        "CCLEANER64.EXE-779BD542.pf",
                        datetime(2015, 3, 25, 15, 15, 50),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000003-00",
                        "Windows/System32/cipher.exe",
                        "cipher.exe",
                        datetime(2009, 7, 14, 1, 38, 59),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_modified) VALUES (?, ?, ?, ?)",
                    (
                        "mft-000000000004-00",
                        "Program Files/CCleaner/CCleaner64.exe",
                        "CCleaner64.exe",
                        datetime(2015, 3, 13, 11, 10, 26),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="antiforensic_activity",
                    answer_id="Q45",
                    section_key="6_appendix",
                    block_heading="12. Antiforensic activity",
                )

            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertEqual({"mft-000000000002-00"}, evidence_ids)

    def test_structured_benchmark_prefetch_fallback_excludes_non_pf_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Windows/Prefetch/PfSvPerfStats.bin",
                        "PfSvPerfStats.bin",
                        "bin",
                        datetime(2015, 3, 25, 15, 31, 0),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, extension, si_modified) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Windows/Prefetch/WINWORD.EXE-CECBA770.pf",
                        "WINWORD.EXE-CECBA770.pf",
                        "pf",
                        datetime(2015, 3, 25, 15, 30, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="application_execution_history",
                    answer_id="Q12",
                    section_key="6_appendix",
                    block_heading="4. Application execution history",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("partial", answer["status"])
            self.assertEqual(["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]])

    def test_structured_desktop_rename_uses_recent_lnk_alias_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000001-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/pricing decision.lnk",
                        "pricing decision.lnk",
                        datetime(2015, 3, 23, 20, 26, 54),
                        datetime(2015, 3, 23, 20, 26, 54),
                    ),
                )
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        "mft-000000000002-00",
                        "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/(secret_project)_pricing_decision.xlsx.lnk",
                        "(secret_project)_pricing_decision.xlsx.lnk",
                        datetime(2015, 3, 23, 20, 26, 53),
                        datetime(2015, 3, 23, 20, 26, 53),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="desktop_rename_candidates",
                    answer_id="Q24",
                    section_key="6_appendix",
                    block_heading="Desktop file renames",
                )

            self.assertEqual("partial", answer["status"])
            self.assertEqual("pricing decision", answer["answer"][0]["original_name"])
            self.assertEqual("(secret_project)_pricing_decision.xlsx", answer["answer"][0]["new_name"])

    def test_citation_gate_accepts_evtx_and_mft_evidence_ids(self) -> None:
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        body = (
            "This may indicate suspicious activity supported by "
            "evtx-security-000000000001 and mft-000000000002-01."
        )
        msg, score = _check_hedge_no_citation(body, ctx)
        self.assertIsNone(msg)
        msg, score = _check_citation_token_no_finding_id(body, ctx)
        self.assertIsNone(msg)

    def test_citation_gate_flags_citation_token_without_ids(self) -> None:
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        body = "The evidence suggests an incident, but the narrative does not name a concrete citation."
        msg, score = _check_citation_token_no_finding_id(body, ctx)
        self.assertIsNotNone(msg)

    def test_prefetch_evidence_ids_validate_against_prefetch_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) VALUES (?, ?)",
                    ("prefetch-winword-exe-cecba770", "WINWORD.EXE"),
                )
                missing = _validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-winword-exe-cecba770.",
                )

            self.assertEqual([], missing)

    def test_log_integrity_keypoints_ignore_non_eventlog_104(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-diagnosis-000000000004",
                        104,
                        datetime(2015, 3, 24, 15, 21, 37),
                        "informant-PC",
                        "Microsoft-Windows-Diagnosis-Scripted/Operational",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Diagnosis-Scripted"}}}',
                    ),
                )
                db.execute(
                    """
                    INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "evtx-eventlog-000000000104",
                        104,
                        datetime(2015, 3, 24, 15, 22, 37),
                        "informant-PC",
                        "System",
                        '{"winlog":{"provider":{"name":"Microsoft-Windows-Eventlog"}}}',
                    ),
                )
                results = _resolve_evidence_results(
                    case,
                    db,
                    keypoints=["timeline_log_clearing", "gaps_log_integrity_events"],
                )

            timeline = next(result for result in results if result["keypoint"] == "timeline_log_clearing")
            gaps = next(result for result in results if result["keypoint"] == "gaps_log_integrity_events")
            self.assertEqual(["evtx-eventlog-000000000104"], timeline["evidence_ids"])
            self.assertEqual(1, timeline["row_count"])
            self.assertEqual([{"event_id": 104, "count": 1}], gaps["sample_rows"])
