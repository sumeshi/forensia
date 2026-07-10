from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from forensia.ai.section_agent import run_section_block_agent
from forensia.ai.section_answers import _is_effectively_empty_body
from forensia.ai.section_block_narrative import (
    _fallback_narrative_body,
    _narrate_paragraph_with_retry,
)
from forensia.ai.section_exec import (
    _question_routing_answer_spec,
    _structured_digest_from_answers,
)
from forensia.ai.section_run_store import _load_reusable_section_facts
from forensia.config import clear_llm_settings_cache, reload_settings
from forensia.core.case import Case
from forensia.core.textutil import normalize_localized_dates
from forensia.db.database import CaseDB
from forensia.questions import resolve_question_spec
from forensia.report.answer_registry import build_structured_answer
from forensia.report.answer_store import render_structured_answer_markdown
from forensia.report.evidence_refs import extract_needed_evidence
from forensia.report.gap_tables import hypothesis_rows
from forensia.report.keypoint_catalog import REPORT_KEYPOINTS, resolve_evidence_results
from forensia.report.quality_gates import (
    GateContext,
    check_citation_token_no_finding_id,
    check_hedge_no_citation,
    check_recommendations_strength,
)
from forensia.report.section_assembly import assemble_section_body
from forensia.report.section_finalize import (
    preprocess_section_body,
    validate_section_evidence_ids,
)
from forensia.report.section_quality import validate_body_evidence_ids
from forensia.report.section_store import dump_section_questions_json
from forensia.report.template_parsing import parse_block_hints


class WriterRQRegressionTests(unittest.TestCase):
    def test_status_only_narration_gets_deterministic_fallback(self) -> None:
        self.assertTrue(_is_effectively_empty_body("**Status:** answered"))
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            reload_settings()
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
            reload_settings()

        self.assertIn("Additional correlation is needed", body)
        self.assertIn("evtx-security-000000000122", body)
        # H-2: fallback must not emit review-metadata phrasing.
        self.assertNotIn("the collected evidence returned", body.lower())
        self.assertNotIn("Representative row:", body)

    def test_not_found_fallback_does_not_emit_block_skipped_marker(self) -> None:
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            reload_settings()
            body = _fallback_narrative_body(
                heading="Network Activity",
                status="not_found",
                collected_results=[
                    {
                        "kind": "rows",
                        "keypoint": "evtx_network_connections",
                        "row_count": 0,
                        "sample_rows": [],
                    }
                ],
                flat_evidence=[],
                actual_query_count=1,
                actual_query_row_counts=[0],
            )
            reload_settings()

        self.assertIn("No supporting evidence was found", body)
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
                with_case_probe = _load_reusable_section_facts(
                    db, "1_overview", include_case_probe=True
                )

            self.assertEqual(["section_fact"], [item["fact_key"] for item in normal])
            self.assertIn(
                "last_human_logon", [item["fact_key"] for item in with_case_probe]
            )

    def test_assemble_section_body_preserves_template_preamble(self) -> None:
        body = assemble_section_body(
            "# Investigation Overview", ["## Executive Summary\n\nBody"]
        )
        self.assertTrue(
            body.startswith("# Investigation Overview\n\n## Executive Summary")
        )

    def test_localized_numeric_date_is_normalized(self) -> None:
        body = normalize_localized_dates("Log clear at 2015年3月22日14時38分16秒.")
        self.assertIn("2015-03-22 14:38:16 UTC", body)
        self.assertNotIn("2015年3月22日", body)

    def test_preprocess_converts_raw_json_rows_to_markdown_table(self) -> None:
        raw = (
            '## Evidence Scope\n\n[{"Metric":"EVTX rows","Value":12,'
            '"Scope":"security"}]'
        )
        body, removed_raw = preprocess_section_body("1_overview", raw)
        self.assertFalse(removed_raw)
        self.assertNotIn('[{"Metric"', body)
        self.assertIn("| Metric | Value | Scope |", body)
        self.assertIn("| EVTX rows | 12 | security |", body)

    def test_recommendation_strength_accepts_japanese_verification_wording(
        self,
    ) -> None:
        ctx = GateContext(
            section_key="5_recommendations",
            title="Recommendations",
            evidence_results=[],
            db=None,
            behaviors=("require_recommendations_strength",),
        )
        note, cap = check_recommendations_strength(
            "Perform additional verification and correlation checks; consider containment after verification.",
            ctx,
        )
        self.assertIsNone(note)
        self.assertIsNone(cap)

    def test_question_routing_resolves_specific_shutdown_and_logon_specs(self) -> None:
        self.assertEqual(
            "last_shutdown_event",
            _question_routing_answer_spec("Last recorded shutdown time", ""),
        )
        self.assertEqual(
            "last_human_logon", _question_routing_answer_spec("Last logged-on user", "")
        )
        self.assertEqual(
            "daily_session_activity",
            _question_routing_answer_spec(
                "Startup, shutdown, logon, and logoff history", ""
            ),
        )

    def test_question_spec_registry_resolves_template_variants(self) -> None:
        samples = [
            ("Last recorded shutdown time", "", "last_shutdown_event"),
            (
                "Most recent shutdown",
                "When did the endpoint last shut down?",
                "last_shutdown_event",
            ),
            ("Final shutdown time", "", "last_shutdown_event"),
            ("Last user", "Who was the last logged-on user?", "last_human_logon"),
            ("Most recent logon user", "", "last_human_logon"),
            ("Evidence Scope", "case time range and event window", "case_event_window"),
        ]
        for heading, body, expected in samples:
            spec, confidence = resolve_question_spec(
                block_heading=heading, template_body=body
            )
            self.assertIsNotNone(spec, heading)
            self.assertEqual(expected, spec.answer_spec)
            self.assertGreater(confidence, 0.0)

    def test_missing_reason_string_renders_as_one_bullet(self) -> None:
        markdown = render_structured_answer_markdown(
            {
                "id": "Q-TEST",
                "status": "answered",
                "answer": [{"value": "example"}],
                "missing_reason": "single reason string",
                "queries_run": ["SELECT 1"],
            },
            "Q-TEST",
        )
        section = markdown.split("### Missing Reason", 1)[1].split(
            "### Queries Run", 1
        )[0]
        bullets = [
            line.strip()
            for line in section.splitlines()
            if line.strip().startswith("-")
        ]
        self.assertEqual(["- single reason string"], bullets)

    def test_narrate_retries_once_when_first_body_is_empty(self) -> None:
        """RPT-FU-05: narrator must get one coaching turn before we surrender to the fallback prose.

        Without the retry, every CFREDS narrative section degenerates into the deterministic
        fallback paragraph (as observed in the prior run). Pin the call sequence so a future
        refactor cannot silently delete the retry.
        """
        calls: list[list[dict[str, str]]] = []

        def fake_llm(
            *, messages, model, base_url, json_schema, audit_callback=None, **kwargs
        ):
            calls.append([dict(m) for m in messages])
            if len(calls) == 1:
                return {"body": ""}
            return {
                "body": "A concrete narrative paragraph that cites evtx-security-000000000122."
            }

        base_messages = [
            {"role": "system", "content": "narrate system"},
            {"role": "user", "content": "narrate user"},
        ]
        with patch("forensia.ai.llm.llm_gateway.request_llm_json", side_effect=fake_llm):
            body = _narrate_paragraph_with_retry(
                narrate_messages=base_messages,
                narrate_schema={"type": "object"},
                model="m",
                base_url="http://x",
                audit_callback=None,
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
            return {
                "body": "A concrete paragraph long enough to pass the empty-body check."
            }

        with patch("forensia.ai.llm.llm_gateway.request_llm_json", side_effect=fake_llm):
            _narrate_paragraph_with_retry(
                narrate_messages=[{"role": "system", "content": "s"}],
                narrate_schema={"type": "object"},
                model="m",
                base_url="http://x",
                audit_callback=None,
            )
        self.assertEqual(1, len(calls))

    def test_missing_reason_section_omitted_when_answered_and_empty(self) -> None:
        """Status=answered with no missing reason should not render `### Missing Reason\\n- none`.

        Codex's earlier fix handled `missing_reason=[]` but kept emitting the section for
        sentinel values (`["none"]`, `["not applicable"]`) that mean the same thing.
        """
        for missing in (
            [],
            ["none"],
            ["None"],
            ["not applicable"],
            ["-"],
            ["", "  "],
        ):
            with self.subTest(missing=missing):
                markdown = render_structured_answer_markdown(
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

        partial_md = render_structured_answer_markdown(
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
        """The fallback paragraph must stay readable (under ~350 chars) and avoid keypoint name leakage.

        RPT-FU-06 / RPT-FU-07: protect against regressions where multiple sample rows were
        joined with ` / ` and exploded the paragraph past 1000 chars, or keypoint identifiers
        (`overview_top_findings=10`) leaked into the prose.
        """
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
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
                            {
                                "timestamp": "2015-03-25T14:45:59",
                                "event_id": 4624,
                                "evidence_id": "evtx-security-000000001166",
                            },
                            {
                                "timestamp": "2015-03-25T15:31:00",
                                "event_id": 6006,
                                "evidence_id": "evtx-system-000000001624",
                            },
                            {
                                "timestamp": "2015-03-25T15:28:47",
                                "event_id": 4688,
                                "evidence_id": "evtx-security-000000001200",
                            },
                        ],
                    },
                    {
                        "kind": "rows",
                        "keypoint": "overview_hosts",
                        "row_count": 3,
                        "evidence_ids": [],
                        "sample_rows": [
                            {
                                "host_id": "informant-PC",
                                "evidence_id": "evtx-security-000000000001",
                            }
                        ],
                    },
                ],
                flat_evidence=[
                    {
                        "timestamp": "2015-03-25T14:45:59",
                        "event_id": 4624,
                        "evidence_id": "evtx-security-000000001166",
                    },
                    {
                        "timestamp": "2015-03-25T15:31:00",
                        "event_id": 6006,
                        "evidence_id": "evtx-system-000000001624",
                    },
                ],
                actual_query_count=2,
                actual_query_row_counts=[13, 3],
            )
            clear_llm_settings_cache()

        self.assertLess(
            len(body),
            350,
            msg=f"fallback paragraph too long ({len(body)} chars): {body!r}",
        )
        self.assertNotIn("overview_top_findings", body)
        self.assertNotIn("overview_hosts", body)
        self.assertNotIn("=10", body)
        self.assertNotIn("=3", body)

    def test_fallback_prefers_key_points_over_meta_phrasing(self) -> None:
        """H-2: when key points are available the fallback states observed
        facts, never review-metadata like 'returned N related rows'."""
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            clear_llm_settings_cache()
            body = _fallback_narrative_body(
                heading="Executive Summary",
                status="answered",
                collected_results=[],
                flat_evidence=[],
                actual_query_count=1,
                actual_query_row_counts=[3],
                key_points=[
                    "Anti-forensic tool CCLEANER64.EXE was executed",
                    "The Event Log service was stopped on informant-PC",
                ],
            )
            clear_llm_settings_cache()

        self.assertIn("CCLEANER64.EXE", body)
        self.assertIn("Event Log service", body)
        self.assertNotIn("the collected evidence returned", body.lower())
        self.assertNotIn("related rows", body.lower())

    def test_structured_markdown_previews_large_tables(self) -> None:
        markdown = render_structured_answer_markdown(
            {
                "id": "Q-BIG",
                "status": "answered",
                "answer": [
                    {"value": index, "paths": [f"path-{sub}" for sub in range(8)]}
                    for index in range(30)
                ],
                "missing_reason": [],
                "queries_run": ["structured:test"],
                "json_path": "structured/answers.json",
                "csv_path": "structured/Q-BIG.csv",
            },
            "Large Answer",
        )

        self.assertIn("### Interpretation", markdown)
        self.assertIn("structured evidence", markdown)
        self.assertIn("... (+3 more)", markdown)
        # STRUCTURED_MARKDOWN_MAX_ROWS is now 200, so all 30 rows are shown
        self.assertIn("| 29 |", markdown)

    def test_structured_markdown_truncates_above_two_hundred(self) -> None:
        """R7-02: structured answer with 250 rows truncates at 200."""
        markdown = render_structured_answer_markdown(
            {
                "id": "Q-HUGE",
                "status": "answered",
                "answer": [{"value": i} for i in range(250)],
                "missing_reason": [],
                "queries_run": ["structured:test"],
                "json_path": "structured/answers.json",
                "csv_path": "structured/Q-HUGE.csv",
            },
            "Huge Answer",
        )

        self.assertIn("_Showing 200 of 250 rows", markdown)
        self.assertNotIn("| 249 |", markdown)

    def test_structured_markdown_hides_evidence_id_columns(self) -> None:
        markdown = render_structured_answer_markdown(
            {
                "id": "Q-EVIDENCE",
                "status": "answered",
                "answer": [
                    {
                        "name": "row",
                        "evidence_id": "evtx-security-000000000001",
                        "evidence_ids": ["mft-000000000001-00"],
                        "source_file": "raw.evtx",
                    }
                ],
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
                results = resolve_evidence_results(
                    case,
                    db,
                    keypoints=[
                        "structured_cloud_artifacts",
                        "structured_resignation_files",
                    ],
                )

            keypoints = {result["keypoint"] for result in results}
            self.assertIn("structured_cloud_artifacts", keypoints)
            self.assertIn("structured_resignation_files", keypoints)
            cloud = next(
                result
                for result in results
                if result["keypoint"] == "structured_cloud_artifacts"
            )
            resignation = next(
                result
                for result in results
                if result["keypoint"] == "structured_resignation_files"
            )
            self.assertGreaterEqual(cloud["row_count"], 1)
            self.assertGreaterEqual(resignation["row_count"], 1)

    def test_resignation_file_timestamps_uses_question_spec_evidence_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000003-01",
                        r"C:\Users\Alice\Desktop\resignation_letter.docx",
                        "resignation_letter.docx",
                        "docx",
                        datetime(2015, 3, 25, 15, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="resignation_file_timestamps",
                    answer_id="Q28",
                    section_key="6_appendix",
                    block_heading="Resignation file timestamps",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(
                ["structured:resignation_file_timestamps:mft_topic_keyword_files"],
                answer.get("queries_run"),
            )
            self.assertEqual(
                "resignation_letter.docx",
                answer["answer"][0].get("file_name"),
            )

    def test_email_data_files_uses_question_spec_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension,
                        si_created, si_modified
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000004-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 10, 0),
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_data_files",
                    answer_id="Q-email",
                    section_key="6_appendix",
                    block_heading="Email data files",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(["structured:email_data_files:mft"], answer["queries_run"])
            self.assertEqual("mailbox.ost", answer["answer"][0].get("file_name"))

    def test_email_application_usage_uses_question_spec_catalog_label(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO mft_entries (
                        evidence_id, file_path, file_name, extension, si_modified
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "mft-000000000005-01",
                        r"C:\Users\Alice\AppData\Local\Microsoft\Outlook\mailbox.ost",
                        "mailbox.ost",
                        "ost",
                        datetime(2015, 3, 25, 14, 20, 0),
                    ),
                )
                answer = build_structured_answer(
                    case,
                    db,
                    answer_spec="email_application_usage",
                    answer_id="Q-email-app",
                    section_key="6_appendix",
                    block_heading="Email application",
                )

            self.assertIsNotNone(answer)
            self.assertEqual("question_spec", answer.get("source"))
            self.assertEqual("answered", answer.get("status"))
            self.assertEqual(
                "Microsoft Outlook", answer["answer"][0].get("application_name")
            )

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
            self.assertEqual(
                [
                    "logon_time",
                    "computer",
                    "user_name",
                    "logon_type",
                    "process_name",
                    "src_ip",
                    "evidence_id",
                ],
                answer["columns"],
            )
            self.assertEqual("informant", answer["answer"][0]["user_name"])
            self.assertIn("2015-03-22T14:34:28", answer["answer"][0]["logon_time"])
            self.assertTrue((case.reports_dir / "structured" / "Q8.csv").exists())
            answers = json.loads(
                (case.reports_dir / "structured" / "answers.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("Q8", answers[0]["id"])

    def test_structured_benchmark_last_shutdown_ignores_overall_last_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000002",
                        4624,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                    ),
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
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
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
                    question_mode=True,
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
                    (
                        "evtx-system-000000000001",
                        6006,
                        datetime(2015, 3, 22, 14, 38, 16),
                        "informant-PC",
                    ),
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
                    question_mode=True,
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
                dump_section_questions_json(case, db, "6_appendix")

            self.assertIsNotNone(row)
            self.assertEqual(
                ("last_shutdown_event", "investigation_window", "resolved"), tuple(row)
            )
            debug_path = case.reports_dir / "debug" / "6_appendix_questions.json"
            self.assertTrue(debug_path.exists())
            self.assertIn("last_shutdown_event", debug_path.read_text(encoding="utf-8"))

    def test_generic_question_spec_builder_executes_yaml_evidence_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
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
            self.assertEqual(
                ["first_event", "last_event", "event_count"], answer["columns"]
            )
            self.assertEqual(1, answer["answer"][0]["event_count"])

    def test_structured_benchmark_antiforensics_excludes_plain_eventlog_shutdown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-system-000000000001",
                        "System",
                        1100,
                        datetime(2015, 3, 25, 15, 31, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-security-000000000002",
                        "Security",
                        1102,
                        datetime(2015, 3, 25, 15, 32, 0),
                        "informant-PC",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer) VALUES (?, ?, ?, ?, ?)",
                    (
                        "evtx-security-000000000003",
                        "Security",
                        1100,
                        datetime(2015, 3, 25, 15, 33, 0),
                        "informant-PC",
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

            self.assertIsNotNone(answer)
            event_ids = {row.get("event_id") for row in answer["answer"]}
            self.assertEqual({1100, 1102}, event_ids)
            evidence_ids = {row.get("evidence_id") for row in answer["answer"]}
            self.assertNotIn("evtx-system-000000000001", evidence_ids)

    def test_structured_benchmark_antiforensics_filters_installed_noise_files(
        self,
    ) -> None:
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

    def test_structured_antiforensics_uses_ioc_catalog_tool_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions "
                    "(evidence_id, executable_name, exec_count, last_exec_time) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        "prefetch-privazer-exe-0001",
                        "PrivaZer.exe",
                        1,
                        datetime(2015, 3, 25, 15, 40, 0),
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
            self.assertIn("prefetch-privazer-exe-0001", evidence_ids)

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
            self.assertEqual(
                ["WINWORD.EXE"], [row["executable_name"] for row in answer["answer"]]
            )

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
            self.assertEqual(
                "(secret_project)_pricing_decision.xlsx",
                answer["answer"][0]["new_name"],
            )

    def test_citation_gate_accepts_evtx_and_mft_evidence_ids(self) -> None:
        ctx = GateContext(section_key="test", title="test", evidence_results=None, db=None)
        body = (
            "This may indicate suspicious activity supported by "
            "evtx-security-000000000001 and mft-000000000002-01."
        )
        msg, score = check_hedge_no_citation(body, ctx)
        self.assertIsNone(msg)
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNone(msg)

    def test_citation_gate_flags_citation_token_without_ids(self) -> None:
        ctx = GateContext(section_key="test", title="test", evidence_results=None, db=None)
        body = "The evidence suggests an incident, but the narrative does not name a concrete citation."
        msg, score = check_citation_token_no_finding_id(body, ctx)
        self.assertIsNotNone(msg)

    def test_prefetch_evidence_ids_validate_against_prefetch_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name) VALUES (?, ?)",
                    ("prefetch-winword-exe-cecba770", "WINWORD.EXE"),
                )
                missing = validate_body_evidence_ids(
                    db,
                    "WINWORD execution is supported by prefetch-winword-exe-cecba770.",
                )

            self.assertEqual([], missing)

    def test_validate_section_evidence_ids_removes_fabricated_keeps_real(self) -> None:
        """Real evidence IDs stay cited while fabricated IDs are removed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        datetime(2015, 3, 22, 14, 34, 28),
                        "informant-PC",
                    ),
                )
                body = (
                    "The real event evtx-security-000000000001 supported by evidence. "
                    "The fabricated event （evtx-security-0001） not in DB. "
                    "Another fabricated one (evtx-mft-9999) also not present."
                )
                cleaned, gaps = validate_section_evidence_ids(db, body)

                self.assertIn("evtx-security-000000000001", cleaned)
                self.assertNotIn("evtx-security-0001", cleaned)
                self.assertNotIn("security-0001", cleaned)
                self.assertNotIn("evtx-mft-9999", cleaned)
                self.assertNotIn("（）", cleaned)
                self.assertNotIn("()", cleaned)
                self.assertNotIn("（,", cleaned)
                self.assertTrue(
                    any("evtx-security-0001" in g for g in gaps),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertTrue(
                    any("evtx-mft-9999" in g for g in gaps),
                    msg=f"gap missing fabricated ID: {gaps}",
                )
                self.assertFalse(
                    any("evtx-security-000000000001" in g for g in gaps),
                    msg=f"real ID in gaps: {gaps}",
                )

    def test_validate_section_evidence_ids_keeps_valid_id_sharing_parens_with_invalid(
        self,
    ) -> None:
        """Removing invalid IDs must not remove valid IDs from the same citation group."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000122",
                        4648,
                        datetime(2015, 3, 22, 15, 57, 54),
                        "informant-PC",
                    ),
                )
                body = (
                    "Invalid first （evtx-security-0001, evtx-security-000000000122） here. "
                    "Invalid last (evtx-security-000000000122, evtx-bogus-1) there."
                )
                cleaned, _gaps = validate_section_evidence_ids(db, body)

                self.assertIn("（evtx-security-000000000122）", cleaned)
                self.assertIn("(evtx-security-000000000122)", cleaned)
                self.assertNotIn("evtx-security-0001", cleaned)
                self.assertNotIn("evtx-bogus-1", cleaned)

    def test_parse_block_hints_combined_comment_syntax(self) -> None:
        """R5-04 follow-up: the packaged templates use the combined one-comment
        syntax `<!-- mode: table; builder: X -->`. The parser previously stored
        mode='table; builder: x' and never extracted the builder, so table mode
        silently never fired for any template that used it."""
        hints = parse_block_hints(
            "<!-- mode: table; builder: overview_evidence_scope -->"
        )
        self.assertEqual("table", hints["mode"])
        self.assertEqual("overview_evidence_scope", hints["builder"])

        narrative = parse_block_hints(
            "<!-- mode: narrative; Write an executive summary -->"
        )
        self.assertEqual("narrative", narrative["mode"])
        self.assertEqual("", narrative["builder"])

        # One-directive-per-comment syntax keeps working
        separate = parse_block_hints(
            "<!-- mode: structured -->\n<!-- answer_id: Q6 -->\n<!-- answer_spec: host_identity -->"
        )
        self.assertEqual("structured", separate["mode"])
        self.assertEqual("Q6", separate["answer_id"])
        self.assertEqual("host_identity", separate["answer_spec"])

    def test_async_render_section_blocks_renders_table_mode_without_llm(self) -> None:
        """R5-04 follow-up: the async render path (used by the investigate loop)
        must execute table builders deterministically instead of routing table
        blocks through the LLM agent."""
        import asyncio

        from forensia.ai.section_refresher import _render_section_blocks
        from forensia.core.memory import MemoryManager

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', '', 0.0, 'draft', 0, TRUE)"
                )
                request = {
                    "case": case,
                    "section_key": "1_overview",
                    "title": "Investigation Overview",
                    "template_preamble": "",
                    "context_sections": {},
                    "report_brief": {},
                    "is_stale": True,
                    "block_requests": [
                        {
                            "heading": "Evidence Scope",
                            "template_body": "<!-- mode: table; builder: overview_evidence_scope -->",
                            "mode": "table",
                            "builder": "overview_evidence_scope",
                            "evidence_keypoints": [],
                        }
                    ],
                }
                memory = MemoryManager(case)
                # base_url points nowhere: if the table branch regresses into the
                # LLM agent path, this test fails loudly instead of passing.
                _, body = asyncio.run(
                    _render_section_blocks(
                        request,
                        case,
                        db,
                        memory,
                        base_url="http://127.0.0.1:1",
                        model="none",
                        max_queries_per_section=1,
                        llm_logger=None,
                        iteration=1,
                        progress_callback=None,
                        focus_sections=None,
                    )
                )
        self.assertIn("## Evidence Scope", body)
        self.assertIn("| Metric | Value |", body)

    def test_render_rows_template_grammar(self) -> None:
        """R6-03: shared placeholder grammar for captions and interpretations."""
        from forensia.report.markdown import render_rows_template

        rows = [
            {"host": "alpha", "events": 10},
            {"host": "beta", "events": 3},
        ]
        out = render_rows_template(
            "{row_count} hosts ({sample(host, 3)}); first={first.host} last={last.host}",
            rows,
        )
        self.assertEqual("2 hosts (alpha, beta); first=alpha last=beta", out)

    def test_render_table_block_prepends_caption(self) -> None:
        """R6-03: a mode:table block renders a declarative caption above the table."""
        from forensia.report.table_registry import render_table_block

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                body = render_table_block(db, "overview_evidence_scope")
        self.assertIsNotNone(body)
        caption, _, rest = body.partition("\n\n")
        self.assertFalse(
            caption.startswith("|"),
            f"caption paragraph expected, got table first: {caption!r}",
        )
        self.assertIn("metrics", caption)
        self.assertIn("| Metric | Value |", rest)

    def test_render_table_block_empty_rows_render_declared_text(self) -> None:
        """R6-03: an empty result renders the declared empty text, not a bare table."""
        from forensia.report.table_registry import render_table_block

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                body = render_table_block(db, "gaps_untestable")
        self.assertIsNotNone(body)
        self.assertNotIn("|", body, "no table for zero rows")
        self.assertIn("untestable", body)

    def test_render_table_block_unknown_builder_returns_none(self) -> None:
        from forensia.report.table_registry import render_table_block

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self.assertIsNone(render_table_block(db, "no_such_builder"))

    def test_markdown_table_truncation_marker_outside_table(self) -> None:
        """R6-06: the Showing-N-of-M marker must not be a fake table row."""
        from forensia.report.markdown import markdown_table

        rows = [{"a": i, "b": i} for i in range(20)]
        table = markdown_table(rows, [("a", "A"), ("b", "B")], max_rows=5)
        self.assertNotIn("| ...", table)
        self.assertIn("_Showing 5 of 20 rows._", table)
        self.assertTrue(table.rstrip().endswith("_Showing 5 of 20 rows._"))

    def testexecution_rows_aggregate_per_executable(self) -> None:
        """R6-06: one table row per executable name, exec counts summed."""
        from forensia.report.summary_rows import execution_rows

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, source_file, executable_name, exec_count, last_exec_time) VALUES "
                    "('prefetch-iexplore-1', 'a.pf', 'IEXPLORE.EXE', 14, TIMESTAMP '2015-03-25 15:22:07'), "
                    "('prefetch-iexplore-2', 'b.pf', 'IEXPLORE.EXE', 2, TIMESTAMP '2015-03-25 15:22:06'), "
                    "('prefetch-winword-1', 'c.pf', 'WINWORD.EXE', 3, TIMESTAMP '2015-03-25 15:24:48')"
                )
                rows = execution_rows(db)
        names = [str(r.get("executable_name")) for r in rows]
        self.assertEqual(
            len(names), len(set(names)), f"duplicate executables in {names}"
        )
        iexplore = next(r for r in rows if r["executable_name"] == "IEXPLORE.EXE")
        self.assertEqual(16, int(iexplore["exec_count"]))
        self.assertIn("15:22:07", str(iexplore["last_exec_time"]))

    def test_prepare_block_context_merges_section_table_digest(self) -> None:
        """R6-05: same-section table digest reaches the narrator context."""
        from forensia.ai.section_block_context import _prepare_block_context

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ctx = _prepare_block_context(
                    case=case,
                    db=db,
                    section_key="2_timeline",
                    title="Activity Timeline",
                    block_heading="Log Integrity",
                    template_body="<!-- mode: narrative; x -->",
                    base_url="http://127.0.0.1:1",
                    model="none",
                    memory=None,
                    max_queries=1,
                    evidence_keypoints=None,
                    question_mode=False,
                    section_table_digest="<SECTION_TABLES>\n### Phase Summary\n| Date |\n</SECTION_TABLES>",
                )
        self.assertIn("<SECTION_TABLES>", ctx.structured_digest)
        self.assertIn("Phase Summary", ctx.structured_digest)

    def test_async_render_blocks_feed_table_digest_to_narrative_in_template_order(
        self,
    ) -> None:
        """R6-05: tables render first and feed the narrative agent; the
        assembled body keeps template order (narrative before table here)."""
        import asyncio
        from unittest import mock

        from forensia.ai import section_refresher
        from forensia.ai.section_exec import SectionBlockResult
        from forensia.core.memory import MemoryManager

        captured: dict = {}

        async def _stub_agent(**kwargs):
            captured.update(kwargs)
            return SectionBlockResult(
                body="narrative body",
                evidence_results=[],
                iterations=1,
                status="answered",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                request = {
                    "case": case,
                    "section_key": "1_overview",
                    "title": "Investigation Overview",
                    "template_preamble": "",
                    "context_sections": {},
                    "report_brief": {},
                    "is_stale": True,
                    "block_requests": [
                        {
                            "heading": "Executive Summary",
                            "template_body": "<!-- mode: narrative; summary -->",
                            "mode": "narrative",
                            "evidence_keypoints": [],
                        },
                        {
                            "heading": "Evidence Scope",
                            "template_body": "<!-- mode: table; builder: overview_evidence_scope -->",
                            "mode": "table",
                            "builder": "overview_evidence_scope",
                            "evidence_keypoints": [],
                        },
                    ],
                }
                with mock.patch.object(
                    section_refresher, "async_run_section_block_agent", _stub_agent
                ):
                    _, body = asyncio.run(
                        section_refresher._render_section_blocks(
                            request,
                            case,
                            db,
                            MemoryManager(case),
                            base_url="http://127.0.0.1:1",
                            model="none",
                            max_queries_per_section=1,
                            llm_logger=None,
                            iteration=1,
                            progress_callback=None,
                            focus_sections=None,
                        )
                    )

        digest = str(captured.get("section_table_digest") or "")
        self.assertIn(
            "<SECTION_TABLES>", digest, "narrative agent must receive the table digest"
        )
        self.assertIn("Evidence Scope", digest)
        self.assertIn("| Metric | Value |", digest)
        self.assertLess(
            body.index("## Executive Summary"),
            body.index("## Evidence Scope"),
            "assembly must keep template order even though tables render first",
        )

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
                results = resolve_evidence_results(
                    case,
                    db,
                    keypoints=["timeline_log_clearing", "gaps_log_integrity_events"],
                )

            timeline = next(
                result
                for result in results
                if result["keypoint"] == "timeline_log_clearing"
            )
            gaps = next(
                result
                for result in results
                if result["keypoint"] == "gaps_log_integrity_events"
            )
            self.assertEqual(["evtx-eventlog-000000000104"], timeline["evidence_ids"])
            self.assertEqual(1, timeline["row_count"])
            self.assertEqual(
                [{"event_id": 104, "count": 1, "citable": False}], gaps["sample_rows"]
            )

    def test_error_reasoning_rows_excluded_from_latest(self) -> None:
        """R2-05: error-phase reasoning entries must not appear as latest_reasoning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, description, summary, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, now(), now())
                    """,
                    ("H-001", "active", "Test hypothesis", "test"),
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, body, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "err-entry",
                        "H-001",
                        "s1",
                        1,
                        "error",
                        "[internal-error] SQL execution error: Binder Error",
                    ),
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, body, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, now() + INTERVAL '1 minute')
                    """,
                    (
                        "normal-entry",
                        "H-001",
                        "s1",
                        1,
                        "plan",
                        "Checked for logon events",
                    ),
                )
                rows = hypothesis_rows(db, "active")
                self.assertEqual(1, len(rows))
                self.assertEqual("H-001", rows[0]["hypothesis_id"])
                self.assertEqual(
                    "Checked for logon events", rows[0]["latest_reasoning"]
                )
                self.assertEqual(2, rows[0]["reasoning_count"])

    def testextract_needed_evidence_parses_missing_questions(self) -> None:
        body = json.dumps(
            {
                "verdict": "inconclusive",
                "missing_questions": ["event_id 4663", "process creation 4688"],
            }
        )
        self.assertEqual(
            "event_id 4663; process creation 4688", extract_needed_evidence(body)
        )

    def testextract_needed_evidence_returns_first_two_only(self) -> None:
        body = json.dumps({"missing_questions": ["a", "b", "c", "d"]})
        self.assertEqual("a; b", extract_needed_evidence(body))

    def testextract_needed_evidence_empty_on_none(self) -> None:
        self.assertEqual("", extract_needed_evidence(None))
        self.assertEqual("", extract_needed_evidence(""))
        self.assertEqual("", extract_needed_evidence("not json"))

    def test_unresolved_resolver_includes_needed_evidence(self) -> None:

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, description, summary, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, now(), now())
                    """,
                    ("H-099", "active", "Suspicious logon pattern detected", "test"),
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, body, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "reason-099",
                        "H-099",
                        "s1",
                        1,
                        "check",
                        json.dumps(
                            {
                                "verdict": "inconclusive",
                                "missing_questions": [
                                    "event_id 4625",
                                    "source IP correlation",
                                ],
                            }
                        ),
                    ),
                )
                _, resolver = REPORT_KEYPOINTS["unresolved_hypotheses_summary"]
                rows = resolver(db)
                self.assertEqual(1, len(rows))
                self.assertEqual(
                    "event_id 4625; source IP correlation", rows[0]["needed_evidence"]
                )
                self.assertEqual(
                    "Suspicious logon pattern detected", rows[0]["description"]
                )

    def test_untestable_resolver_includes_needed_evidence(self) -> None:

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, verdict, description, summary, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, now(), now())
                    """,
                    (
                        "H-100",
                        "active",
                        "untestable",
                        "Missing EDR telemetry for process tree",
                        "test",
                    ),
                )
                db.execute(
                    """
                    INSERT INTO hypothesis_reasoning (
                        entry_id, hypothesis_id, session_id, iteration, phase, body, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, now())
                    """,
                    (
                        "reason-100",
                        "H-100",
                        "s1",
                        1,
                        "check",
                        json.dumps(
                            {
                                "verdict": "inconclusive",
                                "missing_questions": [
                                    "Sysmon event_id 1 not available",
                                    "no EDR process tree",
                                ],
                            }
                        ),
                    ),
                )
                _, resolver = REPORT_KEYPOINTS["untestable_hypotheses_summary"]
                rows = resolver(db)
                self.assertEqual(1, len(rows))
                self.assertEqual(
                    "Sysmon event_id 1 not available; no EDR process tree",
                    rows[0]["needed_evidence"],
                )
                self.assertEqual(
                    "Missing EDR telemetry for process tree", rows[0]["description"]
                )

    def test_structured_digest_empty_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            digest = _structured_digest_from_answers(case)
            self.assertEqual("", digest)

    def test_structured_digest_from_synthetic_answers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            answers_path = case.reports_dir / "structured" / "answers.json"
            answers_path.parent.mkdir(parents=True, exist_ok=True)
            synthetic = [
                {
                    "id": "probe_host_identity",
                    "answer_spec": "host_identity",
                    "status": "answered",
                    "answer": [
                        {
                            "host": "HOST-A",
                            "evidence_id": "E1",
                            "timestamp": "2024-01-15T10:00:00",
                        },
                        {
                            "host": "HOST-B",
                            "evidence_id": "E2",
                            "timestamp": "2024-01-15T11:00:00",
                        },
                    ],
                    "columns": ["host", "timestamp"],
                },
                {
                    "id": "probe_not_searched",
                    "answer_spec": "unused_spec",
                    "status": "not_searched",
                    "answer": [],
                    "columns": [],
                },
                {
                    "id": "antiforensic_activity",
                    "answer_spec": "antiforensic_activity",
                    "status": "answered",
                    "answer": [
                        {
                            "tool_name": "Eraser",
                            "timestamp": "2024-01-15T12:00:00",
                        },
                    ],
                    "columns": ["tool_name", "timestamp"],
                },
            ]
            answers_path.write_text(
                json.dumps(synthetic, ensure_ascii=False), encoding="utf-8"
            )
            digest = _structured_digest_from_answers(case)
            self.assertIn("host_identity", digest)
            self.assertIn("antiforensic_activity", digest)
            self.assertNotIn("unused_spec", digest)
            self.assertNotIn("not_searched", digest)
            self.assertIn("STRUCTURED_OBSERVATIONS", digest)
            self.assertIn("HOST-A | HOST-B", digest)
            self.assertIn("Eraser", digest)
            self.assertIn("rows=2", digest)
            self.assertLess(len(digest), 1500)

    def test_structured_digest_in_prompt_for_overview(self) -> None:
        """Verify that build_paragraph_narrate_messages injects STRUCTURED_OBSERVATIONS for overview blocks."""
        from forensia.ai.prompts.prompt_sections import build_paragraph_narrate_messages

        messages, _schema = build_paragraph_narrate_messages(
            heading="Executive Summary",
            key_points=["Key observation"],
            evidence_rows=[{"evidence_id": "E1", "summary": "test"}],
            template_body="## Executive Summary\nSummary here.",
            structured_digest="<STRUCTURED_OBSERVATIONS>\n  - test_spec: rows=3\n</STRUCTURED_OBSERVATIONS>",
        )
        combined = "\n".join(m.get("content", "") for m in messages)
        self.assertIn("STRUCTURED_OBSERVATIONS", combined)
        self.assertIn("test_spec", combined)
        self.assertIn(
            "Write what the evidence shows, not instructions to the reader", combined
        )

    def test_structured_digest_not_in_prompt_for_appendix(self) -> None:
        """Verify appendix blocks get no STRUCTURED_OBSERVATIONS."""
        from forensia.ai.prompts.prompt_sections import build_paragraph_narrate_messages

        messages, _schema = build_paragraph_narrate_messages(
            heading="Appendix Details",
            key_points=["Appendix data"],
            evidence_rows=[],
            template_body="## Appendix\nExtra data.",
        )
        combined = "\n".join(m.get("content", "") for m in messages)
        self.assertNotIn("STRUCTURED_OBSERVATIONS", combined)

    def test_structured_digest_context_in_prepare_block_context(self) -> None:
        """Verify _prepare_block_context computes digest for overview and not for appendix."""
        from forensia.ai.section_block_context import _prepare_block_context

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            answers_path = case.reports_dir / "structured" / "answers.json"
            answers_path.parent.mkdir(parents=True, exist_ok=True)
            answers_path.write_text(
                json.dumps(
                    [
                        {
                            "id": "probe_host",
                            "answer_spec": "host_identity",
                            "status": "answered",
                            "answer": [
                                {"host": "HOST-A", "timestamp": "2024-01-15T10:00:00"}
                            ],
                            "columns": ["host", "timestamp"],
                        },
                    ]
                ),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                ctx_overview = _prepare_block_context(
                    case=case,
                    db=db,
                    section_key="1_overview",
                    title="Overview",
                    block_heading="Test",
                    template_body="## Test",
                    base_url="",
                    model="test",
                    memory=None,
                    max_queries=3,
                    evidence_keypoints=None,
                    question_mode=False,
                    audit_callback=None,
                    report_brief={},
                )
                ctx_appendix = _prepare_block_context(
                    case=case,
                    db=db,
                    section_key="6_appendix",
                    title="Appendix",
                    block_heading="Test",
                    template_body="## Test",
                    base_url="",
                    model="test",
                    memory=None,
                    max_queries=3,
                    evidence_keypoints=None,
                    question_mode=False,
                    audit_callback=None,
                    report_brief={},
                )
                self.assertIn("host_identity", ctx_overview.structured_digest)
                self.assertEqual(ctx_appendix.structured_digest, "")


class HtmlEvidenceIdAnchorTests(unittest.TestCase):
    def test_html_evidence_id_anchor_rendering(self):
        from forensia.report.html import _render_inline_markdown

        html = _render_inline_markdown("See evtx-security-000000000001.")
        self.assertIn('href="#ev-evtx-security-000000000001"', html)
        # Placeholder title (bare id); _inject_evidence_interactivity swaps in the
        # record summary when the evidence map is available.
        self.assertIn('title="evtx-security-000000000001"', html)
        self.assertIn('class="evidence-ref"', html)

    def test_markdown_table_max_rows_zero_is_unlimited(self) -> None:
        """R7-02: max_rows=0 renders all rows without truncation marker."""
        from forensia.report.markdown import markdown_table

        rows = [{"a": i, "b": i * 10} for i in range(50)]
        table = markdown_table(rows, [("a", "A"), ("b", "B")], max_rows=0)
        self.assertIn("| 49 |", table)
        self.assertNotIn("_Showing", table)

    def test_structured_answer_increased_max_rows(self) -> None:
        """R7-02: structured answer with 68 rows renders all 68 (no truncation below 200)."""
        from forensia.report.answer_store import render_answer_block

        items = [{"idx": i} for i in range(68)]
        lines = render_answer_block(items, columns=["idx"], max_rows=200)
        body = "\n".join(lines)
        self.assertIn("| 67 |", body)
        self.assertNotIn("_Showing", body)
