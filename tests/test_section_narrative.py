from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from forensia.ai.sections.section_answers import (
    extract_answer_by_shape,
    format_question_answer,
    is_effectively_empty_body,
)
from forensia.ai.sections.section_block_narrative import (
    fallback_narrative_body,
    narrate_paragraph_with_retry,
)
from forensia.ai.sections.section_exec import (
    coerce_plan_action,
    question_routing_answer_spec,
)
from forensia.ai.sections.section_run_store import load_reusable_section_facts
from forensia.config import clear_llm_settings_cache, reload_settings
from forensia.core.case import Case
from forensia.core.textutil import normalize_localized_dates
from forensia.db.database import CaseDB
from forensia.knowledge.questions import resolve_question_spec
from forensia.report.answers.answer_store import render_structured_answer_markdown
from forensia.report.sections.quality_gates import (
    GateContext,
    check_json_object_leak,
    check_recommendations_strength,
)
from forensia.report.sections.section_assembly import assemble_section_body
from forensia.report.sections.section_finalize import (
    preprocess_section_body,
)
from forensia.report.sections.section_store import extract_claim_texts


class SectionNarrativeTests(unittest.TestCase):
    """Narration fallbacks, block assembly, markdown preprocessing, question routing."""

    def test_template_dir_overrides_report_wording_and_headings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_dir = Path(tmpdir)
            formats_dir = template_dir / "_formats"
            formats_dir.mkdir()
            (formats_dir / "report.yaml").write_text(
                """version: 1
narrative_fallback:
  unsupported: "CUSTOM EMPTY: {heading}"
structured_answer:
  headings:
    answer: Custom Answer
""",
                encoding="utf-8",
            )
            fallback = fallback_narrative_body(
                heading="Network Activity",
                status="not_found",
                collected_results=[],
                flat_evidence=[],
                actual_query_count=1,
                actual_query_row_counts=[0],
                template_dir=template_dir,
            )
            structured = render_structured_answer_markdown(
                {"id": "Q1", "status": "answered", "answer": ["value"]},
                "Question",
                template_dir=template_dir,
            )

        self.assertEqual("CUSTOM EMPTY: Network Activity", fallback)
        self.assertIn("### Custom Answer", structured)

    def test_status_only_narration_gets_deterministic_fallback(self) -> None:
        self.assertTrue(is_effectively_empty_body("**Status:** answered"))
        with patch.dict(os.environ, {"LLM_OUTPUT_LANGUAGE": "en"}):
            reload_settings()
            body = fallback_narrative_body(
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
            body = fallback_narrative_body(
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
                normal = load_reusable_section_facts(db, "1_overview")
                with_case_probe = load_reusable_section_facts(
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
            question_routing_answer_spec("Last recorded shutdown time", ""),
        )
        self.assertEqual(
            "last_human_logon", question_routing_answer_spec("Last logged-on user", "")
        )
        self.assertEqual(
            "daily_session_activity",
            question_routing_answer_spec(
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
        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=fake_llm
        ):
            body = narrate_paragraph_with_retry(
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

        with patch(
            "forensia.ai.llm.llm_gateway.request_llm_json", side_effect=fake_llm
        ):
            narrate_paragraph_with_retry(
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
            body = fallback_narrative_body(
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
            body = fallback_narrative_body(
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


class AnswerFormattingTests(unittest.TestCase):
    """Plan-action coercion and structured question-answer formatting."""

    def test_comma_separated_keypoint(self):
        result = coerce_plan_action(
            {"action": "keypoint", "keypoint": "benchmark_hosts, benchmark_recent_lnk"},
            section_key="test",
            iteration=0,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.keypoint, "benchmark_hosts, benchmark_recent_lnk")

    def test_format_question_answer_uses_classifier_status(self):
        case = SimpleNamespace(reports_dir=Path(tempfile.mkdtemp()))
        body = format_question_answer(
            {"status": "answered", "picked_row_indices": [], "rationale": "ok"},
            [{"host_id": "INFORMANT-PC"}],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "not_found",
            case,
            question_id="Q6",
        )
        self.assertIn("**Status:** answered", body)
        self.assertIn("INFORMANT-PC", body)

    def test_format_question_answer_missing_reason_string_not_split(self):
        case = SimpleNamespace(reports_dir=Path(tempfile.mkdtemp()))
        body = format_question_answer(
            {
                "status": "answered",
                "picked_row_indices": [],
                "rationale": "empty answer rationale",
            },
            [],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "answered",
            case,
            question_id="Q6",
        )
        self.assertIn("**Status:** wrong_query", body)
        self.assertIn("- empty answer rationale", body)
        self.assertNotIn("- e\n- m", body)

    def test_extract_answer_by_shape_does_not_make_empty_rows(self):
        rows = [
            {
                "summary": "file_path=Windows/Prefetch/GOOGLEDRIVESYNC.EXE-841A0D94.pf evidence_id=mft-000000005619-00"
            }
        ]
        result = extract_answer_by_shape(
            rows,
            {
                "format": "enumerated_services",
                "fields": ["service_name", "exe_found", "paths_found", "config_found"],
            },
            "enumerated_services",
        )
        self.assertEqual(result[0]["service_name"], "Google Drive")
        self.assertNotEqual(result[0]["service_name"], "")


class SectionBodyQualityTests(unittest.TestCase):
    """JSON-leak gate and claim extraction over rendered section bodies."""

    def test_json_object_leak_detected(self):
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        msg, score = check_json_object_leak('{"body": "some text"}', ctx)
        self.assertIsNotNone(msg)

    def test_json_object_leak_clean(self):
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        msg, score = check_json_object_leak("## Heading\n\nSome paragraph text.", ctx)
        self.assertIsNone(msg)

    def test_scaffold_patterns_filter_claims(self):
        body = "**Status:** answered\n\nReal Content\n\nSome actual claim here."
        claims = extract_claim_texts(body)
        self.assertIn("Real Content", claims)
        self.assertNotIn("**Status:**", " ".join(claims))

    def test_claim_extraction_skips_tables_and_structured_metadata(self):
        body = """
## 1. Endpoint identity

**Status:** answered

### Answer
Substantive narrative claim with evidence evtx-security-000000000122.

| host_id | evidence_count |
| --- | --- |
| informant-PC | 10 |

### Queries Run
- structured:host_identity:evtx_distinct_hosts

### Structured Data
- JSON: structured/answers.json
- CSV: structured/Q6.csv
"""
        claims = extract_claim_texts(body)
        joined = " ".join(claims)
        self.assertIn("Substantive narrative claim", joined)
        self.assertNotIn("host_id", joined)
        self.assertNotIn("informant-PC", joined)
        self.assertNotIn("structured:host_identity", joined)
        self.assertNotIn("structured/answers.json", joined)
        self.assertNotIn("### Queries Run", joined)


if __name__ == "__main__":
    unittest.main()
