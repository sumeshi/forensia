from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


class SectionNarrativeTests(unittest.TestCase):
    """Narration fallbacks, block assembly, markdown preprocessing, question routing."""

    def test_template_dir_overrides_report_wording_and_headings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            template_dir = Path(tmpdir)
            formats_dir = template_dir / "_formats"
            formats_dir.mkdir()
            (formats_dir / "report.yaml").write_text(
                """version: 1
structured_answer:
  headings:
    answer: Custom Answer
""",
                encoding="utf-8",
            )
            structured = render_structured_answer_markdown(
                {"id": "Q1", "status": "answered", "answer": ["value"]},
                "Question",
                template_dir=template_dir,
            )

        self.assertIn("### Custom Answer", structured)

    def test_assemble_section_body_preserves_template_preamble(self) -> None:
        body = assemble_section_body(
            "# Investigation Overview", ["## Executive Summary\n\nBody"]
        )
        self.assertTrue(
            body.startswith("# Investigation Overview\n\n## Executive Summary")
        )

    def test_narration_with_new_traceability_failure_is_rejected(self) -> None:
        from forensia.report.sections.section_refresher import (
            _narration_admission_reasons,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                projection = {
                    "request": {"section_key": "1_overview", "title": "Overview"},
                    "evidence_results": [],
                    "blocks": [{"heading": "Overview"}],
                    "first_narrative_index": 0,
                }
                fallback = (
                    "# Overview\n\nObserved activity is summarized from the deterministic "
                    "projection without assigning an unsupported event claim."
                )
                candidate = (
                    "# Overview\n\nEVTX proves unauthorized activity during the interval, "
                    "but this sentence has no machine-detectable evidence reference."
                )

                reasons = _narration_admission_reasons(
                    db, projection, fallback, candidate
                )

        self.assertTrue(
            any(reason.startswith("claim_traceability:") for reason in reasons)
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
        body = preprocess_section_body(raw)
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
        # FORENSIA_REPORT_MARKDOWN_MAX_ROWS is now 200, so all 30 rows are shown
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
                        "evidence_id": "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
                        "evidence_ids": [
                            "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00"
                        ],
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
        self.assertNotIn(
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
            markdown,
        )
        self.assertNotIn(
            "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000000001-00",
            markdown,
        )
        self.assertNotIn("source_file", markdown)
        self.assertNotIn("raw.evtx", markdown)


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


if __name__ == "__main__":
    unittest.main()
