from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime

from forensia.ai.sections.section_exec import (
    structured_digest_from_answers,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.answers.gap_tables import hypothesis_rows
from forensia.report.answers.keypoint_catalog import (
    REPORT_KEYPOINTS,
    resolve_evidence_results,
)
from forensia.report.evidence_refs import extract_needed_evidence
from forensia.report.sections.template_parsing import parse_block_hints


class TableRenderingTests(unittest.TestCase):
    """Table block rendering, digests, block hints, reasoning rows, HTML anchors."""

    def test_parse_block_hints_combined_comment_syntax(self) -> None:
        """The packaged templates use the combined one-comment
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

    def test_section_instructions_reach_each_llm_block(self) -> None:
        from forensia.report.sections.section_assembly import prepare_section_request

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template = case.path / "custom.md"
            template.write_text(
                "---\ntype: report-section-template\ntitle: Report\n"
                "description: Test report section.\ntags: [test, report]\n"
                "timestamp: 2026-07-12\n"
                "instructions: |\n  Separate facts from assessments.\n"
                "---\n# Report\n\n## Finding\n<!-- mode: narrative -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                request = prepare_section_request(case, db, template, {})

        self.assertEqual(
            "Separate facts from assessments.",
            request["template_meta"].instructions,
        )
        self.assertEqual("report-section-template", request["template_meta"].type)
        self.assertEqual(("test", "report"), request["template_meta"].tags)
        block_body = request["block_requests"][0]["template_body"]
        self.assertIn("section_instructions", block_body)
        self.assertIn("Separate facts from assessments.", block_body)
        self.assertIn("<!-- mode: narrative -->", block_body)

    def test_async_render_section_blocks_renders_table_mode_without_llm(self) -> None:
        """The async render path (used by the investigate loop)
        must execute table builders deterministically instead of routing table
        blocks through the LLM agent."""
        import asyncio

        from forensia.ai.sections.section_refresher import render_section_blocks
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
                    render_section_blocks(
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
        from forensia.report.render.markdown import render_rows_template

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
        from forensia.report.answers.table_registry import render_table_block

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
        from forensia.report.answers.table_registry import render_table_block

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                body = render_table_block(db, "gaps_untestable")
        self.assertIsNotNone(body)
        self.assertNotIn("|", body, "no table for zero rows")
        self.assertIn("untestable", body)

    def test_render_table_block_unknown_builder_returns_none(self) -> None:
        from forensia.report.answers.table_registry import render_table_block

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                self.assertIsNone(render_table_block(db, "no_such_builder"))

    def test_markdown_table_truncation_marker_outside_table(self) -> None:
        """R6-06: the Showing-N-of-M marker must not be a fake table row."""
        from forensia.report.render.markdown import markdown_table

        rows = [{"a": i, "b": i} for i in range(20)]
        table = markdown_table(rows, [("a", "A"), ("b", "B")], max_rows=5)
        self.assertNotIn("| ...", table)
        self.assertIn("_Showing 5 of 20 rows._", table)
        self.assertTrue(table.rstrip().endswith("_Showing 5 of 20 rows._"))

    def testexecution_rows_aggregate_per_executable(self) -> None:
        """R6-06: one table row per executable name, exec counts summed."""
        from forensia.report.answers.summary_rows import execution_rows

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
        from forensia.ai.sections.section_block_context import prepare_block_context

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ctx = prepare_block_context(
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

        from forensia.ai.sections import section_refresher
        from forensia.ai.sections.section_exec import SectionBlockResult
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
                        section_refresher.render_section_blocks(
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
            digest = structured_digest_from_answers(case)
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
            digest = structured_digest_from_answers(case)
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
        """Verify prepare_block_context computes digest for overview and not for appendix."""
        from forensia.ai.sections.section_block_context import prepare_block_context

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
                ctx_overview = prepare_block_context(
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
                ctx_appendix = prepare_block_context(
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
        from forensia.report.render.html import render_inline_markdown

        html = render_inline_markdown("See evtx-security-000000000001.")
        self.assertIn('href="#ev-evtx-security-000000000001"', html)
        # Placeholder title (bare id); _inject_evidence_interactivity swaps in the
        # record summary when the evidence map is available.
        self.assertIn('title="evtx-security-000000000001"', html)
        self.assertIn('class="evidence-ref"', html)

    def test_markdown_table_max_rows_zero_is_unlimited(self) -> None:
        """R7-02: max_rows=0 renders all rows without truncation marker."""
        from forensia.report.render.markdown import markdown_table

        rows = [{"a": i, "b": i * 10} for i in range(50)]
        table = markdown_table(rows, [("a", "A"), ("b", "B")], max_rows=0)
        self.assertIn("| 49 |", table)
        self.assertNotIn("_Showing", table)

    def test_structured_answer_increased_max_rows(self) -> None:
        """R7-02: structured answer with 68 rows renders all 68 (no truncation below 200)."""
        from forensia.report.answers.answer_store import render_answer_block

        items = [{"idx": i} for i in range(68)]
        lines = render_answer_block(items, columns=["idx"], max_rows=200)
        body = "\n".join(lines)
        self.assertIn("| 67 |", body)
        self.assertNotIn("_Showing", body)


if __name__ == "__main__":
    unittest.main()
