from __future__ import annotations

"""Guarantees HTML output behavior, not the internal Markdown parser state.

These tests intentionally exercise public rendering entry points so the report
HTML implementation can be refactored without freezing private helper shape.
"""

import json
import tempfile
import unittest
from datetime import UTC, datetime

from markupsafe import Markup

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.render.evidence_map import (
    build_evidence_map,
    render_evidence_references,
)
from forensia.report.render.html import render_html_report, render_markdown_fragment


class RenderMarkdownFragmentTests(unittest.TestCase):
    def test_empty_input(self):
        html = render_markdown_fragment("")
        self.assertIsInstance(html, Markup)
        self.assertIn('class="empty-report"', str(html))
        self.assertIn("No report content yet.", str(html))

    def test_markdown_blocks_render_as_safe_html(self):
        md = (
            "# Title\n\n"
            "Intro `cmd` and **bold** and *italic* with <b>escaped</b>.\n\n"
            "- list one\n"
            "- list two\n\n"
            "1. first\n"
            "2. second\n\n"
            "```python\n"
            "print('<x>')\n"
            "```\n\n"
            "| Col1 | Col2 |\n"
            "|------|------|\n"
            "| A | B |\n\n"
            "---\n\n"
            "Final note."
        )

        html = str(render_markdown_fragment(md))

        self.assertIn("<h2>Title</h2>", html)
        self.assertIn("<code>cmd</code>", html)
        self.assertIn("<strong>bold</strong>", html)
        self.assertIn("<em>italic</em>", html)
        self.assertIn("&lt;b&gt;escaped&lt;/b&gt;", html)
        self.assertIn("<ul>", html)
        self.assertIn("<ol>", html)
        self.assertIn("<pre><code>", html)
        self.assertIn("&lt;x&gt;", html)
        self.assertIn("<table>", html)
        self.assertIn("<th>Col1</th>", html)
        self.assertIn("<td>A</td>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<p>Final note.</p>", html)

    def test_paragraph_boundaries_and_heading_levels(self):
        html = str(render_markdown_fragment("# A\n## B\n\nline1\nline2\n\npara two"))

        self.assertIn("<h2>A</h2>", html)
        self.assertIn("<h3>B</h3>", html)
        self.assertIn("<p>line1<br>line2</p>", html)
        self.assertIn("<p>para two</p>", html)

    def test_evidence_id_renders_as_placeholder_link_before_document_injection(self):
        html = str(render_markdown_fragment("See evtx-security-000000000001."))

        self.assertIn('class="evidence-ref"', html)
        self.assertIn('href="#ev-evtx-security-000000000001"', html)


class EvidenceMapTests(unittest.TestCase):
    def test_evidence_map_builds_from_body(self):
        body = "See evtx-security-000000000001 for details."
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, raw_json) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        "evtx-security-000000000001",
                        4624,
                        "2015-03-22T14:34:28",
                        json.dumps({"event_id": 4624, "target_user": "informant"}),
                    ),
                )
                emap = build_evidence_map(db, body)

        self.assertIn("evtx-security-000000000001", emap)
        info = emap["evtx-security-000000000001"]
        self.assertEqual(info["source"], "evtx_events")
        self.assertIn("4624", info["summary"])

    def test_evidence_references_renders_markdown(self):
        emap = {
            "evtx-security-000000000001": {
                "source": "evtx_events",
                "timestamp": "2015-03-22T14:34:28",
                "summary": "4624 logon",
            },
        }

        md = render_evidence_references(emap)

        self.assertIn("## Evidence References", md)
        self.assertIn("evtx-security-000000000001", md)

    def test_evidence_map_summarizes_mft_and_prefetch_rows(self):
        body = "Files mft-000000078080-01 and runs prefetch-ccleaner64.exe-779bd542."
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_name, file_path, si_modified) VALUES "
                    "('mft-000000078080-01', 'Task List.ersy', 'Users/informant/AppData/Local/Eraser 6/Task List.ersy', TIMESTAMP '2015-03-25 15:29:37')"
                )
                db.execute(
                    "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) VALUES "
                    "('prefetch-ccleaner64.exe-779bd542', 'CCLEANER64.EXE', 2, TIMESTAMP '2015-03-25 15:15:50')"
                )
                emap = build_evidence_map(db, body)

        self.assertIn("Task List.ersy", emap["mft-000000078080-01"]["summary"])
        self.assertIn(
            "CCLEANER64.EXE", emap["prefetch-ccleaner64.exe-779bd542"]["summary"]
        )

    def test_evidence_map_marks_unknown_ids_unresolved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                emap = build_evidence_map(db, "Bogus evtx-security-000000000099 cited.")

        self.assertEqual("unresolved", emap["evtx-security-000000000099"]["source"])


class RenderHtmlReportTests(unittest.TestCase):
    def test_report_document_links_evidence_to_record_and_removes_reference_appendix(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.reports_dir / "report.md").write_text(
                "Logon observed (evtx-security-000000000001).\n\n"
                "## Evidence References\n\n"
                "- `evtx-security-000000000001` 2015-03-22T14:34:28 evtx_events - 4624 logon\n",
                encoding="utf-8",
            )
            (case.reports_dir / "evidence_map.json").write_text(
                json.dumps(
                    {
                        "evtx-security-000000000001": {
                            "source": "evtx_events",
                            "timestamp": "2015-03-22T14:34:28",
                            "summary": "4624 Security informant@informant-PC",
                        }
                    }
                ),
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                output = render_html_report(case, db)
                html = output.read_text(encoding="utf-8")

        self.assertIn('href="/evidence/evtx-security-000000000001"', html)
        self.assertIn('target="_blank"', html)
        self.assertIn("4624 Security informant@informant-PC", html)
        self.assertNotIn('href="#ev-', html)
        self.assertNotIn("<h2>Evidence References</h2>", html)

    def test_report_document_builds_toc_from_headings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.reports_dir / "report.md").write_text(
                "# Investigation Overview\n\n## Executive Summary\n\nText.",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                output = render_html_report(case, db)
                html = output.read_text(encoding="utf-8")

        self.assertIn('<h2 id="sec-0">Investigation Overview</h2>', html)
        self.assertIn('<h3 id="sec-1">Executive Summary</h3>', html)
        self.assertIn(
            '<li class="toc-h2"><a href="#sec-0">Investigation Overview</a></li>',
            html,
        )
        self.assertIn(
            '<li class="toc-h3"><a href="#sec-1">Executive Summary</a></li>',
            html,
        )

    def test_report_footer_groups_duplicate_raw_findings(self):
        now = datetime.now(UTC).replace(tzinfo=None)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.reports_dir / "report.md").write_text(
                "# Report\n\nBody.", encoding="utf-8"
            )
            with CaseDB(case) as db:
                for finding_id, title, confidence in (
                    (
                        "f-1",
                        "Logon attempt with explicit credentials (4648): A -> B",
                        0.7,
                    ),
                    (
                        "f-2",
                        "Logon attempt with explicit credentials (4648): A -> C",
                        0.6,
                    ),
                ):
                    db.execute(
                        """
                        INSERT INTO findings (
                            finding_id, rule_id, title, summary, severity, confidence,
                            status, tags, attack, evidence, ai_summary, missing_checks, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding_id,
                            "rule",
                            title,
                            "raw",
                            "high",
                            confidence,
                            "accepted",
                            "[]",
                            "[]",
                            "[]",
                            "",
                            "[]",
                            now,
                        ),
                    )
                output = render_html_report(case, db)
                html = output.read_text(encoding="utf-8")

        self.assertIn("Explicit credential usage observed (2)", html)
        self.assertNotIn(
            "Logon attempt with explicit credentials (4648): A -&gt; B", html
        )

    def test_report_footer_uses_catalog_driven_tool_theme(self):
        now = datetime.now(UTC).replace(tzinfo=None)
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.reports_dir / "report.md").write_text(
                "# Report\n\nBody.", encoding="utf-8"
            )
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO findings (
                        finding_id, rule_id, title, summary, severity, confidence,
                        status, tags, attack, evidence, ai_summary, missing_checks, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "f-cleaner",
                        "generic-process-observation",
                        "CCleaner execution observed",
                        "Application execution trace",
                        "medium",
                        0.8,
                        "accepted",
                        "[]",
                        "[]",
                        "[]",
                        "",
                        "[]",
                        now,
                    ),
                )
                output = render_html_report(case, db)
                html = output.read_text(encoding="utf-8")

        self.assertIn("Wiping / cleaning tool traces", html)
        self.assertIn("finding-item--medium", html)
