from __future__ import annotations

import unittest

from forensia.report.html import (
    _flush_all,
    _flush_code,
    _flush_list,
    _flush_paragraph,
    _flush_table,
    _group_findings_for_display,
    _handle_code_fence,
    _handle_heading,
    _handle_horizontal_rule,
    _handle_ordered_list_item,
    _handle_table_row,
    _handle_unordered_list_item,
    _is_table_row,
    _is_table_separator,
    _MdState,
    _render_inline_markdown,
    _render_table,
    _split_table_row,
    render_markdown_fragment,
)


class RenderInlineMarkdownTests(unittest.TestCase):
    def test_escapes_html(self):
        self.assertEqual(_render_inline_markdown("<script>"), "&lt;script&gt;")

    def test_code_backticks(self):
        self.assertEqual(_render_inline_markdown("run `cmd.exe`"), "run <code>cmd.exe</code>")

    def test_bold_asterisks(self):
        self.assertEqual(_render_inline_markdown("**alert**"), "<strong>alert</strong>")

    def test_italic_asterisks(self):
        self.assertEqual(_render_inline_markdown("*alert*"), "<em>alert</em>")

    def test_bold_and_italic(self):
        self.assertEqual(
            _render_inline_markdown("***critical***"),
            "<em><strong>critical</strong></em>",
        )

    def test_mixed_inline(self):
        self.assertEqual(
            _render_inline_markdown("`code` and **bold** and *italic*"),
            "<code>code</code> and <strong>bold</strong> and <em>italic</em>",
        )

    def test_escapes_html_inside_code(self):
        result = _render_inline_markdown("`<img>`")
        self.assertIn("&lt;img&gt;", result)
        self.assertIn("<code>", result)

    def test_plain_text_passthrough(self):
        self.assertEqual(_render_inline_markdown("hello world"), "hello world")


class FindingDisplayTests(unittest.TestCase):
    def test_groups_duplicate_raw_finding_titles_for_html_display(self):
        grouped = _group_findings_for_display(
            [
                {
                    "finding_id": "f-1",
                    "title": "Logon attempt with explicit credentials (4648): A -> B",
                    "summary": "raw",
                    "severity": "high",
                    "confidence": 0.7,
                },
                {
                    "finding_id": "f-2",
                    "title": "Logon attempt with explicit credentials (4648): A -> C",
                    "summary": "raw",
                    "severity": "high",
                    "confidence": 0.6,
                },
            ]
        )

        self.assertEqual(1, len(grouped))
        self.assertEqual("明示的資格情報利用の観測 (2件)", grouped[0]["title"])
        self.assertNotIn("Logon attempt", grouped[0]["title"])


class SplitTableRowTests(unittest.TestCase):
    def test_splits_standard_row(self):
        self.assertEqual(_split_table_row("| a | b | c |"), ["a", "b", "c"])

    def test_splits_without_leading_pipe(self):
        self.assertEqual(_split_table_row("a | b"), ["a", "b"])

    def test_empty_cells(self):
        self.assertEqual(_split_table_row("||"), [""])

    def test_single_cell_returns_one_element(self):
        self.assertEqual(_split_table_row("| only |"), ["only"])


class IsTableSeparatorTests(unittest.TestCase):
    def test_standard_separator(self):
        self.assertTrue(_is_table_separator("|---|"))

    def test_colon_aligned_separator(self):
        self.assertTrue(_is_table_separator("|:---:|"))

    def test_invalid_separator(self):
        self.assertFalse(_is_table_separator("|---a---|"))

    def test_two_column_separator(self):
        self.assertTrue(_is_table_separator("|---|---|"))


class IsTableRowTests(unittest.TestCase):
    def test_valid_row(self):
        self.assertTrue(_is_table_row("| a | b |"))

    def test_single_cell_is_not_row(self):
        self.assertFalse(_is_table_row("| a |"))

    def test_no_pipe(self):
        self.assertFalse(_is_table_row("hello world"))

    def test_separator_is_detected_as_row(self):
        self.assertTrue(_is_table_row("|---|---|"))


class RenderTableTests(unittest.TestCase):
    def test_simple_table(self):
        lines = ["| H1 | H2 |", "|---|---|", "| A | B |"]
        html = _render_table(lines)
        self.assertIn("<table>", html)
        self.assertIn("<th>H1</th>", html)
        self.assertIn("<th>H2</th>", html)
        self.assertIn("<td>A</td>", html)
        self.assertIn("<td>B</td>", html)

    def test_table_without_separator(self):
        lines = ["| H1 |", "| V1 |"]
        html = _render_table(lines)
        self.assertIn("<th>H1</th>", html)
        self.assertIn("<td>V1</td>", html)

    def test_table_inline_formatting(self):
        lines = ["| **Name** |", "|------|", "| `cmd` |"]
        html = _render_table(lines)
        self.assertIn("<strong>Name</strong>", html)
        self.assertIn("<code>cmd</code>", html)


class FlushParagraphTests(unittest.TestCase):
    def test_flush_empty_lines(self):
        state = _MdState()
        _flush_paragraph(state)
        self.assertEqual(state.blocks, [])

    def test_flush_single_line(self):
        state = _MdState(paragraph_lines=["hello"])
        _flush_paragraph(state)
        self.assertEqual(state.blocks, ["<p>hello</p>"])

    def test_flush_multi_line_br(self):
        state = _MdState(paragraph_lines=["line1", "line2"])
        _flush_paragraph(state)
        self.assertEqual(state.blocks, ["<p>line1<br>line2</p>"])


class FlushListTests(unittest.TestCase):
    def test_ordered_list(self):
        state = _MdState(list_items=["a", "b"], list_kind="ol")
        _flush_list(state)
        self.assertEqual(state.blocks, ["<ol><li>a</li><li>b</li></ol>"])
        self.assertIsNone(state.list_kind)
        self.assertEqual(state.list_items, [])

    def test_unordered_list(self):
        state = _MdState(list_items=["x", "y"], list_kind="ul")
        _flush_list(state)
        self.assertEqual(state.blocks, ["<ul><li>x</li><li>y</li></ul>"])

    def test_empty_items_does_nothing(self):
        state = _MdState()
        _flush_list(state)
        self.assertEqual(state.blocks, [])


class FlushCodeTests(unittest.TestCase):
    def test_flush_code_lines(self):
        state = _MdState(code_lines=["print(1)", "print(2)"])
        _flush_code(state)
        self.assertEqual(state.blocks, ["<pre><code>print(1)\nprint(2)</code></pre>"])

    def test_flush_escapes_html(self):
        state = _MdState(code_lines=["<script>"])
        _flush_code(state)
        self.assertIn("&lt;script&gt;", state.blocks[0])
        self.assertNotIn("<script>", state.blocks[0])


class FlushTableTests(unittest.TestCase):
    def test_flush_skips_empty(self):
        state = _MdState()
        _flush_table(state)
        self.assertEqual(state.blocks, [])

    def test_flush_table_lines(self):
        state = _MdState(table_lines=["| a | b |"])
        _flush_table(state)
        self.assertEqual(len(state.blocks), 1)
        self.assertIn("<table>", state.blocks[0])


class FlushAllTests(unittest.TestCase):
    def test_flushes_paragraph_and_list_and_table(self):
        state = _MdState(
            paragraph_lines=["p1"],
            list_items=["li1"],
            list_kind="ul",
            table_lines=["| c | d |"],
        )
        _flush_all(state)
        self.assertIn("<p>p1</p>", state.blocks)
        self.assertIn("<ul>", state.blocks[1])
        self.assertIn("<table>", state.blocks[2])


class HandleCodeFenceTests(unittest.TestCase):
    def test_ignores_non_fence(self):
        state = _MdState()
        self.assertFalse(_handle_code_fence(state, "not a fence"))

    def test_opens_code_block(self):
        state = _MdState()
        self.assertTrue(_handle_code_fence(state, "```"))
        self.assertTrue(state.in_code)

    def test_closes_code_block(self):
        state = _MdState(in_code=True, code_lines=["data"])
        self.assertTrue(_handle_code_fence(state, "```"))
        self.assertFalse(state.in_code)
        self.assertIn("<pre><code>data</code></pre>", state.blocks[0])

    def test_flushes_paragraph_before_fence(self):
        state = _MdState(paragraph_lines=["intro"])
        self.assertTrue(_handle_code_fence(state, "```"))
        self.assertIn("<p>intro</p>", state.blocks)

    def test_language_annotation(self):
        state = _MdState()
        self.assertTrue(_handle_code_fence(state, "```python"))
        self.assertTrue(state.in_code)


class HandleHorizontalRuleTests(unittest.TestCase):
    def test_dashes(self):
        state = _MdState()
        self.assertTrue(_handle_horizontal_rule(state, "---"))
        self.assertEqual(state.blocks, ["<hr>"])

    def test_asterisks(self):
        state = _MdState()
        self.assertTrue(_handle_horizontal_rule(state, "***"))
        self.assertEqual(state.blocks, ["<hr>"])

    def test_underscores(self):
        state = _MdState()
        self.assertTrue(_handle_horizontal_rule(state, "___"))
        self.assertEqual(state.blocks, ["<hr>"])

    def test_non_hr_returns_false(self):
        state = _MdState()
        self.assertFalse(_handle_horizontal_rule(state, "hello"))


class HandleTableRowTests(unittest.TestCase):
    def test_detects_table_row(self):
        state = _MdState()
        self.assertTrue(_handle_table_row(state, "| a | b |"))
        self.assertEqual(state.table_lines, ["| a | b |"])

    def test_non_row_flushes_existing_table(self):
        state = _MdState(table_lines=["| a | b |"])
        self.assertFalse(_handle_table_row(state, "not a row"))
        self.assertEqual(state.table_lines, [])
        self.assertIn("<table>", "".join(state.blocks))

    def test_flushes_paragraph_before(self):
        state = _MdState(paragraph_lines=["text"])
        self.assertTrue(_handle_table_row(state, "| a | b |"))
        self.assertIn("<p>text</p>", state.blocks)


class HandleHeadingTests(unittest.TestCase):
    def test_h1(self):
        state = _MdState()
        self.assertTrue(_handle_heading(state, "# Title"))
        self.assertEqual(state.blocks, ["<h2>Title</h2>"])

    def test_h2(self):
        state = _MdState()
        self.assertTrue(_handle_heading(state, "## Subtitle"))
        self.assertEqual(state.blocks, ["<h3>Subtitle</h3>"])

    def test_h6(self):
        state = _MdState()
        self.assertTrue(_handle_heading(state, "###### Deep"))
        self.assertEqual(state.blocks, ["<h6>Deep</h6>"])

    def test_overflow_heading_not_matched(self):
        state = _MdState()
        self.assertFalse(_handle_heading(state, "####### too many"))

    def test_not_a_heading(self):
        state = _MdState()
        self.assertFalse(_handle_heading(state, "not# heading"))

    def test_flushes_paragraph_before(self):
        state = _MdState(paragraph_lines=["intro"])
        self.assertTrue(_handle_heading(state, "# Title"))
        self.assertIn("<p>intro</p>", state.blocks)

    def test_inline_formatting_in_heading(self):
        state = _MdState()
        self.assertTrue(_handle_heading(state, "# `code` in heading"))
        self.assertIn("<code>code</code>", state.blocks[0])


class HandleOrderedListItemTests(unittest.TestCase):
    def test_ordered_item(self):
        state = _MdState()
        self.assertTrue(_handle_ordered_list_item(state, "1. first"))
        self.assertEqual(state.list_items, ["first"])
        self.assertEqual(state.list_kind, "ol")

    def test_ordered_item_with_large_number(self):
        state = _MdState()
        self.assertTrue(_handle_ordered_list_item(state, "100. item"))
        self.assertEqual(state.list_items, ["item"])

    def test_not_ordered_item(self):
        state = _MdState()
        self.assertFalse(_handle_ordered_list_item(state, "1.5 not item"))

    def test_flushes_paragraph_before(self):
        state = _MdState(paragraph_lines=["text"])
        self.assertTrue(_handle_ordered_list_item(state, "1. item"))
        self.assertIn("<p>text</p>", state.blocks)

    def test_flushes_different_list_type(self):
        state = _MdState(list_items=["bullet"], list_kind="ul")
        self.assertTrue(_handle_ordered_list_item(state, "1. item"))
        self.assertIn("<ul>", "".join(state.blocks))
        self.assertEqual(state.list_kind, "ol")
        self.assertEqual(state.list_items, ["item"])


class HandleUnorderedListItemTests(unittest.TestCase):
    def test_unordered_with_dash(self):
        state = _MdState()
        self.assertTrue(_handle_unordered_list_item(state, "- item"))
        self.assertEqual(state.list_items, ["item"])
        self.assertEqual(state.list_kind, "ul")

    def test_unordered_with_star(self):
        state = _MdState()
        self.assertTrue(_handle_unordered_list_item(state, "* item"))

    def test_not_unordered_item(self):
        state = _MdState()
        self.assertFalse(_handle_unordered_list_item(state, "--not"))

    def test_flushes_different_list_type(self):
        state = _MdState(list_items=["1."], list_kind="ol")
        self.assertTrue(_handle_unordered_list_item(state, "- item"))
        self.assertIn("<ol>", "".join(state.blocks))


class RenderMarkdownFragmentTests(unittest.TestCase):
    def test_empty_input(self):
        html = render_markdown_fragment("")
        self.assertIn('class="empty-report"', str(html))
        self.assertIn("No report content yet.", str(html))

    def test_blank_input(self):
        html = render_markdown_fragment("   \n\n  ")
        self.assertIn('class="empty-report"', str(html))

    def test_heading(self):
        html = str(render_markdown_fragment("# Hello"))
        self.assertIn("<h2>Hello</h2>", html)

    def test_multiple_headings(self):
        html = str(render_markdown_fragment("# A\n## B\n### C"))
        self.assertIn("<h2>A</h2>", html)
        self.assertIn("<h3>B</h3>", html)
        self.assertIn("<h4>C</h4>", html)

    def test_paragraph_single_line(self):
        html = str(render_markdown_fragment("just a paragraph"))
        self.assertIn("<p>just a paragraph</p>", html)

    def test_paragraph_multi_line(self):
        html = str(render_markdown_fragment("line1\nline2"))
        self.assertIn("<p>line1<br>line2</p>", html)

    def test_paragraphs_separated_by_blank_line(self):
        html = str(render_markdown_fragment("para one\n\npara two"))
        self.assertIn("<p>para one</p>", html)
        self.assertIn("<p>para two</p>", html)

    def test_ordered_list(self):
        html = str(render_markdown_fragment("1. first\n2. second"))
        self.assertIn("<ol>", html)
        self.assertIn("<li>first</li>", html)
        self.assertIn("<li>second</li>", html)

    def test_unordered_list_dash(self):
        html = str(render_markdown_fragment("- a\n- b"))
        self.assertIn("<ul>", html)
        self.assertIn("<li>a</li>", html)
        self.assertIn("<li>b</li>", html)

    def test_unordered_list_star(self):
        html = str(render_markdown_fragment("* a\n* b"))
        self.assertIn("<ul>", html)

    def test_code_fence_without_language(self):
        html = str(render_markdown_fragment("```\ncode block\n```"))
        self.assertIn("<pre><code>", html)
        self.assertIn("code block", html)

    def test_code_fence_with_language(self):
        html = str(render_markdown_fragment("```python\nprint(1)\n```"))
        self.assertIn("<pre><code>", html)
        self.assertIn("print(1)", html)

    def test_code_fence_escapes_html(self):
        html = str(render_markdown_fragment("```\n<script>\n```"))
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_table(self):
        md = "| H1 | H2 |\n|---|---|\n| A | B |"
        html = str(render_markdown_fragment(md))
        self.assertIn("<table>", html)
        self.assertIn("<th>H1</th>", html)
        self.assertIn("<th>H2</th>", html)
        self.assertIn("<td>A</td>", html)
        self.assertIn("<td>B</td>", html)

    def test_horizontal_rule(self):
        html = str(render_markdown_fragment("---"))
        self.assertIn("<hr>", html)

    def test_horizontal_rule_with_context(self):
        html = str(render_markdown_fragment("before\n\n---\n\nafter"))
        self.assertIn("<p>before</p>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<p>after</p>", html)

    def test_consecutive_same_type_blocks(self):
        html = str(render_markdown_fragment("# A\n\n# B\n\n# C"))
        self.assertEqual(html.count("<h2"), 3)

    def test_alternating_block_types(self):
        html = str(render_markdown_fragment("# Title\n\npara\n\n- item1\n- item2"))
        self.assertIn("<h2>Title</h2>", html)
        self.assertIn("<p>para</p>", html)
        self.assertIn("<ul>", html)

    def test_inline_formatting_in_paragraph(self):
        html = str(render_markdown_fragment("use `cmd` and **bold**"))
        self.assertIn("<code>cmd</code>", html)
        self.assertIn("<strong>bold</strong>", html)

    def test_list_switches_type(self):
        html = str(render_markdown_fragment("- a\n- b\n\n1. c\n2. d"))
        self.assertIn("<ul>", html)
        self.assertIn("<ol>", html)

    def test_nested_formatting_not_supported(self):
        html = str(render_markdown_fragment("**bold *and italic***"))
        self.assertIn("<em>", html)

    def test_code_block_with_blank_lines(self):
        html = str(render_markdown_fragment("```\na\n\nb\n```"))
        self.assertIn("<pre><code>", html)

    def test_mixed_content(self):
        md = "# Title\n\nIntro paragraph.\n\n- list one\n- list two\n\n```\ncode\n```\n\n| Col1 | Col2 |\n|------|------|\n| V1   | V2   |\n\n---\n\nFinal note."
        html = str(render_markdown_fragment(md))
        self.assertEqual(html.count("<h2"), 1)
        self.assertIn("<p>Intro paragraph.</p>", html)
        self.assertIn("<ul>", html)
        self.assertIn("<pre><code>", html)
        self.assertIn("<table>", html)
        self.assertIn("<hr>", html)
        self.assertIn("<p>Final note.</p>", html)

    def test_paragraph_before_list(self):
        html = str(render_markdown_fragment("some text\n- item1\n- item2"))
        self.assertIn("<p>some text</p>", html)
        self.assertIn("<ul>", html)

    def test_escaping_in_paragraphs(self):
        html = str(render_markdown_fragment("use <b>html</b>"))
        self.assertNotIn("<b>", html)
        self.assertIn("&lt;b&gt;", html)

    def test_trailing_newline(self):
        html = str(render_markdown_fragment("para\n"))
        self.assertIn("<p>para</p>", html)

    def test_markup_return_type(self):
        from markupsafe import Markup
        result = render_markdown_fragment("# Hello")
        self.assertIsInstance(result, Markup)


class EvidenceMapTests(unittest.TestCase):
    def test_evidence_map_builds_from_body(self):
        import json
        import tempfile
        from forensia.core.case import Case
        from forensia.db.database import CaseDB
        from forensia.report.evidence_map import build_evidence_map
        body = "See evtx-security-000000000001 for details."
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, raw_json) "
                    "VALUES (?, ?, ?, ?)",
                    ("evtx-security-000000000001", 4624, "2015-03-22T14:34:28",
                     json.dumps({"event_id": 4624, "target_user": "informant"})),
                )
                emap = build_evidence_map(db, body)
        self.assertIn("evtx-security-000000000001", emap)
        info = emap["evtx-security-000000000001"]
        self.assertEqual(info["source"], "evtx_events")
        self.assertIn("4624", info["summary"])

    def test_evidence_references_renders_markdown(self):
        from forensia.report.evidence_map import render_evidence_references
        emap = {
            "evtx-security-000000000001": {"source": "evtx_events", "timestamp": "2015-03-22T14:34:28", "summary": "4624 logon"},
        }
        md = render_evidence_references(emap)
        self.assertIn("## Evidence References", md)
        self.assertIn("evtx-security-000000000001", md)

    def test_evidence_map_summarizes_mft_and_prefetch_rows(self):
        """mft/prefetch references must show file/executable details, not '?'."""
        import tempfile
        from forensia.core.case import Case
        from forensia.db.database import CaseDB
        from forensia.report.evidence_map import build_evidence_map
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
        self.assertIn("CCLEANER64.EXE", emap["prefetch-ccleaner64.exe-779bd542"]["summary"])

    def test_evidence_map_marks_unknown_ids_unresolved(self):
        import tempfile
        from forensia.core.case import Case
        from forensia.db.database import CaseDB
        from forensia.report.evidence_map import build_evidence_map
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                emap = build_evidence_map(db, "Bogus evtx-security-000000000099 cited.")
        self.assertEqual("unresolved", emap["evtx-security-000000000099"]["source"])


class EvidenceTooltipInjectionTests(unittest.TestCase):
    """R7-03: inline citations get hover tooltips; references get anchor targets."""

    EMAP = {
        "evtx-security-000000000001": {
            "source": "evtx_events",
            "timestamp": "2015-03-22T14:34:28",
            "summary": "4624 Security informant@informant-PC",
        }
    }

    def test_inline_citation_gets_summary_tooltip(self):
        from forensia.report.html import _inject_evidence_tooltips
        html = str(render_markdown_fragment("Logon observed (evtx-security-000000000001)."))
        injected = _inject_evidence_tooltips(html, self.EMAP)
        self.assertIn('href="#ev-evtx-security-000000000001"', injected)
        self.assertIn("4624 Security informant@informant-PC", injected)
        self.assertNotIn('title="evtx-security-000000000001"', injected,
                         "placeholder title must be replaced by the record summary")

    def test_reference_entry_gets_anchor_target(self):
        from forensia.report.html import _inject_evidence_tooltips
        md = (
            "Logon observed (evtx-security-000000000001).\n\n"
            "## Evidence References\n\n"
            "- `evtx-security-000000000001` 2015-03-22T14:34:28 evtx_events — 4624 logon\n"
        )
        injected = _inject_evidence_tooltips(str(render_markdown_fragment(md)), self.EMAP)
        self.assertIn('id="ev-evtx-security-000000000001"', injected)
        # the anchor target sits after the references heading, not on the inline citation
        refs_idx = injected.index("Evidence References")
        anchor_idx = injected.index('id="ev-evtx-security-000000000001"')
        self.assertGreater(anchor_idx, refs_idx)

    def test_no_map_leaves_html_untouched(self):
        from forensia.report.html import _inject_evidence_tooltips
        html = str(render_markdown_fragment("Logon observed (evtx-security-000000000001)."))
        self.assertEqual(html, _inject_evidence_tooltips(html, {}))
