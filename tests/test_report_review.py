"""Public cross-component contracts for report safety and presentation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.context.case_profile import build_case_profile, observed_event_ids
from forensia.context.sql_templates import validate_select_sql
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import _load_yaml, catalog_exe_globs, matches_exe_globs
from forensia.report.answers.keypoints_report_meta import _report_sections_with_gaps
from forensia.report.evidence_refs import row_with_evidence_ids
from forensia.report.render.html import _load_report_sections
from forensia.report.render.markdown import build_host_note
from forensia.report.render.writer import (
    build_report_markdown_from_db,
)
from forensia.report.report_brief import build_report_brief
from forensia.report.report_validation import derive_publication_state
from forensia.report.sections.prompts import build_paragraph_narrate_messages
from forensia.report.sections.report_input import (
    ReportSpecError,
    decide_report_sources,
    ensure_report_output_paths,
)


class ReportSafetyContracts(unittest.TestCase):
    def test_fatal_audit_status_is_visible_in_markdown_and_html(self) -> None:
        from forensia.config import Settings, settings_scope
        from forensia.db.investigation_state import (
            ensure_investigation_state,
            save_stop_reason,
        )
        from forensia.report.render.writer import render_written_report

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            stale_brief = case.reports_dir / "report_brief.json"
            stale_brief.write_text('{"report_complete": false}', encoding="utf-8")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO trace.investigation_steps "
                    "(step_id, phase, output_json, created_at) VALUES "
                    "('input-1', 'report-input', ?, now())",
                    [json.dumps({"sections": [{"section_key": "1_overview"}]})],
                )
                db.execute(
                    "INSERT INTO report_sections "
                    "(section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', ?, 0.8, 'ai_exhausted', 1, FALSE)",
                    [
                        "# Overview\n\nEVTX evidence shows suspicious activity without a traceable citation."
                    ],
                )
                db.execute(
                    "INSERT INTO section_runs "
                    "(run_id, section_key, block_heading, iteration, phase, payload, created_at) "
                    "VALUES ('projection-1', '1_overview', '', 1, 'projection', ?, now())",
                    [json.dumps({"input_signature": "current-signature"})],
                )
                ensure_investigation_state(db)
                save_stop_reason(
                    db,
                    status="stopped",
                    stop_reason_code="budget_exhausted",
                    stop_reason="LLM budget exhausted before investigation completion",
                )

                with settings_scope(Settings(llm_output_language="en")):
                    markdown_path, html_path = render_written_report(case, db)
                    validation = json.loads(
                        (case.reports_dir / "report_validation.json").read_text()
                    )
            self.assertFalse(stale_brief.exists())

            markdown = markdown_path.read_text(encoding="utf-8")
            html = html_path.read_text(encoding="utf-8")

        self.assertTrue(validation["report_complete"])
        self.assertFalse(validation["publishable"])
        self.assertEqual("nonpublishable", validation["audit_status"])
        self.assertIn("claim_traceability", markdown)
        self.assertIn("claim_traceability", html)
        self.assertIn("Investigation status", markdown)
        self.assertIn("Report output completeness", markdown)
        self.assertIn("Report output completeness", html)
        self.assertEqual(
            "stopped", validation["publication_state"]["investigation_status"]
        )
        self.assertEqual(
            "budget_exhausted",
            validation["publication_state"]["stop_reason_code"],
        )
        self.assertNotIn(
            "budget_exhausted",
            validation["publication_state"]["investigation_reasons"],
        )
        self.assertIn("budget_exhausted", markdown)
        self.assertIn("budget_exhausted", html)
        self.assertIn(
            "LLM budget exhausted before investigation completion",
            markdown,
        )
        self.assertIn(
            "LLM budget exhausted before investigation completion",
            html,
        )

    def test_refused_human_reviewed_refresh_preserves_evidence_links(self) -> None:
        from forensia.report.sections.section_refresher import _persist_projection
        from forensia.report.sections.section_run_store import replace_section_evidence

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, "
                    "status, update_count, stale) VALUES (?, ?, ?, 1.0, 'human_reviewed', 1, FALSE)",
                    ["01_summary", "Summary", "# Summary\n\nHuman-authored text."],
                )
                replace_section_evidence(
                    db,
                    "01_summary",
                    [
                        {
                            "kind": "rows",
                            "source_ref": "table:old",
                            "evidence_ids": ["old-evidence"],
                        }
                    ],
                )

                with self.assertRaisesRegex(
                    RuntimeError, "human-reviewed section was not replaced"
                ):
                    _persist_projection(
                        db,
                        "01_summary",
                        "Summary",
                        "# Summary\n\nNew projection.",
                        [
                            {
                                "kind": "rows",
                                "source_ref": "table:new",
                                "evidence_ids": ["new-evidence"],
                            }
                        ],
                        session_id="session-1",
                    )

                body, status = db.execute(
                    "SELECT body, status FROM report_sections WHERE section_key = ?",
                    ["01_summary"],
                ).fetchone()
                evidence_ids = db.execute(
                    "SELECT evidence_id FROM section_evidence WHERE section_key = ?",
                    ["01_summary"],
                ).fetchall()

        self.assertEqual("# Summary\n\nHuman-authored text.", body)
        self.assertEqual("human_reviewed", status)
        self.assertEqual([("old-evidence",)], evidence_ids)

    def test_incomplete_report_metadata_follows_output_language(self) -> None:
        from forensia.config import Settings, settings_scope
        from forensia.report.render.writer import render_written_report

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for language in ("ja", "en"):
                    with (
                        self.subTest(language=language),
                        settings_scope(Settings(llm_output_language=language)),
                    ):
                        render_written_report(case, db)
                        validation = json.loads(
                            (case.reports_dir / "report_validation.json").read_text()
                        )
                        self.assertFalse(validation["publishable"])
                        self.assertEqual(
                            "needs_review", validation["publication_status"]
                        )
                        self.assertNotIn(
                            "language_consistency",
                            [
                                issue["check_name"]
                                for issue in validation["fatal_errors"]
                            ],
                        )

    def test_report_prompts_ban_internal_identifiers(self) -> None:
        paragraph, _ = build_paragraph_narrate_messages(
            heading="Test",
            key_points=[],
            evidence_rows=[],
            template_body="## Test",
        )
        system = paragraph[0]["content"]
        self.assertIn("Do not use raw internal IDs", system)
        for marker in ("gap-*", "H-*", "KP-*"):
            self.assertIn(marker, system)
        self.assertIn(
            "<TEMPLATE_CONTEXT>\n## Test\n</TEMPLATE_CONTEXT>",
            paragraph[1]["content"],
        )

    def test_mixed_type_coalesce_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_select_sql("SELECT COALESCE('a', 1) FROM evtx_events")


class EvidencePresentationContracts(unittest.TestCase):
    def test_rows_without_evidence_are_explicitly_non_citable(self) -> None:
        without_id = row_with_evidence_ids({"computer": "host1"})
        with_id = row_with_evidence_ids(
            {
                "evidence_id": "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001"
            }
        )
        self.assertIs(False, without_id["citable"])
        self.assertNotIn("citable", with_id)

    def test_host_note_summarizes_single_and_multiple_epochs(self) -> None:
        active = {
            "label": "active",
            "display_name": "HOST",
            "first_seen": "2015-03-22 10:00:00",
            "last_seen": "2015-03-25 10:00:00",
            "event_count": 4000,
        }
        predeployment = {
            **active,
            "label": "pre-deployment",
            "first_seen": "2010-11-21 03:00:00",
            "last_seen": "2010-11-21 05:00:00",
        }
        self.assertEqual("active", build_host_note([active]))
        note = build_host_note([predeployment, active])
        self.assertIn("pre-deployment bulk (2010", note)
        self.assertIn("2015-03-25", note)


class ReportInputGuardContracts(unittest.TestCase):
    """V2-06: the case REPORT.md is a read-only report input; writes fail before
    they happen when an output target resolves to the input (case-insensitive)."""

    def test_report_output_cannot_overwrite_report_spec_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            spec_path = case.path / "REPORT.md"
            spec_path.write_text("# Report Spec\n", encoding="utf-8")
            with self.assertRaises(ReportSpecError):
                ensure_report_output_paths(case, (spec_path,))
            # Case-insensitive compare: an output at 'report.md' next to the input.
            with self.assertRaises(ReportSpecError):
                ensure_report_output_paths(case, (case.path / "report.md",))
            # Explicit output flag targeting the input also fails.
            with self.assertRaises(ReportSpecError):
                ensure_report_output_paths(
                    case, (spec_path,), report_spec=str(spec_path)
                )
            # Normal output targets under the generated reports directory pass.
            ensure_report_output_paths(
                case,
                (
                    case.reports_dir / "report.md",
                    case.reports_dir / "report.html",
                ),
                report_spec=str(spec_path),
            )
            with self.assertRaisesRegex(ReportSpecError, "same path"):
                ensure_report_output_paths(
                    case,
                    (case.reports_dir / "report.md", case.reports_dir / "REPORT.md"),
                )

    def test_render_written_report_keeps_report_spec_input_untouched(self) -> None:
        from forensia.pipeline import run_report
        from forensia.report.render.html import render_html_report

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            spec_path = case.path / "REPORT.md"
            spec_path.write_text("# Report Spec\n", encoding="utf-8")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, "
                    "status, update_count, stale) VALUES "
                    "('01_overview', 'Overview', '# Overview\\n\\nRendered body text.', "
                    "0.8, 'ai_exhausted', 1, FALSE)"
                )
            custom_output = case.path / "custom.html"
            with patch(
                "forensia.report.render.writer.render_html_report",
                wraps=render_html_report,
            ) as render_html:
                markdown_path, html_path = run_report(case.path, output=custom_output)
            render_html.assert_called_once()
            self.assertEqual(custom_output, html_path)
            self.assertTrue(html_path.exists())
            self.assertFalse((case.reports_dir / "report.html").exists())
            self.assertTrue(markdown_path.exists())
            written = markdown_path.read_text(encoding="utf-8")
            self.assertIn("Rendered body text.", written)
            # The input file is a different path with its original bytes intact.
            self.assertEqual("# Report Spec\n", spec_path.read_text(encoding="utf-8"))
            self.assertNotEqual(spec_path, markdown_path)

    def test_report_revision_pin_and_explicit_reorder_hide_old_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            spec = case.path / "REPORT.md"
            spec.write_text("# Overview\n\n# Timeline\n", encoding="utf-8")
            with CaseDB(case) as db:
                first = decide_report_sources(case, db, case.report_template_dir)
                self.assertEqual(
                    ["01_overview", "02_timeline"],
                    [section.section_key for section in first.sections],
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps (step_id, phase, output_json, created_at) "
                    "VALUES ('a', 'report-input', ?, TIMESTAMP '2026-01-01')",
                    (json.dumps(first.record),),
                )
                for key, title in (
                    ("01_overview", "Old overview"),
                    ("02_timeline", "Old timeline"),
                ):
                    db.execute(
                        "INSERT INTO report_sections (section_key, title, body, confidence) VALUES (?, ?, ?, 0.1)",
                        (key, title, f"# {title}\n\nStored text."),
                    )
                spec.write_text("# Timeline\n", encoding="utf-8")
                pinned = decide_report_sources(case, db, case.report_template_dir)
                self.assertIsNotNone(pinned.notice)
                self.assertEqual(
                    ["01_overview", "02_timeline"],
                    [s.section_key for s in pinned.sections],
                )
                reloaded = decide_report_sources(
                    case, db, case.report_template_dir, spec
                )
                self.assertEqual(
                    ["01_timeline"], [s.section_key for s in reloaded.sections]
                )
                db.execute(
                    "INSERT INTO trace.investigation_steps (step_id, phase, output_json, created_at) "
                    "VALUES ('b', 'report-input', ?, TIMESTAMP '2026-01-02')",
                    (json.dumps(reloaded.record),),
                )
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence) "
                    "VALUES ('01_timeline', 'New timeline', '# New timeline\\n\\nCurrent text.', 0.9)"
                )
                report = build_report_markdown_from_db(db, case)
                self.assertIn("New timeline", report)
                self.assertNotIn("Old overview", report)
                self.assertNotIn("Old timeline", report)
                self.assertEqual(
                    ["01_timeline"],
                    [row["section_key"] for row in _load_report_sections(db)[0]],
                )
                brief = build_report_brief(db, case)
                self.assertNotIn("prior_sections", brief)
                self.assertNotIn("existing_claims", brief)
                self.assertEqual(
                    ["01_timeline"], derive_publication_state(db)["draft_sections"]
                )
                self.assertEqual([], _report_sections_with_gaps(db))
                self.assertEqual(
                    3, db.execute("SELECT count(*) FROM report_sections").fetchone()[0]
                )

    def test_recorded_default_templates_follow_language_without_repinning(self) -> None:
        from forensia.config import Settings, settings_scope

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                with settings_scope(Settings(llm_output_language="ja")):
                    first = decide_report_sources(case, db, None)
                db.execute(
                    "INSERT INTO trace.investigation_steps (step_id, phase, output_json, created_at) "
                    "VALUES ('a', 'report-input', ?, TIMESTAMP '2026-01-01')",
                    (json.dumps(first.record),),
                )

                with settings_scope(Settings(llm_output_language="en")):
                    resumed = decide_report_sources(case, db, None)

            self.assertEqual(
                [section.section_key for section in first.sections],
                [section.section_key for section in resumed.sections],
            )
            self.assertIn("# Summary and Scope", resumed.sections[0].body)
            self.assertNotIn("# 調査概要と対象", resumed.sections[0].body)
            self.assertIsNone(resumed.notice)
            self.assertEqual("Summary and Scope", resumed.sections[0].meta.title)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            spec = case.path / "REPORT.md"
            authored = "# Custom Findings\n\n## Evidence\n\nKeep this wording.\n"
            spec.write_text(authored, encoding="utf-8")
            with CaseDB(case) as db:
                with settings_scope(Settings(llm_output_language="ja")):
                    first = decide_report_sources(case, db, None)
                db.execute(
                    "INSERT INTO trace.investigation_steps (step_id, phase, output_json, created_at) "
                    "VALUES ('a', 'report-input', ?, TIMESTAMP '2026-01-01')",
                    (json.dumps(first.record),),
                )
                with settings_scope(Settings(llm_output_language="en")):
                    resumed = decide_report_sources(case, db, None)

            self.assertEqual(
                ["01_custom_findings"], [s.section_key for s in resumed.sections]
            )
            self.assertEqual(authored.strip(), resumed.sections[0].body)
            self.assertIsNone(resumed.notice)


class SharedPolicyContracts(unittest.TestCase):
    def test_case_profile_reads_current_case_after_ingest_and_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            first_case = Case.init(Path(tmpdir) / "first")
            second_case = Case.init(Path(tmpdir) / "second")
            with CaseDB(first_case) as first, CaseDB(second_case) as second:
                self.assertEqual(set(), observed_event_ids(first))
                first.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id) VALUES ('E1', 4624)"
                )
                self.assertEqual({4624}, observed_event_ids(first))
                self.assertEqual([], build_case_profile(second)["event_ids"])
                first.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id) VALUES ('E2', 4625)"
                )
                self.assertEqual(
                    {4624, 4625},
                    {row["event_id"] for row in build_case_profile(first)["event_ids"]},
                )
            with CaseDB(first_case) as reopened:
                self.assertEqual({4624, 4625}, observed_event_ids(reopened))
                reopened.execute("DROP TABLE evtx_events")
                with self.assertRaises(Exception):
                    build_case_profile(reopened)

    def test_required_declaration_failure_is_not_an_empty_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("forensia.knowledge.catalog._SCHEMA_DIR", Path(tmpdir)):
                for contents in (None, "[invalid", "[]", "{}"):
                    path = Path(tmpdir) / "event_ids.yaml"
                    if contents is not None:
                        path.write_text(contents, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "event_ids.yaml"):
                        _load_yaml("event_ids.yaml")

    def test_antiforensic_catalog_drives_tool_matching(self) -> None:
        globs = catalog_exe_globs("antiforensic_tools")
        self.assertTrue(matches_exe_globs("CCLEANER64.EXE", globs))
        self.assertTrue(matches_exe_globs("Eraser.exe", globs))
        self.assertFalse(matches_exe_globs("notepad.exe", globs))
