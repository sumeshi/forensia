"""Public cross-component contracts for report safety and presentation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forensia.ai.case_profile import build_case_profile, observed_event_ids
from forensia.ai.prompts.prompt_sections import (
    build_paragraph_narrate_messages,
    build_section_outline_messages,
)
from forensia.ai.prompts.sql_templates import validate_select_sql
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.db.database import CaseDB
from forensia.knowledge.catalog import catalog_exe_globs, matches_exe_globs
from forensia.report.answers.keypoints_report_meta import _report_sections_with_gaps
from forensia.report.evidence_refs import row_with_evidence_ids
from forensia.report.render.html import _load_report_sections
from forensia.report.render.markdown import build_host_note
from forensia.report.render.writer import (
    build_report_markdown_from_db,
    render_written_report,
)
from forensia.report.report_brief import _query_prior_sections
from forensia.report.report_validation import derive_publication_state
from forensia.report.sections.narrative_review import review_narrative_body
from forensia.report.sections.report_input import (
    ReportSpecError,
    decide_report_sources,
    ensure_report_output_paths,
)


class ReportSafetyContracts(unittest.TestCase):
    def test_narrative_review_reports_reader_hostile_output(self) -> None:
        body = (
            "Hypothesis H-010 remains open (STRUCTURED_OBSERVATIONS). "
            "IDs evtx-security-000000000001, evtx-security-000000000002, "
            "evtx-security-000000000003, evtx-security-000000000004 were cited."
        )
        problems = review_narrative_body(body)
        self.assertTrue(any("cites 4" in problem for problem in problems))
        self.assertTrue(
            any("STRUCTURED_OBSERVATIONS" in problem for problem in problems)
        )
        self.assertTrue(any("H-010" in problem for problem in problems))

    def test_report_prompts_ban_internal_identifiers(self) -> None:
        paragraph, _ = build_paragraph_narrate_messages(
            heading="Test", key_points=[], evidence_rows=[], template_body="test"
        )
        outline, _ = build_section_outline_messages(
            template_body="## Test", relevant_evidence=[]
        )
        for messages in (paragraph, outline):
            system = messages[0]["content"]
            self.assertIn("Do not use raw internal IDs", system)
            for marker in ("gap-*", "H-*", "KP-*"):
                self.assertIn(marker, system)

    def test_mixed_type_coalesce_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_select_sql("SELECT COALESCE('a', 1) FROM evtx_events")


class EvidencePresentationContracts(unittest.TestCase):
    def test_rows_without_evidence_are_explicitly_non_citable(self) -> None:
        without_id = row_with_evidence_ids({"computer": "host1"})
        with_id = row_with_evidence_ids({"evidence_id": "evtx-security-000000000001"})
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

    def test_render_written_report_keeps_report_spec_input_untouched(self) -> None:
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
                markdown_path, _ = render_written_report(case, db)
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
                    "INSERT INTO investigation_steps (step_id, phase, output_json, created_at) "
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
                    "INSERT INTO investigation_steps (step_id, phase, output_json, created_at) "
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
                self.assertEqual(
                    ["01_timeline"],
                    [row["section_key"] for row in _query_prior_sections(db)],
                )
                self.assertEqual(
                    ["01_timeline"], derive_publication_state(db)["draft_sections"]
                )
                self.assertEqual([], _report_sections_with_gaps(db))
                self.assertEqual(
                    3, db.execute("SELECT count(*) FROM report_sections").fetchone()[0]
                )


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

    def test_antiforensic_catalog_drives_tool_matching(self) -> None:
        globs = catalog_exe_globs("antiforensic_tools")
        self.assertTrue(matches_exe_globs("CCLEANER64.EXE", globs))
        self.assertTrue(matches_exe_globs("Eraser.exe", globs))
        self.assertFalse(matches_exe_globs("notepad.exe", globs))

    def test_timeline_regeneration_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO case_timeline (
                        entry_id, timestamp, source, ref_id, host, summary, evidence_id
                    ) VALUES (
                        'tl-1', '2025-01-01 10:00:00', 'finding', 'F-1',
                        'PC-01', 'test entry', 'evtx-1'
                    )
                    """
                )
                self.assertTrue(memory.regenerate_timeline_from_db(db))
                self.assertFalse(memory.regenerate_timeline_from_db(db))
