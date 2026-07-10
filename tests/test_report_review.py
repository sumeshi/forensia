"""Public cross-component contracts for report safety and presentation."""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.case_profile import get_profile_event_ids, set_case_profile
from forensia.ai.prompts.prompt_sections import (
    build_paragraph_narrate_messages,
    build_section_outline_messages,
)
from forensia.ai.prompts.sql_templates import validate_select_sql
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.db.database import CaseDB
from forensia.knowledge import catalog_exe_globs, matches_exe_globs
from forensia.report.evidence_refs import row_with_evidence_ids
from forensia.report.markdown import build_host_note
from forensia.report.narrative_review import review_narrative_body


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


class SharedPolicyContracts(unittest.TestCase):
    def tearDown(self) -> None:
        set_case_profile(None, None)

    def test_profile_event_ids_are_returned_as_a_copy(self) -> None:
        set_case_profile("profile", {4624, 4648})
        first = get_profile_event_ids()
        assert first is not None
        first.add(99999)
        self.assertEqual({4624, 4648}, get_profile_event_ids())

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
