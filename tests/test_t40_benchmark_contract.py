"""T-40 benchmark contract: answer-first ranking, timeline trace, rename direction,
partial composite answers, and report claim traceability.

These tests exercise the generic requirement/answer contract (declarative knowledge
in question_routing.yaml) rather than special-case branches for question numbers.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.knowledge.questions import (
    question_spec_for_answer_spec,
    resolve_question_spec,
    sub_requirement_coverage,
)
from forensia.report.answers.answer_registry import build_structured_answer
from forensia.report.report_validation import check_claim_traceability


def _init_case() -> Case:
    return Case.init(tempfile.mkdtemp(), source_timezone="America/New_York")


class BenchmarkTimelineTest(unittest.TestCase):
    """Q13 must return an actual 09:00-18:00 trace, not only daily totals."""

    def test_q13_routes_to_timeline_trace_when_window_requested(self) -> None:
        spec, _confidence = resolve_question_spec(
            block_heading="Startup, shutdown, logon, and logoff history between 09:00 and 18:00"
        )
        self.assertIsNotNone(spec)
        self.assertEqual("daily_session_timeline", spec.answer_spec)

    def test_q13_timeline_excludes_out_of_window_events(self) -> None:
        case = _init_case()
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "evtx-early",
                    4624,
                    datetime(2015, 3, 22, 8, 0, 0),
                    "HOST1",
                    "alice",
                    "2",
                ),
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "evtx-in",
                    4624,
                    datetime(2015, 3, 22, 10, 0, 0),
                    "HOST1",
                    "alice",
                    "2",
                ),
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer) VALUES (?, ?, ?, ?)",
                ("evtx-down", 1074, datetime(2015, 3, 22, 17, 30, 0), "HOST1"),
            )
            answer = build_structured_answer(
                case,
                db,
                answer_spec="daily_session_timeline",
                answer_id="Q13",
                section_key="6_appendix",
                block_heading="13. Startup, shutdown, logon, and logoff history between 09:00 and 18:00",
            )
        self.assertEqual("answered", answer["status"])
        row = answer["answer"][0]
        self.assertEqual("2015-03-22 10:00:00", row["first_logon"])
        self.assertEqual("2015-03-22 17:30:00", row["last_shutdown"])
        self.assertTrue(row["first_logon"].startswith("2015-03-22"))


class BenchmarkRenameDirectionTest(unittest.TestCase):
    """Q24 rename results are authoritative from -> to mappings."""

    def test_q24_reports_from_to_mapping(self) -> None:
        case = _init_case()
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                (
                    "mft-rn-1",
                    "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/old name.lnk",
                    "old name.lnk",
                    datetime(2015, 3, 23, 20, 26, 54),
                    datetime(2015, 3, 23, 20, 26, 54),
                ),
            )
            db.execute(
                "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                (
                    "mft-rn-2",
                    "Users/informant/AppData/Roaming/Microsoft/Windows/Recent/new name v2.lnk",
                    "new name v2.lnk",
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
                block_heading="24. Desktop file renames",
            )
        self.assertEqual("candidate_only", answer["status"])
        row = answer["answer"][0]
        self.assertEqual("old name", row["original_name"])
        self.assertEqual("new name v2", row["new_name"])
        self.assertNotEqual(row["original_name"], row["new_name"])


class BenchmarkPartialCompositeTest(unittest.TestCase):
    """Q45 is a composite; a partial sub-requirement set must not claim answered."""

    def test_q45_partial_composite_not_answered(self) -> None:
        case = _init_case()
        with CaseDB(case) as db:
            db.execute(
                "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) VALUES (?, ?, ?, ?)",
                (
                    "prefetch-ccleaner",
                    "CCleaner64.exe",
                    3,
                    datetime(2015, 3, 25, 15, 15, 0),
                ),
            )
            answer = build_structured_answer(
                case,
                db,
                answer_spec="antiforensic_activity",
                answer_id="Q45",
                section_key="6_appendix",
                block_heading="45. Antiforensic activity",
            )
        self.assertEqual("partial", answer["status"])
        spec = question_spec_for_answer_spec("antiforensic_activity")
        coverage = sub_requirement_coverage(spec, answer["answer"])
        satisfied = [c for c in coverage if c["satisfied"]]
        self.assertLess(len(satisfied), len(coverage))
        self.assertTrue(any(c["key"] == "tool_use_install" for c in satisfied))

    def test_path_subrequirements_use_contains_matching(self) -> None:
        spec = question_spec_for_answer_spec("antiforensic_activity")
        rows = [
            {
                "evidence_type": "tool_or_cleanup_artifact",
                "file_name": "deleted-mail.ost",
                "file_path": r"C:\$Recycle.Bin\S-1-5-21\deleted-mail.ost",
                "evidence_id": "mft-recycle-1",
            }
        ]
        coverage = sub_requirement_coverage(spec, rows)
        recycle = next(item for item in coverage if item["key"] == "recycle_bin")
        self.assertTrue(recycle["satisfied"])


class BenchmarkTraceabilityTest(unittest.TestCase):
    """Report claims must expose machine-detectable refs; speculation is rejected."""

    def test_each_evidence_claim_requires_its_own_ref(self) -> None:
        findings = check_claim_traceability(
            "4624 logon events were observed (evtx-security-000000000001).\n\n"
            "4672 special privilege events were observed."
        )
        self.assertTrue(
            any("lacks a machine-detectable" in f.message for f in findings)
        )

if __name__ == "__main__":
    unittest.main()
