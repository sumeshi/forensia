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
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type, channel, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "evtx-early",
                    4624,
                    datetime(2015, 3, 22, 8, 0, 0),
                    "HOST1",
                    "alice",
                    "2",
                    "Security",
                    '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                ),
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type, channel, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "evtx-in",
                    4624,
                    datetime(2015, 3, 22, 10, 0, 0),
                    "HOST1",
                    "alice",
                    "2",
                    "Security",
                    '{"winlog":{"provider":{"name":"Microsoft-Windows-Security-Auditing"}}}',
                ),
            )
            db.execute(
                "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel, raw_json) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "evtx-down",
                    1074,
                    datetime(2015, 3, 22, 17, 30, 0),
                    "HOST1",
                    "System",
                    '{"winlog":{"provider":{"name":"User32"}}}',
                ),
            )
            answer = build_structured_answer(
                case,
                db,
                answer_spec="daily_session_timeline",
                answer_id="Q13",
                section_key="6_appendix",
                block_heading="13. Startup, shutdown, logon, and logoff history between 09:00 and 18:00 UTC",
            )
        self.assertEqual("answered", answer["status"])
        row = answer["answer"][0]
        self.assertEqual("2015-03-22 10:00:00", row["first_logon"])
        self.assertEqual("2015-03-22 17:30:00", row["last_shutdown"])
        self.assertTrue(row["first_logon"].startswith("2015-03-22"))


class UnsupportedEvidenceClaimsTest(unittest.TestCase):
    def test_recent_lnk_pairs_are_not_reported_as_renames(self) -> None:
        case = _init_case()
        with CaseDB(case) as db:
            for evidence_id, name, when in [
                ("lnk-1", "notes.lnk", datetime(2025, 1, 1)),
                ("lnk-2", "tax-return.lnk", datetime(2025, 1, 1, 0, 1)),
            ]:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, file_path, file_name, si_created, fn_created) VALUES (?, ?, ?, ?, ?)",
                    (
                        evidence_id,
                        f"Users/Alice/Windows/Recent/{name}",
                        name,
                        when,
                        when,
                    ),
                )
            db.execute(
                "INSERT INTO mft_entries (evidence_id, file_path, file_name, raw_json) VALUES (?, ?, ?, ?)",
                (
                    "mft-fn-name",
                    "Users/Alice/Desktop/quarterly_budget.xlsx",
                    "quarterly_budget.xlsx",
                    '{"fn_filename":"old_quarterly_budget.xlsx"}',
                ),
            )
            answer = build_structured_answer(
                case,
                db,
                answer_spec="desktop_rename_candidates",
                answer_id="Q24",
                section_key="6_appendix",
                block_heading="File rename history",
            )
        self.assertEqual("unobservable", answer["status"])
        self.assertEqual([], answer["answer"])

    def test_antiforensic_inventory_does_not_require_unrelated_evidence(self) -> None:
        spec = question_spec_for_answer_spec("antiforensic_activity")
        self.assertEqual((), spec.sub_requirements)


class BenchmarkTraceabilityTest(unittest.TestCase):
    """Report claims must expose machine-detectable refs; speculation is rejected."""

    def test_each_evidence_claim_requires_its_own_ref(self) -> None:
        findings = check_claim_traceability(
            "4624 logon events were observed (evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001).\n\n"
            "4672 special privilege events were observed."
        )
        self.assertTrue(
            any("lacks a machine-detectable" in f.message for f in findings)
        )


if __name__ == "__main__":
    unittest.main()
