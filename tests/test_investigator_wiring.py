"""No-LLM smoke test for the investigate() entry point wiring.

Runs one full report_only cycle against an empty case. This exercises session
init (rule seeding, case profile, memory), the cycle body, termination, and
session bookkeeping WITHOUT any LLM call (report refresh is skipped by setting
report_every_n_cycles > max_iter). A missing/renamed argument anywhere in the
investigate() -> _run_cycle_body -> _run_report_phase chain fails this test.
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest

from forensia.core.case import Case
from forensia.db.database import CaseDB


class InvestigateWiringTests(unittest.TestCase):
    def test_report_only_cycle_completes_without_llm(self) -> None:
        from forensia.ai.investigator import investigate

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                result = asyncio.run(
                    investigate(
                        case=case,
                        db=db,
                        base_url="http://127.0.0.1:9",  # never contacted on this path
                        model="dummy-model",
                        max_iter=1,
                        report_only=True,
                        report_every_n_cycles=2,  # 1 % 2 != 0 -> report refresh skipped
                    )
                )
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["iteration"], 1)
                row = db.execute(
                    "SELECT status FROM investigation_sessions WHERE session_id = ?",
                    (result["session_id"],),
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "completed")


if __name__ == "__main__":
    unittest.main()
