"""Tests for log-integrity keypoint selection (RPT-08).

Why this matters: the report's "Log Integrity" section is seeded from
`timeline_log_clearing` / `gaps_log_integrity_events`. If these keypoints do
not surface Security 1100 (event logging service shutdown) and 1102 (audit
log cleared), the section has nothing meaningful to narrate and falls back to
unrelated benign maintenance events (e.g. a single 104 from
Microsoft-Windows-Diagnosis-Scripted/Operational, which is a routine
diagnostics log rotation, not a log-integrity signal). This test pins the
general rule: Security-channel 1100/1102 are log-integrity signals; a 104
from a non-Eventlog provider (such as Diagnosis-Scripted) is not.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.keypoint_catalog import REPORT_KEYPOINTS


def _insert_event(
    db: CaseDB,
    *,
    evidence_id: str,
    channel: str,
    event_id: int,
    timestamp: datetime,
    provider: str | None = None,
) -> None:
    raw_json = "{}"
    if provider is not None:
        raw_json = f'{{"winlog": {{"provider": {{"name": "{provider}"}}}}}}'
    db.execute(
        """
        INSERT INTO evtx_events (evidence_id, channel, event_id, timestamp, computer, raw_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (evidence_id, channel, event_id, timestamp, "test-PC", raw_json),
    )


class TestLogIntegrityKeypointSelection(unittest.TestCase):
    def test_security_1100_is_selected_over_diagnosis_scripted_104(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Real log-integrity signal: Security channel, event logging
                # service shutdown (1100).
                _insert_event(
                    db,
                    evidence_id="evtx-security-1",
                    channel="Security",
                    event_id=1100,
                    timestamp=datetime(2015, 3, 25, 10, 18, 29),
                )
                # Benign maintenance event: 104 from a non-Eventlog provider
                # (Microsoft-Windows-Diagnosis-Scripted/Operational). This
                # must NOT be treated as a log-integrity signal.
                _insert_event(
                    db,
                    evidence_id="evtx-diagnosis-scripted-1",
                    channel="Microsoft-Windows-Diagnosis-Scripted/Operational",
                    event_id=104,
                    timestamp=datetime(2015, 3, 24, 15, 21, 37),
                    provider="Microsoft-Windows-Diagnosis-Scripted",
                )

                _, timeline_resolver = REPORT_KEYPOINTS["timeline_log_clearing"]
                timeline_rows = timeline_resolver(db)
                _, gaps_resolver = REPORT_KEYPOINTS["gaps_log_integrity_events"]
                gaps_rows = gaps_resolver(db)

        timeline_evidence_ids = {row["evidence_id"] for row in timeline_rows}
        self.assertIn("evtx-security-1", timeline_evidence_ids)
        self.assertNotIn("evtx-diagnosis-scripted-1", timeline_evidence_ids)

        gaps_event_ids = {row["event_id"] for row in gaps_rows}
        self.assertIn(1100, gaps_event_ids)
        self.assertNotIn(104, gaps_event_ids)

    def test_104_from_eventlog_provider_is_still_treated_as_log_clear(self) -> None:
        # A 104 event whose provider is Microsoft-Windows-Eventlog is the
        # classic "log cleared" signal and must remain included.
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_event(
                    db,
                    evidence_id="evtx-eventlog-104",
                    channel="System",
                    event_id=104,
                    timestamp=datetime(2015, 3, 25, 10, 0, 0),
                    provider="Microsoft-Windows-Eventlog",
                )

                _, timeline_resolver = REPORT_KEYPOINTS["timeline_log_clearing"]
                timeline_rows = timeline_resolver(db)

        timeline_evidence_ids = {row["evidence_id"] for row in timeline_rows}
        self.assertIn("evtx-eventlog-104", timeline_evidence_ids)


if __name__ == "__main__":
    unittest.main()
