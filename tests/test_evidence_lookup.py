"""Tests for db/evidence_lookup.py — shared evidence-record lookup."""

from __future__ import annotations

import json
import tempfile
import unittest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import (
    fetch_evidence_records,
    lookup_evidence_record,
)


class EvidenceLookupTest(unittest.TestCase):
    """Verify fetch_evidence_records returns correct records for each table type."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        case = Case.init(self._tmpdir.name)
        self.db = CaseDB(case)
        self._populate()

    def tearDown(self):
        self.db.close()
        self._tmpdir.cleanup()

    def _populate(self):
        self.db.execute(
            "INSERT INTO evtx_events (evidence_id, event_id, timestamp, channel, computer, raw_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "evtx-security-000000000001",
                4624,
                "2015-03-22T14:34:28",
                "Security",
                "DESKTOP-01",
                json.dumps({"event_id": 4624, "target_user": "informant"}),
            ),
        )
        self.db.execute(
            "INSERT INTO mft_entries (evidence_id, file_name, file_path, si_modified) VALUES (?, ?, ?, ?)",
            (
                "mft-000000078080-01",
                "Task List.ersy",
                "Users/informant/AppData/Local/Eraser 6/Task List.ersy",
                "2015-03-25 15:29:37",
            ),
        )
        self.db.execute(
            "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) "
            "VALUES (?, ?, ?, ?)",
            (
                "prefetch-ccleaner64.exe-779bd542",
                "CCLEANER64.EXE",
                2,
                "2015-03-25 15:15:50",
            ),
        )
        self.db.execute(
            "INSERT INTO prefetch_timeline (evidence_id, executable_name, exec_time) VALUES (?, ?, ?)",
            ("prefetch-eraser.exe-abc123", "ERASER.EXE", "2015-03-25 14:00:00"),
        )

    # ---- full records per table kind ----

    def test_fetch_evtx_record(self):
        result = fetch_evidence_records(self.db, ["evtx-security-000000000001"])
        self.assertIn("evtx-security-000000000001", result)
        row = result["evtx-security-000000000001"]
        self.assertEqual(row.get("event_id"), 4624)
        self.assertEqual(row.get("channel"), "Security")
        self.assertEqual(row.get("_source"), "evtx_events")

    def test_fetch_mft_record(self):
        result = fetch_evidence_records(self.db, ["mft-000000078080-01"])
        self.assertIn("mft-000000078080-01", result)
        row = result["mft-000000078080-01"]
        self.assertEqual(row.get("file_name"), "Task List.ersy")
        self.assertEqual(row.get("_source"), "mft_entries")

    def test_fetch_prefetch_executions_record(self):
        result = fetch_evidence_records(self.db, ["prefetch-ccleaner64.exe-779bd542"])
        self.assertIn("prefetch-ccleaner64.exe-779bd542", result)
        row = result["prefetch-ccleaner64.exe-779bd542"]
        self.assertEqual(row.get("executable_name"), "CCLEANER64.EXE")
        self.assertEqual(row.get("_source"), "prefetch_executions")

    def test_fetch_prefetch_timeline_record(self):
        result = fetch_evidence_records(self.db, ["prefetch-eraser.exe-abc123"])
        self.assertIn("prefetch-eraser.exe-abc123", result)
        row = result["prefetch-eraser.exe-abc123"]
        self.assertEqual(row.get("executable_name"), "ERASER.EXE")
        self.assertEqual(row.get("_source"), "prefetch_timeline")

    # ---- raw JSON merged ----

    def test_raw_json_merged(self):
        result = fetch_evidence_records(self.db, ["evtx-security-000000000001"])
        row = result["evtx-security-000000000001"]
        self.assertIn("raw", row)
        self.assertEqual(row["raw"]["target_user"], "informant")
        self.assertNotIn("raw_json", row)

    # ---- unknown ID ----

    def test_unknown_id_returns_none(self):
        result = lookup_evidence_record(self.db, "evtx-security-999999999999")
        self.assertIsNone(result)

    # ---- bulk fetch dedupes ----

    def test_bulk_fetch_dedupes(self):
        ids = [
            "evtx-security-000000000001",
            "mft-000000078080-01",
            "prefetch-ccleaner64.exe-779bd542",
            "prefetch-eraser.exe-abc123",
            "evtx-security-999999999999",
        ]
        result = fetch_evidence_records(self.db, ids)
        self.assertEqual(len(result), 4)
        self.assertIn("evtx-security-000000000001", result)
        self.assertIn("mft-000000078080-01", result)
        self.assertIn("prefetch-ccleaner64.exe-779bd542", result)
        self.assertIn("prefetch-eraser.exe-abc123", result)
        self.assertNotIn("evtx-security-999999999999", result)

    def test_fetch_with_empty_ids(self):
        result = fetch_evidence_records(self.db, [])
        self.assertEqual(result, {})

    def test_lookup_evidence_record_returns_single(self):
        rec = lookup_evidence_record(self.db, "mft-000000078080-01")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["file_name"], "Task List.ersy")

    def test_duplicate_ids_not_doubled(self):
        result = fetch_evidence_records(
            self.db,
            [
                "evtx-security-000000000001",
                "evtx-security-000000000001",
            ],
        )
        self.assertEqual(len(result), 1)
