"""Tests for db/evidence_lookup.py — shared evidence-record lookup."""

from __future__ import annotations

import json
import tempfile
import unittest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import (
    fetch_evidence_records,
    find_missing_evidence_ids,
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
        self.db.execute(
            "INSERT INTO registry_artifacts (artifact_id, plugin, hive, key_path) "
            "VALUES (?, ?, ?, ?)",
            (
                "registry-system-services-0001",
                "services",
                "SYSTEM",
                "ControlSet001\\Services\\Example",
            ),
        )

    def test_unknown_id_returns_none(self):
        result = lookup_evidence_record(self.db, "evtx-security-999999999999")
        self.assertIsNone(result)

    # ---- bulk fetch dedupes ----

    def test_bulk_fetch_dedupes(self):
        ids = [
            "evtx-security-000000000001",
            "evtx-security-000000000001",
            "mft-000000078080-01",
            "prefetch-ccleaner64.exe-779bd542",
            "prefetch-eraser.exe-abc123",
            "registry-system-services-0001",
            "evtx-security-999999999999",
        ]
        result = fetch_evidence_records(self.db, ids)
        self.assertEqual(len(result), 5)
        self.assertIn("evtx-security-000000000001", result)
        self.assertIn("mft-000000078080-01", result)
        self.assertIn("prefetch-ccleaner64.exe-779bd542", result)
        self.assertIn("prefetch-eraser.exe-abc123", result)
        self.assertIn("registry-system-services-0001", result)
        self.assertNotIn("evtx-security-999999999999", result)
        evtx = result["evtx-security-000000000001"]
        self.assertEqual(evtx["event_id"], 4624)
        self.assertEqual(evtx["channel"], "Security")
        self.assertEqual(evtx["raw"]["target_user"], "informant")
        self.assertNotIn("raw_json", evtx)
        self.assertEqual(result["mft-000000078080-01"]["file_name"], "Task List.ersy")
        self.assertEqual(
            result["prefetch-ccleaner64.exe-779bd542"]["executable_name"],
            "CCLEANER64.EXE",
        )
        self.assertEqual(
            result["prefetch-eraser.exe-abc123"]["executable_name"], "ERASER.EXE"
        )
        expected_sources = [
            "evtx_events",
            "mft_entries",
            "prefetch_executions",
            "prefetch_timeline",
            "registry_artifacts",
        ]
        for evidence_id, source in zip(
            dict.fromkeys(ids[:-1]), expected_sources, strict=True
        ):
            self.assertEqual(result[evidence_id]["_source"], source)
        self.assertEqual(
            lookup_evidence_record(self.db, "mft-000000078080-01"),
            result["mft-000000078080-01"],
        )
        self.assertEqual(
            find_missing_evidence_ids(self.db, ids),
            ["evtx-security-999999999999"],
        )
