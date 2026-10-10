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
                "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
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
                "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01",
                "Task List.ersy",
                "Users/informant/AppData/Local/Eraser 6/Task List.ersy",
                "2015-03-25 15:29:37",
            ),
        )
        self.db.execute(
            "INSERT INTO prefetch_executions (evidence_id, executable_name, exec_count, last_exec_time) "
            "VALUES (?, ?, ?, ?)",
            (
                "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ccleaner64.exe-779bd542",
                "CCLEANER64.EXE",
                2,
                "2015-03-25 15:15:50",
            ),
        )
        self.db.execute(
            "INSERT INTO prefetch_timeline (evidence_id, executable_name, exec_time) VALUES (?, ?, ?)",
            (
                "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-eraser.exe-abc123",
                "ERASER.EXE",
                "2015-03-25 14:00:00",
            ),
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
        result = lookup_evidence_record(
            self.db,
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
        )
        self.assertIsNone(result)

    def test_same_local_evtx_record_from_two_sources_resolves_independently(self):
        source_a = "c" * 64
        source_b = "d" * 64
        first_id = f"evtx-{source_a}-security-000000000001"
        second_id = f"evtx-{source_b}-security-000000000001"
        self.db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, channel, record_id, computer) "
            "VALUES (?, ?, 'Security', 1, ?), (?, ?, 'Security', 1, ?)",
            (first_id, source_a, "HOST-A", second_id, source_b, "HOST-B"),
        )

        found = fetch_evidence_records(self.db, [first_id, second_id])

        self.assertEqual({first_id, second_id}, set(found))
        self.assertEqual("HOST-A", found[first_id]["computer"])
        self.assertEqual("HOST-B", found[second_id]["computer"])
        self.assertEqual([], find_missing_evidence_ids(self.db, [first_id, second_id]))

    def test_conflicting_duplicate_rows_for_one_identity_are_rejected(self):
        source = "c" * 64
        evidence_id = f"evtx-{source}-security-000000000002"
        self.db.execute(
            "INSERT INTO evtx_events (evidence_id, source_file, record_id, computer) "
            "VALUES (?, ?, 2, 'HOST-A'), (?, ?, 2, 'HOST-B')",
            (evidence_id, source, evidence_id, source),
        )

        with self.assertRaisesRegex(ValueError, "conflicting rows share evidence ID"):
            lookup_evidence_record(self.db, evidence_id)

    # ---- bulk fetch dedupes ----

    def test_bulk_fetch_dedupes(self):
        ids = [
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
            "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01",
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ccleaner64.exe-779bd542",
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-eraser.exe-abc123",
            "registry-system-services-0001",
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
        ]
        result = fetch_evidence_records(self.db, ids)
        self.assertEqual(len(result), 5)
        self.assertIn(
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001",
            result,
        )
        self.assertIn(
            "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01",
            result,
        )
        self.assertIn(
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ccleaner64.exe-779bd542",
            result,
        )
        self.assertIn(
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-eraser.exe-abc123",
            result,
        )
        self.assertIn("registry-system-services-0001", result)
        self.assertNotIn(
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999",
            result,
        )
        evtx = result[
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-000000000001"
        ]
        self.assertEqual(evtx["event_id"], 4624)
        self.assertEqual(evtx["channel"], "Security")
        self.assertEqual(evtx["raw"]["target_user"], "informant")
        self.assertNotIn("raw_json", evtx)
        self.assertEqual(
            result[
                "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01"
            ]["file_name"],
            "Task List.ersy",
        )
        self.assertEqual(
            result[
                "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ccleaner64.exe-779bd542"
            ]["executable_name"],
            "CCLEANER64.EXE",
        )
        self.assertEqual(
            result[
                "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-eraser.exe-abc123"
            ]["executable_name"],
            "ERASER.EXE",
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
            lookup_evidence_record(
                self.db,
                "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01",
            ),
            result[
                "mft-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-000000078080-01"
            ],
        )
        self.assertEqual(
            find_missing_evidence_ids(self.db, ids),
            [
                "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-security-999999999999"
            ],
        )
