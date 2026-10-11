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
from forensia.db.views import case_detail
from forensia.investigation.hypotheses.hypothesis_runner import _result_evidence_ids


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
        eraser_id = (
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
            "eraser.exe-abc123"
        )
        self.db.execute(
            "INSERT INTO prefetch_executions "
            "(evidence_id, executable_name, exec_count, last_exec_time, exec_times) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                eraser_id,
                "ERASER.EXE",
                2,
                "2015-03-25 14:30:00",
                json.dumps(["2015-03-25 14:00:00", "2015-03-25 14:30:00"]),
            ),
        )
        self.db.execute(
            "INSERT INTO prefetch_timeline "
            "(timeline_id, evidence_id, executable_name, exec_time) "
            "VALUES (?, ?, ?, ?), (?, ?, ?, ?)",
            (
                "timeline-eraser-1",
                eraser_id,
                "ERASER.EXE",
                "2015-03-25 14:00:00",
                "timeline-eraser-2",
                eraser_id,
                "ERASER.EXE",
                "2015-03-25 14:30:00",
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

    def test_timeline_id_is_not_an_evidence_identity(self):
        self.assertEqual(
            [],
            _result_evidence_ids(
                [
                    {
                        "timeline_id": "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1"
                    }
                ]
            ),
        )

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
        canonical_prefetch = result[
            "prefetch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-eraser.exe-abc123"
        ]
        self.assertEqual(
            canonical_prefetch["exec_times"],
            ["2015-03-25 14:00:00", "2015-03-25 14:30:00"],
        )
        self.assertNotIn("exec_time", canonical_prefetch)
        expected_sources = [
            "evtx_events",
            "mft_entries",
            "prefetch_executions",
            "prefetch_executions",
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

    def test_typed_detail_uses_evidence_lookup_and_rejects_unknown_kind(self):
        evidence_id = (
            "evtx-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-"
            "security-000000000001"
        )
        detail = case_detail(self.db, "evidence", evidence_id)
        self.assertEqual(detail["evidence_id"], evidence_id)
        self.assertEqual(detail["raw"]["target_user"], "informant")
        with self.assertRaisesRegex(ValueError, "unsupported detail kind"):
            case_detail(self.db, "SELECT * FROM findings", evidence_id)  # type: ignore[arg-type]

    def test_query_receipt_detail_expands_trace_receipt_and_evidence(self):
        evidence_id = "evtx-" + "a" * 64 + "-security-000000000001"
        receipt_id = "receipt-S-1-1-query-hash"
        self.db.execute(
            "INSERT INTO trace.investigation_steps (step_id, session_id, hypothesis_id, iteration, phase, input_json, output_json) "
            "VALUES ('S-1-01-do-Q-1-01', 'S-1', 'H-1', 1, 'do', ?, ?)",
            (
                json.dumps(
                    {
                        "planned_query": {
                            "query_id": "Q-1",
                            "sql": "SELECT * FROM evtx_events",
                        }
                    }
                ),
                json.dumps(
                    {
                        "tool_receipt": {
                            "receipt_id": receipt_id,
                            "arguments": {"sql": "SELECT * FROM evtx_events"},
                            "result_refs": {"evidence_ids": [evidence_id]},
                        },
                        "row_count": 1,
                        "sample_rows": [{"evidence_id": evidence_id}],
                    }
                ),
            ),
        )
        detail = case_detail(self.db, "query_receipt", receipt_id)
        self.assertIsNotNone(detail)
        assert detail is not None
        self.assertEqual(
            "SELECT * FROM evtx_events", detail["input_json"]["planned_query"]["sql"]
        )
        self.assertEqual(evidence_id, detail["evidence"][0]["evidence_id"])
        self.assertEqual(1, detail["output_json"]["row_count"])
        self.assertIsNone(case_detail(self.db, "query_receipt", "Q-1"))

    def test_trace_details_recover_full_prompt_and_domain_references(self):
        request = {"messages": [{"content": "x" * 20000 + "unseen-tail"}]}
        self.db.execute(
            "INSERT INTO trace.llm_logical_calls (logical_call_id, session_id) "
            "VALUES ('lc-1', 'session-1')"
        )
        self.db.execute(
            "INSERT INTO trace.llm_provider_attempts "
            "(attempt_id, logical_call_id, request_body) VALUES ('pa-1', 'lc-1', ?)",
            [json.dumps(request)],
        )
        call = case_detail(self.db, "llm_call", "lc-1")
        self.assertEqual(call["attempt_ids"], ["pa-1"])
        page = case_detail(self.db, "llm_attempt", "pa-1")
        pieces = [page["text"]]
        while page["next_offset"] is not None:
            page = case_detail(
                self.db, "llm_attempt", "pa-1", offset=page["next_offset"]
            )
            pieces.append(page["text"])
        self.assertEqual(json.loads("".join(pieces))["request_body"], request)

        self.db.execute(
            "INSERT INTO hypothesis_evidence "
            "(link_id, hypothesis_id, evidence_id, assessment_id, role, derivation_group) "
            "VALUES ('link-1', 'H-1', 'evtx-1', 'EA-1', 'supporting', 'source-1')"
        )
        assessment = case_detail(self.db, "assessment", "EA-1")
        self.assertEqual(assessment["evidence_ids"], ["evtx-1"])
        self.assertEqual(assessment["derivation_groups"], ["source-1"])
        grounds = {
            "assessment_id": "EA-1",
            "evidence_ids": ["evtx-1"],
            "role": "supporting",
        }
        self.db.execute(
            "INSERT INTO trace.investigation_steps "
            "(step_id, phase, output_json, created_at) "
            "VALUES ('check-1', 'check', ?, now())",
            [json.dumps({"assessment": grounds})],
        )
        self.db.execute("DELETE FROM hypothesis_evidence WHERE assessment_id = 'EA-1'")
        retained = case_detail(self.db, "assessment", "EA-1")
        self.assertEqual(retained["assessment"], grounds)
        self.assertIsNone(retained["current_links"])
        self.db.execute(
            "INSERT INTO trace.hypothesis_reasoning (entry_id, body) "
            "VALUES ('reason-1', 'This is an interpretation, not Evidence.')"
        )
        self.assertIn(
            "interpretation", case_detail(self.db, "reasoning", "reason-1")["body"]
        )
