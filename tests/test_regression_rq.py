import datetime
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from forensia.ai.llm.schemas import PARAGRAPH_NARRATE_SCHEMA
from forensia.ai.prompts.prompt_context import _slim_report_brief_for_section
from forensia.ai.prompts.prompt_sections import build_paragraph_narrate_messages
from forensia.ai.sections.section_answers import (
    _build_daily_session_timeline,
    _extract_answer_by_shape,
    _format_question_answer,
)
from forensia.ai.sections.section_exec import _coerce_plan_action
from forensia.report.answers.answer_builders_host import _load_event_class_definitions
from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.sections.quality_gates import GateContext, check_json_object_leak
from forensia.report.sections.section_store import extract_claim_texts


class TestRegressionRQ(unittest.TestCase):
    def test_comma_separated_keypoint(self):
        result = _coerce_plan_action(
            {"action": "keypoint", "keypoint": "benchmark_hosts, benchmark_recent_lnk"},
            section_key="test",
            iteration=0,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.keypoint, "benchmark_hosts, benchmark_recent_lnk")

    def test_benchmark_format_uses_classifier_status(self):
        case = SimpleNamespace(reports_dir=Path(tempfile.mkdtemp()))
        body = _format_question_answer(
            {"status": "answered", "picked_row_indices": [], "rationale": "ok"},
            [{"host_id": "INFORMANT-PC"}],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "not_found",
            case,
            question_id="Q6",
        )
        self.assertIn("**Status:** answered", body)
        self.assertIn("INFORMANT-PC", body)

    def test_benchmark_missing_reason_string_not_split_by_formatter(self):
        case = SimpleNamespace(reports_dir=Path(tempfile.mkdtemp()))
        body = _format_question_answer(
            {
                "status": "answered",
                "picked_row_indices": [],
                "rationale": "empty answer rationale",
            },
            [],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "answered",
            case,
            question_id="Q6",
        )
        self.assertIn("**Status:** wrong_query", body)
        self.assertIn("- empty answer rationale", body)
        self.assertNotIn("- e\n- m", body)

    def test_extract_answer_by_shape_does_not_make_empty_rows(self):
        rows = [
            {
                "summary": "file_path=Windows/Prefetch/GOOGLEDRIVESYNC.EXE-841A0D94.pf evidence_id=mft-000000005619-00"
            }
        ]
        result = _extract_answer_by_shape(
            rows,
            {
                "format": "enumerated_services",
                "fields": ["service_name", "exe_found", "paths_found", "config_found"],
            },
            "enumerated_services",
        )
        self.assertEqual(result[0]["service_name"], "Google Drive")
        self.assertNotEqual(result[0]["service_name"], "")

    def test_json_object_leak_detected(self):
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        msg, score = check_json_object_leak('{"body": "some text"}', ctx)
        self.assertIsNotNone(msg)

    def test_json_object_leak_clean(self):
        ctx = GateContext(
            section_key="test", title="test", evidence_results=None, db=None
        )
        msg, score = check_json_object_leak("## Heading\n\nSome paragraph text.", ctx)
        self.assertIsNone(msg)

    def test_evidence_id_pattern_matches_evtx(self):
        self.assertIsNotNone(EVIDENCE_ID_PATTERN.search("evtx-security-000000000120"))
        self.assertIsNotNone(EVIDENCE_ID_PATTERN.search("mft-000000072008-00"))

    def test_evidence_id_pattern_rejects_old_format(self):
        self.assertIsNone(EVIDENCE_ID_PATTERN.search("ev-0001"))
        self.assertIsNone(EVIDENCE_ID_PATTERN.search("KP-0001"))

    def test_paragraph_narrate_schema_required_body(self):
        self.assertIn("required", PARAGRAPH_NARRATE_SCHEMA)
        self.assertIn("body", PARAGRAPH_NARRATE_SCHEMA["required"])
        messages, _ = build_paragraph_narrate_messages(
            heading="Executive Summary",
            key_points=[],
            evidence_rows=[],
            template_body="## Executive Summary",
        )
        self.assertIn('{"body"', messages[0]["content"])
        self.assertIn("Do not return a bare string", messages[0]["content"])

    def test_scaffold_patterns_filter_claims(self):
        body = "**Status:** answered\n\nReal Content\n\nSome actual claim here."
        claims = extract_claim_texts(body)
        self.assertIn("Real Content", claims)
        self.assertNotIn("**Status:**", " ".join(claims))

    def test_claim_extraction_skips_tables_and_structured_metadata(self):
        body = """
## 1. Endpoint identity

**Status:** answered

### Answer
Substantive narrative claim with evidence evtx-security-000000000122.

| host_id | evidence_count |
| --- | --- |
| informant-PC | 10 |

### Queries Run
- structured:host_identity:evtx_distinct_hosts

### Structured Data
- JSON: structured/answers.json
- CSV: structured/Q6.csv
"""
        claims = extract_claim_texts(body)
        joined = " ".join(claims)
        self.assertIn("Substantive narrative claim", joined)
        self.assertNotIn("host_id", joined)
        self.assertNotIn("informant-PC", joined)
        self.assertNotIn("structured:host_identity", joined)
        self.assertNotIn("structured/answers.json", joined)
        self.assertNotIn("### Queries Run", joined)

    def test_slim_report_brief_keeps_case_level_context_for_narrative_sections(self):
        brief = {
            "time_range": {"start": "2015-03-22", "end": "2015-03-23"},
            "source_timezone": "UTC",
            "top_findings": [
                {
                    "finding_id": "finding-1",
                    "title": "Explicit credential logon",
                    "summary": "4648 activity involving informant.",
                    "severity": "high",
                    "confidence": 0.9,
                    "evidence_ids": ["evtx-security-000000000122"],
                    "large_unused_field": "x" * 200,
                }
            ],
            "confirmed_hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "description": "Explicit credentials were used.",
                    "status": "confirmed",
                    "verdict": "confirmed",
                }
            ],
            "active_hypotheses": [
                {"hypothesis_id": "H-002", "description": "Missing collection gap."}
            ],
        }

        technical = _slim_report_brief_for_section(brief, "3_technical")
        gaps = _slim_report_brief_for_section(brief, "4_gaps")

        self.assertEqual(
            "Explicit credential logon", technical["top_findings"][0]["title"]
        )
        self.assertIn("confirmed_hypotheses", technical)
        self.assertNotIn("large_unused_field", technical["top_findings"][0])
        self.assertEqual("H-002", gaps["active_hypotheses"][0]["hypothesis_id"])
        self.assertNotIn("top_findings", gaps)


class TestDailySessionTimelineBuilder(unittest.TestCase):
    def test_load_event_class_definitions(self):
        classes = _load_event_class_definitions()
        self.assertIn("startup", classes)
        self.assertIn("shutdown", classes)
        self.assertIn("logon", classes)
        self.assertIn("logoff", classes)
        self.assertEqual(classes["startup"]["event_ids"], [6005, 12])
        self.assertEqual(classes["shutdown"]["event_ids"], [6006, 13, 1074])
        # 4648 (explicit credential use) is deliberately NOT in the logon
        # class: session/daily-timeline builders count logons from this class,
        # and explicit credential use is not a logon. It lives in the separate
        # explicit_credential class consumed by auth-pattern code paths.
        self.assertEqual(classes["logon"]["event_ids"], [4624])
        self.assertEqual(classes["explicit_credential"]["event_ids"], [4648])
        self.assertEqual(classes["logon"]["logon_types"], [2, 10, 11])
        self.assertEqual(classes["logoff"]["event_ids"], [4634, 4647])

    def test_builder_with_empty_db_returns_empty_list(self):
        import tempfile

        from forensia.core.case import Case
        from forensia.db.database import CaseDB

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                rows = _build_daily_session_timeline(db)
                self.assertEqual(rows, [])

    def test_builder_returns_correct_shape_over_two_days(self):
        import tempfile

        from forensia.core.case import Case
        from forensia.db.database import CaseDB

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Day 1: 2015-03-22
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e1",
                        6005,
                        datetime.datetime(2015, 3, 22, 8, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e2",
                        4624,
                        datetime.datetime(2015, 3, 22, 8, 15, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e3",
                        4624,
                        datetime.datetime(2015, 3, 22, 9, 0, 0),
                        "HOST1",
                        "bob",
                        "10",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e4",
                        4634,
                        datetime.datetime(2015, 3, 22, 17, 0, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e5",
                        1074,
                        datetime.datetime(2015, 3, 22, 17, 30, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )

                # Day 2: 2015-03-23
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e6",
                        12,
                        datetime.datetime(2015, 3, 23, 7, 45, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e7",
                        4624,
                        datetime.datetime(2015, 3, 23, 8, 5, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e8",
                        4647,
                        datetime.datetime(2015, 3, 23, 16, 45, 0),
                        "HOST1",
                        "charlie",
                        "2",
                    ),
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e9",
                        6006,
                        datetime.datetime(2015, 3, 23, 17, 0, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )

                rows = _build_daily_session_timeline(db)

        self.assertEqual(len(rows), 2)

        day1 = rows[0]
        self.assertEqual(day1["date"], "2015-03-22")
        self.assertEqual(day1["first_startup"], "2015-03-22 08:00:00")
        self.assertEqual(day1["first_logon"], "2015-03-22 08:15:00")
        self.assertEqual(day1["last_logoff"], "2015-03-22 17:00:00")
        self.assertEqual(day1["last_shutdown"], "2015-03-22 17:30:00")
        self.assertIn("alice", day1["logon_users"])
        self.assertIn("bob", day1["logon_users"])
        self.assertEqual(day1["interactive_logon_count"], 2)

        day2 = rows[1]
        self.assertEqual(day2["date"], "2015-03-23")
        self.assertEqual(day2["first_startup"], "2015-03-23 07:45:00")
        self.assertEqual(day2["first_logon"], "2015-03-23 08:05:00")
        self.assertEqual(day2["last_logoff"], "2015-03-23 16:45:00")
        self.assertEqual(day2["last_shutdown"], "2015-03-23 17:00:00")
        self.assertIn("charlie", day2["logon_users"])
        self.assertEqual(day2["interactive_logon_count"], 1)

    def test_builder_respects_hour_qualifiers(self):
        import tempfile

        from forensia.core.case import Case
        from forensia.db.database import CaseDB

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e1",
                        6005,
                        datetime.datetime(2015, 3, 22, 9, 5, 0),
                        "HOST1",
                        None,
                        None,
                    ),
                )
                # This logon is outside qualifier window (before 09:00) so should be excluded
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e2",
                        4624,
                        datetime.datetime(2015, 3, 22, 8, 0, 0),
                        "HOST1",
                        "bob",
                        "2",
                    ),
                )
                # This logon is within the window (09:00-18:00)
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, target_user, logon_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        "evtx-e3",
                        4624,
                        datetime.datetime(2015, 3, 22, 9, 0, 0),
                        "HOST1",
                        "alice",
                        "2",
                    ),
                )

                qualifiers = {"hour_from": "09:00", "hour_to": "18:00"}
                rows = _build_daily_session_timeline(db, qualifiers)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["date"], "2015-03-22")
        self.assertEqual(rows[0]["first_startup"], "2015-03-22 09:05:00")
        self.assertEqual(rows[0]["first_logon"], "2015-03-22 09:00:00")
        self.assertEqual(rows[0]["last_logoff"], "")
        self.assertEqual(rows[0]["last_shutdown"], "")
        self.assertEqual(rows[0]["interactive_logon_count"], 1)  # bob at 08:00 excluded
