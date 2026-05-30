import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace

from forensia.ai.schemas import PARAGRAPH_NARRATE_SCHEMA
from forensia.ai.section_agent import _coerce_plan_action, _extract_answer_by_shape, _format_benchmark_answer
from forensia.report.writer import (
    EVIDENCE_ID_PATTERN,
    _check_json_object_leak,
    _extract_claim_texts,
    _GateCtx,
)


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
        body = _format_benchmark_answer(
            {"status": "answered", "picked_row_indices": [], "rationale": "ok"},
            [{"host_id": "INFORMANT-PC"}],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "not_found",
            case,
            benchmark_id="Q6",
        )
        self.assertIn("**Status:** answered", body)
        self.assertIn("INFORMANT-PC", body)

    def test_benchmark_missing_reason_string_not_split_by_formatter(self):
        case = SimpleNamespace(reports_dir=Path(tempfile.mkdtemp()))
        body = _format_benchmark_answer(
            {"status": "answered", "picked_row_indices": [], "rationale": "empty answer rationale"},
            [],
            {"fields": ["host_id"]},
            "6_appendix",
            "1. host",
            "answered",
            case,
            benchmark_id="Q6",
        )
        self.assertIn("**Status:** wrong_query", body)
        self.assertIn("- empty answer rationale", body)
        self.assertNotIn("- e\n- m", body)

    def test_extract_answer_by_shape_does_not_make_empty_rows(self):
        rows = [{"summary": "file_path=Windows/Prefetch/GOOGLEDRIVESYNC.EXE-841A0D94.pf evidence_id=mft-000000005619-00"}]
        result = _extract_answer_by_shape(
            rows,
            {"format": "enumerated_services", "fields": ["service_name", "exe_found", "paths_found", "config_found"]},
            "enumerated_services",
        )
        self.assertEqual(result[0]["service_name"], "Google Drive")
        self.assertNotEqual(result[0]["service_name"], "")

    def test_json_object_leak_detected(self):
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        msg, score = _check_json_object_leak('{"body": "some text"}', ctx)
        self.assertIsNotNone(msg)

    def test_json_object_leak_clean(self):
        ctx = _GateCtx(section_key="test", title="test", evidence_results=None, db=None)
        msg, score = _check_json_object_leak("## Heading\n\nSome paragraph text.", ctx)
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

    def test_scaffold_patterns_filter_claims(self):
        body = "**Status:** answered\n\nReal Content\n\nSome actual claim here."
        claims = _extract_claim_texts(body)
        self.assertIn("Real Content", claims)
        self.assertNotIn("**Status:**", " ".join(claims))
