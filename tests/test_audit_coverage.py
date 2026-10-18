from __future__ import annotations

import unittest

from forensia.knowledge.catalog import expand_catalog_sql_placeholders


class AuditCoverageTests(unittest.TestCase):
    def test_catalog_sql_placeholders_expand_before_audit(self) -> None:
        sql = (
            "SELECT file_path FROM mft_entries WHERE "
            "{{catalog_path_sql:browser_artifacts:file_path}}"
        )
        expanded = expand_catalog_sql_placeholders(sql)
        self.assertNotIn("{{", expanded)
        self.assertIn("google/chrome/application/chrome.exe", expanded.lower())

    def test_catalog_label_sql_placeholder_expands_to_case_expression(self) -> None:
        sql = (
            "SELECT "
            "{{catalog_label_sql:email_artifacts:client:exe_patterns,paths,data_files:"
            "file_name,file_path:application_name}} FROM mft_entries"
        )
        expanded = expand_catalog_sql_placeholders(sql)
        self.assertNotIn("{{", expanded)
        self.assertIn("CASE WHEN", expanded)
        self.assertIn("Microsoft Outlook", expanded)
        self.assertIn("AS application_name", expanded)


class VerdictEnforcementTests(unittest.TestCase):
    def test_hypothesis_rejects_invalid_verdict(self) -> None:
        from pydantic import ValidationError

        from forensia.core.session import Hypothesis

        with self.assertRaises(ValidationError):
            Hypothesis(id="H-TEST", description="test", verdict="invalid_value")

    def test_history_entry_rejects_invalid_verdict(self) -> None:
        from pydantic import ValidationError

        from forensia.core.session import HistoryEntry

        with self.assertRaises(ValidationError):
            HistoryEntry(
                iteration=1, query_id="Q-TEST", summary="test", verdict="bogus"
            )

    def test_store_section_run_rejects_invalid(self) -> None:
        from forensia.core.verdicts import assert_valid_verdict

        with self.assertRaises(ValueError):
            assert_valid_verdict("bogus_verdict", "section_verdict")
        with self.assertRaises(ValueError):
            assert_valid_verdict("anything", "missing_category")

    def test_benchmark_answer_normalization_enforces_taxonomy(self) -> None:
        from forensia.report.answers.answer_store import normalize_structured_answer

        result = normalize_structured_answer(
            {"status": "bogus_status"},
            section_key="6_appendix",
            block_heading="Q01: Test",
            status="insufficient_evidence",
        )
        self.assertEqual(result["status"], "insufficient_evidence")
