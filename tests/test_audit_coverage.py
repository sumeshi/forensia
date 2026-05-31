from __future__ import annotations

import unittest
from pathlib import Path

from scripts.audit_schema_coverage import (
    _extract_event_ids_from_sql,
    _collect_rule_event_ids,
    _audit_question_routing_eval,
    _audit_question_specs,
)


class AuditCoverageTests(unittest.TestCase):
    def test_extract_event_id_equality(self) -> None:
        ids = _extract_event_ids_from_sql(
            "SELECT * FROM evtx_events WHERE event_id = 4624"
        )
        self.assertIn(4624, ids)

    def test_extract_event_id_in_clause(self) -> None:
        ids = _extract_event_ids_from_sql(
            "SELECT * FROM evtx_events WHERE event_id IN (4624, 4625, 4648)"
        )
        self.assertEqual(ids, {4624, 4625, 4648})

    def test_extract_event_id_empty_sql(self) -> None:
        self.assertEqual(_extract_event_ids_from_sql(""), set())

    def test_extract_event_id_no_match(self) -> None:
        ids = _extract_event_ids_from_sql("SELECT * FROM mft_files")
        self.assertEqual(ids, set())

    def test_collect_rule_ids_finds_known_events(self) -> None:
        rules_dir = Path(__file__).resolve().parent.parent / "src" / "forensia" / "rulepacks" / "windows"
        ids = _collect_rule_event_ids(rules_dir)
        self.assertIn(4624, ids, "Security 4624 (logon) should be found")
        self.assertIn(4688, ids, "Security 4688 (process creation) should be found")
        self.assertIn(7036, ids, "System 7036 (service) should be found")
        self.assertGreater(len(ids), 50, "Should extract 50+ event IDs from rules")

    def test_question_specs_have_valid_contracts(self) -> None:
        self.assertEqual([], _audit_question_specs())

    def test_question_routing_mutation_corpus_passes(self) -> None:
        self.assertEqual([], _audit_question_routing_eval())


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
            HistoryEntry(iteration=1, query_id="Q-TEST", summary="test", verdict="bogus")

    def test_hypothesis_accepts_valid_verdict(self) -> None:
        from forensia.core.session import Hypothesis
        h = Hypothesis(id="H-TEST", description="test", verdict="confirmed")
        self.assertEqual(h.verdict, "confirmed")

    def test_history_entry_accepts_valid_verdict(self) -> None:
        from forensia.core.session import HistoryEntry
        h = HistoryEntry(iteration=1, query_id="Q-TEST", summary="test", verdict="confirmed")
        self.assertEqual(h.verdict, "confirmed")

    def test_assert_valid_verdict_accepts_valid(self) -> None:
        from forensia.core.verdicts import assert_valid_verdict
        assert_valid_verdict("confirmed", "hypothesis_verdict")  # no error
        assert_valid_verdict("block_supported", "section_verdict")  # no error
        assert_valid_verdict("answered", "structured_status")  # no error
        assert_valid_verdict("answered", "benchmark_status")  # no error

    def test_store_section_run_rejects_invalid(self) -> None:
        from forensia.core.verdicts import assert_valid_verdict
        with self.assertRaises(ValueError):
            assert_valid_verdict("bogus_verdict", "section_verdict")

    def test_benchmark_answer_normalization_enforces_taxonomy(self) -> None:
        from forensia.report.writer import _normalize_benchmark_answer
        result = _normalize_benchmark_answer(
            {"status": "bogus_status"},
            section_key="6_appendix",
            block_heading="Q01: Test",
            status="insufficient_evidence",
        )
        self.assertEqual(result["status"], "insufficient_evidence")
