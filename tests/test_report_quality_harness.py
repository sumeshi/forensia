"""R7-12: Report quality harness — contract tests for publishability.

These tests verify machine-evaluable invariants that a publishable report must
satisfy. They run against a synthetic case DB and do NOT require LLM calls.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.report_validation import (
    check_failure_markers,
    check_sufficiency_consistency,
    validate_report,
)


class TestReportQualityContract(unittest.TestCase):
    """Contract tests for report publishability invariants."""

    def test_failure_marker_not_in_output(self) -> None:
        """Failure markers must not appear in final report body."""
        body_with_marker = "Some text\n*Section block failed: ValueError*\nMore text"
        body_clean = "Some text\nMore text"

        findings = check_failure_markers(body_with_marker)
        self.assertGreater(len(findings), 0, "Should detect failure marker")

        findings = check_failure_markers(body_clean)
        self.assertEqual(len(findings), 0, "Clean body should have no markers")

    def test_persisted_failure_is_fatal_but_omitted_from_rendered_prose(self) -> None:
        from forensia.report.render.writer import build_report_markdown_from_db

        marker = "_Section could not be generated due to an internal error._"
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections "
                    "(section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_bad', 'Bad', ?, 0, 'draft', 1, FALSE), "
                    "('2_good', 'Good', '# Good\n\nValid body.', 1, 'stable', 1, FALSE)",
                    [marker],
                )
                rendered = build_report_markdown_from_db(db, case)
                findings = validate_report({}, report_body=rendered, db=db)
                self.assertNotIn(marker, rendered)
                self.assertIn("Valid body", rendered)
                self.assertTrue(
                    any(
                        item.check_name == "section_generation_failure"
                        and item.severity == "error"
                        for item in findings
                    )
                )

    def test_source_status_uses_stable_ids_not_colliding_basenames(self) -> None:
        """Two sources with the same filename retain independent row counts."""
        from forensia.db.evidence_sources import register_evidence_source
        from forensia.evidence.normalize import _update_source_status

        source_a = "a" * 64
        source_b = "b" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                for source_id, path in (
                    (source_a, "/disk-a/APP.EXE-1234.pf"),
                    (source_b, "/disk-b/APP.EXE-1234.pf"),
                ):
                    db.execute(
                        "INSERT INTO ingested_files "
                        "(sha256, path, source_kind, size, ingested_at) "
                        "VALUES (?, ?, 'prefetch', 1, now())",
                        [source_id, path],
                    )
                    register_evidence_source(
                        db,
                        source_id=source_id,
                        artifact_family="prefetch",
                        display_path=Path(path).name,
                        ingest_status="parsed",
                    )
                db.execute(
                    "INSERT INTO prefetch_executions "
                    "(evidence_id, source_file, executable_name, exec_count) VALUES "
                    "('E-A', ?, 'APP.EXE', 1), "
                    "('E-B1', ?, 'APP.EXE', 1), "
                    "('E-B2', ?, 'APP.EXE', 1)",
                    [source_a, source_b, source_b],
                )
                _update_source_status(db, None, {})
                counts = dict(
                    db.execute(
                        "SELECT source_id, row_count FROM evidence_sources"
                    ).fetchall()
                )
                self.assertEqual(1, counts[source_a])
                self.assertEqual(2, counts[source_b])

    def test_empty_raw_evtx_is_not_a_normalization_failure(self) -> None:
        from forensia.db.evidence_sources import register_evidence_source
        from forensia.evidence.normalize import _update_source_status

        source_id = "c" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / f"evtx-{source_id[:12]}-empty.jsonl").write_text("")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO ingested_files "
                    "(sha256, path, source_kind, size, ingested_at) "
                    "VALUES (?, '/evidence/empty.evtx', 'evtx', 1, now())",
                    [source_id],
                )
                register_evidence_source(
                    db,
                    source_id=source_id,
                    artifact_family="evtx",
                    display_path="empty.evtx",
                    ingest_status="parsed",
                )
                _update_source_status(db, None, {}, raw_dir=case.raw_dir)
                status, error_code = db.execute(
                    "SELECT ingest_status, error_code FROM evidence_sources "
                    "WHERE source_id = ?",
                    [source_id],
                ).fetchone()
                self.assertEqual("empty", status)
                self.assertEqual("", error_code)

    def test_nonempty_raw_without_normalized_rows_is_failure(self) -> None:
        from forensia.db.evidence_sources import register_evidence_source
        from forensia.evidence.normalize import _update_source_status

        source_id = "d" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            (case.raw_dir / f"evtx-{source_id[:12]}-lost.jsonl").write_text("{}\n")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO ingested_files "
                    "(sha256, path, source_kind, size, ingested_at) "
                    "VALUES (?, '/evidence/lost.evtx', 'evtx', 1, now())",
                    [source_id],
                )
                register_evidence_source(
                    db,
                    source_id=source_id,
                    artifact_family="evtx",
                    display_path="lost.evtx",
                    ingest_status="parsed",
                )
                with self.assertLogs(
                    "forensia.evidence.normalize", level="ERROR"
                ) as logs:
                    _update_source_status(db, None, {}, raw_dir=case.raw_dir)
                status, error_code = db.execute(
                    "SELECT ingest_status, error_code FROM evidence_sources "
                    "WHERE source_id = ?",
                    [source_id],
                ).fetchone()
                self.assertEqual("failed", status)
                self.assertEqual("normalized_rows_missing", error_code)
                self.assertIn("Normalization output missing", " ".join(logs.output))

    def test_candidate_only_not_asserted(self) -> None:
        """candidate_only status must not be displayed as 'answered'."""
        from forensia.report.answers.answer_store import (
            _structured_answer_interpretation,
        )

        answer = {
            "status": "candidate_only",
            "answer": [{"key": "value"}],
        }
        interp = _structured_answer_interpretation(answer, "Test")
        self.assertIn("candidate", interp.lower())
        # Should explicitly say these are NOT confirmed facts
        self.assertIn("not confirmed", interp.lower())

    def test_sufficiency_consistency_check(self) -> None:
        """confirmed + insufficient must be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (hypothesis_id, status, verdict, description, summary,
                        sufficiency_status, created_at, updated_at)
                    VALUES ('H-TEST', 'confirmed', 'confirmed', 'Test', 'test',
                        'insufficient', now(), now())
                    """
                )
                findings = check_sufficiency_consistency(db)
                self.assertGreater(
                    len(findings), 0, "Should detect confirmed+insufficient"
                )

    def test_confirmed_without_evidence_links(self) -> None:
        """confirmed hypothesis without evidence links must be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (hypothesis_id, status, verdict, description, summary,
                        sufficiency_status, created_at, updated_at)
                    VALUES ('H-NOEV', 'confirmed', 'confirmed', 'Test', 'test',
                        'sufficient', now(), now())
                    """
                )
                findings = check_sufficiency_consistency(db)
                error_findings = [f for f in findings if f.severity == "error"]
                self.assertGreater(
                    len(error_findings),
                    0,
                    "Confirmed claims without evidence links must be fatal",
                )

    def test_confirmation_without_links_is_reconciled_to_inconclusive(self) -> None:
        """An LLM confirmation cannot override an empty evidence graph."""
        from forensia.ai.checking.sufficiency import assess_and_persist_sufficiency

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, verdict, description, summary,
                        created_at, updated_at
                    ) VALUES ('H-NOLINK', 'active', NULL, 'Test', '', now(), now())
                    """
                )
                result, verdict, _reason, _caps = assess_and_persist_sufficiency(
                    db,
                    hypothesis_id="H-NOLINK",
                    investigation_text="",
                    evidence_requirements={},
                    llm_verdict="confirmed",
                )
                self.assertNotEqual("sufficient", result.status)
                self.assertEqual("inconclusive", verdict)

    def test_writer_emits_non_publishable_validation_artifact(self) -> None:
        """The writer must persist machine-readable fatal validation state."""
        from forensia.report.render.writer import render_written_report

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, verdict, description, summary,
                        sufficiency_status, created_at, updated_at
                    ) VALUES (
                        'H-BAD', 'confirmed', 'confirmed', 'Unlinked claim', '',
                        'insufficient', now(), now()
                    )
                    """
                )
                html_path = case.reports_dir / "report.html"
                with (
                    patch(
                        "forensia.report.render.writer.render_html_report",
                        return_value=html_path,
                    ),
                    patch("forensia.report.render.evidence_map.write_evidence_map"),
                ):
                    render_written_report(
                        case,
                        db,
                        filled_sections={"1_summary": "# Clean report"},
                    )
                artifact = json.loads(
                    (case.reports_dir / "report_validation.json").read_text()
                )
                self.assertFalse(artifact["publishable"])
                self.assertTrue(artifact["fatal_errors"])

    def test_table_validation_catches_empty_required_columns(self) -> None:
        """Table with all-empty required columns must be flagged."""
        from forensia.report.answers.table_registry import _validate_table_output

        rows = [{"col1": None, "col2": ""}]
        columns = [("col1", "Column 1"), ("col2", "Column 2")]
        errors = _validate_table_output("test_table", rows, columns)
        empty_errors = [e for e in errors if e.error_type == "all_empty"]
        self.assertGreater(len(empty_errors), 0, "Should detect empty required columns")

    def test_table_validation_passes_with_data(self) -> None:
        """Table with data in required columns must pass."""
        from forensia.report.answers.table_registry import _validate_table_output

        rows = [{"col1": "value1", "col2": "value2"}]
        columns = [("col1", "Column 1"), ("col2", "Column 2")]
        errors = _validate_table_output("test_table", rows, columns)
        self.assertEqual(len(errors), 0, "Table with data should pass validation")

    def test_verdict_taxonomy_includes_candidate_only(self) -> None:
        """candidate_only must be a valid structured_status."""
        from forensia.core.verdicts import valid_verdicts

        valid = valid_verdicts("structured_status")
        self.assertIn("candidate_only", valid)
        self.assertIn("answered", valid)
        self.assertIn("partial", valid)

    def test_validate_report_detects_failure_markers(self) -> None:
        """Full report validation must detect failure markers."""
        report_brief = {}
        report_body = "Some text\n*Section block failed: error*\nMore text"

        findings = validate_report(report_brief, report_body=report_body)
        marker_findings = [f for f in findings if f.check_name == "failure_marker"]
        self.assertGreater(
            len(marker_findings), 0, "Should detect failure marker in full validation"
        )


class TestRuleSemanticsContract(unittest.TestCase):
    """Contract tests for rule semantics — normal lifecycle not flagged as malicious."""

    def test_1100_rule_is_low_severity(self) -> None:
        """Event 1100 (log service shutdown) must be low severity, not high."""
        from forensia.knowledge.rules.loader import load_rules_from_dir

        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_1100 = next(
            (r for r in rules if r.id == "windows-security-1100-evtlog-shutdown"), None
        )
        self.assertIsNotNone(rule_1100, "Rule 1100 should exist")
        self.assertEqual(rule_1100.severity, "low", "Event 1100 should be low severity")

    def test_6005_6006_rule_is_low_severity(self) -> None:
        """Events 6005/6006 (log service start/stop) must be low severity."""
        from forensia.knowledge.rules.loader import load_rules_from_dir

        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)
        rule_6005_6006 = next(
            (r for r in rules if r.id == "windows-system-6005-6006-eventlog-service"),
            None,
        )
        self.assertIsNotNone(rule_6005_6006, "Rule 6005/6006 should exist")
        self.assertEqual(
            rule_6005_6006.severity, "low", "Events 6005/6006 should be low severity"
        )

    def test_4735_rule_separated_from_membership(self) -> None:
        """Group metadata events must be separate from membership and user changes."""
        from forensia.knowledge.rules.loader import load_rules_from_dir

        rules_dir = Path("src/forensia/knowledge/rulepacks")
        profile_path = Path("src/forensia/knowledge/profiles/windows-basic.yaml")
        rules = load_rules_from_dir(rules_dir, profile_path)

        rule_4728 = next(
            (r for r in rules if r.id == "windows-security-4728-group-change"), None
        )
        rule_4735 = next(
            (
                r
                for r in rules
                if r.id == "windows-security-4735-group-metadata-changed"
            ),
            None,
        )
        self.assertIsNotNone(rule_4728, "Rule 4728 should exist")
        self.assertIsNotNone(rule_4735, "Rule 4735 should exist")
        # 4728 should NOT contain 4735/4738
        self.assertNotIn("4735", rule_4728.query)
        self.assertNotIn("4738", rule_4728.query)


if __name__ == "__main__":
    unittest.main()
