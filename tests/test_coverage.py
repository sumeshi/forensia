"""Tests for M1: evidence source tracking and coverage computation."""

from __future__ import annotations

import tempfile
import unittest

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.knowledge.coverage import (
    get_coverage_summary,
    load_artifact_capabilities,
    load_evidence_sufficiency_policy,
    refresh_evidence_coverage,
)


class EvidenceSourceTests(unittest.TestCase):
    """Test evidence_sources table operations."""

    def test_register_evidence_source_creates_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="abc123",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="parsed",
                    parser_name="evtx2es",
                    row_count=100,
                    channel="Security",
                )
                row = db.execute(
                    "SELECT source_id, artifact_family, ingest_status, row_count FROM evidence_sources WHERE source_id = 'abc123'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "abc123")
                self.assertEqual(row[1], "evtx")
                self.assertEqual(row[2], "parsed")
                self.assertEqual(row[3], 100)

    def test_register_evidence_source_upserts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="abc123",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="parsed",
                )
                register_evidence_source(
                    db,
                    source_id="abc123",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="normalized",
                    row_count=200,
                )
                row = db.execute(
                    "SELECT ingest_status, row_count FROM evidence_sources WHERE source_id = 'abc123'"
                ).fetchone()
                self.assertEqual(row[0], "normalized")
                self.assertEqual(row[1], 200)

    def test_register_with_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="fail1",
                    artifact_family="mft",
                    display_path="$MFT",
                    ingest_status="failed",
                    error_code="PARSE_ERROR",
                    error_summary="corrupt file",
                )
                row = db.execute(
                    "SELECT ingest_status, error_code, error_summary FROM evidence_sources WHERE source_id = 'fail1'"
                ).fetchone()
                self.assertEqual(row[0], "failed")
                self.assertEqual(row[1], "PARSE_ERROR")
                self.assertEqual(row[2], "corrupt file")


class CoverageComputationTests(unittest.TestCase):
    """Test evidence coverage computation."""

    def test_empty_sources_returns_all_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                count = refresh_evidence_coverage(db)
                # All capabilities declared in YAML get an unavailable entry
                self.assertGreater(count, 0)
                rows = db.execute(
                    "SELECT DISTINCT state FROM evidence_coverage"
                ).fetchall()
                self.assertEqual(rows[0][0], "unavailable")

    def test_evtx_source_produces_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="evtx1",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="normalized",
                    row_count=1000,
                    channel="Security",
                )
                count = refresh_evidence_coverage(db)
                self.assertGreater(count, 0)
                rows = db.execute(
                    "SELECT capability, state FROM evidence_coverage WHERE source_family = 'evtx'"
                ).fetchall()
                states = {r[0]: r[1] for r in rows}
                self.assertIn("process_execution", states)
                self.assertIn("logon", states)
                self.assertEqual(states["logon"], "partial")

    def test_matching_event_makes_only_relevant_capability_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="evtx1",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="normalized",
                    row_count=1,
                    channel="Security",
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, channel, "
                    "event_id) VALUES ('evtx-1', 'Security.evtx', 'Security', 4624)"
                )
                refresh_evidence_coverage(db)
                states = dict(
                    db.execute(
                        "SELECT capability, state FROM evidence_coverage "
                        "WHERE source_family = 'evtx'"
                    ).fetchall()
                )
                self.assertEqual(states["logon"], "available")
                self.assertEqual(states["process_execution"], "partial")

    def test_failed_source_produces_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="evtx_fail",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="failed",
                    error_summary="parse error",
                )
                count = refresh_evidence_coverage(db)
                self.assertGreater(count, 0)
                rows = db.execute(
                    "SELECT state FROM evidence_coverage WHERE source_family = 'evtx'"
                ).fetchall()
                for r in rows:
                    self.assertEqual(r[0], "degraded")

    def test_no_source_returns_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                refresh_evidence_coverage(db)
                rows = db.execute(
                    "SELECT state, reason_code FROM evidence_coverage WHERE source_family = 'evtx'"
                ).fetchall()
                for r in rows:
                    self.assertEqual(r[0], "unavailable")
                    self.assertEqual(r[1], "artifact_not_collected")

    def test_get_coverage_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                register_evidence_source(
                    db,
                    source_id="evtx1",
                    artifact_family="evtx",
                    display_path="Security.evtx",
                    ingest_status="normalized",
                    row_count=500,
                )
                refresh_evidence_coverage(db)
                summary = get_coverage_summary(db)
                self.assertIn("evtx:logon", summary)
                self.assertEqual(summary["evtx:logon"]["state"], "partial")


class CapabilityDeclarationTests(unittest.TestCase):
    """Test YAML declaration loading."""

    def test_load_artifact_capabilities(self) -> None:
        caps = load_artifact_capabilities()
        self.assertIn("families", caps)
        self.assertIn("evtx", caps["families"])
        self.assertIn("mft", caps["families"])
        self.assertIn("prefetch", caps["families"])

    def test_evtx_has_process_execution_capability(self) -> None:
        caps = load_artifact_capabilities()
        evtx_caps = caps["families"]["evtx"]["capabilities"]
        self.assertIn("process_execution", evtx_caps)
        self.assertIn(4688, evtx_caps["process_execution"]["event_ids"])

    def test_load_evidence_sufficiency_policy(self) -> None:
        policy = load_evidence_sufficiency_policy()
        self.assertIn("common_rules", policy)
        self.assertTrue(policy["common_rules"]["zero_rows_is_not_support"])
        self.assertIn("default_sufficiency", policy)

    def test_cross_artifact_corroboration(self) -> None:
        caps = load_artifact_capabilities()
        self.assertIn("cross_artifact_corroboration", caps)
        pe = caps["cross_artifact_corroboration"]["process_execution"]
        self.assertIn("prefetch", pe["preferred_families"])
