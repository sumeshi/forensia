"""Database-level tests for timestamp coverage and source lineage."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record
from forensia.evidence.normalize import _update_source_status
from forensia.knowledge.coverage import (
    compute_evidence_coverage,
    get_coverage_summary,
    refresh_evidence_coverage,
)


class CoverageLineageTests(unittest.TestCase):
    """Test coverage lineage with source_ids."""

    def test_available_coverage_has_source_ids(self) -> None:
        """Available capability must have at least 1 source_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Insert a source with plausible timestamps
                db.execute(
                    "INSERT INTO evidence_sources ("
                    "source_id, artifact_family, ingest_status, row_count, "
                    "min_time, max_time, created_at, updated_at"
                    ") VALUES ('src-001', 'evtx', 'normalized', 100, "
                    "'2015-06-15 10:00:00', '2015-12-25 18:00:00', now(), now())"
                )
                entries = compute_evidence_coverage(db)
                available = [e for e in entries if e["state"] == "available"]
                for entry in available:
                    self.assertIn("src-001", entry["source_ids"])

    def test_sentinel_excluded_from_coverage_window(self) -> None:
        """Raw sentinel/overflow rows are counted, while 2015 defines bounds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evidence_sources ("
                    "source_id, artifact_family, ingest_status, row_count, "
                    "min_time, max_time, created_at, updated_at"
                    ") VALUES ('src-001', 'mft', 'normalized', 1, "
                    "'2015-06-15', '2015-06-15', now(), now())"
                )
                db.execute(
                    "INSERT INTO mft_timeline "
                    "(timeline_id, evidence_id, source_file, timestamp, timestamp_type) VALUES "
                    "('t-1', 'mft-1', 'src-001', '1601-01-01', 'si_created'), "
                    "('t-2', 'mft-1', 'src-001', '2015-06-15', 'si_modified'), "
                    "('t-3', 'mft-1', 'src-001', '3320-11-16', 'fn_created')"
                )
                entries = compute_evidence_coverage(db)
                entry = next(
                    e
                    for e in entries
                    if e["source_family"] == "mft"
                    and e["capability"] == "file_activity"
                )
                self.assertEqual(entry["start_time"], datetime(2015, 6, 15))
                self.assertEqual(entry["end_time"], datetime(2015, 6, 15))
                self.assertEqual(entry["excluded_timestamps"]["sentinel"], 1)
                self.assertEqual(entry["excluded_timestamps"]["overflow"], 1)

    def test_analysis_window_exclusion_uses_reference_source_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evidence_sources (source_id, artifact_family, "
                    "ingest_status, row_count, min_time, max_time, created_at, updated_at) "
                    "VALUES ('evtx-source', 'evtx', 'normalized', 1, '2015-06-15', "
                    "'2015-06-15', now(), now()), ('mft-source', 'mft', 'normalized', "
                    "2, '2015-06-15', '2080-06-15', now(), now())"
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file, timestamp, channel) "
                    "VALUES ('evtx-id', 'evtx-source', '2015-06-15', 'Security')"
                )
                db.execute(
                    "INSERT INTO mft_timeline (timeline_id, evidence_id, source_file, "
                    "timestamp, timestamp_type) VALUES "
                    "('mft-in', 'mft-id', 'mft-source', '2015-06-15', 'si_created'), "
                    "('mft-out', 'mft-id', 'mft-source', '2080-06-15', 'si_modified')"
                )

                entry = next(
                    item
                    for item in compute_evidence_coverage(db)
                    if item["source_family"] == "mft"
                    and item["capability"] == "file_activity"
                )

                self.assertEqual(datetime(2015, 6, 15), entry["start_time"])
                self.assertEqual(datetime(2015, 6, 15), entry["end_time"])
                self.assertEqual(
                    1, entry["excluded_timestamps"]["outside-analysis-window"]
                )

    def test_overflow_excluded_from_coverage_window(self) -> None:
        """Excluded values remain available through the raw artifact lookup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO mft_entries (evidence_id, source_file, raw_json) "
                    "VALUES ('mft-raw-1', 'src-001', "
                    '\'{"si_created":"1601-01-01T00:00:00",'
                    '"fn_created":"3320-11-16T00:00:00"}\')'
                )
                record = lookup_evidence_record(db, "mft-raw-1")
                self.assertEqual(record["raw"]["si_created"], "1601-01-01T00:00:00")
                self.assertEqual(record["raw"]["fn_created"], "3320-11-16T00:00:00")


class CoverageSummarySourceIdsTests(unittest.TestCase):
    """Test that get_coverage_summary includes source_ids."""

    def test_summary_includes_source_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evidence_sources ("
                    "source_id, artifact_family, ingest_status, row_count, "
                    "created_at, updated_at"
                    ") VALUES ('src-001', 'evtx', 'normalized', 100, now(), now())"
                )
                refresh_evidence_coverage(db)
                summary = get_coverage_summary(db)
                # Find an available entry
                available_entries = [
                    v for v in summary.values() if v["state"] == "available"
                ]
                if available_entries:
                    self.assertIn("source_ids", available_entries[0])
                    self.assertIn("src-001", available_entries[0]["source_ids"])


class CoverageRefreshIdempotentTests(unittest.TestCase):
    """Test that refresh_evidence_coverage is idempotent."""

    def test_double_refresh_doesnt_double_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evidence_sources ("
                    "source_id, artifact_family, ingest_status, row_count, "
                    "min_time, max_time, created_at, updated_at"
                    ") VALUES ('src-001', 'evtx', 'normalized', 100, "
                    "'2015-06-15 10:00:00', '2015-12-25 18:00:00', now(), now())"
                )
                # Refresh twice
                count1 = refresh_evidence_coverage(db)
                count2 = refresh_evidence_coverage(db)
                # Should have same number of entries
                self.assertEqual(count1, count2)
                # Check that source_ids aren't duplicated
                rows = db.execute(
                    "SELECT source_ids FROM evidence_coverage WHERE state = 'available'"
                ).fetchall()
                for row in rows:
                    source_ids = row[0]
                    if isinstance(source_ids, str):
                        import json

                        source_ids = json.loads(source_ids)
                    # Should not have duplicates
                    self.assertEqual(len(source_ids), len(set(source_ids)))


class EVTXSourceMetadataTests(unittest.TestCase):
    """Test EVTX source metadata consistency."""

    def test_evidence_sources_hosts_populated(self) -> None:
        """Repeated backfill derives, rather than assumes, EVTX metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                source_id = "1" * 64
                db.execute(
                    "INSERT INTO ingested_files (sha256, path, source_kind) "
                    "VALUES (?, '/evidence/Security.evtx', 'evtx')",
                    [source_id],
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, row_count, hosts, "
                    "created_at, updated_at) VALUES "
                    "(?, 'evtx', 'parsed', 0, [], now(), now())",
                    [source_id],
                )
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, source_file, channel, computer, timestamp) VALUES "
                    "('evtx-1', ?, 'Security', 'HOST-PC', '2015-06-15 10:00:00'), "
                    "('evtx-2', ?, 'Security', 'HOST-PC', '2015-06-15 10:01:00')",
                    [source_id, source_id],
                )
                counts = {"evtx_rows": 2}
                _update_source_status(db, [source_id], counts)
                _update_source_status(db, [source_id], counts)
                row = db.execute(
                    "SELECT row_count, hosts, channel, min_time, max_time "
                    "FROM evidence_sources "
                    "WHERE source_id = ?",
                    [source_id],
                ).fetchone()
                self.assertEqual(row[0], 2)
                hosts = row[1]
                if isinstance(hosts, str):
                    import json

                    hosts = json.loads(hosts)
                self.assertEqual(hosts, ["HOST-PC"])
                self.assertEqual(row[2], "Security")
                self.assertEqual(row[3].year, 2015)
                self.assertEqual(row[4].year, 2015)

    def test_rows_under_legacy_path_identity_are_flagged_not_matched(self) -> None:
        """Normalized rows keyed by the old path identity are not silently re-read."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            source_id = "2" * 64
            (case.raw_dir / f"evtx-{source_id}-security.jsonl").write_text("{}\n")
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO ingested_files (sha256, path, source_kind) "
                    "VALUES (?, '/evidence/Security.evtx', 'evtx')",
                    [source_id],
                )
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, source_file) "
                    "VALUES ('evtx-1', '/evidence/Security.evtx')"
                )
                with self.assertLogs(
                    "forensia.evidence.normalize", level="ERROR"
                ) as logs:
                    _update_source_status(
                        db, [source_id], {"evtx_rows": 1}, raw_dir=case.raw_dir
                    )
                status, error_code = db.execute(
                    "SELECT ingest_status, error_code FROM evidence_sources "
                    "WHERE source_id = ?",
                    [source_id],
                ).fetchone()

            self.assertEqual(
                ("failed", "normalized_rows_missing"), (status, error_code)
            )
            self.assertTrue(
                any(source_id in message for message in logs.output),
                logs.output,
            )


class ReportValidationCoverageLineageTests(unittest.TestCase):
    """Test report validation for coverage lineage."""

    def test_available_with_empty_source_ids_is_error(self) -> None:
        """Available coverage with empty source_ids should be flagged."""
        from forensia.report.report_validation import check_coverage_lineage

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Insert coverage with empty source_ids
                db.execute(
                    "INSERT INTO evidence_coverage ("
                    "capability, source_family, state, source_ids, confidence, derived_at"
                    ") VALUES ('test_cap', 'evtx', 'available', '[]', 0.9, now())"
                )
                findings = check_coverage_lineage(db)
                errors = [f for f in findings if f.severity == "error"]
                self.assertTrue(any("empty source_ids" in f.message for f in errors))

    def test_coverage_with_valid_source_ids_passes(self) -> None:
        """Coverage with valid source_ids should pass."""
        from forensia.report.report_validation import check_coverage_lineage

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Insert a source
                db.execute(
                    "INSERT INTO evidence_sources ("
                    "source_id, artifact_family, ingest_status, created_at, updated_at"
                    ") VALUES ('src-001', 'evtx', 'normalized', now(), now())"
                )
                # Insert coverage with valid source_ids
                db.execute(
                    "INSERT INTO evidence_coverage ("
                    "capability, source_family, state, source_ids, confidence, derived_at"
                    ") VALUES ('test_cap', 'evtx', 'available', ['src-001'], 0.9, now())"
                )
                findings = check_coverage_lineage(db)
                lineage_errors = [
                    f
                    for f in findings
                    if f.check_name == "coverage_lineage" and f.severity == "error"
                ]
                self.assertEqual(len(lineage_errors), 0)


if __name__ == "__main__":
    unittest.main()
