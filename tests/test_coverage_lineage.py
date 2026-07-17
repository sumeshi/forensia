"""Tests for R8-03: Coverage timestamp boundary and source lineage normalization.

Tests verify:
- 1601 sentinel, 3320 overflow, normal 2015 timestamp → analysis window is 2015 only
- Raw artifact API can show excluded timestamps
- Available capability traces back to at least 1 source_id
- EVTX source hosts/channel/min/max match normalized rows
- add/backfill multiple times doesn't double-count metadata
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_lookup import lookup_evidence_record
from forensia.evidence.normalize import _update_source_status
from forensia.evidence.timestamp_policy import (
    TimestampPolicy,
    classify_timestamp,
    compute_plausible_bounds,
    filter_plausible_timestamps,
    is_plausible_timestamp,
)
from forensia.knowledge.coverage import (
    compute_evidence_coverage,
    get_coverage_summary,
    refresh_evidence_coverage,
)


class TimestampClassificationTests(unittest.TestCase):
    """Test timestamp classification logic."""

    def test_1601_sentinel_is_not_plausible(self) -> None:
        ts = datetime(1601, 1, 1)
        cls = classify_timestamp(ts)
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "sentinel_1601")

    def test_3320_overflow_is_not_plausible(self) -> None:
        ts = datetime(3320, 11, 16)
        cls = classify_timestamp(ts)
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "overflow")

    def test_1979_is_not_plausible(self) -> None:
        ts = datetime(1979, 12, 31)
        cls = classify_timestamp(ts)
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "pre_dos_epoch")

    def test_2015_is_plausible(self) -> None:
        ts = datetime(2015, 6, 15, 10, 30, 0)
        cls = classify_timestamp(ts)
        self.assertTrue(cls.is_plausible)
        self.assertEqual(cls.reason, "valid")

    def test_2024_is_plausible(self) -> None:
        ts = datetime(2024, 1, 15)
        cls = classify_timestamp(ts)
        self.assertTrue(cls.is_plausible)
        self.assertEqual(cls.reason, "valid")

    def test_none_is_not_plausible(self) -> None:
        cls = classify_timestamp(None)
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "null")

    def test_far_future_is_not_plausible(self) -> None:
        ts = datetime(2201, 1, 1)
        cls = classify_timestamp(ts)
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "overflow")

    def test_case_window_is_declarative_not_wall_clock_based(self) -> None:
        policy = TimestampPolicy(case_window_margin_days=30)
        cls = classify_timestamp(
            datetime(2014, 1, 1),
            policy,
            (datetime(2015, 1, 1), datetime(2015, 1, 31)),
        )
        self.assertFalse(cls.is_plausible)
        self.assertEqual(cls.reason, "outside-analysis-window")


class PlausibleBoundsTests(unittest.TestCase):
    """Test plausible bounds computation."""

    def test_mixed_timestamps_filter_sentinel(self) -> None:
        """1601 sentinel + 3320 overflow + normal 2015 → bounds are 2015 only."""
        timestamps = [
            datetime(1601, 1, 1),  # sentinel
            datetime(3320, 11, 16),  # overflow
            datetime(2015, 6, 15, 10, 30, 0),  # normal
            datetime(2015, 12, 25, 18, 0, 0),  # normal
        ]
        bounds = compute_plausible_bounds(timestamps)
        self.assertIsNotNone(bounds.min_time)
        self.assertIsNotNone(bounds.max_time)
        self.assertEqual(bounds.min_time.year, 2015)
        self.assertEqual(bounds.max_time.year, 2015)
        self.assertEqual(bounds.excluded_count, 2)
        self.assertIn("sentinel_1601", bounds.excluded_reasons)
        self.assertIn("overflow", bounds.excluded_reasons)

    def test_all_sentinel_returns_none_bounds(self) -> None:
        """All sentinel timestamps → None bounds."""
        timestamps = [
            datetime(1601, 1, 1),
            datetime(1601, 1, 1),
        ]
        bounds = compute_plausible_bounds(timestamps)
        self.assertIsNone(bounds.min_time)
        self.assertIsNone(bounds.max_time)
        self.assertEqual(bounds.excluded_count, 2)

    def test_empty_list_returns_none_bounds(self) -> None:
        bounds = compute_plausible_bounds([])
        self.assertIsNone(bounds.min_time)
        self.assertIsNone(bounds.max_time)
        self.assertEqual(bounds.excluded_count, 0)

    def test_normal_timestamps_return_correct_bounds(self) -> None:
        timestamps = [
            datetime(2015, 1, 1),
            datetime(2015, 6, 15),
            datetime(2015, 12, 31),
        ]
        bounds = compute_plausible_bounds(timestamps)
        self.assertEqual(bounds.min_time, datetime(2015, 1, 1))
        self.assertEqual(bounds.max_time, datetime(2015, 12, 31))
        self.assertEqual(bounds.excluded_count, 0)


class FilterTimestampsTests(unittest.TestCase):
    """Test timestamp filtering."""

    def test_filter_separates_plausible_from_sentinel(self) -> None:
        timestamps = [
            datetime(1601, 1, 1),
            datetime(2015, 6, 15),
            datetime(3320, 11, 16),
            datetime(2020, 1, 1),
        ]
        plausible, excluded = filter_plausible_timestamps(timestamps)
        self.assertEqual(len(plausible), 2)
        self.assertEqual(plausible[0], datetime(2015, 6, 15))
        self.assertEqual(plausible[1], datetime(2020, 1, 1))
        self.assertEqual(excluded["sentinel_1601"], 1)
        self.assertEqual(excluded["overflow"], 1)

    def test_quick_check(self) -> None:
        self.assertTrue(is_plausible_timestamp(datetime(2015, 1, 1)))
        self.assertFalse(is_plausible_timestamp(datetime(1601, 1, 1)))
        self.assertFalse(is_plausible_timestamp(None))


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

    def test_migration_backfills_source_metadata_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO ingested_files (sha256, path, source_kind) "
                    "VALUES ('legacy-evtx', '/legacy/Security.evtx', 'evtx')"
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, row_count, hosts, "
                    "min_time, max_time, created_at, updated_at) VALUES "
                    "('legacy-evtx', 'evtx', 'normalized', 99, [], "
                    "'1601-01-01', '3320-11-16', now(), now())"
                )
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, source_file, channel, computer, timestamp) VALUES "
                    "('evtx-legacy', '/legacy/Security.evtx', 'Security', "
                    "'HOST-1', '2015-03-22')"
                )
                db.execute(
                    "DELETE FROM schema_migrations "
                    "WHERE migration_key = 'r8_03_coverage_lineage_v2'"
                )
            with CaseDB(case) as db:
                row = db.execute(
                    "SELECT row_count, channel, hosts, min_time, max_time "
                    "FROM evidence_sources WHERE source_id = 'legacy-evtx'"
                ).fetchone()
                self.assertEqual(row[0], 1)
                self.assertEqual(row[1], "Security")
                self.assertIn("HOST-1", str(row[2]))
                self.assertEqual(row[3], datetime(2015, 3, 22))
                self.assertEqual(row[4], datetime(2015, 3, 22))


class EVTXSourceMetadataTests(unittest.TestCase):
    """Test EVTX source metadata consistency."""

    def test_evidence_sources_hosts_populated(self) -> None:
        """Repeated backfill derives, rather than assumes, EVTX metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO ingested_files (sha256, path, source_kind) "
                    "VALUES ('src-001', '/evidence/Security.evtx', 'evtx')"
                )
                db.execute(
                    "INSERT INTO evidence_sources "
                    "(source_id, artifact_family, ingest_status, row_count, hosts, "
                    "created_at, updated_at) VALUES "
                    "('src-001', 'evtx', 'parsed', 0, [], now(), now())"
                )
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, source_file, channel, computer, timestamp) VALUES "
                    "('evtx-1', 'src-001', 'Security', 'HOST-PC', '2015-06-15 10:00:00'), "
                    "('evtx-2', 'src-001', 'Security', 'HOST-PC', '2015-06-15 10:01:00')"
                )
                counts = {"evtx_rows": 2}
                _update_source_status(db, ["src-001"], counts)
                _update_source_status(db, ["src-001"], counts)
                row = db.execute(
                    "SELECT row_count, hosts, channel, min_time, max_time "
                    "FROM evidence_sources "
                    "WHERE source_id = 'src-001'"
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
