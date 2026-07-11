from __future__ import annotations

import tempfile
import unittest

import duckdb

from forensia.core.case import Case, detect_epochs
from forensia.db.database import CaseDB
from forensia.report.answers.summary_rows import host_summary_rows


def _create_db_with_events(rows: list[tuple]) -> duckdb.DuckDBPyConnection:
    """Create an in-memory DuckDB with evtx_events table and insert rows.

    Each row is (evidence_id, event_id, timestamp, computer, channel).
    """
    conn = duckdb.connect(":memory:")
    conn.execute(
        "CREATE TABLE evtx_events ("
        "  evidence_id VARCHAR, event_id INTEGER, timestamp TIMESTAMP,"
        "  computer VARCHAR, channel VARCHAR"
        ")"
    )
    for row in rows:
        conn.execute(
            "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel) VALUES (?, ?, ?, ?, ?)",
            row,
        )
    return conn


class HostEpochDetectionTests(unittest.TestCase):
    """R2-16: Host identity epoch detection and canonicalization."""

    def test_pre_deployment_host_labeled(self) -> None:
        """Host with pre-2010 bulk and 2015 trickle -> bulk pre-deployment, trickle active."""
        conn = _create_db_with_events(
            [
                # Host A: active only
                ("evtx-hostA-001", 4624, "2026-03-01 10:00:00", "HOST-A", "Security"),
                ("evtx-hostA-002", 4624, "2026-03-02 10:00:00", "HOST-A", "Security"),
                ("evtx-hostA-003", 4624, "2026-03-03 10:00:00", "HOST-A", "Security"),
                ("evtx-hostA-004", 4624, "2026-03-04 10:00:00", "HOST-A", "Security"),
                # Host B: bulk in 2010 + trickle in 2015
                ("evtx-hostB-001", 4624, "2010-06-01 08:00:00", "HOST-B", "Security"),
                ("evtx-hostB-002", 4624, "2010-06-02 08:00:00", "HOST-B", "Security"),
                ("evtx-hostB-003", 4624, "2010-06-03 08:00:00", "HOST-B", "Security"),
                ("evtx-hostB-004", 4624, "2015-03-25 10:00:00", "HOST-B", "Security"),
            ]
        )
        epochs = detect_epochs(conn, epoch_gap_days=90)
        self.assertIn("HOST-A", epochs)
        self.assertEqual(len(epochs["HOST-A"]), 1)
        self.assertEqual(epochs["HOST-A"][0]["label"], "active")
        self.assertIn("HOST-B", epochs)
        self.assertEqual(len(epochs["HOST-B"]), 2)
        pre = [c for c in epochs["HOST-B"] if c["label"] == "pre-deployment"]
        act = [c for c in epochs["HOST-B"] if c["label"] == "active"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["event_count"], 3)
        self.assertEqual(len(act), 1)
        self.assertEqual(act[0]["event_count"], 1)

    def test_case_folded_duplicates_merge(self) -> None:
        """Case/whitespace duplicates merge to one canonical row."""
        conn = _create_db_with_events(
            [
                ("evtx-001", 4624, "2026-03-01 10:00:00", "informant-PC", "Security"),
                ("evtx-002", 4624, "2026-03-02 10:00:00", "INFORMANT-PC", "Security"),
                (
                    "evtx-003",
                    4624,
                    "2026-03-03 10:00:00",
                    "  informant-PC  ",
                    "Security",
                ),
            ]
        )
        epochs = detect_epochs(conn)
        # All three variant names map to the same canonical key
        self.assertEqual(len(epochs), 1)
        canonical = list(epochs.keys())[0]
        self.assertEqual(canonical, "INFORMANT-PC")

    def test_all_active_no_note_column(self) -> None:
        """When all hosts are active, the note column is omitted."""
        conn = _create_db_with_events(
            [
                ("evtx-001", 4624, "2026-03-01 10:00:00", "HOST-A", "Security"),
                ("evtx-002", 4624, "2026-03-02 10:00:00", "HOST-B", "Security"),
            ]
        )
        epochs = detect_epochs(conn)
        for host_key in ("HOST-A", "HOST-B"):
            self.assertEqual(epochs[host_key][0]["label"], "active")

    def test_dominant_time_range_excludes_pre_deployment(self) -> None:
        """extract_time_range excludes within-host pre-deployment clusters from dominant range."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel) VALUES "
                    "('evtx-a1', 4624, '2026-03-01 10:00:00', 'HOST-A', 'Security'),"
                    "('evtx-a2', 4624, '2026-03-02 10:00:00', 'HOST-A', 'Security'),"
                    # Host B has both pre-deployment bulk and active trickle
                    "('evtx-b1', 4624, '2010-06-01 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b2', 4624, '2010-06-02 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b3', 4624, '2010-06-03 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b4', 4624, '2015-03-25 10:00:00', 'HOST-B', 'Security')"
                )
                case.extract_time_range(db)
                tr = case.time_range
                full = case.full_time_range
                # Full range includes both epochs
                self.assertEqual(full["earliest"], "2010-06-01 08:00:00")
                self.assertEqual(full["latest"], "2026-03-02 10:00:00")
                # Dominant range excludes within-host pre-deployment clusters (2010 bulk)
                self.assertEqual(tr["earliest"], "2015-03-25 10:00:00")
                self.assertEqual(tr["latest"], "2026-03-02 10:00:00")

    def testhost_summary_rows_annotated(self) -> None:
        """host_summary_rows includes note for hosts with pre-deployment clusters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events (evidence_id, event_id, timestamp, computer, channel) VALUES "
                    "('evtx-a1', 4624, '2026-03-01 10:00:00', 'HOST-A', 'Security'),"
                    "('evtx-a2', 4624, '2026-03-02 10:00:00', 'HOST-A', 'Security'),"
                    # Host B has both pre-deployment bulk and active trickle
                    "('evtx-b1', 4624, '2010-06-01 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b2', 4624, '2010-06-02 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b3', 4624, '2010-06-03 08:00:00', 'HOST-B', 'Security'),"
                    "('evtx-b4', 4624, '2015-03-25 10:00:00', 'HOST-B', 'Security')"
                )
                rows = host_summary_rows(db)
                # Host A should be active
                host_a = next(r for r in rows if str(r.get("host")).upper() == "HOST-A")
                self.assertIn("note", host_a)
                self.assertEqual(host_a["note"], "active")
                # Host B should have pre-deployment note
                host_b = next(r for r in rows if str(r.get("host")).upper() == "HOST-B")
                self.assertIn("note", host_b)
                self.assertIn("pre-deployment", host_b["note"])

    def test_empty_db_returns_empty_epochs(self) -> None:
        """detect_epochs returns empty dict for an empty evtx_events table."""
        conn = _create_db_with_events([])
        epochs = detect_epochs(conn)
        self.assertEqual(epochs, {})

    def test_single_host_is_active(self) -> None:
        """A single host with events is always active."""
        conn = _create_db_with_events(
            [
                ("evtx-001", 4624, "2026-03-01 10:00:00", "HOST-A", "Security"),
            ]
        )
        epochs = detect_epochs(conn)
        self.assertEqual(epochs["HOST-A"][0]["label"], "active")

    def test_multi_cluster_host(self) -> None:
        """Host with pre-2010 bulk and 2015 trickle gets two clusters, bulk pre-deployment."""
        conn = _create_db_with_events(
            [
                # 5 events in 2010 (pre-deployment bulk)
                ("evtx-b1", 4624, "2010-06-01 10:00:00", "HOST-B", "Security"),
                ("evtx-b2", 4624, "2010-06-02 10:00:00", "HOST-B", "Security"),
                ("evtx-b3", 4624, "2010-06-03 10:00:00", "HOST-B", "Security"),
                ("evtx-b4", 4624, "2010-06-04 10:00:00", "HOST-B", "Security"),
                ("evtx-b5", 4624, "2010-06-05 10:00:00", "HOST-B", "Security"),
                # 2 events in 2015 (active window)
                ("evtx-b6", 4624, "2015-03-25 10:00:00", "HOST-B", "Security"),
                ("evtx-b7", 4624, "2015-03-26 10:00:00", "HOST-B", "Security"),
            ]
        )
        epochs = detect_epochs(conn, epoch_gap_days=90)
        self.assertIn("HOST-B", epochs)
        self.assertEqual(len(epochs["HOST-B"]), 2)
        pre = [c for c in epochs["HOST-B"] if c["label"] == "pre-deployment"]
        act = [c for c in epochs["HOST-B"] if c["label"] == "active"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(len(act), 1)
        # Bulk (5 events in 2010) is pre-deployment
        self.assertEqual(pre[0]["event_count"], 5)
        self.assertIn("2010", pre[0]["first_seen"])
        # Trickle (2 events in 2015) is active
        self.assertEqual(act[0]["event_count"], 2)
        self.assertIn("2015", act[0]["first_seen"])


if __name__ == "__main__":
    unittest.main()
