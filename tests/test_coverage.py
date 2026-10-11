"""Tests for M1: evidence source tracking and coverage computation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.knowledge.coverage import (
    _load_yaml,
    derive_required_capabilities,
    get_coverage_summary,
    observation_catalog,
    observation_condition_error,
    refresh_evidence_coverage,
)


class RequiredCapabilityDerivationTests(unittest.TestCase):
    """T02: one shared derivation owner with declared-spec priority."""

    def test_declared_capabilities_short_circuit_inference(self) -> None:
        self.assertEqual(
            derive_required_capabilities(
                ["logon"],
                support_conditions={"keywords": ["evtx_events 4624"]},
            ),
            ["logon"],
        )

    def test_support_conditions_derive_capabilities(self) -> None:
        self.assertEqual(
            derive_required_capabilities(
                support_conditions={"keywords": ["registry_artifacts"]},
            ),
            ["registry_observation"],
        )
        self.assertEqual(
            derive_required_capabilities(
                support_conditions={"co_observed_event_ids": [4688]},
            ),
            ["process_execution"],
        )
        # Structured conditions are the only inference input; without them
        # nothing is inferred (and no prose inference exists).
        self.assertEqual(
            derive_required_capabilities(required_capabilities=[]),
            [],
        )
        self.assertEqual(
            derive_required_capabilities(
                support_conditions={
                    "observation": {
                        "family": "prefetch",
                        "capability": "process_execution",
                        "field": "executable_name",
                        "operator": "equals",
                        "value": "powershell.exe",
                    }
                }
            ),
            ["process_execution"],
        )

    def test_observation_catalog_uses_capability_families_and_schema_fields(
        self,
    ) -> None:
        catalog = observation_catalog()
        self.assertIn("process_execution", catalog["prefetch"]["capabilities"])
        self.assertIn("executable_name", catalog["prefetch"]["fields"])
        self.assertIn("exec_times", catalog["prefetch"]["fields"])
        self.assertNotIn("exec_time", catalog["prefetch"]["fields"])
        self.assertIn("file_path", catalog["mft"]["fields"])
        self.assertNotIn("timestamp", catalog["mft"]["fields"])
        self.assertEqual(
            catalog["mft"]["boolean_fields"], ["is_deleted", "is_directory"]
        )
        self.assertIn("registry_observation", catalog["registry"]["capabilities"])
        self.assertIn("key_path", catalog["registry"]["fields"])

    def test_observation_condition_validation_is_shared_and_typed(self) -> None:
        observation = {
            "family": "registry",
            "capability": "registry_observation",
            "field": "key_path",
            "operator": "contains",
            "value": "Run\\",
        }
        self.assertIsNone(observation_condition_error({"observation": observation}))
        self.assertIsNone(
            observation_condition_error({"observation": observation, "min_count": 2})
        )
        self.assertEqual(
            observation_condition_error(
                {
                    "observation": {
                        "family": "prefetch",
                        "capability": "process_execution",
                        "field": "exec_time",
                        "operator": "equals",
                        "value": "2015-03-25 14:00:00",
                    }
                }
            ),
            "observation-field-unsupported",
        )
        invalid = (
            (
                {"observation": {**observation, "family": "evtx"}},
                "observation-family-unsupported",
            ),
            (
                {
                    "observation": observation,
                    "co_observed_event_ids": [4624],
                },
                "mixed-verification-condition-kinds",
            ),
            (
                {"observation": {**observation, "value": "   "}},
                "observation-value-invalid",
            ),
            (
                {"observation": observation, "min_count": True},
                "observation-min-count-invalid",
            ),
            (
                {"observation": observation, "min_count": 0},
                "observation-min-count-invalid",
            ),
            (
                {
                    "observation": {
                        **observation,
                        "operator": "equals",
                        "value": "Infinity",
                    }
                },
                "observation-value-invalid",
            ),
            (
                {"observation": {**observation, "operator": "contains", "value": 5}},
                "observation-operator-value-invalid",
            ),
            (
                {
                    "observation": {
                        **observation,
                        "operator": "greater_than",
                        "value": "sometime later",
                    }
                },
                "observation-operator-value-invalid",
            ),
        )
        for condition, error in invalid:
            with self.subTest(condition=condition):
                self.assertEqual(observation_condition_error(condition), error)

    def test_boolean_observations_require_boolean_equality(self) -> None:
        observation = {
            "family": "mft",
            "capability": "file_activity",
            "field": "is_deleted",
            "operator": "equals",
            "value": True,
        }
        self.assertIsNone(observation_condition_error({"observation": observation}))
        self.assertIsNone(
            observation_condition_error(
                {"observation": {**observation, "value": False}}
            )
        )
        self.assertEqual(
            "observation-value-invalid",
            observation_condition_error(
                {"observation": {**observation, "value": "true"}}
            ),
        )
        self.assertEqual(
            "observation-operator-value-invalid",
            observation_condition_error(
                {
                    "observation": {
                        **observation,
                        "operator": "contains",
                    }
                }
            ),
        )
        self.assertEqual(
            "observation-value-invalid",
            observation_condition_error(
                {
                    "observation": {
                        **observation,
                        "field": "size",
                    }
                }
            ),
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
                    "event_id) VALUES ('evtx-1', 'evtx1', 'Security', 4624)"
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
    """Schema declarations are checked by the doctor audit, not pinned here."""

    def test_required_yaml_loader_reports_missing_and_non_mapping_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "required.yaml"
            with self.assertRaisesRegex(FileNotFoundError, str(path)):
                _load_yaml(path)
            path.write_text("- item\n", encoding="utf-8")
            with self.assertRaisesRegex(TypeError, str(path)):
                _load_yaml(path)
