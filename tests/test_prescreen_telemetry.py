"""Tests for G-8: Pre-screen telemetry availability at seeding time.

Verifies that hypotheses requiring event IDs absent from the case are
immediately resolved as 'untestable' during seeding, avoiding wasted LLM
cycles.
"""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.seeding import _prescreen_telemetry_availability
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB


class PrescreenTelemetryAvailabilityTests(unittest.TestCase):
    """_prescreen_telemetry_availability resolves hypotheses with
    entirely missing event IDs as untestable at seeding time."""

    def _make_session(
        self, db: CaseDB, session_id: str = "test-session"
    ) -> SessionState:
        """Create a SessionState with the investigation_sessions row."""
        db.execute(
            "INSERT INTO investigation_sessions "
            "(session_id, started_at, finished_at, iterations, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (session_id, "2025-01-01 00:00:00", None, 0, "running"),
        )
        return SessionState(session_id=session_id, iteration=0)

    def test_hypothesis_with_all_missing_event_ids_resolved_untestable(
        self,
    ) -> None:
        """A hypothesis requiring event_id 99999 (not in case) should be
        resolved as untestable at seeding time."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Insert only event_id 4624 in the case
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, event_id, timestamp, computer) "
                    "VALUES (?, ?, ?, ?)",
                    ("evtx-001", 4624, "2025-01-01 10:00:00", "PC-01"),
                )
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Hypothesis requiring missing event 99999",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={
                        "co_observed_event_ids": [99999],
                    },
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                # Should be resolved as untestable
                self.assertEqual(0, len(state.active_hypotheses))
                self.assertEqual(1, len(state.resolved_hypotheses))
                resolved = state.resolved_hypotheses[0]
                self.assertEqual("untestable", resolved.verdict)
                self.assertEqual("untestable", resolved.status)
                self.assertIn("99999", resolved.summary)
                self.assertIn("absence of telemetry", resolved.summary)

    def test_hypothesis_with_some_existing_event_ids_proceeds(self) -> None:
        """A hypothesis requiring event_ids [4624, 99999] should proceed
        (not resolved) because 4624 exists in the case."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, event_id, timestamp, computer) "
                    "VALUES (?, ?, ?, ?)",
                    ("evtx-001", 4624, "2025-01-01 10:00:00", "PC-01"),
                )
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Hypothesis requiring existing event 4624",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={
                        "co_observed_event_ids": [4624, 99999],
                    },
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                # Should remain active (some required IDs exist)
                self.assertEqual(1, len(state.active_hypotheses))
                self.assertEqual(0, len(state.resolved_hypotheses))
                self.assertEqual(
                    "draft-rule-1-decl-1", state.active_hypotheses[0].id
                )

    def test_hypothesis_without_confirm_when_is_skipped(self) -> None:
        """A hypothesis without confirm_when is not affected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Hypothesis without confirm_when",
                    status="active",
                    source_rule_ids=["some-rule"],
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                self.assertEqual(1, len(state.active_hypotheses))
                self.assertEqual(0, len(state.resolved_hypotheses))

    def test_hypothesis_without_co_observed_event_ids_is_skipped(self) -> None:
        """A hypothesis with confirm_when but no co_observed_event_ids is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Hypothesis with confirm_when but no co_observed",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={"same_host": True, "within_minutes": 30},
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                self.assertEqual(1, len(state.active_hypotheses))
                self.assertEqual(0, len(state.resolved_hypotheses))

    def test_mixed_hypotheses_partial_resolution(self) -> None:
        """With multiple hypotheses, only those with all-missing IDs are resolved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Only event_id 4624 exists
                db.execute(
                    "INSERT INTO evtx_events "
                    "(evidence_id, event_id, timestamp, computer) "
                    "VALUES (?, ?, ?, ?)",
                    ("evtx-001", 4624, "2025-01-01 10:00:00", "PC-01"),
                )
                state = self._make_session(db)
                hyp_active = Hypothesis(
                    id="hyp-active",
                    description="Needs 4624 which exists",
                    status="active",
                    source_rule_ids=["rule-1"],
                    confirm_when={"co_observed_event_ids": [4624]},
                )
                hyp_untestable = Hypothesis(
                    id="hyp-untestable",
                    description="Needs 99999 which does not exist",
                    status="active",
                    source_rule_ids=["rule-2"],
                    confirm_when={"co_observed_event_ids": [99999]},
                )
                state.active_hypotheses = [hyp_active, hyp_untestable]

                _prescreen_telemetry_availability(db, state, "test-session")

                self.assertEqual(1, len(state.active_hypotheses))
                self.assertEqual("hyp-active", state.active_hypotheses[0].id)
                self.assertEqual(1, len(state.resolved_hypotheses))
                self.assertEqual("hyp-untestable", state.resolved_hypotheses[0].id)
                self.assertEqual(
                    "untestable", state.resolved_hypotheses[0].verdict
                )

    def test_untestable_verdict_is_not_refuted(self) -> None:
        """The verdict taxonomy is preserved: untestable != refuted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Requires missing event",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={"co_observed_event_ids": [99999]},
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                resolved = state.resolved_hypotheses[0]
                self.assertEqual("untestable", resolved.verdict)
                self.assertNotEqual("refuted", resolved.verdict)
                self.assertNotEqual("confirmed", resolved.verdict)

    def test_no_evtx_events_table_does_not_crash(self) -> None:
        """If evtx_events table doesn't exist, screening is a no-op."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Drop the evtx_events table to simulate missing table
                db.execute("DROP TABLE IF EXISTS evtx_events")
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Requires event",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={"co_observed_event_ids": [99999]},
                )
                state.active_hypotheses = [hyp]

                # Should not crash
                _prescreen_telemetry_availability(db, state, "test-session")

                # With no available event_ids, ALL required are missing → untestable
                self.assertEqual(0, len(state.active_hypotheses))
                self.assertEqual(1, len(state.resolved_hypotheses))
                self.assertEqual(
                    "untestable", state.resolved_hypotheses[0].verdict
                )

    def test_empty_co_observed_event_ids_is_skipped(self) -> None:
        """A hypothesis with an empty co_observed_event_ids list is skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = self._make_session(db)
                hyp = Hypothesis(
                    id="draft-rule-1-decl-1",
                    description="Hypothesis with empty co_observed",
                    status="active",
                    source_rule_ids=["some-rule"],
                    confirm_when={"co_observed_event_ids": []},
                )
                state.active_hypotheses = [hyp]

                _prescreen_telemetry_availability(db, state, "test-session")

                self.assertEqual(1, len(state.active_hypotheses))
                self.assertEqual(0, len(state.resolved_hypotheses))


if __name__ == "__main__":
    unittest.main()
