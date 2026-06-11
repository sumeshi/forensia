"""Regression tests for defects found in the post-implementation review (R2 round).

Covers:
- _resolve_hypothesis accepts sample_rows (production TypeError) and interpolates
  follow-up questions / feeds verdict timeline entries (R2-03 / R2-11 feeder b)
- get_profile_event_ids returns a copy (global case-profile pollution)
- validate_select_sql still rejects mixed-type COALESCE (swallowed ValueError)
- benign-context gate restricted to required_entities columns (R2-06)
- _co_observation_satisfied sliding window over noisy multi-day rows (R2-04)
- MemoryManager.regenerate_timeline_from_db idempotence
"""

from __future__ import annotations

import datetime
import tempfile
import unittest
from typing import Any

from forensia.ai.case_profile import get_profile_event_ids, set_case_profile
from forensia.ai.checker import _co_observation_satisfied, _verify_verdict_consistency
from forensia.ai.hypothesis_manager import (
    _feed_verdict_to_timeline,
    _interpolate_follow_up,
    _resolve_hypothesis,
)
from forensia.ai.sql_templates import validate_select_sql
from forensia.core.case import Case
from forensia.core.memory import MemoryManager
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB


class ResolveHypothesisSampleRowsTests(unittest.TestCase):
    """_resolve_hypothesis must accept sample_rows and feed the case timeline."""

    def test_resolve_accepts_sample_rows_and_feeds_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(id="H-1", description="logon activity on host", status="active")
                    ],
                )
                rows = [
                    {
                        "event_id": 4624,
                        "timestamp": "2025-01-01 10:00:00",
                        "computer": "PC-01",
                        "evidence_id": "evtx-security-000000000001",
                    }
                ]
                # Regression: this call raised TypeError (unexpected keyword
                # argument 'sample_rows') before the fix.
                _resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-1",
                    verdict="confirmed",
                    summary="confirmed by query",
                    session_id="S-1",
                    sample_rows=rows,
                )
                self.assertEqual(0, len(state.active_hypotheses))
                self.assertEqual(1, len(state.resolved_hypotheses))
                timeline = db.execute(
                    "SELECT source, ref_id, host, evidence_id FROM case_timeline"
                ).fetchall()
                self.assertEqual(1, len(timeline))
                self.assertEqual(("verdict", "H-1", "PC-01", "evtx-security-000000000001"), timeline[0])


class FollowUpInterpolationTests(unittest.TestCase):
    def test_placeholders_filled_from_sample_rows(self) -> None:
        rows = [{"src_ip": "10.0.0.5", "computer": "PC-01"}]
        rendered = _interpolate_follow_up(
            "Is {src_ip} consistent with the session source on {computer}?", rows
        )
        self.assertEqual("Is 10.0.0.5 consistent with the session source on PC-01?", rendered)

    def test_unresolvable_placeholder_returns_none(self) -> None:
        rows = [{"computer": "PC-01", "src_ip": None}]
        self.assertIsNone(
            _interpolate_follow_up("Is {src_ip} consistent on {computer}?", rows)
        )

    def test_no_placeholders_passthrough(self) -> None:
        self.assertEqual("plain question", _interpolate_follow_up("plain question", []))

    def test_feed_verdict_skips_rows_without_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _feed_verdict_to_timeline(db, "H-9", "confirmed", "desc", [{"computer": "PC"}])
                count = db.execute("SELECT COUNT(*) FROM case_timeline").fetchone()[0]
                self.assertEqual(0, count)


class ProfileEventIdsCopyTests(unittest.TestCase):
    """Mutating the returned set must not pollute the module-global profile."""

    def tearDown(self) -> None:
        set_case_profile(None, None)

    def test_returned_set_is_a_copy(self) -> None:
        set_case_profile("profile", {4624, 4648})
        first = get_profile_event_ids()
        assert first is not None
        first.add(99999)
        second = get_profile_event_ids()
        self.assertEqual({4624, 4648}, second)


class CoalesceValidationRegressionTests(unittest.TestCase):
    """The broad sqlglot exception guard must not swallow validation errors."""

    def test_mixed_coalesce_literals_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_select_sql(
                "SELECT COALESCE('a', 1) FROM evtx_events"
            )


class BenignGateRequiredEntitiesTests(unittest.TestCase):
    """Benign-context downgrade only counts rules on required_entities columns."""

    def test_machine_subject_does_not_veto_human_target_hypothesis(self) -> None:
        hypothesis = Hypothesis(
            id="h-human",
            description="user logons on host",
            required_entities=["target_user", "computer"],
        )
        rows = [
            {"subject_user": "PC-01$", "target_user": "alice", "computer": "PC-01", "evidence_id": "ev1"},
            {"subject_user": "PC-01$", "target_user": "bob", "computer": "PC-01", "evidence_id": "ev2"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4624],
            "evidence_ids": ["ev1", "ev2"],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", hypothesis, result_summary)
        self.assertEqual("confirmed", verdict)
        self.assertIsNone(reason)

    def test_machine_target_vetoes_when_target_user_is_required(self) -> None:
        hypothesis = Hypothesis(
            id="h-machine",
            description="explicit credentials targeting account",
            required_entities=["target_user"],
        )
        rows = [
            {"subject_user": "admin", "target_user": "WIN-ABC$", "evidence_id": "ev1"},
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4648],
            "evidence_ids": ["ev1"],
        }
        verdict, reason = _verify_verdict_consistency("confirmed", "", hypothesis, result_summary)
        self.assertEqual("inconclusive", verdict)
        self.assertIsNotNone(reason)
        self.assertIn("benign-context", reason)


class CoObservationSlidingWindowTests(unittest.TestCase):
    """A valid co-observed pair inside a noisy multi-day result set must satisfy."""

    def test_valid_pair_inside_noisy_span(self) -> None:
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        rows = [
            # Noise: required-id rows days apart
            {"event_id": 25, "computer": "PC-01", "timestamp": (base - datetime.timedelta(days=2)).isoformat()},
            {"event_id": 4624, "computer": "PC-01", "timestamp": (base + datetime.timedelta(days=3)).isoformat()},
            # The valid pair: 2 minutes apart
            {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
            {"event_id": 4624, "computer": "PC-01", "timestamp": (base + datetime.timedelta(minutes=2)).isoformat()},
        ]
        satisfied, reason = _co_observation_satisfied(
            {"co_observed_event_ids": [25, 4624], "same_host": True, "within_minutes": 5},
            rows,
        )
        self.assertTrue(satisfied, reason)

    def test_no_pair_within_window(self) -> None:
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        rows = [
            {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
            {"event_id": 4624, "computer": "PC-01", "timestamp": (base + datetime.timedelta(hours=2)).isoformat()},
        ]
        satisfied, _reason = _co_observation_satisfied(
            {"co_observed_event_ids": [25, 4624], "same_host": True, "within_minutes": 5},
            rows,
        )
        self.assertFalse(satisfied)


class TimelineRegenerationIdempotenceTests(unittest.TestCase):
    def test_second_regeneration_reports_no_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            memory = MemoryManager(case)
            with CaseDB(case) as db:
                db.execute(
                    """
                    INSERT INTO case_timeline (entry_id, timestamp, source, ref_id, host, summary, evidence_id)
                    VALUES ('tl-1', '2025-01-01 10:00:00', 'finding', 'F-1', 'PC-01', 'test entry', 'evtx-1')
                    """
                )
                changed_first = memory.regenerate_timeline_from_db(db)
                changed_second = memory.regenerate_timeline_from_db(db)
                self.assertTrue(changed_first)
                self.assertFalse(changed_second)


if __name__ == "__main__":
    unittest.main()


# =====================================================================
# R3 review round (report pipeline simplification) regressions
# =====================================================================

from pathlib import Path

from forensia.ai.section_agent import _insufficient_evidence_placeholder
from forensia.report.writer import (
    _GateCtx,
    _build_host_note,
    _catalog_exe_globs,
    _catalog_path_terms,
    _check_failure_spam,
    _exe_glob_sql,
    _matches_exe_globs,
)
from forensia.rules.engine import (
    _annotate_finding_benign_context,
    _co_occurs_satisfied,
    build_co_occur_index,
)
from forensia.rules.models import Finding


class InsufficientEvidencePlaceholderTests(unittest.TestCase):
    """The skip placeholder must not trip the section quality gates."""

    def test_placeholder_passes_failure_spam_gate(self) -> None:
        ctx = _GateCtx(section_key="2_timeline", title="t", evidence_results=None, db=None)
        body = _insufficient_evidence_placeholder()
        note, cap = _check_failure_spam(body, ctx)
        self.assertIsNone(note)
        self.assertIsNone(cap)

    def test_placeholder_has_no_open_question_markers(self) -> None:
        body = _insufficient_evidence_placeholder()
        for marker in ("?", "？", "TBD", "要確認", "未調査", "XXX", "Block skipped"):
            self.assertNotIn(marker, body)


class CatalogDrivenIndicatorTests(unittest.TestCase):
    """Indicator lists must come from dfir_ioc_catalog.yaml, not code literals."""

    def test_no_case_specific_literals_in_writer_source(self) -> None:
        import forensia.report.writer as writer_module

        source = Path(writer_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("secret_project", source)
        self.assertNotIn("CCLEANER64.EXE", source)
        self.assertNotIn("'ERASER.EXE'", source)
        self.assertNotIn("GOOGLEDRIVESYNC", source)

    def test_catalog_globs_cover_known_tool_families(self) -> None:
        globs = _catalog_exe_globs("antiforensic_tools")
        self.assertTrue(globs)
        self.assertTrue(_matches_exe_globs("CCLEANER64.EXE", globs))
        self.assertTrue(_matches_exe_globs("Eraser.exe", globs))
        self.assertFalse(_matches_exe_globs("notepad.exe", globs))

    def test_exe_glob_sql_renders_like_predicates(self) -> None:
        sql = _exe_glob_sql("executable_name", ("ccleaner*.exe", "eraser.exe"))
        self.assertIn("LIKE 'ccleaner%.exe'", sql)
        self.assertIn("LIKE 'eraser.exe'", sql)
        self.assertEqual("FALSE", _exe_glob_sql("executable_name", ()))

    def test_catalog_path_terms_strip_env_tokens(self) -> None:
        terms = _catalog_path_terms("cloud_sync_artifacts")
        self.assertTrue(any("google/drive" in term for term in terms))
        self.assertFalse(any("%" in term for term in terms))


class CoOccursProximityTests(unittest.TestCase):
    """finding_benign_context co_occurs_event_ids must verify real proximity."""

    @staticmethod
    def _make_finding(service_name: str, timestamp: str) -> Finding:
        return Finding(
            finding_id="f-1",
            rule_id="r-1",
            title="service install",
            summary="",
            severity="critical",
            confidence=0.9,
            tags=["persistence"],
            evidence=[{
                "service_name": service_name,
                "timestamp": timestamp,
                "computer": "PC-01",
                "evidence_id": "evtx-system-000000000001",
            }],
        )

    def test_boot_proximate_install_downgraded(self) -> None:
        finding = self._make_finding("Microsoft Memory Module Driver", "2015-03-25 10:15:00")
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "PC-01")]}
        _annotate_finding_benign_context(finding, index)
        self.assertTrue(any(t.startswith("benign-context:") for t in finding.tags))
        self.assertLess(finding.confidence, 0.5)

    def test_install_far_from_boot_not_downgraded_by_boot_rule(self) -> None:
        finding = self._make_finding("Microsoft Memory Module Driver", "2015-03-25 14:00:00")
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "PC-01")]}
        _annotate_finding_benign_context(finding, index)
        self.assertNotIn("benign-context:boot-window-service-install", finding.tags)

    def test_missing_timestamp_is_conservative(self) -> None:
        condition = {"co_occurs_event_ids": [6005], "within_minutes": 10}
        self.assertFalse(_co_occurs_satisfied(condition, {"computer": "PC-01"}, {6005: []}))

    def test_different_host_does_not_match(self) -> None:
        condition = {"co_occurs_event_ids": [6005], "within_minutes": 10}
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "OTHER-PC")]}
        row = {"timestamp": "2015-03-25 10:15:00", "computer": "PC-01"}
        self.assertFalse(_co_occurs_satisfied(condition, row, index))


class HostNoteTests(unittest.TestCase):
    def test_multi_epoch_note_summarizes_both(self) -> None:
        clusters = [
            {"label": "pre-deployment", "display_name": "H", "first_seen": "2010-11-21 03:00:00", "last_seen": "2010-11-21 05:00:00", "event_count": 700},
            {"label": "active", "display_name": "H", "first_seen": "2015-03-25 10:00:00", "last_seen": "2015-03-25 10:20:00", "event_count": 5},
        ]
        note = _build_host_note(clusters)
        self.assertIn("pre-deployment bulk (2010", note)
        self.assertIn("2015-03-25", note)

    def test_single_active_epoch(self) -> None:
        clusters = [
            {"label": "active", "display_name": "H", "first_seen": "2015-03-22 10:00:00", "last_seen": "2015-03-25 10:00:00", "event_count": 4000},
        ]
        self.assertEqual("active", _build_host_note(clusters))
