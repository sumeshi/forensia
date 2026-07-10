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
from forensia.ai.check_guardrails import (
    _co_observation_satisfied,
    _verify_verdict_consistency,
)
from forensia.ai.hypothesis_manager import (
    _feed_verdict_to_timeline,
    _interpolate_follow_up,
    _resolve_hypothesis,
)
from forensia.ai.prompts.prompt_sections import (
    build_paragraph_narrate_messages,
    build_section_outline_messages,
)
from forensia.ai.prompts.sql_templates import validate_select_sql
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
                        Hypothesis(
                            id="H-1",
                            description="logon activity on host",
                            status="active",
                        )
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
                self.assertEqual(
                    ("verdict", "H-1", "PC-01", "evtx-security-000000000001"),
                    timeline[0],
                )


class FollowUpInterpolationTests(unittest.TestCase):
    def test_placeholders_filled_from_sample_rows(self) -> None:
        rows = [{"src_ip": "10.0.0.5", "computer": "PC-01"}]
        rendered = _interpolate_follow_up(
            "Is {src_ip} consistent with the session source on {computer}?", rows
        )
        self.assertEqual(
            "Is 10.0.0.5 consistent with the session source on PC-01?", rendered
        )

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
                _feed_verdict_to_timeline(
                    db, "H-9", "confirmed", "desc", [{"computer": "PC"}]
                )
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
            validate_select_sql("SELECT COALESCE('a', 1) FROM evtx_events")


class BenignGateRequiredEntitiesTests(unittest.TestCase):
    """Benign-context downgrade only counts rules on required_entities columns."""

    def test_machine_subject_does_not_veto_human_target_hypothesis(self) -> None:
        hypothesis = Hypothesis(
            id="h-human",
            description="user logons on host",
            required_entities=["target_user", "computer"],
        )
        rows = [
            {
                "subject_user": "PC-01$",
                "target_user": "alice",
                "computer": "PC-01",
                "evidence_id": "ev1",
            },
            {
                "subject_user": "PC-01$",
                "target_user": "bob",
                "computer": "PC-01",
                "evidence_id": "ev2",
            },
        ]
        result_summary: dict[str, Any] = {
            "sample_rows": rows,
            "event_id_set": [4624],
            "evidence_ids": ["ev1", "ev2"],
        }
        verdict, reason = _verify_verdict_consistency(
            "confirmed", "", hypothesis, result_summary
        )
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
        verdict, reason = _verify_verdict_consistency(
            "confirmed", "", hypothesis, result_summary
        )
        self.assertEqual("inconclusive", verdict)
        self.assertIsNotNone(reason)
        self.assertIn("benign-context", reason)


class CoObservationSlidingWindowTests(unittest.TestCase):
    """A valid co-observed pair inside a noisy multi-day result set must satisfy."""

    def test_valid_pair_inside_noisy_span(self) -> None:
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        rows = [
            # Noise: required-id rows days apart
            {
                "event_id": 25,
                "computer": "PC-01",
                "timestamp": (base - datetime.timedelta(days=2)).isoformat(),
            },
            {
                "event_id": 4624,
                "computer": "PC-01",
                "timestamp": (base + datetime.timedelta(days=3)).isoformat(),
            },
            # The valid pair: 2 minutes apart
            {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
            {
                "event_id": 4624,
                "computer": "PC-01",
                "timestamp": (base + datetime.timedelta(minutes=2)).isoformat(),
            },
        ]
        satisfied, reason = _co_observation_satisfied(
            {
                "co_observed_event_ids": [25, 4624],
                "same_host": True,
                "within_minutes": 5,
            },
            rows,
        )
        self.assertTrue(satisfied, reason)

    def test_no_pair_within_window(self) -> None:
        base = datetime.datetime(2025, 1, 1, 10, 0, 0)
        rows = [
            {"event_id": 25, "computer": "PC-01", "timestamp": base.isoformat()},
            {
                "event_id": 4624,
                "computer": "PC-01",
                "timestamp": (base + datetime.timedelta(hours=2)).isoformat(),
            },
        ]
        satisfied, _reason = _co_observation_satisfied(
            {
                "co_observed_event_ids": [25, 4624],
                "same_host": True,
                "within_minutes": 5,
            },
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


class RowWithEvidenceIdsCitableTests(unittest.TestCase):
    """row_with_evidence_ids must tag rows as citable: False when no evidence_id is present."""

    def test_row_without_evidence_id_gets_citable_false(self) -> None:
        from forensia.report.evidence_refs import row_with_evidence_ids

        row = {"src_ip": "10.0.0.5", "computer": "host1", "event_id": 4624}
        normalized = row_with_evidence_ids(row)
        self.assertIs(False, normalized.get("citable"))
        self.assertNotIn("evidence_id", normalized)
        self.assertNotIn("evidence_ids", normalized)

    def test_row_with_evidence_id_does_not_get_citable_false(self) -> None:
        from forensia.report.evidence_refs import row_with_evidence_ids

        row = {"src_ip": "10.0.0.5", "evidence_id": "evtx-security-000000000001"}
        normalized = row_with_evidence_ids(row)
        self.assertNotIn("citable", normalized)
        self.assertEqual("evtx-security-000000000001", normalized.get("evidence_id"))

    def testrow_with_evidence_ids_list_does_not_get_citable_false(self) -> None:
        from forensia.report.evidence_refs import row_with_evidence_ids

        row = {
            "src_ip": "10.0.0.5",
            "evidence_ids": [
                "evtx-security-000000000001",
                "evtx-security-000000000002",
            ],
        }
        normalized = row_with_evidence_ids(row)
        self.assertNotIn("citable", normalized)
        self.assertIn("evtx-security-000000000001", normalized.get("evidence_ids", []))


class VerdictLabeledKeyPointsTests(unittest.TestCase):
    """RC5: Verdict-labeled key points for narrative blocks."""

    def test_label_refuted_from_source_verdict(self) -> None:
        from forensia.ai.section_block_narrative import _label_key_points_with_verdicts

        outline = [
            {
                "heading": "Logon Activity",
                "key_points": ["Suspicious logon from WIN-PC"],
                "evidence_ids": ["evtx-001"],
            },
        ]
        collected = [
            {
                "evidence_ids": ["evtx-001"],
                "source_verdict": "block_contradicted",
                "finding_ids": [],
            },
        ]
        labeled = _label_key_points_with_verdicts(
            outline, collected, "block_contradicted"
        )
        self.assertEqual(1, len(labeled))
        self.assertTrue(labeled[0].startswith("[refuted]"), labeled[0])

    def test_label_confirmed_from_source_verdict(self) -> None:
        from forensia.ai.section_block_narrative import _label_key_points_with_verdicts

        outline = [
            {
                "heading": "Execution",
                "key_points": ["Eraser.exe was launched"],
                "evidence_ids": ["evtx-002"],
            },
        ]
        collected = [
            {
                "evidence_ids": ["evtx-002"],
                "source_verdict": "block_supported",
                "finding_ids": [],
            },
        ]
        labeled = _label_key_points_with_verdicts(outline, collected, "block_supported")
        self.assertEqual(1, len(labeled))
        self.assertTrue(labeled[0].startswith("[confirmed]"), labeled[0])

    def test_label_finding_confidence_from_confidence_field(self) -> None:
        from forensia.ai.section_block_narrative import _label_key_points_with_verdicts

        outline = [
            {
                "heading": "Services",
                "key_points": ["Service install detected"],
                "evidence_ids": ["evtx-003"],
            },
        ]
        collected = [
            {
                "evidence_ids": ["evtx-003"],
                "finding_ids": ["finding-1"],
                "confidence": 0.85,
            },
        ]
        labeled = _label_key_points_with_verdicts(outline, collected, "block_supported")
        self.assertEqual(1, len(labeled))
        self.assertIn("[finding, confidence=", labeled[0])
        self.assertIn("0.85", labeled[0])

    def test_unlabeled_when_no_verdict_info(self) -> None:
        from forensia.ai.section_block_narrative import _label_key_points_with_verdicts

        outline = [
            {
                "heading": "Misc",
                "key_points": ["Generic observation"],
                "evidence_ids": [],
            },
        ]
        labeled = _label_key_points_with_verdicts(outline, [], "")
        self.assertEqual(["Generic observation"], labeled)

    def test_fallback_to_overall_verdict_when_no_per_result_verdicts(self) -> None:
        from forensia.ai.section_block_narrative import _label_key_points_with_verdicts

        outline = [
            {
                "heading": "Seed",
                "key_points": ["Seed observation"],
                "evidence_ids": ["evtx-004"],
            },
        ]
        collected = [
            {"evidence_ids": ["evtx-004"], "finding_ids": [], "confidence": None},
        ]
        labeled = _label_key_points_with_verdicts(outline, collected, "block_supported")
        self.assertEqual(1, len(labeled))
        self.assertTrue(labeled[0].startswith("[confirmed]"), labeled[0])

    def test_narrate_prompt_rules_contain_verdict_label_guidance(self) -> None:
        from forensia.ai.prompts.prompt_sections import build_paragraph_narrate_messages

        messages, schema = build_paragraph_narrate_messages(
            heading="Test Heading",
            key_points=["[confirmed] observation one", "[refuted] false claim"],
            evidence_rows=[],
            template_body="Test template body",
        )
        system_content = messages[0]["content"]
        self.assertIn("[confirmed]", system_content)
        self.assertIn("[refuted]", system_content)
        self.assertIn("[finding, confidence=N]", system_content)
        self.assertIn(
            "Refuted items may only be mentioned as ruled-out", system_content
        )


if __name__ == "__main__":
    unittest.main()


# =====================================================================
# R3 review round (report pipeline simplification) regressions
# =====================================================================

from pathlib import Path

from forensia.ai.section_answers import _insufficient_evidence_placeholder
from forensia.knowledge import (
    catalog_exe_globs,
    catalog_path_terms,
    exe_glob_sql,
    matches_exe_globs,
)
from forensia.report.markdown import build_host_note
from forensia.report.quality_gates import GateContext, check_failure_spam
from forensia.rules.engine import (
    _annotate_finding_benign_context,
    _co_occurs_satisfied,
)
from forensia.rules.models import Finding


class InsufficientEvidencePlaceholderTests(unittest.TestCase):
    """The skip placeholder must not trip the section quality gates."""

    def test_placeholder_passes_failure_spam_gate(self) -> None:
        ctx = GateContext(
            section_key="2_timeline", title="t", evidence_results=None, db=None
        )
        body = _insufficient_evidence_placeholder()
        note, cap = check_failure_spam(body, ctx)
        self.assertIsNone(note)
        self.assertIsNone(cap)

    def test_placeholder_has_no_open_question_markers(self) -> None:
        body = _insufficient_evidence_placeholder()
        for marker in ("?", "？", "TBD", "XXX", "Block skipped"):
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
        globs = catalog_exe_globs("antiforensic_tools")
        self.assertTrue(globs)
        self.assertTrue(matches_exe_globs("CCLEANER64.EXE", globs))
        self.assertTrue(matches_exe_globs("Eraser.exe", globs))
        self.assertFalse(matches_exe_globs("notepad.exe", globs))

    def test_exe_glob_sql_renders_like_predicates(self) -> None:
        sql = exe_glob_sql("executable_name", ("ccleaner*.exe", "eraser.exe"))
        self.assertIn("LIKE 'ccleaner%.exe'", sql)
        self.assertIn("LIKE 'eraser.exe'", sql)
        self.assertEqual("FALSE", exe_glob_sql("executable_name", ()))

    def test_catalog_path_terms_strip_env_tokens(self) -> None:
        terms = catalog_path_terms("cloud_sync_artifacts")
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
            evidence=[
                {
                    "service_name": service_name,
                    "timestamp": timestamp,
                    "computer": "PC-01",
                    "evidence_id": "evtx-system-000000000001",
                }
            ],
        )

    def test_boot_proximate_install_downgraded(self) -> None:
        finding = self._make_finding(
            "Microsoft Memory Module Driver", "2015-03-25 10:15:00"
        )
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "PC-01")]}
        _annotate_finding_benign_context(finding, index)
        self.assertTrue(any(t.startswith("benign-context:") for t in finding.tags))
        self.assertLess(finding.confidence, 0.5)

    def test_install_far_from_boot_not_downgraded_by_boot_rule(self) -> None:
        finding = self._make_finding(
            "Microsoft Memory Module Driver", "2015-03-25 14:00:00"
        )
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "PC-01")]}
        _annotate_finding_benign_context(finding, index)
        self.assertNotIn("benign-context:boot-window-service-install", finding.tags)

    def test_missing_timestamp_is_conservative(self) -> None:
        condition = {"co_occurs_event_ids": [6005], "within_minutes": 10}
        self.assertFalse(
            _co_occurs_satisfied(condition, {"computer": "PC-01"}, {6005: []})
        )

    def test_different_host_does_not_match(self) -> None:
        condition = {"co_occurs_event_ids": [6005], "within_minutes": 10}
        index = {6005: [(datetime.datetime(2015, 3, 25, 10, 14, 0), "OTHER-PC")]}
        row = {"timestamp": "2015-03-25 10:15:00", "computer": "PC-01"}
        self.assertFalse(_co_occurs_satisfied(condition, row, index))


class HostNoteTests(unittest.TestCase):
    def test_multi_epoch_note_summarizes_both(self) -> None:
        clusters = [
            {
                "label": "pre-deployment",
                "display_name": "H",
                "first_seen": "2010-11-21 03:00:00",
                "last_seen": "2010-11-21 05:00:00",
                "event_count": 700,
            },
            {
                "label": "active",
                "display_name": "H",
                "first_seen": "2015-03-25 10:00:00",
                "last_seen": "2015-03-25 10:20:00",
                "event_count": 5,
            },
        ]
        note = build_host_note(clusters)
        self.assertIn("pre-deployment bulk (2010", note)
        self.assertIn("2015-03-25", note)

    def test_single_active_epoch(self) -> None:
        clusters = [
            {
                "label": "active",
                "display_name": "H",
                "first_seen": "2015-03-22 10:00:00",
                "last_seen": "2015-03-25 10:00:00",
                "event_count": 4000,
            },
        ]
        self.assertEqual("active", build_host_note(clusters))


class SectionReviewerTests(unittest.TestCase):
    """Deterministic rubric checks for narrative body quality (R7-01)."""

    def test_check_citation_overload_flags_paragraphs(self) -> None:
        from forensia.report.narrative_review import check_citation_overload

        body = "One cite evtx-security-000000000001.\n\nPara with evtx-security-000000000002, evtx-security-000000000003, evtx-security-000000000004, evtx-security-000000000005."
        problems = check_citation_overload(body)
        self.assertGreaterEqual(len(problems), 1)

    def test_check_pseudo_citations_flags_labels(self) -> None:
        from forensia.report.narrative_review import check_pseudo_citations

        body = (
            "The analysis shows (antiforensic_activity) and (STRUCTURED_OBSERVATIONS)."
        )
        problems = check_pseudo_citations(body)
        self.assertEqual(2, len(problems), problems)

    def test_check_pseudo_citations_fullwidth_parens(self) -> None:
        from forensia.report.narrative_review import check_pseudo_citations

        body = "Confirmed (antiforensic_activity) event."
        self.assertEqual(1, len(check_pseudo_citations(body)))

    def test_check_pseudo_citations_ignores_plain_words_and_ids(self) -> None:
        """Ordinary parenthesized words and real evidence IDs are not pseudo-citations."""
        from forensia.report.narrative_review import check_pseudo_citations

        body = "informant (informant) logged on (evtx-security-000000000122) at (4624)."
        self.assertEqual([], check_pseudo_citations(body))

    def test_review_narrative_body_combines_checks(self) -> None:
        from forensia.report.narrative_review import review_narrative_body

        body = (
            "Hypothesis H-010 remains open (STRUCTURED_OBSERVATIONS). "
            "IDs evtx-security-000000000001, evtx-security-000000000002, "
            "evtx-security-000000000003, evtx-security-000000000004 were cited."
        )
        problems = review_narrative_body(body)
        self.assertTrue(any("cites 4" in p for p in problems), problems)
        self.assertTrue(any("STRUCTURED_OBSERVATIONS" in p for p in problems), problems)
        self.assertTrue(any("H-010" in p for p in problems), problems)

    def test_review_and_rewrite_narrative_runs_at_most_one_rewrite(self) -> None:
        """R7-01 contract: dirty text gets at most one rewrite; clean text
        bypasses the LLM reviewer."""
        import tempfile
        from unittest import mock

        from forensia.ai import (
            section_block_context,
            section_block_narrative,
        )
        from forensia.ai.llm import llm_gateway
        from forensia.core.case import Case
        from forensia.db.database import CaseDB

        clean_body = "informant logon confirmed (evtx-security-000000000122)."
        dirty_body = (
            "As observed (STRUCTURED_OBSERVATIONS) gap-8b9254d65e is unresolved."
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                ctx = section_block_context._prepare_block_context(
                    case=case,
                    db=db,
                    section_key="1_overview",
                    title="Overview",
                    block_heading="Executive Summary",
                    template_body="<!-- mode: narrative; x -->",
                    base_url="http://127.0.0.1:1",
                    model="none",
                    memory=None,
                    max_queries=1,
                    evidence_keypoints=None,
                    question_mode=False,
                )
                narrate_calls = []
                with (
                    mock.patch.object(
                        llm_gateway,
                        "request_llm_json",
                        return_value={
                            "verdict": "rewrite",
                            "problems": ["dump"],
                            "guidance": "summarize",
                        },
                    ) as review_call,
                    mock.patch.object(
                        section_block_narrative,
                        "_narrate_paragraph_with_retry",
                        side_effect=lambda **kw: narrate_calls.append(kw) or clean_body,
                    ),
                ):
                    result = section_block_narrative._review_and_rewrite_narrative(
                        ctx,
                        dirty_body,
                        narrate_messages=[{"role": "system", "content": "narrate"}],
                        narrate_schema={"type": "object"},
                    )
                self.assertEqual(clean_body, result)
                self.assertEqual(1, review_call.call_count)
                self.assertEqual(1, len(narrate_calls), "exactly one rewrite call")
                rewrite_prompt = str(narrate_calls[0]["narrate_messages"])
                self.assertIn(
                    dirty_body, rewrite_prompt, "rewrite must see the previous body"
                )

                # Clean output passes the deterministic review without LLM calls.
                with (
                    mock.patch.object(
                        llm_gateway,
                        "request_llm_json",
                        return_value={
                            "verdict": "rewrite",
                            "problems": [],
                            "guidance": "",
                        },
                    ) as clean_review_call,
                    mock.patch.object(
                        section_block_narrative,
                        "_narrate_paragraph_with_retry",
                        return_value=dirty_body,
                    ) as clean_rewrite_call,
                ):
                    kept = section_block_narrative._review_and_rewrite_narrative(
                        ctx,
                        clean_body,
                        narrate_messages=[{"role": "system", "content": "narrate"}],
                        narrate_schema={"type": "object"},
                    )
                self.assertEqual(clean_body, kept)
                clean_review_call.assert_not_called()
                clean_rewrite_call.assert_not_called()

    def test_check_internal_ids_flags_gap_h(self) -> None:
        from forensia.report.narrative_review import check_internal_ids

        body = "The hypothesis H-010 and gap-8b9254d65e are unresolved."
        problems = check_internal_ids(body)
        self.assertGreaterEqual(len(problems), 2)

    def test_build_section_review_messages_includes_problems(self) -> None:
        from forensia.ai.prompts.prompt_sections import (
            SECTION_REVIEW_SCHEMA,
            build_section_review_messages,
        )

        msgs, schema = build_section_review_messages(
            "test", "body text", None, ["Citation overload"]
        )
        self.assertIn("Citation overload", msgs[1]["content"])
        self.assertTrue(schema == SECTION_REVIEW_SCHEMA or "verdict" in str(schema))


class HumanReadableIdsInstructionTests(unittest.TestCase):
    """Prompt rules must tell LLMs to use descriptions instead of raw internal IDs."""

    def test_narrator_rules_ban_raw_internal_ids(self) -> None:
        msgs, _ = build_paragraph_narrate_messages(
            heading="Test Section",
            key_points=["A key point"],
            evidence_rows=[],
            template_body="test",
        )
        system = msgs[0]["content"]
        self.assertIn("Do not use raw internal IDs", system)
        self.assertIn("gap-*", system)
        self.assertIn("H-*", system)
        self.assertIn("KP-*", system)

    def test_outline_rules_ban_raw_internal_ids(self) -> None:
        msgs, _ = build_section_outline_messages(
            template_body="## Test\nContent",
            relevant_evidence=[],
        )
        system = msgs[0]["content"]
        self.assertIn("Do not use raw internal IDs", system)
        self.assertIn("gap-*", system)
        self.assertIn("H-*", system)
        self.assertIn("KP-*", system)
