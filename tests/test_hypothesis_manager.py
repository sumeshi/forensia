"""Tests for hypothesis lifecycle in hypothesis_manager / hypothesis_model.

Covers:
  - similarity / semantic triple extraction used to merge duplicate hypotheses
  - stale propagation from hypothesis resolution to report sections
    (target_keypoint_id -> owning section, description keyword matching,
    rulepack-declared report_sections, update_count cap enforcement)
"""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.hypotheses.hypothesis_manager import (
    MAX_SECTION_UPDATES,
    mark_section_stale,
    merge_active_hypotheses,
    resolve_hypothesis,
)
from forensia.ai.hypotheses.hypothesis_model import (
    extract_semantic_triple,
    hypothesis_evidence_strength,
    hypothesis_similarity,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB
from forensia.report.sections.section_taxonomy import sections_for_keypoint


class TestSufficiencyIndependence(unittest.TestCase):
    def test_resolution_does_not_rewrite_machine_sufficiency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                state = SessionState(
                    session_id="S-1",
                    active_hypotheses=[
                        Hypothesis(id="H-SUFF", description="Unlinked claim")
                    ],
                )
                db.execute(
                    """
                    INSERT INTO hypotheses (
                        hypothesis_id, status, description, summary,
                        sufficiency_status, sufficiency_reason,
                        created_at, updated_at
                    ) VALUES (
                        'H-SUFF', 'active', 'Unlinked claim', '',
                        'insufficient', 'no evidence links', now(), now()
                    )
                    """
                )
                resolve_hypothesis(
                    db,
                    state,
                    "H-SUFF",
                    "confirmed",
                    "LLM confirmation",
                    "S-1",
                )
                status, reason = db.execute(
                    "SELECT sufficiency_status, sufficiency_reason "
                    "FROM hypotheses WHERE hypothesis_id = 'H-SUFF'"
                ).fetchone()
                self.assertEqual("insufficient", status)
                self.assertEqual("no evidence links", reason)


class TestExtractSemanticTriple:
    def test_target_fallback_pattern_does_not_crash(self) -> None:
        """Descriptions with a target keyword but no 'to/on/into/onto <word>' phrase
        previously raised IndexError (fallback pattern had no capturing group)."""
        triple = extract_semantic_triple(
            "Repeated 4625 failures targeting one account indicate brute-force"
        )
        assert triple["target"] == "account"

    def test_full_triple(self) -> None:
        triple = extract_semantic_triple(
            "Lateral movement by attacker to a server via stolen credentials"
        )
        assert triple["actor"] not in ("", None)
        assert triple["action"] == "lateral movement"
        assert triple["target"] == "server"

    def test_empty_description(self) -> None:
        triple = extract_semantic_triple("")
        assert triple == {"actor": "unknown", "action": "unknown", "target": "unknown"}


class TestHypothesisSimilarity:
    def test_similarity_handles_keyword_only_descriptions(self) -> None:
        """End-to-end: similarity between rule-seeded style descriptions must not raise."""
        left = "Explicit credential logon for account informant may indicate misuse"
        right = "Service installed shortly after logon suggests persistence"
        score = hypothesis_similarity(left, right)
        assert 0.0 <= score <= 1.0

    def test_identical_descriptions_score_high(self) -> None:
        text = "Repeated failed logons from a single source ip targeting one user"
        assert hypothesis_similarity(text, text) >= 0.85


class TestResolvedHypothesisDedup:
    """Regression: near-duplicate of a resolved hypothesis must not create
    a conflicting active hypothesis with opposite verdict."""

    def test_similar_to_resolved_is_bound_not_duplicated(self, capsys) -> None:
        """Hypothesis B with a near-identical description to a confirmed
        resolved hypothesis A is bound to A, not added as a separate active."""
        desc_a = "RDP lateral movement to deploy service on remote host"
        desc_b = "RDP lateral movement was used to deploy service on remote host"

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                # Persist H-001 as confirmed (resolved)
                db.execute(
                    """INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES (
                        'H-001', ?, 'confirmed', 'confirmed', 'done', 'broad_plan',
                        'S-1', 'S-2', now(), now(), '["rule-1"]', '["host"]', NULL
                    )""",
                    (desc_a,),
                )

                resolved = [
                    Hypothesis(
                        id="H-001",
                        description=desc_a,
                        status="confirmed",
                        verdict="confirmed",
                        summary="done",
                        source_rule_ids=["rule-1"],
                    ),
                ]

                merged = merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-new",
                            description=desc_b,
                            status="active",
                            source_rule_ids=["rule-2"],
                            required_entities=["host"],
                        ),
                    ],
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )

                # B should NOT appear as a separate active hypothesis
                assert len(merged) == 0, (
                    f"expected no active hypotheses, got {len(merged)}: "
                    f"{[h.description for h in merged]}"
                )

                # The resolved hypothesis should still be in DB with its verdict
                rows = db.execute(
                    "SELECT hypothesis_id, status, verdict "
                    "FROM hypotheses ORDER BY hypothesis_id"
                ).fetchall()
                assert len(rows) == 1, f"expected 1 row, got {len(rows)}"
                assert rows[0][0] == "H-001"
                assert rows[0][1] == "confirmed", (
                    f"resolved hypothesis status changed to {rows[0][1]}"
                )
                assert rows[0][2] == "confirmed"

                # Verify log records the binding decision
                captured = capsys.readouterr()
                assert "bound to resolved H-001" in captured.out, (
                    f"expected log about binding, got: {captured.out}"
                )

    def test_identical_to_resolved_not_duplicated(self, capsys) -> None:
        """Exact description match against a resolved hypothesis
        does not create a new active hypothesis."""
        desc = "Backdoor via service install using explicit credentials"

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                db.execute(
                    """INSERT INTO hypotheses (
                        hypothesis_id, description, status, verdict, summary, origin,
                        created_session, resolved_session, created_at, updated_at,
                        source_rule_ids, required_entities, confirm_when
                    ) VALUES (
                        'H-004', ?, 'confirmed', 'confirmed',
                        'confirmed by evidence', 'broad_plan',
                        'S-1', 'S-2', now(), now(),
                        '["rule-backdoor"]', '["service"]',
                        '{"co_observed_event_ids": ["E-001"]}'
                    )""",
                    (desc,),
                )

                resolved = [
                    Hypothesis(
                        id="H-004",
                        description=desc,
                        status="confirmed",
                        verdict="confirmed",
                        summary="confirmed by evidence",
                        source_rule_ids=["rule-backdoor"],
                        confirm_when={"co_observed_event_ids": ["E-001"]},
                    ),
                ]

                merged = merge_active_hypotheses(
                    db=db,
                    current=[],
                    updates=[
                        Hypothesis(
                            id="H-draft",
                            description=desc,
                            status="active",
                            source_rule_ids=["rule-backdoor"],
                            required_entities=["service"],
                        ),
                    ],
                    resolved=resolved,
                    session_id="session-test",
                    origin="broad_plan",
                )

                # Should not be added to active
                assert len(merged) == 0

                captured = capsys.readouterr()
                assert "bound to resolved H-004" in captured.out


class TestHypothesisEvidenceStrength:
    """Unit tests for hypothesis_evidence_strength scoring."""

    def test_llm_speculated_scores_zero(self) -> None:
        h = Hypothesis(
            id="H-000",
            description="LLM-speculated hypothesis",
            status="active",
        )
        assert hypothesis_evidence_strength(h) == 0

    def test_rule_seeded_only_scores_one(self) -> None:
        h = Hypothesis(
            id="H-001",
            description="Rule-seeded hypothesis",
            status="active",
            source_rule_ids=["rule-1"],
        )
        assert hypothesis_evidence_strength(h) == 1

    def test_rule_seeded_with_evidence_scores_two(self) -> None:
        h = Hypothesis(
            id="H-002",
            description="Rule-seeded with evidence",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"co_observed_event_ids": ["E-001"]},
        )
        assert hypothesis_evidence_strength(h) == 2

    def test_zero_rows_placeholder_not_strong_evidence(self) -> None:
        h = Hypothesis(
            id="H-003",
            description="Rule-seeded with zero_rows placeholder",
            status="active",
            source_rule_ids=["rule-1"],
            confirm_when={"zero_rows": True},
        )
        assert hypothesis_evidence_strength(h) == 1

    def test_refute_when_also_counts_as_evidence(self) -> None:
        h = Hypothesis(
            id="H-004",
            description="Rule-seeded with refute criteria",
            status="active",
            source_rule_ids=["rule-1"],
            refute_when={"co_observed_event_ids": ["E-002"]},
        )
        assert hypothesis_evidence_strength(h) == 2


def _insert_section(db: CaseDB, section_key: str, update_count: int = 0) -> None:
    """Insert a minimal report_sections row."""
    db.execute(
        """INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale)
           VALUES (?, ?, '', 0.5, 'draft', ?, FALSE)
           ON CONFLICT (section_key) DO UPDATE SET update_count = excluded.update_count, stale = FALSE""",
        (section_key, section_key, update_count),
    )


def _stale_status(db: CaseDB, section_key: str) -> bool:
    row = db.execute(
        "SELECT stale FROM report_sections WHERE section_key = ?",
        (section_key,),
    ).fetchone()
    return bool(row[0]) if row else False


class StalePropagationViaTargetKeypointTests(unittest.TestCase):
    """Resolving a draft-origin hypothesis with target_keypoint_id marks its section stale."""

    def test_resolve_with_target_keypoint_marks_section_stale(self) -> None:
        """A hypothesis with target_keypoint_id='host_execution_activity' should
        mark section '3_technical' stale (family '3' owns that keypoint)."""
        keypoint = "host_execution_activity"
        # Expect family "3" which maps to section key 3_technical
        owning_sections = sections_for_keypoint(keypoint)
        self.assertIn(
            "3_technical",
            owning_sections,
            f"{keypoint} should map to section 3_technical, got {owning_sections}",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-1",
                            description="suspicious process execution",
                            status="active",
                            target_keypoint_id=keypoint,
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-1",
                    verdict="confirmed",
                    summary="confirmed by query",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "3_technical"),
                    "section 3_technical should be marked stale",
                )

    def test_target_keypoint_marks_correct_section_only(self) -> None:
        """A timeline keypoint should only mark 2_timeline stale, not 3_technical."""
        keypoint = "timeline_log_clearing"
        owning = sections_for_keypoint(keypoint)
        self.assertIn("2_timeline", owning)
        self.assertNotIn("3_technical", owning)

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "2_timeline")
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-2",
                            description="log clearing detected",
                            status="active",
                            target_keypoint_id=keypoint,
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-2",
                    verdict="refuted",
                    summary="no log clearing found",
                    session_id="S-1",
                )
                self.assertTrue(_stale_status(db, "2_timeline"))
                self.assertFalse(_stale_status(db, "3_technical"))

    def test_target_keypoint_none_does_not_mark_sections(self) -> None:
        """No target_keypoint_id should not mark any section stale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-3",
                            description="suspicious activity",
                            status="active",
                            target_keypoint_id=None,
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-3",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertFalse(_stale_status(db, "3_technical"))


class StalePropagationViaDescriptionTests(unittest.TestCase):
    """Resolving a gap-origin hypothesis marks sections guessed from description stale."""

    def test_gap_description_matches_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical")
                _insert_section(db, "4_gaps")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-4",
                            description="unknown persistence mechanism on host PC-01",
                            status="active",
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-4",
                    verdict="refuted",
                    summary="no persistence found",
                    session_id="S-1",
                )
                # "host" and "persistence" both match 3_technical
                self.assertTrue(_stale_status(db, "3_technical"))


class StalePropagationUpdateCountCapTests(unittest.TestCase):
    """Sections with update_count >= max should not be marked stale."""

    def test_section_at_cap_not_marked_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical", update_count=MAX_SECTION_UPDATES)
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-5",
                            description="suspicious execution on host",
                            status="active",
                            target_keypoint_id="host_execution_activity",
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-5",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertFalse(
                    _stale_status(db, "3_technical"),
                    "section at update_count cap should NOT be marked stale",
                )

    def test_section_below_cap_marked_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "3_technical", update_count=MAX_SECTION_UPDATES - 1)
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-6",
                            description="suspicious execution on host",
                            status="active",
                            target_keypoint_id="host_execution_activity",
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-6",
                    verdict="confirmed",
                    summary="confirmed",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "3_technical"),
                    "section below cap should be marked stale",
                )


class StalePropagationRulepackDeclTests(unittest.TestCase):
    """Resolving a rulepack-origin hypothesis marks sections from its declaration."""

    def test_rulepack_declaration_marks_sections(self) -> None:
        """A hypothesis originating from a rulepack with report_sections should
        mark those sections stale."""
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "2_timeline")
                _insert_section(db, "3_technical")
                state = SessionState(
                    session_id="S-1",
                    iteration=1,
                    active_hypotheses=[
                        Hypothesis(
                            id="H-7",
                            description="log clearing indicator",
                            status="active",
                            source_rule_ids=["windows-system-104-log-cleared"],
                        )
                    ],
                )
                resolve_hypothesis(
                    db=db,
                    state=state,
                    hypothesis_id="H-7",
                    verdict="confirmed",
                    summary="log clear confirmed",
                    session_id="S-1",
                )
                self.assertTrue(
                    _stale_status(db, "2_timeline"),
                    "rulepack declaration should mark 2_timeline stale",
                )


class MarkSectionStaleTests(unittest.TestCase):
    """Direct tests for mark_section_stale helper."""

    def test_mark_section_stale_below_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "4_gaps", update_count=2)
                mark_section_stale(db, "4_gaps")
                self.assertTrue(_stale_status(db, "4_gaps"))

    def test_mark_section_stale_at_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "4_gaps", update_count=MAX_SECTION_UPDATES)
                mark_section_stale(db, "4_gaps")
                self.assertFalse(
                    _stale_status(db, "4_gaps"),
                    "at-cap section must not be marked stale",
                )


class CollectSectionRequestsTests(unittest.TestCase):
    """R6-01: the stale-section query must survive contact with real DuckDB rows.

    The previous implementation did dict-style access on raw fetchall() tuples
    and crashed with TypeError on the first stale row — killing every report
    refresh after the initial fill (sessions 89dae1d15b9a / 907bd96e669c)."""

    def test_stale_section_produces_render_request(self) -> None:
        from pathlib import Path

        from forensia.ai.sections.section_refresher import collect_section_requests

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "templates"
            template_dir.mkdir()
            (template_dir / "1_overview.md").write_text(
                "# Investigation Overview\n\n## Executive Summary\n<!-- mode: narrative; summary -->\n",
                encoding="utf-8",
            )
            (template_dir / "4_gaps.md").write_text(
                "# Investigation Gaps\n\n## Evidence Gaps\n<!-- mode: table; builder: gaps_evidence -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                # 1_overview: filled and fresh → must NOT be re-rendered.
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', 'filled body text', 0.8, 'stable', 1, FALSE)"
                )
                # 4_gaps: filled but stale → must be re-rendered.
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('4_gaps', 'Gaps', 'old gap body', 0.5, 'draft', 1, TRUE)"
                )
                prior_filled = {
                    "1_overview": "filled body text",
                    "4_gaps": "old gap body",
                }
                requests = collect_section_requests(
                    case,
                    db,
                    sorted(template_dir.glob("[0-9]*_*.md")),
                    prior_filled,
                    report_brief={},
                )

        keys = [str(r.get("section_key")) for r in requests]
        self.assertIn("4_gaps", keys, "stale section must produce a render request")
        self.assertNotIn("1_overview", keys, "fresh filled section must be skipped")
        gap_request = next(r for r in requests if r["section_key"] == "4_gaps")
        self.assertTrue(gap_request["is_stale"])

    def test_force_all_returns_every_template(self) -> None:
        from pathlib import Path

        from forensia.ai.sections.section_refresher import collect_section_requests

        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            template_dir = Path(tmpdir) / "templates"
            template_dir.mkdir()
            (template_dir / "1_overview.md").write_text(
                "# Investigation Overview\n\n## Executive Summary\n<!-- mode: narrative; summary -->\n",
                encoding="utf-8",
            )
            (template_dir / "4_gaps.md").write_text(
                "# Investigation Gaps\n\n## Evidence Gaps\n<!-- mode: table; builder: gaps_evidence -->\n",
                encoding="utf-8",
            )
            with CaseDB(case) as db:
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('1_overview', 'Overview', 'filled body text', 0.8, 'stable', 1, FALSE)"
                )
                db.execute(
                    "INSERT INTO report_sections (section_key, title, body, confidence, status, update_count, stale) "
                    "VALUES ('4_gaps', 'Gaps', 'old gap body', 0.5, 'draft', 5, FALSE)"
                )
                prior_filled = {
                    "1_overview": "filled body text",
                    "4_gaps": "old gap body",
                }
                requests = collect_section_requests(
                    case,
                    db,
                    sorted(template_dir.glob("[0-9]*_*.md")),
                    prior_filled,
                    report_brief={},
                    force_all=True,
                )

        keys = [str(r.get("section_key")) for r in requests]
        self.assertIn("1_overview", keys, "force_all must include fresh sections")
        self.assertIn("4_gaps", keys, "force_all must include at-cap sections")
        for r in requests:
            self.assertTrue(
                r["is_stale"], f"force_all must mark {r['section_key']} as stale"
            )
            self.assertTrue(
                r["needs_refresh"],
                f"force_all must mark {r['section_key']} as needs_refresh",
            )


if __name__ == "__main__":
    unittest.main()
