"""Tests for R5-03: stale propagation from hypothesis resolution to report sections.

Verifies that _resolve_hypothesis marks report sections stale via:
  - target_keypoint_id → owning section
  - description keyword matching (_guess_related_sections)
  - rulepack declaration report_sections
  - update_count cap enforcement
"""

from __future__ import annotations

import tempfile
import unittest

from forensia.ai.hypotheses.hypothesis_manager import (
    _MAX_SECTION_UPDATES,
    _mark_section_stale,
    _resolve_hypothesis,
    _sections_for_keypoint,
)
from forensia.core.case import Case
from forensia.core.session import Hypothesis, SessionState
from forensia.db.database import CaseDB


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
        owning_sections = _sections_for_keypoint(keypoint)
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
                _resolve_hypothesis(
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
        owning = _sections_for_keypoint(keypoint)
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
                _resolve_hypothesis(
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
                _resolve_hypothesis(
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
                _resolve_hypothesis(
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
                _insert_section(db, "3_technical", update_count=_MAX_SECTION_UPDATES)
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
                _resolve_hypothesis(
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
                _insert_section(
                    db, "3_technical", update_count=_MAX_SECTION_UPDATES - 1
                )
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
                _resolve_hypothesis(
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
                _resolve_hypothesis(
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
    """Direct tests for _mark_section_stale helper."""

    def test_mark_section_stale_below_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "4_gaps", update_count=2)
                _mark_section_stale(db, "4_gaps")
                self.assertTrue(_stale_status(db, "4_gaps"))

    def test_mark_section_stale_at_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            with CaseDB(case) as db:
                _insert_section(db, "4_gaps", update_count=_MAX_SECTION_UPDATES)
                _mark_section_stale(db, "4_gaps")
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

        from forensia.ai.sections.section_refresher import _collect_section_requests

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
                requests = _collect_section_requests(
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

        from forensia.ai.sections.section_refresher import _collect_section_requests

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
                requests = _collect_section_requests(
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
