"""Regression tests for dist/cfreds report output invariants.

These tests verify that the generated report brief conforms to quality
invariants. They do NOT require LLM or full pipeline execution — they
read the pre-generated report_brief.json if available, or use synthetic
fixtures.

Rule 16: asserts are on generic DFIR properties, not benchmark question IDs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DIST_ROOT = Path(__file__).resolve().parent.parent / "dist" / "cfreds"
DIST_CFREDS = DIST_ROOT / "reports"
BRIEF_PATH = DIST_CFREDS / "report_brief.json"
CASE_DB_PATH = DIST_ROOT / "db" / "case.duckdb"


def _load_brief() -> dict | None:
    if not BRIEF_PATH.exists():
        return None
    with open(BRIEF_PATH) as f:
        return json.load(f)


def _rebuild_top_findings_from_db() -> list | None:
    """Rebuild top_findings from the dist case DB, exercising current code.

    The static report_brief.json is a frozen artifact from the last run; a
    path-sanitize fix in the code cannot retroactively clean it. Rebuilding
    top_findings from the case DB runs the real (fixed) deterministic builder
    against the real data, which is the meaningful regression. Returns None
    when the DB is absent (CI without dist).
    """
    if not CASE_DB_PATH.exists():
        return None
    import duckdb

    from forensia.report.report_brief import _query_top_findings

    conn = duckdb.connect(str(CASE_DB_PATH), read_only=True)
    try:
        return _query_top_findings(conn, 8)
    finally:
        conn.close()


def _make_synthetic_brief() -> dict:
    """Create a synthetic report brief for CI environments without dist/cfreds."""
    return {
        "executive_summary": "",
        "top_findings": [],
        "confirmed_hypotheses": [],
        "refuted_hypotheses": [],
        "evidence_gaps": [],
    }


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


class TestThesisAlignment:
    """Executive Summary must not claim intrusion without strong evidence."""

    def test_no_intrusion_without_strong_evidence(self) -> None:
        """If summary uses intrusion language, must have rule-seeded non-benign confirmed."""
        brief = _load_brief() or _make_synthetic_brief()
        # Check: if summary contains intrusion keywords, there must be at least one
        # strong confirmed hypothesis (rule-seeded + no benign tag)
        summary = str(brief.get("executive_summary") or "").lower()
        intrusion_kw = ["intrusion", "lateral movement", "remote access"]
        has_intrusion_lang = any(kw in summary for kw in intrusion_kw)
        if not has_intrusion_lang:
            pytest.skip("No intrusion language in summary")

        confirmed = brief.get("confirmed_hypotheses") or []
        strong = [
            h
            for h in confirmed
            if h.get("source_rule_ids") and not any(
                "benign" in str(t) for t in (h.get("tags") or [])
            )
        ]
        assert len(strong) > 0, (
            "Executive Summary uses intrusion language but no strong confirmed "
            "hypothesis exists to support it"
        )


class TestVerdictConsistency:
    """Same claim must not be both confirmed and refuted."""

    def test_no_overlap_between_confirmed_and_refuted(self) -> None:
        brief = _load_brief() or _make_synthetic_brief()
        confirmed = {
            _normalize(h.get("description", ""))
            for h in brief.get("confirmed_hypotheses", [])
        }
        refuted = {
            _normalize(h.get("description", ""))
            for h in brief.get("refuted_hypotheses", [])
        }
        overlap = confirmed & refuted
        assert len(overlap) == 0, (
            f"{len(overlap)} claim(s) appear in both confirmed and refuted: "
            f"{list(overlap)[:3]}"
        )


class TestTopFindings:
    """Top findings must not be dominated by benign loopback 4648."""

    def test_top_finding_not_benign_4648(self) -> None:
        """Verify that first top finding is not a benign loopback 4648."""
        brief = _load_brief() or _make_synthetic_brief()
        findings = brief.get("top_findings") or []
        if not findings:
            pytest.skip("No top findings")
        first = findings[0]
        title = str(first.get("title", "")).lower()
        tags = [str(t).lower() for t in (first.get("tags") or [])]
        is_4648 = "4648" in title or "explicit" in title
        is_benign = any("benign" in t for t in tags)
        is_loopback = any("loopback" in t or "127.0.0.1" in t for t in tags)
        assert not (is_4648 and (is_benign or is_loopback)), (
            f"Top finding is a benign loopback 4648: {title[:80]}"
        )


class TestLocalPathLeak:
    """Report must not contain local ingest paths."""

    def test_no_sample_path_in_rebuilt_top_findings(self) -> None:
        """Rebuild top_findings from the case DB with current code; no leak."""
        top_findings = _rebuild_top_findings_from_db()
        if top_findings is None:
            pytest.skip("dist/cfreds case DB not present")
        blob = json.dumps(top_findings).lower()
        assert "sample/" not in blob, (
            "Local ingest path 'sample/' present in freshly-built top_findings"
        )

    def test_static_brief_leak_is_documented(self) -> None:
        """The frozen brief predates the sanitize fix and may still leak.

        This is expected: the static artifact is a measuring instrument
        (Rule 17), not regenerated here. The rebuilt-from-DB test above is the
        real regression. This test only asserts the static file is readable so
        a genuinely missing/corrupt artifact still fails loudly.
        """
        brief = _load_brief()
        if brief is None:
            pytest.skip("no static brief present")
        assert isinstance(brief.get("top_findings"), list)
