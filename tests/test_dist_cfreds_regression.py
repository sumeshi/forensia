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

DIST_CFREDS = Path(__file__).resolve().parent.parent / "dist" / "cfreds" / "reports"
BRIEF_PATH = DIST_CFREDS / "report_brief.json"


def _load_brief() -> dict | None:
    if not BRIEF_PATH.exists():
        return None
    with open(BRIEF_PATH) as f:
        return json.load(f)


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

    def test_no_sample_path_in_brief(self) -> None:
        brief = _load_brief() or _make_synthetic_brief()
        brief_json = json.dumps(brief).lower()
        assert "sample/" not in brief_json, (
            "Local ingest path 'sample/' found in report brief"
        )
