"""Unit tests for report_validation checks.

All tests use synthetic briefs — no dist/cfreds data required.
"""

from __future__ import annotations

from forensia.report.evidence_refs import EVIDENCE_ID_PATTERN
from forensia.report.report_validation import (
    check_fallback_stub,
    check_language_consistency,
    check_local_path_leak,
    check_refuted_leakage,
    check_thesis_alignment,
    check_verdict_contradiction,
    validate_report,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _brief(
    *,
    executive_summary: str = "",
    confirmed_hypotheses: list[dict] | None = None,
    refuted_hypotheses: list[dict] | None = None,
    evidence_gaps: list[dict] | None = None,
) -> dict:
    return {
        "executive_summary": executive_summary,
        "confirmed_hypotheses": confirmed_hypotheses or [],
        "refuted_hypotheses": refuted_hypotheses or [],
        "evidence_gaps": evidence_gaps or [],
    }


# ---------------------------------------------------------------------------
# Thesis alignment
# ---------------------------------------------------------------------------


class TestThesisAlignment:
    def test_error_when_intrusion_keywords_without_strong_confirmed(self) -> None:
        """Summary with intrusion keywords but no strong confirmed hypotheses → finding."""
        brief = _brief(
            executive_summary="Evidence suggests an intrusion via lateral movement",
            confirmed_hypotheses=[
                {"description": "something", "source_rule_ids": [], "tags": []}
            ],
        )
        findings = check_thesis_alignment(brief)
        assert len(findings) == 1
        assert findings[0].check_name == "thesis_alignment"
        assert findings[0].severity == "error"

    def test_pass_when_intrusion_keywords_with_strong_confirmed(self) -> None:
        """Summary with intrusion keywords AND strong confirmed hypothesis → no finding."""
        brief = _brief(
            executive_summary="Evidence suggests an intrusion via lateral movement",
            confirmed_hypotheses=[
                {
                    "description": "confirmed intrusion",
                    "source_rule_ids": ["RULE-001"],
                    "tags": ["lateral-movement"],
                }
            ],
        )
        findings = check_thesis_alignment(brief)
        assert findings == []

    def test_pass_when_no_intrusion_keywords(self) -> None:
        """Summary without intrusion keywords → no finding regardless of hypotheses."""
        brief = _brief(
            executive_summary="Normal activity detected during monitoring period",
            confirmed_hypotheses=[],
        )
        findings = check_thesis_alignment(brief)
        assert findings == []

    def test_pass_when_empty_summary(self) -> None:
        """Empty summary → no finding."""
        assert check_thesis_alignment(_brief()) == []


# ---------------------------------------------------------------------------
# Verdict contradiction
# ---------------------------------------------------------------------------


class TestVerdictContradiction:
    def test_error_when_same_description_in_both(self) -> None:
        """Identical claim in confirmed and refuted → finding."""
        brief = _brief(
            confirmed_hypotheses=[{"description": "Malware execution via PowerShell"}],
            refuted_hypotheses=[{"description": "Malware execution via PowerShell"}],
        )
        findings = check_verdict_contradiction(brief)
        assert len(findings) == 1
        assert findings[0].check_name == "verdict_contradiction"

    def test_pass_when_no_overlap(self) -> None:
        """Different descriptions → no finding."""
        brief = _brief(
            confirmed_hypotheses=[{"description": "Lateral movement detected"}],
            refuted_hypotheses=[{"description": "Data exfiltration confirmed"}],
        )
        findings = check_verdict_contradiction(brief)
        assert findings == []

    def test_pass_when_empty_hypotheses(self) -> None:
        """No hypotheses at all → no finding."""
        assert check_verdict_contradiction(_brief()) == []


# ---------------------------------------------------------------------------
# Local path leak
# ---------------------------------------------------------------------------


class TestLocalPathLeak:
    def test_error_when_sample_path_in_body(self) -> None:
        """Body containing 'sample/' → finding."""
        findings = check_local_path_leak(
            "The file was found in sample/evidence/malware.exe"
        )
        assert len(findings) == 1
        assert findings[0].check_name == "local_path_leak"

    def test_error_when_mnt_path_in_body(self) -> None:
        """Body containing '/mnt/c/' → finding."""
        findings = check_local_path_leak("Evidence from /mnt/c/Users/test/evidence/")
        assert len(findings) == 1
        assert findings[0].check_name == "local_path_leak"

    def test_pass_when_clean_body(self) -> None:
        """Clean body → no finding."""
        findings = check_local_path_leak("All evidence references are normalized.")
        assert findings == []

    def test_pass_when_empty_body(self) -> None:
        """Empty string → no finding."""
        assert check_local_path_leak("") == []


class TestFallbackStub:
    """H-2: narrator-fallback stubs must never ship as report prose."""

    def test_error_when_stub_phrase_present(self) -> None:
        body = (
            "## Executive Summary\n\nFor Executive Summary, the collected "
            "evidence returned 14 related rows. Representative row: evtx-1."
        )
        findings = check_fallback_stub(body)
        assert findings
        assert all(f.check_name == "fallback_stub" for f in findings)
        assert all(f.severity == "error" for f in findings)

    def test_pass_when_real_prose(self) -> None:
        body = (
            "## Executive Summary\n\nAnti-forensic tooling (CCleaner, Eraser) "
            "was executed on informant-PC shortly before the Event Log service "
            "was stopped."
        )
        assert check_fallback_stub(body) == []

    def test_validate_report_includes_fallback_check(self) -> None:
        body = "For X, the collected evidence returned 3 related rows."
        findings = validate_report({}, report_body=body)
        assert any(f.check_name == "fallback_stub" for f in findings)


class TestLanguageConsistency:
    def test_error_when_expected_english_but_japanese_body(self) -> None:
        body = "## Summary\n\nこのセクションは日本語で記述され、追加の説明を含みます。"
        findings = check_language_consistency(body, "en")
        assert findings
        assert findings[0].check_name == "language_consistency"

    def test_pass_when_expected_english_and_english_body(self) -> None:
        body = (
            "## Summary\n\nThe report describes observed authentication and "
            "file activity using a single consistent language for the reader."
        )
        assert check_language_consistency(body, "en") == []

    def test_validate_report_can_include_language_check(self) -> None:
        body = "## Summary\n\nこの本文は設定言語と一致しません。"
        findings = validate_report({}, report_body=body, expected_language="en")
        assert any(f.check_name == "language_consistency" for f in findings)


# ---------------------------------------------------------------------------
# Refuted leakage
# ---------------------------------------------------------------------------


class TestRefutedLeakage:
    def test_error_when_token_leaks_to_gaps(self) -> None:
        """Refuted .exe token appearing in gaps → finding."""
        brief = _brief(
            refuted_hypotheses=[{"description": "suspicious_tool.exe was downloaded"}],
            evidence_gaps=[{"item": "Locate suspicious_tool.exe in MFT"}],
        )
        findings = check_refuted_leakage(brief)
        assert len(findings) >= 1
        assert any(f.check_name == "refuted_leakage" for f in findings)

    def test_pass_when_no_token_overlap(self) -> None:
        """No token overlap between refuted and gaps → no finding."""
        brief = _brief(
            refuted_hypotheses=[{"description": "suspicious_tool.exe was downloaded"}],
            evidence_gaps=[{"item": "Identify network connections"}],
        )
        findings = check_refuted_leakage(brief)
        assert findings == []

    def test_pass_when_empty_refuted(self) -> None:
        """No refuted hypotheses → no finding."""
        assert check_refuted_leakage(_brief()) == []


# ---------------------------------------------------------------------------
# validate_report orchestrator
# ---------------------------------------------------------------------------


class TestValidateReport:
    def test_no_issues_on_clean_brief(self) -> None:
        """Clean brief with proper confirmed hypothesis → empty list."""
        brief = _brief(
            executive_summary="No intrusion indicators found",
            confirmed_hypotheses=[
                {
                    "description": "normal user activity",
                    "source_rule_ids": ["RULE-001"],
                    "tags": [],
                }
            ],
        )
        findings = validate_report(brief, report_body="Clean evidence summary.")
        assert findings == []

    def test_multiple_issues_when_all_problems_present(self) -> None:
        """Brief with all problems → multiple findings."""
        overlap_desc = "Unauthorized access was confirmed"
        brief = _brief(
            executive_summary="Intrusion via lateral movement was detected",
            confirmed_hypotheses=[{"description": overlap_desc}],
            refuted_hypotheses=[
                {"description": overlap_desc},
                {"description": "bad.exe was executed"},
            ],
            evidence_gaps=[{"item": "Locate bad.exe in prefetch"}],
        )

        findings = validate_report(
            brief, report_body="See sample/evidence/bad.exe for analysis."
        )
        check_names = {f.check_name for f in findings}
        # thesis_alignment: intrusion keywords + no strong confirmed
        # verdict_contradiction: same description in both
        # refuted_leakage: bad.exe token in gaps
        # local_path_leak: sample/ in body
        assert "thesis_alignment" in check_names
        assert "verdict_contradiction" in check_names
        assert "refuted_leakage" in check_names
        assert "local_path_leak" in check_names
        assert len(findings) >= 4


class TestEvidenceIdPattern:
    def test_matches_current_evidence_id_formats(self) -> None:
        assert EVIDENCE_ID_PATTERN.search("evtx-security-000000000120")
        assert EVIDENCE_ID_PATTERN.search("mft-000000072008-00")

    def test_rejects_old_evidence_id_formats(self) -> None:
        assert EVIDENCE_ID_PATTERN.search("ev-0001") is None
        assert EVIDENCE_ID_PATTERN.search("KP-0001") is None
