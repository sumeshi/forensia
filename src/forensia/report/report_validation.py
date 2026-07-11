"""Post-generation report validation checks.

Each check is a pure function that inspects a generated report (its brief,
body, or JSON) and returns a list of ``ValidationFinding`` objects.

Checks are deterministic — no LLM calls. They are wired into ``forensia doctor``
to catch regressions after generation.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from forensia.report.sections.quality_gates import _detect_body_language

_SCHEMA_DIR = Path(__file__).parent.parent / "rulepacks" / "_schema"
_VOCAB_PATH = _SCHEMA_DIR / "report_validation_vocab.yaml"


# ---------------------------------------------------------------------------
# Vocabulary loader (YAML-backed, same pattern as knowledge.py)
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_vocab() -> dict[str, Any]:
    """Load detection vocabulary from report_validation_vocab.yaml."""
    if not _VOCAB_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(_VOCAB_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _get_intrusion_keywords() -> tuple[str, ...]:
    """Return intrusion keywords from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("intrusion_keywords") or []
    return tuple(str(k).lower() for k in raw) if isinstance(raw, list) else ()


def _get_path_leak_patterns() -> tuple[re.Pattern, ...]:
    """Return path-leak regex patterns from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("path_leak_patterns") or []
    if not isinstance(raw, list):
        return ()
    return tuple(re.compile(p, re.IGNORECASE) for p in raw if isinstance(p, str))


def _get_fallback_stub_phrases() -> tuple[str, ...]:
    """Return narrative-fallback stub phrases from YAML vocabulary."""
    vocab = _load_vocab()
    raw = vocab.get("fallback_stub_phrases") or []
    return tuple(str(p).lower() for p in raw) if isinstance(raw, list) else ()


class ValidationFinding:
    """A single validation issue found in the report output."""

    def __init__(
        self,
        check_name: str,
        severity: str,
        message: str,
        details: str | None = None,
    ) -> None:
        self.check_name = check_name
        self.severity = severity  # "error" or "warning"
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.check_name}: {self.message}"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_thesis_alignment(report_brief: dict[str, Any]) -> list[ValidationFinding]:
    """Verify Executive Summary thesis is backed by strong confirmed hypotheses.

    If the summary uses intrusion language but no rule-seeded, non-benign
    confirmed hypothesis exists, flag a misalignment.
    """
    findings: list[ValidationFinding] = []
    summary = str(report_brief.get("executive_summary") or "")
    if not summary:
        return findings

    _intrusion_kw = _get_intrusion_keywords()
    has_intrusion_language = any(kw in summary.lower() for kw in _intrusion_kw)
    if not has_intrusion_language:
        return findings

    # Check for strong confirmed hypotheses
    confirmed = report_brief.get("confirmed_hypotheses") or []
    strong_count = 0
    for hyp in confirmed:
        source_rules = hyp.get("source_rule_ids") or []
        tags = hyp.get("tags") or []
        is_benign = any("benign" in str(t) for t in tags)
        if source_rules and not is_benign:
            strong_count += 1

    if strong_count == 0:
        findings.append(
            ValidationFinding(
                "thesis_alignment",
                "error",
                "Executive Summary uses intrusion language but no strong "
                "confirmed hypotheses exist to support it",
                f"keywords matched: {[kw for kw in _intrusion_kw if kw in summary.lower()]}",
            )
        )
    return findings


def check_refuted_leakage(report_brief: dict[str, Any]) -> list[ValidationFinding]:
    """Detect refuted-hypothesis claims leaking into gap sections."""
    findings: list[ValidationFinding] = []
    refuted = report_brief.get("refuted_hypotheses") or []
    gaps_text = json.dumps(report_brief.get("evidence_gaps", []))

    for hyp in refuted:
        desc = str(hyp.get("description") or "")
        if not desc:
            continue
        # Extract key tokens from refuted description
        tokens = re.findall(r"[A-Za-z0-9_\-\.]+\.(?:exe|dll|sys|bat|ps1)", desc)
        for token in tokens:
            if token.lower() in gaps_text.lower():
                findings.append(
                    ValidationFinding(
                        "refuted_leakage",
                        "warning",
                        f"Refuted hypothesis token '{token}' found in gaps section",
                        f"Hypothesis: {desc[:120]}",
                    )
                )
    return findings


def check_local_path_leak(content: str) -> list[ValidationFinding]:
    """Detect local ingest paths in report content."""
    findings: list[ValidationFinding] = []
    for pattern in _get_path_leak_patterns():
        matches = pattern.findall(content)
        if matches:
            findings.append(
                ValidationFinding(
                    "local_path_leak",
                    "error",
                    f"Local ingest path pattern '{pattern.pattern}' found "
                    f"in report content ({len(matches)} matches)",
                    f"Samples: {matches[:3]}",
                )
            )
    return findings


def check_fallback_stub(content: str) -> list[ValidationFinding]:
    """Detect deterministic narrative-fallback stubs shipped as report prose.

    When the LLM narrator fails twice, a deterministic fallback paragraph is
    produced. If its fixed phrasing reaches the rendered report, a narrator
    failure was shipped verbatim (e.g. as an Executive Summary) instead of a
    real summary — a Fail-loud violation the pipeline must surface.
    """
    findings: list[ValidationFinding] = []
    lowered = content.lower()
    for phrase in _get_fallback_stub_phrases():
        if phrase and phrase in lowered:
            findings.append(
                ValidationFinding(
                    "fallback_stub",
                    "error",
                    "Narrative fallback stub phrase found in report body "
                    f"('{phrase}'); a narrator failure was shipped as prose",
                    None,
                )
            )
    return findings


def _normalize_expected_language(expected_lang: str) -> str:
    value = str(expected_lang or "").strip().lower()
    if value in {"ja", "jp", "japanese"}:
        return "ja"
    if value in {"en", "english"}:
        return "en"
    return value


def check_language_consistency(
    content: str, expected_lang: str
) -> list[ValidationFinding]:
    """Detect report-body language that conflicts with the configured output language."""
    expected = _normalize_expected_language(expected_lang)
    if expected not in {"en", "ja"}:
        return []
    detected = _detect_body_language(content)
    if detected in {"unknown", expected}:
        return []
    return [
        ValidationFinding(
            "language_consistency",
            "error",
            f"Report body language mismatch: expected={expected}, detected={detected}",
            None,
        )
    ]


def check_verdict_contradiction(
    report_brief: dict[str, Any],
) -> list[ValidationFinding]:
    """Detect identical claims in both confirmed and refuted hypotheses."""
    findings: list[ValidationFinding] = []
    confirmed = report_brief.get("confirmed_hypotheses") or []
    refuted = report_brief.get("refuted_hypotheses") or []

    confirmed_descs = {
        _normalize_for_compare(h.get("description", "")) for h in confirmed
    }
    refuted_descs = {_normalize_for_compare(h.get("description", "")) for h in refuted}

    overlap = confirmed_descs & refuted_descs
    if overlap:
        findings.append(
            ValidationFinding(
                "verdict_contradiction",
                "error",
                f"{len(overlap)} claim(s) appear in both confirmed and refuted hypotheses",
                f"Overlapping descriptions: {list(overlap)[:3]}",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def _normalize_for_compare(text: str) -> str:
    """Normalize a hypothesis description for comparison."""
    return re.sub(r"\s+", " ", text).strip().lower()


def validate_report(
    report_brief: dict[str, Any],
    *,
    report_body: str | None = None,
    expected_language: str | None = None,
) -> list[ValidationFinding]:
    """Run all validation checks on a generated report.

    Args:
        report_brief: The report brief dict (from report_brief.json).
        report_body: Optional full report markdown body for path leak checks.

    Returns:
        List of ``ValidationFinding`` objects (empty if all checks pass).
    """
    all_findings: list[ValidationFinding] = []
    all_findings.extend(check_thesis_alignment(report_brief))
    all_findings.extend(check_refuted_leakage(report_brief))
    all_findings.extend(check_verdict_contradiction(report_brief))
    if report_body:
        all_findings.extend(check_local_path_leak(report_body))
        all_findings.extend(check_fallback_stub(report_body))
        if expected_language:
            all_findings.extend(
                check_language_consistency(report_body, expected_language)
            )
    return all_findings
