"""Deterministic rubric checks for narrative report blocks (no LLM).

These run before the LLM section_reviewer: anything code can decide is
decided here, and the resulting problem list is handed to the reviewer as
ground truth (Rule 5).
"""

from __future__ import annotations

import re

from forensia.report.keypoints import EVIDENCE_ID_PATTERN

_INTERNAL_ID_RE = re.compile(r"\bgap-[0-9a-f]{6,}\b|\bH-\d{3}\b|\bKP-\d{4}\b")

# A pseudo-citation is a parenthesized snake_case label (digest/keypoint names
# like `(antiforensic_activity)` or `(STRUCTURED_OBSERVATIONS)`). Requiring at
# least one underscore avoids flagging ordinary parenthesized words such as
# `(informant)`. Both ASCII and full-width parentheses appear in ja output.
_PSEUDO_CITATION_RE = re.compile(r"[（(]\s*([A-Za-z]+(?:_[A-Za-z]+)+)\s*[)）]")


def check_citation_overload(body: str, max_citations: int = 3) -> list[str]:
    """Flag paragraphs citing more evidence IDs than a reader can verify."""
    problems = []
    for index, paragraph in enumerate(body.split("\n\n"), start=1):
        citations = EVIDENCE_ID_PATTERN.findall(paragraph)
        if len(citations) > max_citations:
            problems.append(
                f"Paragraph {index} cites {len(citations)} evidence IDs (max {max_citations}): "
                f"{', '.join(citations[:5])}..."
            )
    return problems


def check_pseudo_citations(body: str) -> list[str]:
    """Flag parenthesized snake_case labels masquerading as citations."""
    return [
        f"Pseudo-citation '({token})' — not an evidence ID; cite real IDs or drop the parenthetical"
        for token in dict.fromkeys(_PSEUDO_CITATION_RE.findall(body))
    ]


def check_internal_ids(body: str) -> list[str]:
    """Flag internal IDs (gap-*, H-*, KP-*) leaking into prose."""
    found = dict.fromkeys(_INTERNAL_ID_RE.findall(body))
    return [
        f"Internal ID '{token}' in prose — replace with a human-readable description"
        for token in found
    ]


def review_narrative_body(body: str, max_citations: int = 3) -> list[str]:
    """Run all deterministic narrative checks and return the combined problem list."""
    return [
        *check_citation_overload(body, max_citations=max_citations),
        *check_pseudo_citations(body),
        *check_internal_ids(body),
    ]
