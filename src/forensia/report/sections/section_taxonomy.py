"""Section-key taxonomy: canonical lists of section keys and classification helpers.

All section-key→family/section/playbook mappings are managed here.
The module depends only on the standard library at import time;
lazy imports (e.g. from keypoints) are done inside functions.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Canonical section key list (template order)
# ---------------------------------------------------------------------------

SECTION_KEYS: tuple[str, ...] = (
    "1_overview",
    "2_timeline",
    "3_technical",
    "4_gaps",
    "5_recommendations",
    "6_appendix",
)

# ---------------------------------------------------------------------------
# Section key → family (prefix after the numeric part)
# ---------------------------------------------------------------------------

_SECTION_FAMILY_MAP: dict[str, str] = {
    "1_overview": "overview",
    "2_timeline": "timeline",
    "3_technical": "technical",
    "4_gaps": "gaps",
    "5_recommendations": "recommendations",
    "6_appendix": "appendix",
}


def section_family(section_key: str) -> str:
    """Return the family name for a section key (e.g. '3_technical' → 'technical')."""
    return _SECTION_FAMILY_MAP.get(section_key, section_key)


def report_slug_family(key: str) -> str | None:
    """Known canonical family for a positional report key (``NN_<slug>``).

    Matches a canonical family word (``overview``/``timeline``/``technical``/
    ``gaps``/``recommendations``/``appendix``) when the slug part equals it or
    ends with ``_`` + word. Also resolves canonical keys themselves
    (``1_overview`` → ``overview``). Purely derived from the key string;
    returns None for anything else.
    """
    match = re.match(r"^\d+_(.+)$", str(key or "").strip())
    slug = match.group(1) if match else str(key or "").strip()
    if not slug:
        return None
    words = set(_SECTION_FAMILY_MAP.values())
    if slug in words:
        return slug
    for word in sorted(words):
        if slug.endswith("_" + word):
            return word
    return None


# ---------------------------------------------------------------------------
# Keypoint → section keys (which sections include a given keypoint)
# ---------------------------------------------------------------------------


def sections_for_keypoint(keypoint_name: str) -> list[str]:
    """Return section keys whose default keypoints include *keypoint_name*."""
    from forensia.report.answers.keypoint_catalog import _default_keypoints_for_section

    results: list[str] = []
    for section_key in SECTION_KEYS:
        if keypoint_name in _default_keypoints_for_section(section_key):
            results.append(section_key)
    return results


# ---------------------------------------------------------------------------
# Text → related section keys (keyword heuristic)
# ---------------------------------------------------------------------------

_TEXT_SECTION_KEYWORDS: dict[str, list[str]] = {
    "1_overview": ["overview", "first evidence", "summary", "fec", "initial"],
    "2_timeline": ["timeline", "time", "log clear", "reboot", "shutdown", "when"],
    "3_technical": [
        "host",
        "computer",
        "server",
        "workstation",
        "account",
        "user",
        "credential",
        "password",
        "logon",
        "rdp",
        "admin",
        "service",
        "task",
        "powershell",
        "defender",
        "persistence",
        "execution",
        "ioc",
        "ip",
        "process",
        "file",
        "path",
        "indicator",
    ],
    "4_gaps": ["gap", "unknown", "insufficient", "unresolved"],
    "5_recommendations": ["mitigation", "recommendation", "countermeasure"],
}


def guess_related_sections(text: str) -> list[str]:
    """Guess which report sections a text relates to by keyword matching."""
    lowered = text.lower()
    matches = [
        section
        for section, keywords in _TEXT_SECTION_KEYWORDS.items()
        if any(keyword in lowered for keyword in keywords)
    ]
    return matches or ["4_gaps"]
