"""Section-key taxonomy: canonical lists of section keys and classification helpers.

All section-key→family/section/playbook mappings are managed here.
The module depends only on the standard library at import time;
lazy imports (e.g. from keypoints) are done inside functions.
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# Section key → playbook section name
# ---------------------------------------------------------------------------

SECTION_KEY_PLAYBOOK_MAP: dict[str, str] = {
    "events": "event_ids",
    "priority": "event_ids",
    "logon": "logon_types",
    "fp": "fp_guidance",
    "schema": "schema",
    "extractor": "schema",
    "app": "app_catalog",
    "artifact": "artifact_inference",
    "ioc": "ioc_catalog",
}

# ---------------------------------------------------------------------------
# Keypoint → section keys (which sections include a given keypoint)
# ---------------------------------------------------------------------------


def sections_for_keypoint(keypoint_name: str) -> list[str]:
    """Return section keys whose default keypoints include *keypoint_name*."""
    from forensia.report.keypoint_catalog import _default_keypoints_for_section

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
