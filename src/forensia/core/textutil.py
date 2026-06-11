from __future__ import annotations

import re


def slugify(value: str) -> str:
    """Convert a string to a lowercase, dash-separated filesystem-safe slug.

    Preserves dots, underscores, and hyphens for paths/IPs/versions.
    Uses regex to collapse runs of disallowed characters into a single dash.
    Unicode-aware via re.UNICODE flag.
    """
    if not value:
        return "unknown"
    cleaned = re.sub(r"[^\w.\-]+", "-", value.strip(), flags=re.UNICODE)
    return cleaned.strip("-").lower() or "unknown"


def strict_slugify(value: str) -> str:
    """Strict slug: only alphanumeric preserved, individual char replacement.

    Each non-alnum character is replaced with a dash (no collapsing).
    No dot/underscore/hyphen preservation. Use for evidence IDs.
    """
    if not value:
        return "unknown"
    result = "".join(c.lower() if c.isalnum() else "-" for c in value.strip())
    return result.strip("-") or "unknown"


def normalize_text(text: str) -> str:
    """Normalize text: lowercase, keep only alphanumeric tokens, collapse whitespace."""
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def token_set_similarity(a: str, b: str) -> float:
    """Compute token-set overlap ratio between two strings.

    Returns len(a_tokens & b_tokens) / max(len(a_tokens), len(b_tokens)).
    Used for overview dedup in investigator's _apply_memory_updates.
    """
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a or not tokens_b:
        return 0.0
    return len(tokens_a & tokens_b) / max(len(tokens_a), len(tokens_b))


def jaccard_similarity(a: str, b: str) -> float:
    """Jaccard token-set similarity between two pre-normalized strings.

    Returns len(intersection) / len(union).
    """
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)
