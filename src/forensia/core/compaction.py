"""Shared content compaction for prompt-budget enforcement.

Stage 1 (this module): mechanical compaction — deterministic, no LLM.
Collapses blank runs and truncates at line boundaries with an explicit
marker, so downstream readers can tell content was reduced.

Stage 2 (LLM summarisation with caching and fact-preservation guards)
lives in the ai layer and falls back to this module on any failure.
"""

from __future__ import annotations

import re

TRUNCATION_MARKER = "…[truncated]"

_BLANK_RUN = re.compile(r"\n{3,}")


def mechanical_compact(
    text: str, budget: int, *, marker: str = TRUNCATION_MARKER
) -> str:
    """Reduce *text* to at most *budget* characters, deterministically.

    Order of operations:
    1. Collapse runs of 3+ newlines to 2.
    2. If still over budget, keep whole lines from the top until the next
       line would overflow, then append *marker*.
    3. If even the first line does not fit, hard-cut at the character level.

    Returns "" when budget is too small to hold the marker itself.
    """
    if budget <= 0:
        return ""
    if len(text) <= budget:
        return text

    text = _BLANK_RUN.sub("\n\n", text).strip()
    if len(text) <= budget:
        return text

    if budget <= len(marker):
        return text[:budget]

    limit = budget - len(marker) - 1  # -1 for the newline before the marker
    kept: list[str] = []
    used = 0
    for line in text.splitlines():
        line_cost = len(line) + (1 if kept else 0)
        if used + line_cost > limit:
            break
        kept.append(line)
        used += line_cost

    if not kept:
        return text[:limit] + marker

    return "\n".join(kept) + "\n" + marker
