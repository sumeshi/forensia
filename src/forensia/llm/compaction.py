"""Bounded compaction of oversized LLM request content.

Wraps ``core.compaction.mechanical_compact`` (Stage 1) and adds an optional
LLM summarisation step.  Falls back to the mechanical stage on any failure,
when the LLM call fails. If the requested budget cannot retain required
references, it raises ``CompactionPreservationError``.

Design rules
------------
- Lives in ``llm/``; shares transport and low-level context budgets.
- Never silently claims that references survived when they did not.
- Only called from sites that **already** have an LLM client (base_url/model),
  never from pure prompt-builder functions.
- (R10) Every reduction here is one-way: nothing claims to re-generate the
  reduced content; what survives is stated inside the block and the durable
  refs (event/evidence ids, paths, tables) remain the expansion path.
"""

from __future__ import annotations

import logging
import re

from forensia.core.compaction import mechanical_compact
from forensia.core.session import LLMBudgetExceededError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Essential-token extraction
# ---------------------------------------------------------------------------

# Event IDs: 3-5 digit numbers commonly used in Windows event logs
_EVENT_ID_RE = re.compile(r"\b\d{3,5}\b")

# Table names that appear in SQL / schema references
_TABLE_NAME_RE = re.compile(
    r"\b(?:evtx_events|mft_entries|mft_timeline|prefetch_executions|prefetch_timeline|registry_artifacts|registry_timeline|findings)\b",
    re.IGNORECASE,
)

# File paths: Windows (C:\...) and Unix (/...)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s,;\"']+")
_UNIX_PATH_RE = re.compile(r"(?<!\w)/[^\s,;\"']+")

# Evidence IDs: evtx-security-NNNNNNNNNN, mft-..., etc.
_EVIDENCE_ID_RE = re.compile(
    r"\b(?:evtx|mft|prefetch)-[0-9a-f]{64}-[\w-]+\b"
    r"|\bregistry-[0-9a-f]{64}\b",
    re.IGNORECASE,
)


class CompactionPreservationError(ValueError):
    """Raised when a reduction cannot retain every required reference."""


def _extract_essential_tokens(text: str) -> set[str]:
    """Extract tokens that *must* survive compaction."""
    tokens: set[str] = set()
    tokens.update(_EVENT_ID_RE.findall(text))
    tokens.update(m.group().lower() for m in _TABLE_NAME_RE.finditer(text))
    tokens.update(_WIN_PATH_RE.findall(text))
    tokens.update(_UNIX_PATH_RE.findall(text))
    tokens.update(_EVIDENCE_ID_RE.findall(text))
    # Deduplicate case-insensitively for table names
    return {t for t in tokens if len(t) >= 3}


def _essential_tokens_present(original_tokens: set[str], compacted: str) -> bool:
    """Return True if all essential tokens from the original appear in *compacted*."""
    if not original_tokens:
        return True
    compacted_lower = compacted.lower()
    for token in original_tokens:
        if token.lower() not in compacted_lower:
            return False
    return True


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

_SUMMARISE_SYSTEM = (
    "You are a text compactor.  Summarise the user-supplied text into the "
    "requested character budget.  Rules:\n"
    "- Preserve ALL numeric event IDs, evidence IDs, file paths, table names, "
    "  IP addresses, user names, and host names verbatim.\n"
    "- Do NOT add explanation, markdown fences, or commentary — output only "
    "  the summarised text.\n"
    "- Keep the same language as the input.\n"
    "- Stay within the character budget."
)


def _call_llm(text: str, budget: int, *, base_url: str, model: str) -> str:
    """Ask the LLM to compact *text* into *budget* characters.

    Uses ``chat_completion`` directly (plain text, no JSON schema).
    """
    from forensia.llm.llm_client import chat_completion

    user_msg = (
        f"Summarise the following text into at most {budget} characters. "
        "Preserve all event IDs, evidence IDs, file paths, and table names verbatim.\n\n"
        f"{text}"
    )
    messages = [
        {"role": "system", "content": _SUMMARISE_SYSTEM},
        {"role": "user", "content": user_msg},
    ]
    # Estimate tokens needed: roughly budget/4, but at least 512
    max_tokens = max(512, budget // 2)
    return chat_completion(
        messages=messages,
        model=model,
        base_url=base_url,
        max_tokens=max_tokens,
        phase="compaction",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Ratio: if original text is less than this * budget, mechanical is good enough
_MECHANICAL_SUFFICIENCY_RATIO = 1.5


def llm_compact(
    text: str,
    budget: int,
    *,
    base_url: str,
    model: str,
    preserve_patterns: list[str] | None = None,
) -> str:
    """Compact *text* to at most *budget* characters.

    Pipeline:
    1. If already within budget → return as-is.
    2. If mechanical compaction is sufficient (text < 1.5× budget) → mechanical only.
    3. Otherwise → LLM summarise, then guard against essential-token loss.
    4. On any failure or guard violation → fall back to mechanical.

    Parameters
    ----------
    text:
        Source text to compact.
    budget:
        Maximum character count for the output.
    base_url, model:
        LLM endpoint (caller already has these).
    preserve_patterns:
        Extra regex patterns whose matches must survive compaction.
    """
    if budget <= 0:
        return ""
    if len(text) <= budget:
        return text

    # Extract essential tokens from the original
    essential = _extract_essential_tokens(text)
    if preserve_patterns:
        for pat in preserve_patterns:
            try:
                # ``findall`` returns tuples for patterns with capture groups;
                # use the complete match so every valid regex is handled as a
                # preservation token consistently.
                essential.update(match.group(0) for match in re.finditer(pat, text))
            except re.error:
                pass

    def mechanical_fallback() -> str:
        result = mechanical_compact(text, budget)
        if not _essential_tokens_present(essential, result):
            raise CompactionPreservationError(
                "The character budget is too small to preserve all required references"
            )
        return result

    if len(text) < budget * _MECHANICAL_SUFFICIENCY_RATIO:
        return mechanical_fallback()

    # Try LLM summarisation
    try:
        llm_output = _call_llm(text, budget, base_url=base_url, model=model)
    except LLMBudgetExceededError:
        raise
    except Exception as exc:
        logger.debug(
            "llm_compact: LLM call failed (%s), falling back to mechanical", exc
        )
        return mechanical_fallback()

    # Guard: essential tokens must be present
    if not _essential_tokens_present(essential, llm_output):
        missing = {t for t in essential if t.lower() not in llm_output.lower()}
        logger.info(
            "llm_compact: LLM output dropped %d essential token(s), falling back to mechanical. "
            "Examples: %s",
            len(missing),
            list(missing)[:5],
        )
        return mechanical_fallback()

    # Guard: output must be within budget
    if len(llm_output) > budget:
        llm_output = mechanical_compact(llm_output, budget)
        if not _essential_tokens_present(essential, llm_output):
            return mechanical_fallback()

    # Guard: empty output
    if not llm_output.strip():
        return mechanical_fallback()

    return llm_output


# ---------------------------------------------------------------------------
# Context-overflow compaction (R10 honesty contract)
# ---------------------------------------------------------------------------
#
# ``structured_compact`` performs ONE bounded, deterministic reduction of
# request content: the most recent existing sections are kept verbatim,
# older content is condensed with an essential-token guard (event/evidence
# IDs, paths, table names), and anything the condensation drops is reduced
# mechanically instead.
#
# Contract: this reduces the request to fit the context window.  It does NOT
# claim to re-generate anything — nothing here reconstructs the original,
# so the reduction block carries no version/source-revision or
# "regeneratable" labels.  What the reduction preserves (critical refs) is
# stated inside the block, and the durable expansion path is the same one
# that existed before the reduction: the Case/Trace records (investigation
# steps and receipts) addressed by the surviving tokens.  A block
# produced by this compaction is never condensed again.

_COMPACTED_MARKER_RE = re.compile(r"<COMPACTED_CONTEXT\b[^>]*>")

_TURN_DELIMITER = "\n\n"


def is_compacted_content(text: str) -> bool:
    """Return True if *text* is already an output of structured_compact."""
    return bool(_COMPACTED_MARKER_RE.search(text or ""))


def structured_compact(
    text: str,
    budget: int,
    *,
    base_url: str,
    model: str,
    preserve_recent_sections: int = 3,
) -> str:
    """Reduce *text* to fit *budget*; the reduction is one-way (R10).

    The request content is split on blank lines into its natural sections.
    The last ``preserve_recent_sections`` sections are kept verbatim; older
    sections are condensed (LLM) with the essential-token guard, falling
    back to the mechanical reduction whenever the LLM condensation is
    unavailable or would drop a preserved token.  The output states what is
    preserved and names the durable expansion path; it never claims that the
    original is reconstructible.  Content produced by an earlier reduction
    is returned unchanged instead of being reduced a second time.
    """
    if budget <= 0:
        return ""
    if is_compacted_content(text):
        # Never reduce a reduction: keep the existing block intact.
        return text
    sections = text.split(_TURN_DELIMITER) if _TURN_DELIMITER in text else [text]
    essential = _extract_essential_tokens(text)

    def bounded_projection(value: str) -> str:
        result = value if len(value) <= budget else mechanical_compact(value, budget)
        if not _essential_tokens_present(essential, result):
            raise CompactionPreservationError(
                "The context budget is too small to preserve all required references"
            )
        return result

    if len(sections) <= preserve_recent_sections + 1:
        # Too few sections to split; one bounded mechanical reduction.
        return bounded_projection(text)

    recent = sections[-preserve_recent_sections:]
    older = sections[:-preserve_recent_sections]
    older_text = _TURN_DELIMITER.join(older)

    summary = llm_compact(
        older_text, max(512, budget // 2), base_url=base_url, model=model
    )
    recent_block = _TURN_DELIMITER.join(recent)
    projection = (
        '<COMPACTED_CONTEXT note="one-way reduction to fit the context '
        "window; nothing is re-generated; surviving refs (event/evidence "
        'ids, paths, table names) address the Case/Trace originals">\n'
        "Preserved verbatim (most recent sections):\n"
        f"{recent_block}\n"
        "Condensed from the older sections; event/evidence ids, paths and "
        "table names are preserved verbatim, and anything still dropped was "
        "reduced mechanically:\n"
        f"{summary}\n"
        "</COMPACTED_CONTEXT>"
    )
    return bounded_projection(projection)
