"""Stage-2 LLM compaction with fact-preservation guards and caching.

Wraps ``core.compaction.mechanical_compact`` (Stage 1) and adds an optional
LLM summarisation step.  Falls back to the mechanical stage on any failure,
when essential tokens are lost, or when the LLM output still exceeds budget.

Design rules
------------
- Lives in ``ai/`` (may import from ``core/`` and ``ai.llm``).
- Never raises to the caller — always degrades to mechanical compaction.
- Process-level cache keyed on ``(sha256(text), budget)`` to avoid redundant
  LLM calls for identical inputs within a single forensia run.
- Only called from sites that **already** have an LLM client (base_url/model),
  never from pure prompt-builder functions.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading

from forensia.core.compaction import mechanical_compact

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Essential-token extraction
# ---------------------------------------------------------------------------

# Event IDs: 3-5 digit numbers commonly used in Windows event logs
_EVENT_ID_RE = re.compile(r"\b\d{3,5}\b")

# Table names that appear in SQL / schema references
_TABLE_NAME_RE = re.compile(
    r"\b(?:evtx_events|mft_entries|mft_timeline|prefetch_executions|prefetch_timeline|findings)\b",
    re.IGNORECASE,
)

# File paths: Windows (C:\...) and Unix (/...)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s,;\"']+")
_UNIX_PATH_RE = re.compile(r"(?<!\w)/[^\s,;\"']+")

# Evidence IDs: evtx-security-NNNNNNNNNN, mft-..., etc.
_EVIDENCE_ID_RE = re.compile(r"\b(?:evtx|mft|prefetch)-[\w-]+\b", re.IGNORECASE)


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
    from forensia.ai.llm.llm_client import chat_completion

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
    )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

_CACHE_SIZE = 256

# Bounded FIFO cache: oldest entry evicted once _CACHE_SIZE is reached.
_cache: dict[tuple[str, int], str] = {}
_cache_lock = threading.Lock()


def _cache_key(text: str, budget: int) -> tuple[str, int]:
    """SHA-256 hash of text + budget for cache lookup."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (h, budget)


def _cache_get(text: str, budget: int) -> str | None:
    with _cache_lock:
        return _cache.get(_cache_key(text, budget))


def _cache_store(key: tuple[str, int], value: str) -> None:
    with _cache_lock:
        if key not in _cache and len(_cache) >= _CACHE_SIZE:
            _cache.pop(next(iter(_cache)))
        _cache[key] = value


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

    # Fast path: mechanical is likely good enough
    if len(text) < budget * _MECHANICAL_SUFFICIENCY_RATIO:
        return mechanical_compact(text, budget)

    # Cache check
    cached = _cache_get(text, budget)
    if cached is not None:
        return cached

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

    # Try LLM summarisation
    try:
        llm_output = _call_llm(text, budget, base_url=base_url, model=model)
    except Exception as exc:
        logger.debug(
            "llm_compact: LLM call failed (%s), falling back to mechanical", exc
        )
        result = mechanical_compact(text, budget)
        _cache_store(_cache_key(text, budget), result)
        return result

    # Guard: essential tokens must be present
    if not _essential_tokens_present(essential, llm_output):
        missing = {t for t in essential if t.lower() not in llm_output.lower()}
        logger.info(
            "llm_compact: LLM output dropped %d essential token(s), falling back to mechanical. "
            "Examples: %s",
            len(missing),
            list(missing)[:5],
        )
        result = mechanical_compact(text, budget)
        _cache_store(_cache_key(text, budget), result)
        return result

    # Guard: output must be within budget
    if len(llm_output) > budget:
        llm_output = mechanical_compact(llm_output, budget)
        if not _essential_tokens_present(essential, llm_output):
            result = mechanical_compact(text, budget)
            _cache_store(_cache_key(text, budget), result)
            return result

    # Guard: empty output
    if not llm_output.strip():
        result = mechanical_compact(text, budget)
        _cache_store(_cache_key(text, budget), result)
        return result

    _cache_store(_cache_key(text, budget), llm_output)
    return llm_output


def clear_compaction_cache() -> None:
    """Reset the process-level compaction cache (for testing)."""
    with _cache_lock:
        _cache.clear()


# ---------------------------------------------------------------------------
# Structured compaction (T-22): versioned, regeneratable projection
# ---------------------------------------------------------------------------
#
# Context-overflow compaction must preserve recent turns verbatim and fold
# older turns into a *versioned structured projection*. The projection is
# explicitly regeneratable from the durable conversation/Case State and is
# NEVER treated as authority. On resume we validate the referenced revision
# and the referenced IDs; recursive summarization of an already-summarized
# projection is refused to prevent degradation.

_TURN_DELIMITER = "\n\n"

_STRUCTURED_PROJECTION_RE = re.compile(
    r"<STRUCTURED_PROJECTION\b[^>]*\brevision=\"(\d+)\"[^>]*>", re.DOTALL
)


def is_structured_projection(text: str) -> bool:
    """Return True if *text* is already a structured projection (a summary)."""
    return bool(_STRUCTURED_PROJECTION_RE.search(text or ""))


def _extract_projection_revision(text: str) -> int | None:
    """Return the revision integer of a structured projection, or None."""
    match = _STRUCTURED_PROJECTION_RE.search(text or "")
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _next_revision(source_revision: int | str | None) -> int:
    """Derive the next projection revision from a source revision."""
    try:
        base = int(source_revision or 0)
    except TypeError, ValueError:
        base = 0
    return base + 1


def structured_compact(
    text: str,
    budget: int,
    *,
    base_url: str,
    model: str,
    revision: int | None = None,
    source_revision: int | str | None = None,
    preserve_recent_turns: int = 3,
) -> str:
    """Compact *text* into a versioned structured projection.

    Recent turns (split on blank lines) are preserved verbatim inside
    ``<RECENT_VERBATIM>``; older turns are summarized (LLM) into
    ``<SUMMARY>``. The wrapper ``<STRUCTURED_PROJECTION>`` carries a
    ``revision``, the ``source_revision`` it was derived from, and
    ``regeneratable="true"`` to mark it as a non-authoritative projection.

    Recursive degradation guard: if *text* is already a structured
    projection it is returned unchanged — a summary is never summarized
    again.
    """
    if budget <= 0:
        return ""
    if is_structured_projection(text):
        # Refuse to summarize a summary: keep the existing projection intact.
        return text
    turns = (
        text.split(_TURN_DELIMITER)
        if _TURN_DELIMITER in text
        else [text]
    )
    if len(turns) <= preserve_recent_turns + 1:
        # Too few turns to benefit from a structured projection.
        return mechanical_compact(text, budget)

    recent = turns[-preserve_recent_turns:]
    older = turns[:-preserve_recent_turns]
    older_text = _TURN_DELIMITER.join(older)
    rev = revision if revision is not None else _next_revision(source_revision)

    summary = llm_compact(
        older_text, max(512, budget // 2), base_url=base_url, model=model
    )
    recent_block = _TURN_DELIMITER.join(recent)
    projection = (
        f'<STRUCTURED_PROJECTION revision="{rev}" '
        f'source_revision="{source_revision or 0}" regeneratable="true">\n'
        f"<RECENT_VERBATIM>\n{recent_block}\n</RECENT_VERBATIM>\n"
        f'<SUMMARY revision="{rev}" regeneratable="true">\n{summary}\n</SUMMARY>\n'
        f"</STRUCTURED_PROJECTION>"
    )
    if len(projection) > budget:
        projection = mechanical_compact(projection, budget)
    return projection


def validate_projection_revision(
    projection: str, expected_revision: int | str | None
) -> bool:
    """Validate that *projection* carries the expected revision.

    Used on resume to confirm the loaded projection has not drifted from the
    durable revision it claims to represent. Returns True when the projection
    is not a structured projection (nothing to validate) or revisions match.
    """
    rev = _extract_projection_revision(projection)
    if rev is None:
        return True
    try:
        return rev == int(expected_revision or 0)
    except TypeError, ValueError:
        return False


def validate_projection_ids(
    projection: str, required_ids: list[str]
) -> tuple[bool, list[str]]:
    """Validate that every *required_id* is still referenced in *projection*.

    Returns ``(ok, missing)``. A structured projection may reference durable
    IDs (e.g. event IDs, evidence IDs) that must still exist on resume; this
    confirms they are present. IDs are matched as whole-token substrings.
    """
    if not required_ids:
        return True, []
    haystack = (projection or "").lower()
    missing = [rid for rid in required_ids if str(rid).lower() not in haystack]
    return (not missing), missing
