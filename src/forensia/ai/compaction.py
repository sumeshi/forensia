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


def _essential_tokens_present(
    original_tokens: set[str], compacted: str
) -> bool:
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
        logger.debug("llm_compact: LLM call failed (%s), falling back to mechanical", exc)
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
