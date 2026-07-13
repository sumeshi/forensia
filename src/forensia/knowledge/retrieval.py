"""Deterministic 3-stage knowledge snippet selection.

Stage 1 – Tag filtering: keep docs whose tags intersect with *tags*.
          If no intersection, keep all docs (tolerates untagged corpora).
Stage 2 – File selection: score docs by query-term hits in title+description,
          then in body (top-K=20 only).  Select *max_files* by total score.
          Zero-score files are never selected.
Stage 3 – Section extraction: split selected files into ``##`` sections,
          score each by query-term hits, keep up to *max_sections_per_file*
          within *char_budget*.

All matching is case-insensitive substring.  Ties are broken by path
ascending.  No LLM calls are made.
"""

from __future__ import annotations

import re
from functools import lru_cache

from forensia.core.compaction import mechanical_compact
from forensia.knowledge.external import (
    KnowledgeDoc,
    KnowledgeSection,
    load_body,
    split_sections,
)

# Sections smaller than this are not worth compacting into leftover budget.
_MIN_COMPACT_CHARS = 200


@lru_cache(maxsize=1024)
def _term_pattern(term: str) -> re.Pattern[str]:
    # Token-boundary match so "log" does not hit "logon"/"catalog".
    return re.compile(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])")


def _score_text(text: str, terms: list[str]) -> int:
    """Count case-insensitive token-boundary occurrences of *terms* in *text*."""
    lower = text.lower()
    return sum(len(_term_pattern(t).findall(lower)) for t in terms if t)


def select_snippets(
    docs: list[KnowledgeDoc],
    *,
    query_terms: list[str],
    tags: list[str],
    max_files: int = 3,
    max_sections_per_file: int = 3,
    char_budget: int = 4000,
) -> list[KnowledgeSection]:
    """Return relevant knowledge sections using a deterministic 3-stage pipeline.

    Parameters
    ----------
    docs:
        Pre-scanned knowledge documents (from :func:`scan_knowledge_dir`).
    query_terms:
        Search terms (caller is responsible for tokenisation).
        Must already be lowercased for consistent scoring.
    tags:
        Tags to filter by.  Empty list disables tag filtering.
    max_files:
        Maximum number of source files to include.
    max_sections_per_file:
        Maximum sections per source file.
    char_budget:
        Hard character budget for the combined formatted output
        (source lines + section text; wrapper tags excluded).  A section
        that overflows the leftover budget is mechanically compacted at
        line boundaries rather than dropped.
    """
    if not docs or not query_terms:
        return []

    terms = [t.lower() for t in query_terms if t]

    # ── Stage 1: tag filtering ──────────────────────────────────────
    if tags:
        tag_set = {t.lower() for t in tags}
        candidates = [
            d for d in docs if tag_set & {t.lower() for t in d.tags}
        ]
        if not candidates:
            candidates = list(docs)
    else:
        candidates = list(docs)

    # ── Stage 2: file selection ─────────────────────────────────────
    _BODY_PREVIEW_LIMIT = 20

    scored: list[tuple[float, str, KnowledgeDoc]] = []
    for doc in candidates:
        meta_score = _score_text(
            f"{doc.title} {doc.description}", terms
        )
        scored.append((meta_score, str(doc.path), doc))

    # sort by meta_score desc, then path asc for determinism
    scored.sort(key=lambda x: (-x[0], x[1]))

    # load body and re-score top K=20 only
    top_k = scored[:_BODY_PREVIEW_LIMIT]
    rescored: list[tuple[float, str, KnowledgeDoc]] = []
    for meta_score, path_str, doc in top_k:
        body = load_body(doc)
        body_score = _score_text(body, terms)
        total = meta_score + body_score
        if total > 0:
            rescored.append((total, path_str, doc))

    # sort again by total desc, path asc
    rescored.sort(key=lambda x: (-x[0], x[1]))
    selected_docs = [doc for _, _, doc in rescored[:max_files]]

    if not selected_docs:
        return []

    # ── Stage 3: section extraction ─────────────────────────────────
    # The budget covers the formatted snippet size: the "[doc #heading]"
    # source line plus the section text (wrapper tags excluded).
    result: list[KnowledgeSection] = []
    total_chars = 0
    budget_exhausted = False

    for doc in selected_docs:
        if budget_exhausted:
            break
        body = load_body(doc)
        sections = split_sections(doc.name, body)

        # score each section
        section_scores: list[tuple[int, KnowledgeSection]] = []
        for sec in sections:
            score = _score_text(sec.text, terms)
            section_scores.append((score, sec))

        # Use the lead only as a fallback when no actual section matched.
        # Including it alongside matching sections spends budget on unrelated
        # prose and contradicts the Stage-3 selection contract.
        matching_sections = [item for item in section_scores if item[0] > 0]
        if matching_sections:
            section_scores = matching_sections
        else:
            section_scores = [item for item in section_scores if item[1].heading == ""]

        # sort by score desc (stable sort preserves original order for ties)
        section_scores.sort(key=lambda x: -x[0])

        picked = 0
        for score, sec in section_scores:
            if picked >= max_sections_per_file:
                break
            header_len = len(sec.doc_name) + len(sec.heading) + 6  # "[.. #..]\n"
            remaining = char_budget - total_chars - header_len
            if len(sec.text) > remaining:
                # Stage-1 compaction: fit the section into the leftover
                # budget at line boundaries instead of dropping it whole.
                if remaining >= _MIN_COMPACT_CHARS:
                    compacted = mechanical_compact(sec.text, remaining)
                    if compacted:
                        result.append(
                            KnowledgeSection(
                                doc_name=sec.doc_name,
                                heading=sec.heading,
                                text=compacted,
                            )
                        )
                        total_chars += header_len + len(compacted)
                budget_exhausted = True
                break
            result.append(sec)
            total_chars += header_len + len(sec.text)
            picked += 1

    return result


def knowledge_terms_for_hypothesis(
    title: str = "",
    description: str = "",
    tables: list[str] | None = None,
    extra_words: list[str] | None = None,
) -> list[str]:
    """Extract lowercase search terms from hypothesis text.

    Tokenises on non-alphanumeric, drops tokens shorter than 3 chars,
    and filters common English stop words.
    """
    import re

    _STOP = {
        "the", "and", "for", "are", "but", "not", "you", "all", "can",
        "has", "her", "was", "one", "our", "out", "this", "that", "with",
        "have", "from", "they", "been", "said", "each", "which", "their",
        "will", "other", "about", "many", "then", "them", "these", "some",
        "would", "make", "like", "into", "could", "time", "very", "when",
        "come", "made", "after", "also", "did", "just", "than", "what",
        "how", "its", "over", "such", "any", "new", "most", "may",
    }

    raw = f"{title} {description}"
    if extra_words:
        raw += " " + " ".join(extra_words)
    tokens = re.findall(r"[a-z0-9]{3,}", raw.lower())
    seen: set[str] = set()
    result: list[str] = []
    for tok in tokens:
        if tok in _STOP or tok in seen:
            continue
        seen.add(tok)
        result.append(tok)

    # add table names as-is (they are useful search terms)
    for tbl in tables or []:
        t = tbl.lower()
        if t not in seen:
            seen.add(t)
            result.append(t)

    return result
