"""Tests for forensia.knowledge.retrieval — 3-stage selection logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensia.knowledge.external import KnowledgeDoc, scan_knowledge_dir
from forensia.knowledge.retrieval import (
    knowledge_terms_for_hypothesis,
    select_snippets,
)


@pytest.fixture()
def sample_docs() -> list[KnowledgeDoc]:
    sample_dir = Path(__file__).resolve().parent.parent / "knowledge.sample"
    return scan_knowledge_dir(sample_dir)


# ── T2 acceptance: deterministic output ──────────────────────────────────────


class TestSelectSnippets:
    def test_rdp_query_returns_rdp_sections_first(self, sample_docs) -> None:
        """query_terms=['rdp'] should surface 20-rdp-remote-access sections."""
        snippets = select_snippets(
            sample_docs,
            query_terms=["rdp"],
            tags=[],
        )
        assert len(snippets) > 0
        # First snippet should come from the rdp doc
        assert "rdp" in snippets[0].doc_name.lower()

    def test_deterministic_output(self, sample_docs) -> None:
        """Same input → same output (order included)."""
        r1 = select_snippets(sample_docs, query_terms=["rdp"], tags=[])
        r2 = select_snippets(sample_docs, query_terms=["rdp"], tags=[])
        assert [(s.doc_name, s.heading) for s in r1] == [
            (s.doc_name, s.heading) for s in r2
        ]

    def test_char_budget_respected(self, sample_docs) -> None:
        """Budget covers formatted size: '[doc #heading]' line + section text."""
        for budget in (500, 1000, 4000):
            snippets = select_snippets(
                sample_docs,
                query_terms=["event"],
                tags=[],
                char_budget=budget,
            )
            total = sum(
                len(s.doc_name) + len(s.heading) + 6 + len(s.text) for s in snippets
            )
            assert total <= budget

    def test_overflow_section_is_compacted_not_dropped(self, sample_docs) -> None:
        """A section that overflows leftover budget is line-truncated, not skipped."""
        from forensia.core.compaction import TRUNCATION_MARKER

        snippets = select_snippets(
            sample_docs,
            query_terms=["rdp"],
            tags=[],
            char_budget=800,
        )
        assert snippets, "expected a compacted snippet within a small budget"
        assert any(s.text.endswith(TRUNCATION_MARKER) for s in snippets)
        total = sum(
            len(s.doc_name) + len(s.heading) + 6 + len(s.text) for s in snippets
        )
        assert total <= 800

    def test_token_boundary_scoring(self) -> None:
        """'log' must not match 'logon' or 'catalog'."""
        from forensia.knowledge.retrieval import _score_text

        assert _score_text("logon catalog logging", ["log"]) == 0
        assert _score_text("the log was cleared. log-rotation", ["log"]) == 2
        assert _score_text("event 4624: ログオン成功", ["4624"]) == 1

    def test_max_files_respected(self, sample_docs) -> None:
        snippets = select_snippets(
            sample_docs,
            query_terms=["windows"],
            tags=[],
            max_files=1,
        )
        doc_names = {s.doc_name for s in snippets}
        assert len(doc_names) <= 1

    def test_max_sections_per_file_respected(self, sample_docs) -> None:
        snippets = select_snippets(
            sample_docs,
            query_terms=["event"],
            tags=[],
            max_sections_per_file=1,
        )
        from collections import Counter

        counts = Counter(s.doc_name for s in snippets)
        assert all(c <= 1 for c in counts.values())

    def test_empty_query_returns_empty(self, sample_docs) -> None:
        assert select_snippets(sample_docs, query_terms=[], tags=[]) == []

    def test_empty_docs_returns_empty(self) -> None:
        assert select_snippets([], query_terms=["test"], tags=[]) == []

    def test_no_match_returns_empty(self, sample_docs) -> None:
        snippets = select_snippets(
            sample_docs,
            query_terms=["zzzznonexistentzzzz"],
            tags=[],
        )
        assert snippets == []

    def test_tag_filtering(self, sample_docs) -> None:
        """Tag filtering narrows candidates."""
        all_snippets = select_snippets(
            sample_docs,
            query_terms=["event"],
            tags=[],
        )
        # Use a tag that only some docs have
        rdp_snippets = select_snippets(
            sample_docs,
            query_terms=["event"],
            tags=["rdp"],
        )
        # rdp-tagged snippets should be a subset or equal
        assert len(rdp_snippets) <= len(all_snippets)

    def test_tag_filtering_no_match_falls_back_to_all(self, sample_docs) -> None:
        """If no docs match tags, fall back to all docs."""
        snippets = select_snippets(
            sample_docs,
            query_terms=["event"],
            tags=["nonexistent_tag_xyz"],
        )
        # Should still return something (fallback to all docs)
        assert len(snippets) > 0

    def test_zero_score_lead_section_included(self, sample_docs) -> None:
        """When no section has a hit, lead section (heading='') is included."""
        # Use a very specific term that only appears in one doc's title/description
        snippets = select_snippets(
            sample_docs,
            query_terms=["rdp"],
            tags=["rdp"],
            max_files=1,
            char_budget=10000,
        )
        # At least one snippet from the rdp doc
        assert any("rdp" in s.doc_name.lower() for s in snippets)

    def test_lead_section_excluded_when_heading_matches(self, tmp_path: Path) -> None:
        path = tmp_path / "focused.md"
        path.write_text(
            "---\ntype: knowledge\ntitle: Focused RDP guide\n"
            "description: RDP procedures\ntags: [rdp]\n---\n"
            "Unrelated introductory prose.\n\n"
            "## RDP checks\nRDP evidence details.\n",
            encoding="utf-8",
        )
        snippets = select_snippets(
            scan_knowledge_dir(tmp_path), query_terms=["rdp"], tags=["rdp"]
        )
        assert snippets
        assert all(snippet.heading == "RDP checks" for snippet in snippets)


class TestKnowledgeTermsForHypothesis:
    def test_extracts_terms(self) -> None:
        terms = knowledge_terms_for_hypothesis(
            title="RDP logon from external IP",
            description="Investigate RDP connection attempts",
        )
        assert "rdp" in terms
        assert "logon" in terms
        assert "external" in terms

    def test_drops_short_tokens(self) -> None:
        terms = knowledge_terms_for_hypothesis(title="A B CD")
        assert "a" not in terms
        assert "b" not in terms
        assert "cd" not in terms

    def test_drops_stop_words(self) -> None:
        terms = knowledge_terms_for_hypothesis(title="The event of the system")
        assert "the" not in terms
        assert "of" not in terms

    def test_includes_table_names(self) -> None:
        terms = knowledge_terms_for_hypothesis(
            title="test",
            tables=["evtx_events", "mft_entries"],
        )
        assert "evtx_events" in terms
        assert "mft_entries" in terms

    def test_extra_words_included(self) -> None:
        terms = knowledge_terms_for_hypothesis(extra_words=["customterm"])
        assert "customterm" in terms

    def test_empty_input_returns_empty(self) -> None:
        assert knowledge_terms_for_hypothesis() == []
