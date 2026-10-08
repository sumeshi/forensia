"""Tests for forensia.knowledge.retrieval — 3-stage selection logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensia.ai.prompts.prompt_context import _org_knowledge_guidance
from forensia.knowledge.external import (
    KnowledgeDoc,
    KnowledgeSection,
    scan_knowledge_dir,
)
from forensia.knowledge.retrieval import (
    _section_overhead,
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
            tags=["rdp"],
            max_files=1,
            max_sections_per_file=1,
        )
        assert len(snippets) == 1
        assert snippets[0].title and snippets[0].summary
        # First snippet should come from the rdp doc
        assert "rdp" in snippets[0].doc_name.lower()

    def test_combined_fragment_overhead_includes_joining_newline(self) -> None:
        sections = [
            KnowledgeSection("one.md", "One", "BODY 1", "Topic one", "Summary"),
            KnowledgeSection("two.md", "Two", "BODY 2", "Topic two", "Summary"),
        ]
        rendered = _org_knowledge_guidance(sections)
        start = rendered.index("<KNOWLEDGE>")
        end = rendered.rindex("</KNOWLEDGE>") + len("</KNOWLEDGE>")
        fragments = rendered[start:end]
        expected = sum(_section_overhead(s) + len(s.text) for s in sections) + 1
        assert len(fragments) == expected

    def test_overflow_section_is_compacted_not_dropped(self, tmp_path: Path) -> None:
        """A section that overflows leftover budget is line-truncated, not skipped."""
        from forensia.core.compaction import TRUNCATION_MARKER

        lines = "\n".join(f"- rdp detail line {i}" for i in range(100))
        (tmp_path / "long.md").write_text(
            "---\ntype: knowledge\ntitle: RDP long guide\n"
            "description: RDP details\ntags: [rdp]\n---\n"
            f"## RDP events\n{lines}\n",
            encoding="utf-8",
        )
        snippets = select_snippets(
            scan_knowledge_dir(tmp_path),
            query_terms=["rdp"],
            tags=[],
            char_budget=800,
        )
        assert snippets, "expected a compacted snippet within a small budget"
        assert any(s.text.endswith(TRUNCATION_MARKER) for s in snippets)
        rendered = _org_knowledge_guidance(snippets)
        start = rendered.index("<KNOWLEDGE>")
        end = rendered.rindex("</KNOWLEDGE>") + len("</KNOWLEDGE>")
        assert len(rendered[start:end]) <= 800

    def test_token_boundary_scoring(self) -> None:
        """'log' must not match 'logon' or 'catalog'."""
        from forensia.knowledge.retrieval import _score_text

        assert _score_text("logon catalog logging", ["log"]) == 0
        assert _score_text("the log was cleared. log-rotation", ["log"]) == 2
        assert _score_text("event 4624: ログオン成功", ["4624"]) == 1

    def test_no_match_returns_empty(self, sample_docs) -> None:
        snippets = select_snippets(
            sample_docs,
            query_terms=["zzzznonexistentzzzz"],
            tags=[],
        )
        assert snippets == []

    def test_tag_filtering_no_match_falls_back_to_all(self, sample_docs) -> None:
        """If no docs match tags, fall back to all docs."""
        snippets = select_snippets(
            sample_docs,
            query_terms=["event"],
            tags=["nonexistent_tag_xyz"],
        )
        # Should still return something (fallback to all docs)
        assert len(snippets) > 0

    def test_lead_used_only_for_docs_without_sections(self, tmp_path: Path) -> None:
        """A doc with no ## sections still contributes its lead paragraph."""
        path = tmp_path / "leadonly.md"
        path.write_text(
            "---\ntype: knowledge\ntitle: RDP quick note\n"
            "description: RDP note without sections\ntags: [rdp]\n---\n"
            "RDP lead-only prose.\n",
            encoding="utf-8",
        )
        snippets = select_snippets(
            scan_knowledge_dir(tmp_path), query_terms=["rdp"], tags=["rdp"]
        )
        assert snippets
        assert all(s.heading == "" for s in snippets)

    def test_lead_never_injected_alongside_sections(self, tmp_path: Path) -> None:
        """When a doc has ## sections, its lead paragraph is not injected even
        if it matches: the document description covers that context."""
        path = tmp_path / "withlead.md"
        path.write_text(
            "---\ntype: knowledge\ntitle: RDP guide\n"
            "description: RDP guide with lead\ntags: [rdp]\n---\n"
            "RDP lead prose that matches the query.\n\n"
            "## RDP checks\nRDP evidence details.\n",
            encoding="utf-8",
        )
        snippets = select_snippets(
            scan_knowledge_dir(tmp_path), query_terms=["rdp"], tags=["rdp"]
        )
        assert snippets
        assert all(s.heading == "RDP checks" for s in snippets)

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

    def test_includes_table_names(self) -> None:
        terms = knowledge_terms_for_hypothesis(
            title="test",
            tables=["evtx_events", "mft_entries"],
        )
        assert "evtx_events" in terms
        assert "mft_entries" in terms
