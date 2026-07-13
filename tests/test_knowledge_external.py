"""Tests for forensia.knowledge.external — scan, index, section split."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from forensia.knowledge.external import (
    KnowledgeDoc,
    get_knowledge_docs,
    load_body,
    scan_knowledge_dir,
    set_knowledge_docs,
    split_sections,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def sample_dir() -> Path:
    """Return the path to the bundled knowledge.sample/ directory."""
    return Path(__file__).resolve().parent.parent / "knowledge.sample"


@pytest.fixture()
def synthetic_dir(tmp_path: Path) -> Path:
    """Create a tmp dir with a valid knowledge file and a non-knowledge file."""
    d = tmp_path / "knowledge"
    d.mkdir()
    (d / "valid.md").write_text(
        "---\ntype: knowledge\ntitle: Test\ndescription: A test doc\ntags: [test]\n---\n# Body\n\nSome text.\n",
        encoding="utf-8",
    )
    (d / "readme.md").write_text(
        "# README\n\nThis is not a knowledge file.\n",
        encoding="utf-8",
    )
    (d / "broken.md").write_text(
        "---\ntype: knowledge\n: invalid yaml\n---\nBody\n",
        encoding="utf-8",
    )
    return d


# ── T1 acceptance: scan knowledge.sample ─────────────────────────────────────


class TestScanKnowledgeDir:
    def test_scan_sample_returns_all_knowledge_docs(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        assert len(docs) == 7

    def test_scan_sample_excludes_readme(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        names = {d.name for d in docs}
        assert "README" not in names

    def test_scan_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        assert scan_knowledge_dir(tmp_path / "nope") == []

    def test_scan_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        assert scan_knowledge_dir(d) == []

    def test_scan_skips_non_knowledge_files(self, synthetic_dir: Path) -> None:
        docs = scan_knowledge_dir(synthetic_dir)
        names = {d.name for d in docs}
        assert "valid" in names
        assert "readme" not in names

    def test_scan_skips_broken_frontmatter(self, synthetic_dir: Path) -> None:
        docs = scan_knowledge_dir(synthetic_dir)
        names = {d.name for d in docs}
        # broken.md has invalid YAML — parse_frontmatter returns {} → skipped
        assert "broken" not in names

    def test_scan_warns_on_broken_frontmatter(
        self, synthetic_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            scan_knowledge_dir(synthetic_dir)
        assert "invalid frontmatter" in caplog.text

    def test_scan_reads_only_frontmatter(self, tmp_path: Path) -> None:
        """8 KB+ file: frontmatter parsed, body NOT read during scan."""
        d = tmp_path / "big"
        d.mkdir()
        body = "x" * 50000
        (d / "big.md").write_text(
            f"---\ntype: knowledge\ntitle: Big\ndescription: Large file\ntags: [big]\n---\n{body}",
            encoding="utf-8",
        )
        docs = scan_knowledge_dir(d)
        assert len(docs) == 1
        assert docs[0].title == "Big"

    def test_scan_recursive(self, tmp_path: Path) -> None:
        d = tmp_path / "root"
        sub = d / "sub"
        sub.mkdir(parents=True)
        (sub / "a.md").write_text(
            "---\ntype: knowledge\ntitle: A\ndescription: d\ntags: [x]\n---\nBody\n",
            encoding="utf-8",
        )
        docs = scan_knowledge_dir(d)
        assert len(docs) == 1

    def test_doc_fields(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        rdp = [d for d in docs if "rdp" in d.name][0]
        assert rdp.title != ""
        assert rdp.description != ""
        assert len(rdp.tags) > 0


class TestLoadBody:
    def test_load_body_strips_frontmatter(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        body = load_body(docs[0])
        assert not body.startswith("---")

    def test_load_body_has_content(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        for doc in docs:
            body = load_body(doc)
            assert len(body) > 0


class TestSplitSections:
    def test_split_includes_lead_section(self) -> None:
        body = "Lead text.\n\n## Heading 1\nBody 1.\n## Heading 2\nBody 2.\n"
        secs = split_sections("test", body)
        assert secs[0].heading == ""
        assert "Lead text" in secs[0].text

    def test_split_heading_sections(self) -> None:
        body = "Lead.\n\n## Alpha\nContent A\n## Beta\nContent B\n"
        secs = split_sections("test", body)
        headings = [s.heading for s in secs]
        assert "Alpha" in headings
        assert "Beta" in headings

    def test_split_no_headings(self) -> None:
        body = "Just plain text without any headings."
        secs = split_sections("test", body)
        assert len(secs) == 1
        assert secs[0].heading == ""

    def test_split_h1_ignored(self) -> None:
        body = "# H1 Title\n\n## H2 Section\nBody.\n"
        secs = split_sections("test", body)
        # H1 is treated as body text, not a section break
        assert secs[0].heading == ""
        assert "H1 Title" in secs[0].text


class TestKnowledgeSampleRdpMatch:
    """T1 acceptance: sample scan includes the RDP knowledge document."""

    def test_rdp_doc_present(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        names = [d.name for d in docs]
        assert any("rdp" in n for n in names)


class TestSingleton:
    def test_set_and_get(self) -> None:
        set_knowledge_docs([])
        assert get_knowledge_docs() == []
        docs = [
            KnowledgeDoc(
                path=Path("/fake"), name="x", title="X", description="d", tags=()
            )
        ]
        set_knowledge_docs(docs)
        assert len(get_knowledge_docs()) == 1
        set_knowledge_docs([])


# ── Scale test ───────────────────────────────────────────────────────────────


class TestScalePerformance:
    def test_scan_1000_files_under_2_seconds(self, tmp_path: Path) -> None:
        d = tmp_path / "scale"
        d.mkdir()
        for i in range(1000):
            (d / f"doc-{i:04d}.md").write_text(
                f"---\ntype: knowledge\ntitle: Doc {i}\ndescription: Test document number {i}\ntags: [tag{i % 10}]\n---\n# Body {i}\n\nContent for doc {i}.\n",
                encoding="utf-8",
            )
        start = time.monotonic()
        docs = scan_knowledge_dir(d)
        elapsed = time.monotonic() - start
        assert len(docs) == 1000
        assert elapsed < 2.0, f"scan took {elapsed:.2f}s (>2s)"

    def test_select_snippets_1000_files_under_2_seconds(self, tmp_path: Path) -> None:
        from forensia.knowledge.retrieval import select_snippets

        d = tmp_path / "scale"
        d.mkdir()
        for i in range(1000):
            (d / f"doc-{i:04d}.md").write_text(
                f"---\ntype: knowledge\ntitle: Doc {i}\ndescription: keyword{i} test document\ntags: [tag{i % 10}]\n---\n# Body {i}\n\nContent for doc {i}.\n",
                encoding="utf-8",
            )
        docs = scan_knowledge_dir(d)
        start = time.monotonic()
        snippets = select_snippets(
            docs,
            query_terms=["keyword500"],
            tags=[],
        )
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"select took {elapsed:.2f}s (>2s)"
        assert len(snippets) > 0
