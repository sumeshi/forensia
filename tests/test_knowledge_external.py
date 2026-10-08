"""Tests for forensia.knowledge.external — scan, index, section split."""

from __future__ import annotations

import logging
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
    def test_scan_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        assert scan_knowledge_dir(tmp_path / "nope") == []

    def test_scan_skips_non_knowledge_files(self, synthetic_dir: Path) -> None:
        docs = scan_knowledge_dir(synthetic_dir)
        names = {d.name for d in docs}
        assert "valid" in names
        assert "readme" not in names

    def test_scan_warns_on_broken_frontmatter(
        self, synthetic_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            docs = scan_knowledge_dir(synthetic_dir)
        assert [doc.name for doc in docs] == ["valid"]
        assert "invalid frontmatter" in caplog.text

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
        assert (docs[0].title, docs[0].description, docs[0].tags) == ("A", "d", ("x",))


class TestLoadBody:
    def test_load_body_strips_frontmatter(self, sample_dir: Path) -> None:
        docs = scan_knowledge_dir(sample_dir)
        body = load_body(docs[0])
        assert body.strip()
        assert not body.startswith("---")


class TestSplitSections:
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
