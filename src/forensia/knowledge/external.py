"""External knowledge file scanner, indexer, and section splitter.

Loads ``*.md`` files with ``type: knowledge`` frontmatter from a user-specified
directory.  Designed for thousands of files: scanning reads only the first 8 KB
of each file (frontmatter only), and body text is loaded lazily via
:func:`load_body`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from forensia.core.frontmatter import parse_frontmatter

logger = logging.getLogger(__name__)

_FRONTMATTER_READ_LIMIT = 8192  # 8 KB

# Module-level singleton for the knowledge index, initialized at CLI startup.
_knowledge_docs: list[KnowledgeDoc] = []


@dataclass(frozen=True)
class KnowledgeDoc:
    """Index entry for one knowledge file (body not loaded)."""

    path: Path
    name: str  # stem without extension
    title: str
    description: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class KnowledgeSection:
    """One ``##``-delimited section extracted from a knowledge file.

    ``title`` and ``summary`` carry the parent document's frontmatter so a
    section can be injected as a self-contained fragment without exposing
    file names or tags to the LLM.
    """

    doc_name: str
    heading: str  # "" for lead text before the first ##
    text: str
    title: str = ""
    summary: str = ""


def set_knowledge_docs(docs: list[KnowledgeDoc]) -> None:
    """Set the global knowledge index (called once at CLI startup)."""
    global _knowledge_docs
    _knowledge_docs = list(docs)


def get_knowledge_docs() -> list[KnowledgeDoc]:
    """Return the current knowledge index (empty list if not configured)."""
    return _knowledge_docs


def scan_knowledge_dir(root: Path) -> list[KnowledgeDoc]:
    """Recursively scan *root* for ``*.md`` knowledge files.

    Only the first 8 KB of each file is read (frontmatter).  Files without
    ``type: knowledge``, with missing/unparseable frontmatter, or with parse
    errors are silently skipped with a warning log.
    """
    if not root.exists() or not root.is_dir():
        return []

    docs: list[KnowledgeDoc] = []
    for md_path in sorted(root.rglob("*.md")):
        try:
            # The scale contract is expressed in bytes, not Unicode code points.
            # Decode only the bounded prefix; an incomplete final code point is
            # irrelevant to frontmatter that must close inside this prefix.
            with md_path.open("rb") as fh:
                raw = fh.read(_FRONTMATTER_READ_LIMIT).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning("knowledge: cannot read %s: %s", md_path, exc)
            continue

        meta = parse_frontmatter(raw)
        if not meta:
            if raw.startswith("---\n"):
                logger.warning("knowledge: invalid frontmatter in %s", md_path)
            continue
        if str(meta.get("type", "")).strip() != "knowledge":
            continue

        raw_tags = meta.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = tuple(str(t).strip() for t in raw_tags if str(t).strip())

        docs.append(
            KnowledgeDoc(
                path=md_path,
                name=md_path.stem,
                title=str(meta.get("title") or "").strip(),
                description=str(meta.get("description") or "").strip(),
                tags=tags,
            )
        )
    return docs


def load_body(doc: KnowledgeDoc) -> str:
    """Return the Markdown body of *doc* (everything after the frontmatter)."""
    text = doc.path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return text
    parts = text.split("---\n", 2)
    if len(parts) < 3:
        return ""
    return parts[2]


def split_sections(
    doc_name: str, body: str, *, title: str = "", summary: str = ""
) -> list[KnowledgeSection]:
    """Split *body* into sections at ``## `` headings.

    Text before the first ``##`` heading is included as a section with
    ``heading=""`` (the lead paragraph).  ``#`` (h1) headings are treated
    as ordinary body text.  *title* and *summary* (the parent document's
    frontmatter) are attached to every section.
    """
    sections: list[KnowledgeSection] = []
    current_heading: str | None = None
    current_lines: list[str] = []

    def _flush() -> None:
        text = "\n".join(current_lines).strip()
        if current_heading is not None or text:
            sections.append(
                KnowledgeSection(
                    doc_name=doc_name,
                    heading="" if current_heading is None else current_heading,
                    text=text,
                    title=title,
                    summary=summary,
                )
            )

    for line in body.splitlines():
        if line.startswith("## "):
            _flush()
            current_heading = line[3:].strip()
            current_lines = []
        else:
            current_lines.append(line)

    _flush()
    return sections
