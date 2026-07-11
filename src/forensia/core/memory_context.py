"""Context loading and relevance selection for investigation memory."""

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MemoryContextMixin:
    def _memory_line(
        self,
        text: str,
        evidence_ids: list[str],
        *,
        hypothesis_id: str | None = None,
        provisional: bool = False,
    ) -> str:
        """Build a Markdown list item with optional hypothesis/evidence/provisional metadata."""
        body = str(text).strip()
        if not body:
            return ""
        meta: list[str] = []
        if hypothesis_id:
            meta.append(f"hypothesis: {str(hypothesis_id).strip()}")
        meta.append("provisional" if provisional else "confirmed")
        normalized_ids = [
            str(item).strip() for item in evidence_ids if str(item).strip()
        ]
        if normalized_ids:
            meta.append(f"evidence: {', '.join(normalized_ids)}")
        if meta:
            body += f" [{' | '.join(meta)}]"
        return f"- {body}"

    @staticmethod
    def _extract_line_text(line: str) -> str:
        """Extract the text content from a formatted memory line for comparison.

        Strips the leading '- ' bullet, trailing metadata brackets like
        '[confirmed | evidence: E-001]', and detail IDs like '[fact-001]'.
        """
        text = line.strip()
        if text.startswith("- "):
            text = text[2:]
        # Strip trailing metadata brackets: [confirmed | evidence: ...]
        # or [provisional | evidence: ...]
        meta_match = re.search(
            r"\s*\[(?:confirmed|provisional)(?:\s*\|.*)?\]\s*$", text
        )
        if meta_match:
            text = text[: meta_match.start()]
        # Strip detail IDs like [fact-001] that are unique per entry
        text = re.sub(r"\s*\[fact-\d+\]\s*", " ", text)
        return text.strip()

    @staticmethod
    def _extract_evidence_ids(line: str) -> list[str]:
        """Extract evidence IDs from a formatted memory line."""
        match = re.search(r"evidence:\s*([^\]]+)\]", line)
        if not match:
            return []
        raw = match.group(1)
        return sorted(e.strip() for e in raw.split(",") if e.strip())

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Split text into lowercase tokens for relevance matching."""
        return {t.casefold() for t in re.findall(r"\w+", text) if len(t) > 1}

    @staticmethod
    def _file_matches_relevance(
        rel_path: str, base_dir: Path, relevance_terms: set[str], head_lines: int = 10
    ) -> bool:
        """Return True if a file's filename or first *head_lines* contain any relevance token."""
        # Check filename tokens
        fname_tokens = set()
        for part in Path(rel_path).stem.split("_"):
            fname_tokens.update(MemoryContextMixin._tokenize(part))
        if fname_tokens & relevance_terms:
            return True
        # Check first N lines of file content
        full = (base_dir / rel_path).resolve()
        try:
            if full.exists() and full.is_file():
                with full.open(encoding="utf-8") as fh:
                    for i, line in enumerate(fh):
                        if i >= head_lines:
                            break
                        if MemoryContextMixin._tokenize(line) & relevance_terms:
                            return True
        except OSError, UnicodeDecodeError:
            pass
        return False

    @staticmethod
    def build_relevance_terms_from_hypothesis(hypothesis: Any) -> set[str]:
        """Extract relevance tokens from a Hypothesis's description + required_entities."""
        if hypothesis is None:
            return set()
        terms: set[str] = set()
        desc = getattr(hypothesis, "description", None)
        if desc:
            terms.update(MemoryContextMixin._tokenize(desc))
        for ent in getattr(hypothesis, "required_entities", []) or []:
            terms.update(MemoryContextMixin._tokenize(ent))
        return terms

    def investigation_context_files(
        self,
        hypothesis_id: str | None = None,
        *,
        relevance_terms: set[str] | None = None,
        include_archive: bool = True,
        include_overview: bool = True,
        include_entities: bool = True,
        include_keypoints: bool = True,
        include_scratch: bool = True,
    ) -> list[str]:
        """Assemble a deduplicated list of memory file paths for LLM context.

        When *relevance_terms* is provided and non-empty, entity and keypoint
        files are filtered to those whose filename or first few lines contain
        at least one token matching a relevance term (case-insensitive).
        When empty or None, all entity/keypoint files are included (backward
        compatible).
        """
        files: list[str] = []
        if include_overview:
            files.extend(["overview.md", "facts.md", "timeline.md", "tasks.md"])
        if include_archive:
            files.extend(["archive/refuted.md", "archive/resolved_gaps.md"])
        if include_entities:
            ent_files = self._markdown_files(self.entities_dir)
            if relevance_terms:
                ent_files = [
                    f
                    for f in ent_files
                    if self._file_matches_relevance(f, self.base_dir, relevance_terms)
                ]
            files.extend(ent_files)
        if include_keypoints:
            kp_files = self._markdown_files(self.keypoints_dir)
            if relevance_terms:
                kp_files = [
                    f
                    for f in kp_files
                    if self._file_matches_relevance(f, self.base_dir, relevance_terms)
                ]
            files.extend(kp_files)
        if include_scratch:
            files.extend(self._markdown_files(self.scratch_global_dir))
            if hypothesis_id:
                files.extend(
                    self._markdown_files(self._hypothesis_scratch_dir(hypothesis_id))
                )
        deduped: list[str] = []
        seen: set[str] = set()
        for item in files:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    def load_investigation_context(
        self,
        hypothesis_id: str | None = None,
        *,
        relevance_terms: set[str] | None = None,
        max_bytes: int | None = None,
        include_archive: bool = True,
        include_overview: bool = True,
        include_entities: bool = True,
        include_keypoints: bool = True,
        include_scratch: bool = True,
    ) -> str:
        """Load investigation context files respecting a byte budget via compact context."""
        return self.load_compact_context(
            self.investigation_context_files(
                hypothesis_id,
                relevance_terms=relevance_terms,
                include_archive=include_archive,
                include_overview=include_overview,
                include_entities=include_entities,
                include_keypoints=include_keypoints,
                include_scratch=include_scratch,
            ),
            max_bytes=max_bytes,
        )

    # Priority constants for memory trimming — lower number = higher priority.
    PRIORITY_P0 = 0  # overview, facts — NEVER fully removed
    PRIORITY_P1 = 1  # timeline, tasks, archive
    PRIORITY_P2 = 2  # entities, keypoints
    PRIORITY_P3 = 3  # scratch — cut first

    # Minimum lines to preserve for P0 files even under extreme budget pressure.
    _P0_MIN_LINES = 5

    def _file_priority(self, relative_path: str) -> int:
        """Assign a trimming priority to a memory file by its relative path."""
        if relative_path in ("overview.md", "facts.md"):
            return self.PRIORITY_P0
        if relative_path.startswith("scratch/"):
            return self.PRIORITY_P3
        if relative_path.startswith("entities/") or relative_path.startswith(
            "keypoints/"
        ):
            return self.PRIORITY_P2
        # timeline, tasks, archive/*, etc.
        return self.PRIORITY_P1

    def load_compact_context(
        self, files: list[str], max_bytes: int | None = None
    ) -> str:
        """Load context from files, trimming lowest-priority files first when over budget.

        Priority order (lowest cuts first):
          P3 scratch  →  P2 entities/keypoints  →  P1 timeline/tasks/archive  →  P0 overview/facts

        P0 files are never fully removed — at least ``_P0_MIN_LINES`` are kept.
        Within each priority level, trimming removes lines from the TAIL.
        """
        budget = max_bytes if max_bytes is not None else self.max_bytes

        # Read each file individually with its priority.
        original_order: list[str] = []
        file_data: dict[str, tuple[int, list[str]]] = {}  # rel -> (priority, lines)

        for relative in files:
            path = (self.base_dir / relative).resolve()
            try:
                path.relative_to(self.base_dir.resolve())
            except ValueError:
                continue
            if path.exists() and path.is_file():
                text = path.read_text(encoding="utf-8")
                priority = self._file_priority(relative)
                original_order.append(relative)
                file_data[relative] = (priority, text.splitlines(keepends=True))

        # Fast path: everything fits.
        def _assemble(data: dict[str, tuple[int, list[str]]]) -> str:
            parts: list[str] = []
            for rel in original_order:
                if rel in data:
                    _, lines = data[rel]
                    parts.append(f"# {rel}\n\n{''.join(lines)}")
            return "\n\n".join(parts)

        total_bytes = len(_assemble(file_data).encode("utf-8"))
        if total_bytes <= budget:
            return _assemble(file_data)

        # Sort files by priority descending (P3 first) for cutting order.
        cut_order = sorted(original_order, key=lambda r: -file_data[r][0])

        for rel in cut_order:
            priority, lines = file_data.get(rel, (self.PRIORITY_P3, []))
            if not lines:
                continue

            # --- Try removing entire file first (skip for P0) ---
            if priority > self.PRIORITY_P0:
                test = {k: v for k, v in file_data.items() if k != rel}
                if len(_assemble(test).encode("utf-8")) <= budget:
                    logger.info(
                        "memory trim: removed %s (P%d) to fit budget %d bytes",
                        rel,
                        priority,
                        budget,
                    )
                    file_data.pop(rel, None)
                    return _assemble(file_data)

            # --- Truncate from TAIL in 25 % chunks ---
            keep_count = len(lines)
            min_lines = self._P0_MIN_LINES if priority == self.PRIORITY_P0 else 0
            step = max(1, len(lines) // 4)

            while keep_count > min_lines:
                keep_count -= step
                if keep_count < min_lines:
                    keep_count = min_lines
                file_data[rel] = (priority, lines[:keep_count])
                if len(_assemble(file_data).encode("utf-8")) <= budget:
                    logger.info(
                        "memory trim: truncated %s (P%d) %d → %d lines",
                        rel,
                        priority,
                        len(lines),
                        keep_count,
                    )
                    return _assemble(file_data)

            # Could not trim this file enough — drop it (non-P0 only).
            if priority > self.PRIORITY_P0:
                file_data.pop(rel, None)
                logger.info(
                    "memory trim: removed %s (P%d) entirely (min lines reached)",
                    rel,
                    priority,
                )
                if len(_assemble(file_data).encode("utf-8")) <= budget:
                    return _assemble(file_data)

        # Budget still exceeded — return what we have.
        logger.warning(
            "memory trim: budget %d bytes still exceeded after all cuts (%d bytes)",
            budget,
            len(_assemble(file_data).encode("utf-8")),
        )
        return _assemble(file_data)
