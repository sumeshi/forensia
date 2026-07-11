"""Size-budget compaction and timeline regeneration for memory files."""

import logging
from math import ceil
from pathlib import Path

from forensia.config import get_llm_settings

logger = logging.getLogger(__name__)


class MemoryCompactionMixin:
    def _rotate_timeline(self, max_lines: int = 100, keep_lines: int = 80) -> None:
        """Move older timeline entries to the archive when the timeline exceeds max_lines."""
        if not self.timeline_path.exists():
            return
        lines = self.timeline_path.read_text(encoding="utf-8").splitlines()
        anchor_lines = [line for line in lines if line.startswith("- ")]
        if len(anchor_lines) <= max_lines:
            return
        archived = anchor_lines[:-keep_lines]
        retained = anchor_lines[-keep_lines:]
        archive_path = self.archive_dir / "timeline_archive.md"
        archive_existing = (
            archive_path.read_text(encoding="utf-8").rstrip()
            if archive_path.exists()
            else "# Timeline Archive"
        )
        archive_lines = set(archive_existing.splitlines())
        appendable = [line for line in archived if line not in archive_lines]
        if appendable:
            archive_path.write_text(
                archive_existing + "\n\n" + "\n".join(appendable) + "\n",
                encoding="utf-8",
            )
        rebuilt = "# Timeline"
        if retained:
            rebuilt += "\n\n" + "\n".join(retained)
        self.timeline_path.write_text(rebuilt.rstrip() + "\n", encoding="utf-8")

    def compact_overview_if_needed(self, base_url: str, model: str) -> bool:
        """Compress the overview via LLM if it exceeds the byte budget."""
        if (
            not self.overview_path.exists()
            or self.overview_path.stat().st_size <= self.max_bytes
        ):
            return False
        current = self.overview_path.read_text(encoding="utf-8").strip()
        if not current:
            return False
        output_language = str(get_llm_settings()["output_language"]).lower()
        language_instruction = f"Write the compressed overview in {output_language}."
        body = self._call_llm_compact(
            text=current,
            system_prompt=(
                "Compress the following investigation overview to 600 words or fewer. "
                "Preserve conclusions, timeline, and unresolved threads. "
                "Output only the overview body. "
                f"{language_instruction}"
            ),
            base_url=base_url,
            model=model,
            error_message="overview compaction failed",
        )
        if not body:
            return False
        self.overview_path.write_text(body + "\n", encoding="utf-8")
        return True

    def compact_oversized_with_llm(self, base_url: str, model: str) -> list[str]:
        """Compress oversized hypothesis and entity markdown files via LLM."""
        changed_paths: list[str] = []
        for path in self._llm_compaction_targets():
            if not path.exists() or path.stat().st_size <= self.max_bytes:
                continue
            current = path.read_text(encoding="utf-8").strip()
            if not current:
                continue
            output_language = str(get_llm_settings()["output_language"]).lower()
            language_instruction = (
                f"Write the compressed markdown in {output_language}."
            )
            body = self._call_llm_compact(
                text=current,
                system_prompt=(
                    "Compress the following investigation memory markdown so it fits into a smaller context window. "
                    "Preserve the top-level markdown heading, confirmed facts, verdicts, key timeline facts, and unresolved questions. "
                    "Prefer compact bullet points over prose. "
                    "Keep markdown structure valid and output only the rewritten markdown document. "
                    f"{language_instruction}"
                ),
                base_url=base_url,
                model=model,
                error_message=f"memory compaction failed: {path}",
            )
            if not body:
                continue
            compacted = self._ensure_markdown_heading(body, current)
            encoded = compacted.encode("utf-8")
            if len(encoded) > self.max_bytes:
                compacted = (
                    encoded[: self.max_bytes].decode("utf-8", errors="ignore").rstrip()
                    + "\n"
                )
                compacted = self._ensure_markdown_heading(compacted, current)
            path.write_text(compacted, encoding="utf-8")
            changed_paths.append(str(path))
        return changed_paths

    def _llm_compaction_targets(self) -> list[Path]:
        """Return the list of file paths eligible for LLM-based compaction."""
        targets: list[Path] = []
        for directory in (
            self.hypotheses_dir,
            self.entities_user_dir,
            self.entities_host_dir,
            self.entities_ip_dir,
        ):
            targets.extend(sorted(directory.glob("*.md")))
        return targets

    def _ensure_markdown_heading(self, body: str, original: str) -> str:
        """Ensure the compacted body retains the original markdown heading."""
        compacted = body.strip()
        if not compacted.startswith("# "):
            original_heading = next(
                (
                    line.strip()
                    for line in original.splitlines()
                    if line.strip().startswith("# ")
                ),
                "",
            )
            if original_heading:
                compacted = f"{original_heading}\n\n{compacted}".strip()
            else:
                compacted = f"# Compacted Memory\n\n{compacted}".strip()
        return compacted.rstrip() + "\n"

    def _call_llm_compact(
        self,
        text: str,
        system_prompt: str,
        base_url: str,
        model: str,
        error_message: str,
    ) -> str | None:
        """Call the LLM to compact memory text, returning None on failure."""
        if self._summarize is None:
            logger.info("no summarizer available, skipping compaction")
            return None
        try:
            result = self._summarize(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text},
                ],
                model,
            )
            return result.strip() if result else None
        except Exception:
            logger.exception(error_message)
            return None

    def _trim_rows_to_budget(
        self,
        path: Path,
        prefix_lines: list[str],
        data_lines: list[str],
        separator_lines: list[str] | None = None,
    ) -> bool:
        """Trim data rows by removing the oldest 20% at a time until the file fits the byte budget."""
        keep_lines = data_lines
        separator_lines = separator_lines or []
        while keep_lines:
            remove_count = max(1, ceil(len(keep_lines) * 0.2))
            keep_lines = keep_lines[remove_count:]
            rebuilt = (
                "\n".join(prefix_lines + separator_lines + keep_lines).strip() + "\n"
            )
            path.write_text(rebuilt, encoding="utf-8")
            if path.stat().st_size <= self.max_bytes or len(keep_lines) <= 1:
                return True
        return True

    def _compact_tasks(self, path: Path) -> bool:
        """Trim the tasks file by removing oldest entries until it fits the byte budget."""
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
        lines = path.read_text(encoding="utf-8").splitlines()
        task_lines = [line for line in lines if line.startswith("- [")]
        if not task_lines:
            return False
        prefix_lines: list[str] = []
        for line in lines:
            if line.startswith("- ["):
                break
            prefix_lines.append(line)
        return self._trim_rows_to_budget(
            path, prefix_lines, task_lines, separator_lines=[""]
        )

    def _compact_suspicious(self, path: Path) -> bool:
        """Trim the suspicious evidence table by removing oldest rows until it fits the byte budget."""
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
        lines = path.read_text(encoding="utf-8").splitlines()
        data_lines = [
            line
            for line in lines
            if line.startswith("|")
            and not line.startswith("| evidence_id ")
            and not line.startswith("|---")
        ]
        if not data_lines:
            return False
        prefix_lines: list[str] = []
        for line in lines:
            prefix_lines.append(line)
            if line.startswith("|---"):
                break
        return self._trim_rows_to_budget(path, prefix_lines, data_lines)

    def regenerate_timeline_from_db(self, db) -> bool:
        """Regenerate memory/timeline.md from the case_timeline DB table.

        Reads all rows ordered by timestamp ASC, groups into per-day sections,
        and writes the result to timeline.md. Returns True when content changed.
        """
        from forensia.db.query import fetch_records

        rows = fetch_records(
            db,
            """
            SELECT timestamp, source, ref_id, host, summary, evidence_id
            FROM case_timeline
            WHERE timestamp IS NOT NULL
            ORDER BY timestamp ASC
            """,
        )
        if not rows:
            if self.timeline_path.exists():
                self.timeline_path.write_text(
                    "# Timeline\n\n_No timeline entries yet._\n", encoding="utf-8"
                )
            return False
        date_groups: dict[str, list[dict]] = {}
        for row in rows:
            ts = str(row.get("timestamp") or "")
            date_key = ts[:10] if len(ts) >= 10 else "unknown"
            date_groups.setdefault(date_key, []).append(row)
        lines = ["# Timeline", ""]
        for date_key in sorted(date_groups):
            date_rows = date_groups[date_key]
            for row in date_rows:
                ts = str(row.get("timestamp") or "")
                summary = str(row.get("summary") or "-")[:160]
                host = str(row.get("host") or "")
                src = str(row.get("source") or "")
                ref = str(row.get("ref_id") or "")
                evidence_id = str(row.get("evidence_id") or "")
                meta_parts = [p for p in [src, host, ref, evidence_id] if p]
                meta = f" [{', '.join(meta_parts)}]" if meta_parts else ""
                lines.append(f"- {ts} {summary}{meta}")
            lines.append("")
        content = "\n".join(lines).strip() + "\n"
        existing = (
            self.timeline_path.read_text(encoding="utf-8")
            if self.timeline_path.exists()
            else ""
        )
        if content.strip() == existing.strip():
            return False
        self.timeline_path.write_text(content, encoding="utf-8")
        return True

    def compact_if_oversized(self, path: Path) -> bool:
        """Dispatch compaction for a path if it exceeds the byte budget, returning True if trimmed."""
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
        if path in {
            self.facts_path,
            self.timeline_path,
            self.refuted_hypotheses_path,
            self.resolved_gaps_path,
        }:
            return False
        if path == self.tasks_memory_path:
            return self._compact_tasks(path)
        if path == self.suspicious_path:
            return self._compact_suspicious(path)
        return False
