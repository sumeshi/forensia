"""Size-budget compaction and timeline regeneration for memory files."""

import re
from math import ceil
from pathlib import Path


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

        The written file is a deterministic, regeneratable projection: a
        ``projection:vN source=case_timeline regeneratable=true`` header marks
        the revision and declares it derived from ``case_timeline`` (never
        Case State authority).  Regenerating equal DB state is idempotent,
        so the file can always be re-derived — never trusted for anything
        not present in the DB.
        """
        from forensia.db.query import fetch_records

        prior_revision = self.timeline_projection_revision()
        # A projection revision changes only when the derived content changes.
        # Regenerating the same DB state must be idempotent.
        new_revision = prior_revision or 1

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
            content = (
                f"# Timeline (projection:v{new_revision} source=case_timeline "
                f"regeneratable=true)\n\n_No timeline entries yet._\n"
            )
            if (
                self.timeline_path.exists()
                and self.timeline_path.read_text(encoding="utf-8").strip()
                == content.strip()
            ):
                return False
            if prior_revision is not None:
                new_revision = prior_revision + 1
                content = content.replace(
                    f"projection:v{prior_revision}",
                    f"projection:v{new_revision}",
                    1,
                )
            self.timeline_path.write_text(content, encoding="utf-8")
            return True
        date_groups: dict[str, list[dict]] = {}
        for row in rows:
            ts = str(row.get("timestamp") or "")
            date_key = ts[:10] if len(ts) >= 10 else "unknown"
            date_groups.setdefault(date_key, []).append(row)
        lines = [
            f"# Timeline (projection:v{new_revision} source=case_timeline "
            f"regeneratable=true)",
            "",
        ]
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
        if prior_revision is not None:
            new_revision = prior_revision + 1
            content = content.replace(
                f"projection:v{prior_revision}",
                f"projection:v{new_revision}",
                1,
            )
        self.timeline_path.write_text(content, encoding="utf-8")
        return True

    _TIMELINE_PROJECTION_RE = re.compile(r"projection:v(\d+)")

    def timeline_projection_revision(self) -> int | None:
        """Return the embedded revision of the timeline projection, or None."""
        if not self.timeline_path.exists():
            return None
        try:
            head = self.timeline_path.read_text(encoding="utf-8").splitlines()[:1]
        except OSError:
            return None
        if not head:
            return None
        match = self._TIMELINE_PROJECTION_RE.search(head[0])
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

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
