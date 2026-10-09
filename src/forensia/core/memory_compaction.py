"""Size-budget compaction and timeline regeneration for memory files."""

import logging
import re
from datetime import UTC, datetime
from math import ceil
from pathlib import Path

from forensia.config import get_llm_settings

logger = logging.getLogger(__name__)

# Labels written by ``_with_condensation_label`` (R10).  A reused summary
# must carry its source, generation time, and an honest currentness/
# restorability statement — never a regeneration promise it cannot keep.
# Timeline's deterministic ``regeneratable=true`` stays there; LLM-written
# condensations carry these labels instead.
_CONDENSATION_LABEL_RE = re.compile(r"(?m)^> condensed: .*\n")

#: Upper bound of one label line's encoded size, reserved from the byte
#: budget so truncation cannot clip the label and the whole body out.
_CONDENSATION_LABEL_MAX_BYTES = 240


def _strip_condensation_labels(text: str) -> str:
    """Remove previous condensation labels so they are not re-condensed."""
    return _CONDENSATION_LABEL_RE.sub("", text)


def _condensation_stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label_line(source: str, regeneratable: str, preserved: str) -> str:
    """Build the single ``> condensed:`` annotation line (R10)."""
    regeneratable = regeneratable or ""
    if regeneratable:
        currentness = (
            f"regeneratable=true ({regeneratable}); the DuckDB row is the "
            "original - query or re-derive it for currentness"
        )
    else:
        currentness = "not regeneratable - " + (
            preserved or "the condensed-away prose is not retained"
        )
    return f"> condensed: {_condensation_stamp()} source={source}; {currentness}"


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
        """Compress the overview via LLM if it exceeds the byte budget.

        The overview is authored/generated Markdown whose earlier prose is not
        kept anywhere, so the condensed result is labelled: source file,
        generation time, and the explicit fact that the earlier text is not
        retained (R10 — a restoration that cannot happen is never claimed).
        """
        if (
            not self.overview_path.exists()
            or self.overview_path.stat().st_size <= self.max_bytes
        ):
            return False
        current = self.overview_path.read_text(encoding="utf-8").strip()
        if not current:
            return False
        current = _strip_condensation_labels(current)
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
        body = self._with_condensation_label(
            body,
            source="overview.md",
            regeneratable="",
            preserved="reduced overview prose is not retained",
        )
        self.overview_path.write_text(body + "\n", encoding="utf-8")
        return True

    def compact_oversized_with_llm(self, base_url: str, model: str) -> list[str]:
        """Compress oversized hypothesis and entity markdown files via LLM.

        Hypothesis cards are DB-derived projections (regenerated on every
        memory sync), so their condensation label names the DB original and
        the re-derivation path. Entity/overview cards are authored or
        checker-generated Markdown whose earlier prose is not retained, so
        their label says exactly that (R10).
        """
        changed_paths: list[str] = []
        for path in self._llm_compaction_targets():
            if not path.exists() or path.stat().st_size <= self.max_bytes:
                continue
            current = path.read_text(encoding="utf-8").strip()
            if not current:
                continue
            current = _strip_condensation_labels(current)
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
            # Reserve room for the label so truncation never clips the whole
            # condensation block back out of existence.
            is_db_card = path.parent == self.hypotheses_dir
            source = (
                f"hypotheses DB row ({path.stem})"
                if is_db_card
                else f"{path.relative_to(self.base_dir)}"
            )
            regeneratable = (
                "re-renders from the DuckDB row at the next memory sync"
                if is_db_card
                else ""
            )
            preserved = (
                "reduced prose not retained; the DuckDB hypothesis row is the original"
                if is_db_card
                else "reduced prose not retained"
            )
            reserve_bytes = max(self.max_bytes - _CONDENSATION_LABEL_MAX_BYTES, 64)
            compacted = body.strip()
            encoded = compacted.encode("utf-8")
            if len(encoded) > reserve_bytes:
                compacted = (
                    encoded[:reserve_bytes].decode("utf-8", errors="ignore").rstrip()
                )
            compacted = self._ensure_markdown_heading(compacted, current)
            compacted = self._with_condensation_label(
                compacted,
                source=source,
                regeneratable=regeneratable,
                preserved=preserved,
            )
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

    def _with_condensation_label(
        self, body: str, *, source: str, regeneratable: str, preserved: str
    ) -> str:
        """Label a condensed Markdown body with source/currentness (R10).

        Replaces any prior condensation label and records the generation
        time.  A ``regeneratable`` statement is only ever true when there is
        a deterministic re-derivation path; otherwise the label says the
        condensed-away prose is not retained.
        """
        stripped = _strip_condensation_labels(body).rstrip()
        label = _label_line(source, regeneratable, preserved)
        lines = stripped.split("\n")
        if lines and lines[0].startswith("# "):
            return "\n".join([lines[0], "", label, *lines[1:]]).rstrip() + "\n"
        return f"{label}\n\n{stripped}\n"

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
