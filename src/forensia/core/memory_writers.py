"""Append/upsert writers for overview, facts, timeline, and scratch."""

import hashlib
import logging
import re
import shutil
from pathlib import Path
from re import sub

from forensia.core.session import ENTITY_TYPE_ALIASES
from forensia.core.textutil import jaccard_similarity, normalize_text, slugify

logger = logging.getLogger(__name__)


class MemoryWriterMixin:
    def _append_markdown_entry(
        self, path: Path, heading: str, line: str, *, fuzzy_dedup: bool = False
    ) -> bool:
        """Append a line under a heading in a Markdown file, skipping if the line is already present.

        When *fuzzy_dedup* is enabled, near-duplicate entries are suppressed
        using jaccard_similarity.  Entries are considered near-duplicates when
        their normalized text similarity >= 0.75 **and** they carry the same
        evidence IDs — different evidence for the same fact is always kept.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = (
            path.read_text(encoding="utf-8").rstrip() if path.exists() else heading
        )
        if not existing:
            existing = heading
        existing_lines = set(existing.splitlines())
        if line in existing_lines:
            return False

        # --- fuzzy near-duplicate suppression (Rule 12) ---
        if fuzzy_dedup and existing_lines:
            new_text = self._extract_line_text(line)
            new_norm = normalize_text(new_text)
            new_evidence = self._extract_evidence_ids(line)
            if new_norm:
                for existing_line in existing_lines:
                    existing_text = self._extract_line_text(existing_line)
                    existing_norm = normalize_text(existing_text)
                    if not existing_norm:
                        continue
                    similarity = jaccard_similarity(new_norm, existing_norm)
                    if similarity >= 0.75:
                        existing_evidence = self._extract_evidence_ids(existing_line)
                        if new_evidence == existing_evidence:
                            logger.debug(
                                "fuzzy_dedup suppressed entry (sim=%.2f): %s",
                                similarity,
                                new_text[:80],
                            )
                            return False

        path.write_text(existing + "\n\n" + line + "\n", encoding="utf-8")
        return True

    def update_overview(self, content: str) -> None:
        self.overview_path.write_text(content, encoding="utf-8")

    # Placeholder bullets cleared when real content lands in a section
    # (includes the Active Tasks seed lines from _initialize_overview).
    _OVERVIEW_PLACEHOLDERS = (
        "- none",
        "- Awaiting initial investigation",
    )
    _TASK_VERB_RE = re.compile(
        r"^(?:task:|todo:|(?:investigate|verify|check|review|correlate|confirm)\b)",
        re.IGNORECASE,
    )

    def append_overview(self, content: str) -> bool:
        """Insert content as a bullet under the matching overview heading.

        Facts (the default) go under '## Key Findings'; imperative/task items
        under '## Active Tasks'; scope statements under '## Case Scope'.
        Placeholder bullets in the target section are cleared. Falls back to
        appending at the end only when the target heading is missing.
        """
        content = content.strip()
        if not content:
            return False
        existing = self.load_overview()
        lowered = content.lower()
        if self._TASK_VERB_RE.match(lowered):
            target_heading = "## Active Tasks"
        elif lowered.startswith("scope") or "case scope" in lowered:
            target_heading = "## Case Scope"
        else:
            target_heading = "## Key Findings"
        bullet = content if content.startswith("- ") else f"- {content}"

        if target_heading in existing:
            sections = re.split(r"(?=^## )", existing, flags=re.MULTILINE)
            for index, section in enumerate(sections):
                if not section.startswith(target_heading):
                    continue
                for placeholder in self._OVERVIEW_PLACEHOLDERS:
                    section = section.replace(placeholder + "\n", "").replace(
                        placeholder, ""
                    )
                stripped = section.rstrip("\n")
                trailing = section[len(stripped) :] or "\n"
                sections[index] = stripped + "\n" + bullet + trailing
                self.update_overview("".join(sections))
                return True

        # Fall back: target heading missing — append to end
        self.update_overview(existing.rstrip() + "\n\n" + content + "\n")
        return True

    _R3_REFUTED_RE = re.compile(
        r"^- The hypothesis regarding .* was refuted\..*$",
        re.MULTILINE | re.IGNORECASE,
    )

    def collapse_refuted_overview_lines(self) -> None:
        """Collapse multiple 'hypothesis regarding X was refuted' lines into a counter."""
        if not self.overview_path.exists():
            return
        existing = self.overview_path.read_text(encoding="utf-8").rstrip()
        if not existing:
            return
        refuted_lines = self._R3_REFUTED_RE.findall(existing)
        if not refuted_lines:
            return
        cleaned = self._R3_REFUTED_RE.sub("", existing).strip()
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        counter = f"- {len(refuted_lines)} hypotheses refuted so far"
        if counter not in cleaned:
            cleaned = cleaned + "\n\n" + counter if cleaned else counter
        self.update_overview(cleaned + "\n")

    def upsert_entity(self, entity_type: str, name: str, content: str) -> None:
        """Write entity content to the appropriate entity type subdirectory."""
        path = self._entity_path(entity_type, name)
        if path is None:
            return
        path.write_text(content, encoding="utf-8")

    def upsert_hypothesis(self, hyp_id: str, slug: str, content: str) -> None:
        """Write hypothesis content, removing any stale legacy files with the same slug prefix."""
        stable_id = (
            sub(r"[^a-zA-Z0-9._-]+", "-", str(hyp_id).strip()).strip("-") or "unknown"
        )
        path = self.hypotheses_dir / f"{stable_id}.md"
        for legacy_path in self.hypotheses_dir.glob(f"{slugify(hyp_id)}-*.md"):
            if legacy_path != path:
                legacy_path.unlink(missing_ok=True)
        path.write_text(content, encoding="utf-8")

    def upsert_keypoint(self, kp_id: str, content: str) -> None:
        """Write a keypoint file, using an upper-case slug as filename."""
        path = self.keypoints_dir / f"{slugify(kp_id).upper()}.md"
        path.write_text(content, encoding="utf-8")

    def append_confirmed_fact(
        self,
        text: str,
        evidence_ids: list[str],
        hypothesis_id: str | None = None,
        provisional: bool = False,
    ) -> None:
        """Record a fact in the facts file (or scratch if provisional), deduplicating by content hash."""
        body = str(text).strip()
        if not body:
            return
        # R2-03: Reject fact bodies containing unresolved placeholder tokens
        if re.search(r"\{\w+\}", body):
            logger.warning("dropped fact with placeholder tokens: %s", body[:60])
            return
        normalized_ids = sorted(
            {str(item).strip() for item in evidence_ids if str(item).strip()}
        )
        line = self._memory_line(
            body,
            normalized_ids,
            hypothesis_id=hypothesis_id,
            provisional=provisional,
        )
        if not line:
            return
        if provisional:
            self._append_markdown_entry(
                self._hypothesis_scratch_path(hypothesis_id, "facts"),
                "# Facts",
                line,
            )
            return
        fact_hash = self._fact_hash(body, normalized_ids)
        if fact_hash in self._fact_hashes:
            return
        detail_id = self._alloc_fact_detail_id()
        # R2-10: Truncate at word boundary ≥160 chars, never mid-token
        preview = body
        if len(preview) > 160:
            truncated = preview[:160]
            last_space = truncated.rfind(" ")
            if last_space > 0:
                preview = truncated[:last_space] + "…"
            else:
                preview = truncated + "…"
        shared_line = self._memory_line(
            f"[{detail_id}] {preview}",
            normalized_ids,
            hypothesis_id=hypothesis_id,
            provisional=False,
        )
        if self._append_markdown_entry(
            self.facts_path, "# Facts", shared_line, fuzzy_dedup=True
        ):
            self._write_fact_detail(detail_id, body, normalized_ids)
            self._fact_hashes.add(fact_hash)

    def append_timeline_anchor(
        self,
        timestamp: str,
        description: str,
        evidence_ids: list[str],
        hypothesis_id: str | None = None,
        provisional: bool = False,
    ) -> None:
        """Record a timestamped event in the timeline (or scratch if provisional)."""
        timestamp_text = str(timestamp).strip()
        description_text = str(description).strip()
        if not timestamp_text or not description_text:
            return
        line = self._memory_line(
            f"{timestamp_text}: {description_text}",
            evidence_ids,
            hypothesis_id=hypothesis_id,
            provisional=provisional,
        )
        if line and self._append_markdown_entry(
            self._hypothesis_scratch_path(hypothesis_id, "timeline")
            if provisional
            else self.timeline_path,
            "# Timeline",
            line,
            fuzzy_dedup=True,
        ):
            self._rotate_timeline()

    def append_task(
        self,
        text: str,
        kind: str,
        hypothesis_id: str | None = None,
        provisional: bool = False,
    ) -> None:
        """Append a task entry to the tasks file (or scratch if provisional), compacting when oversized."""
        task_text = str(text).strip()
        normalized_kind = str(kind).strip()
        if normalized_kind not in {
            "internal_db_check",
            "evidence_acquisition",
            "external_lookup",
            "human_decision",
        }:
            normalized_kind = "human_decision"
        if not task_text:
            return
        line = f"- [{normalized_kind}] {task_text}"

        if not provisional:
            path = self.tasks_memory_path
            if path.exists():
                existing_content = path.read_text(encoding="utf-8")
                existing_lines = existing_content.splitlines()
                existing_task_lines = [l for l in existing_lines if l.startswith("- [")]

                # R2-10: Jaccard dedup
                norm_new = normalize_text(task_text)
                is_duplicate = False
                for el in existing_task_lines:
                    existing_text = el.split("] ", 1)[-1] if "] " in el else el
                    norm_existing = normalize_text(existing_text)
                    if jaccard_similarity(norm_new, norm_existing) >= 0.6:
                        is_duplicate = True
                        break
                if is_duplicate:
                    return

                # R2-10: Cap open [human_decision] tasks at 10, evict oldest
                if normalized_kind == "human_decision":
                    human_lines = [
                        (i, l)
                        for i, l in enumerate(existing_lines)
                        if l.startswith("- [human_decision]")
                    ]
                    if len(human_lines) >= 10:
                        oldest_idx = human_lines[0][0]
                        existing_lines.pop(oldest_idx)
                        path.write_text(
                            "\n".join(existing_lines) + "\n", encoding="utf-8"
                        )

        self._append_markdown_entry(
            self._hypothesis_scratch_path(hypothesis_id, "tasks")
            if provisional
            else self.tasks_memory_path,
            "# Tasks",
            line,
        )
        if not provisional:
            self.compact_if_oversized(self.tasks_memory_path)

    def append_refuted_hypothesis(
        self, hypothesis_id: str, description: str, reason: str
    ) -> None:
        """Log a refuted hypothesis to the archive with its reasoning."""
        hyp_id = str(hypothesis_id).strip()
        description_text = str(description).strip()
        reason_text = str(reason).strip()
        if not hyp_id or not description_text:
            return
        line = f"- {hyp_id}: {description_text}"
        if reason_text:
            line += f" | reason: {reason_text}"
        self._append_markdown_entry(
            self.refuted_hypotheses_path, "# Refuted Hypotheses", line
        )

    def append_resolved_gap(self, text: str, evidence_ids: list[str]) -> None:
        """Record a resolved gap in the archive."""
        body = str(text).strip()
        if not body:
            return
        line = self._memory_line(body, evidence_ids)
        if line:
            self._append_markdown_entry(
                self.resolved_gaps_path, "# Resolved Gaps", line
            )

    @staticmethod
    def _split_claim(body: str) -> tuple[str, str]:
        """Split a body at observation/interpretation markers.

        Returns (observation, interpretation).  When no marker is found the
        entire body is returned as observation and interpretation is empty.
        """
        body = str(body).strip()
        for sep in (", indicating ", ", suggesting ", " — ", " —"):
            if sep in body:
                parts = body.split(sep, 1)
                return parts[0].strip(), parts[1].strip()
        return body, ""

    def append_confirmed_hypothesis_fact(
        self,
        hypothesis_description: str,
        verdict: str,
        query_id: str,
        evidence_ids: list[str],
    ) -> None:
        """Write one deterministic confirmed-fact line from a hypothesis outcome.

        R2-09: splits description at observation/interpretation markers
        and stores only the observation half as confirmed.  The interpretation
        half (if any) is stored as a provisional scratch fact instead.
        """
        observation, interpretation = self._split_claim(hypothesis_description)
        text = f"{observation} — {verdict} (query {query_id})"
        # R2-03: Reject confirmed hypothesis fact with placeholder tokens
        if re.search(r"\{\w+\}", text):
            logger.warning(
                "dropped confirmed hypothesis fact with placeholder tokens: %s",
                text[:60],
            )
            return
        self.append_confirmed_fact(text, evidence_ids, provisional=False)
        if interpretation:
            self.append_confirmed_fact(interpretation, evidence_ids, provisional=True)

    def append_suspicious(self, rows: list[dict]) -> bool:
        """Append rows of suspicious evidence, deduplicating by evidence_id, and compact when oversized."""
        if not rows:
            return False
        header = "| evidence_id | reason | confidence |\n|---|---|---|\n"
        existing = ""
        seen: set[str] = set()
        if self.suspicious_path.exists():
            existing = self.suspicious_path.read_text(encoding="utf-8")
            for line in existing.splitlines():
                if (
                    line.startswith("|")
                    and not line.startswith("| evidence_id ")
                    and not line.startswith("|---")
                ):
                    parts = [item.strip() for item in line.strip("|").split("|")]
                    if parts:
                        seen.add(parts[0])
        else:
            existing = "# Suspicious Evidence\n\n" + header

        appended: list[str] = []
        for row in rows:
            evidence_id = str(row.get("evidence_id") or "").strip()
            if not evidence_id or evidence_id in seen:
                continue
            reason = str(row.get("reason") or "").replace("\n", " ")
            confidence = row.get("confidence")
            appended.append(f"| {evidence_id} | {reason} | {confidence} |")
            seen.add(evidence_id)

        if not appended:
            return False
        content = existing.rstrip() + "\n" + "\n".join(appended) + "\n"
        self.suspicious_path.write_text(content, encoding="utf-8")
        self._compact_suspicious(self.suspicious_path)
        return True

    def _alloc_fact_detail_id(self) -> str:
        detail_id = f"fact-{self._next_fact_id:03d}"
        self._next_fact_id += 1
        return detail_id

    def _write_fact_detail(
        self, detail_id: str, text: str, evidence_ids: list[str]
    ) -> None:
        """Write a detailed fact record with evidence references to the details directory."""
        lines = [f"# {detail_id}", "", text.strip()]
        if evidence_ids:
            lines.extend(["", "## Evidence", *[f"- {item}" for item in evidence_ids]])
        (self.details_dir / f"{detail_id}.md").write_text(
            "\n".join(lines).rstrip() + "\n", encoding="utf-8"
        )

    def _fact_hash(self, text: str, evidence_ids: list[str]) -> str:
        """Generate a SHA-256 hash for deduplicating fact entries."""
        payload = "\n".join([text.strip(), *sorted(evidence_ids)])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _parse_fact_detail(self, detail: list[str]) -> tuple[str, list[str]] | None:
        """Parse a fact detail file back into (text, evidence_ids) tuple."""
        if len(detail) < 3:
            return None
        text_lines: list[str] = []
        for line in detail[2:]:
            if line.strip() == "## Evidence":
                break
            text_lines.append(line)
        existing_text = "\n".join(text_lines).strip()
        if not existing_text:
            return None
        evidence_ids: list[str] = []
        in_evidence = False
        for line in detail[2:]:
            stripped = line.strip()
            if stripped == "## Evidence":
                in_evidence = True
                continue
            if in_evidence and stripped.startswith("- "):
                evidence_ids.append(stripped[2:].strip())
        return existing_text, evidence_ids

    def _load_existing_fact_hashes(self) -> None:
        """Pre-populate fact hashes from existing detail files on startup to prevent duplicates."""
        max_n = 0
        for path in sorted(self.details_dir.glob("fact-*.md")):
            try:
                max_n = max(max_n, int(path.stem[5:]))
            except ValueError:
                continue
            parsed = self._parse_fact_detail(
                path.read_text(encoding="utf-8").splitlines()
            )
            if parsed is None:
                continue
            text, evidence_ids = parsed
            self._fact_hashes.add(self._fact_hash(text, evidence_ids))
        self._next_fact_id = max_n + 1

    def promote_hypothesis_scratch(self, hypothesis_id: str | None) -> list[str]:
        """Move provisional scratch entries for a hypothesis into the confirmed memory files."""
        scratch_dir = self._hypothesis_scratch_dir(hypothesis_id)
        if not scratch_dir.exists():
            return []
        promoted: list[str] = []
        for relative_name, target_path, heading in (
            ("facts.md", self.facts_path, "# Facts"),
            ("timeline.md", self.timeline_path, "# Timeline"),
            ("tasks.md", self.tasks_memory_path, "# Tasks"),
        ):
            path = scratch_dir / relative_name
            if not path.exists():
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped.startswith("- "):
                    continue
                promoted_line = stripped.replace(" [provisional]", " [confirmed]")
                if self._append_markdown_entry(target_path, heading, promoted_line):
                    promoted.append(promoted_line)
        shutil.rmtree(scratch_dir, ignore_errors=True)
        return promoted

    def archive_hypothesis_scratch(self, hypothesis_id: str | None) -> list[str]:
        """Move a hypothesis scratch directory into the archive for long-term retention."""
        scratch_dir = self._hypothesis_scratch_dir(hypothesis_id)
        if not scratch_dir.exists():
            return []
        target_dir = self.scratch_archive_dir / self._scratch_key(hypothesis_id)
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(scratch_dir), str(target_dir))
        return [str(target_dir)]

    def archive_untestable_hypothesis_scratch(
        self, hypothesis_id: str | None
    ) -> list[str]:
        """Append hypothesis scratch content to archive/untestable.md instead of full directory move."""
        scratch_dir = self._hypothesis_scratch_dir(hypothesis_id)
        if not scratch_dir.exists():
            return []
        lines: list[str] = [f"## Untestable Hypothesis: {hypothesis_id}", ""]
        for relative_name in ("facts.md", "timeline.md", "tasks.md"):
            path = scratch_dir / relative_name
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8").strip()
            if content:
                lines.append(f"### {relative_name}")
                lines.append(content)
                lines.append("")
        entry = "\n".join(lines).strip()
        self._append_markdown_entry(
            self.untestable_hypotheses_path, "# Untestable Hypotheses", entry
        )
        shutil.rmtree(scratch_dir, ignore_errors=True)
        return [str(self.untestable_hypotheses_path)]

    def _entity_path(self, entity_type: str, name: str) -> Path | None:
        """Resolve the filesystem path for an entity by type and name, using alias resolution."""
        normalized_type = str(entity_type).strip().lower()
        normalized_name = str(name).strip()
        if not normalized_name:
            return None
        normalized_type = ENTITY_TYPE_ALIASES.get(normalized_type, normalized_type)
        base = {
            "user": self.entities_user_dir,
            "host": self.entities_host_dir,
            "ip": self.entities_ip_dir,
            "machine_account": self.entities_machine_account_dir,
            "group": self.entities_group_dir,
            "process": self.entities_process_dir,
            "service": self.entities_service_dir,
            "file": self.entities_file_dir,
            "registry": self.entities_registry_dir,
            "unknown": self.entities_unknown_dir,
        }.get(normalized_type)
        if base is None:
            return None
        return base / f"{slugify(normalized_name)}.md"
