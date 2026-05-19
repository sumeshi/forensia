from __future__ import annotations

import hashlib
import logging
from math import ceil
from pathlib import Path
from re import sub

from forensia.ai.lmstudio import chat_completion
from forensia.core.case import Case
from forensia.config import get_llm_settings


logger = logging.getLogger(__name__)


def _slugify(value: str) -> str:
    cleaned = sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    return cleaned.strip("-").lower() or "unknown"


class MemoryManager:
    def __init__(self, case: Case):
        self.case = case
        self.base_dir = case.memory_dir
        self.hosts_dir = self.base_dir / "hosts"
        self.users_dir = self.base_dir / "users"
        self.hypotheses_dir = self.base_dir / "hypotheses"
        self.evidence_dir = self.base_dir / "evidence"
        self.details_dir = self.base_dir / "details"
        for directory in (
            self.base_dir,
            self.hosts_dir,
            self.users_dir,
            self.hypotheses_dir,
            self.evidence_dir,
            self.details_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self._fact_hashes: set[str] = set()
        self._load_existing_fact_hashes()

    @property
    def overview_path(self) -> Path:
        return self.base_dir / "overview.md"

    @property
    def confirmed_facts_path(self) -> Path:
        return self.base_dir / "confirmed_facts.md"

    @property
    def timeline_anchors_path(self) -> Path:
        return self.base_dir / "timeline_anchors.md"

    @property
    def open_questions_path(self) -> Path:
        return self.base_dir / "open_questions.md"

    @property
    def narrative_path(self) -> Path:
        return self.base_dir / "narrative.md"

    @property
    def refuted_hypotheses_path(self) -> Path:
        return self.base_dir / "refuted_hypotheses.md"

    @property
    def important_entities_path(self) -> Path:
        return self.base_dir / "important_entities.md"

    @property
    def suspicious_path(self) -> Path:
        return self.evidence_dir / "suspicious.md"

    def has_overview(self) -> bool:
        return self.overview_path.exists()

    @property
    def max_bytes(self) -> int:
        return int(get_llm_settings()["memory_max_bytes"])

    def load_overview(self) -> str:
        if not self.overview_path.exists():
            return (
                "# Investigation Overview\n\n"
                "## Confirmed Hosts\n- none\n\n"
                "## Confirmed Timeline\n- none\n\n"
                "## Active Hypotheses\n- none\n\n"
                "## Open Questions\n- none\n"
            )
        return self.overview_path.read_text(encoding="utf-8")

    def load_context(self, files: list[str]) -> str:
        parts: list[str] = []
        for relative in files:
            path = (self.base_dir / relative).resolve()
            try:
                path.relative_to(self.base_dir.resolve())
            except ValueError:
                continue
            if path.exists() and path.is_file():
                parts.append(f"# {relative}\n\n{path.read_text(encoding='utf-8')}")
        return "\n\n".join(parts)

    def load_compact_context(self, files: list[str], max_bytes: int | None = None) -> str:
        budget = max_bytes if max_bytes is not None else self.max_bytes
        text = self.load_context(files)
        encoded = text.encode("utf-8")
        if len(encoded) <= budget:
            return text
        tail = encoded[-budget:].decode("utf-8", errors="ignore")
        split = tail.find("\n# ")
        if split > 0:
            tail = tail[split + 1 :]
        return tail

    def update_overview(self, content: str) -> None:
        self.overview_path.write_text(content, encoding="utf-8")
        self.compact_if_oversized(self.overview_path)

    def append_overview(self, content: str) -> bool:
        content = content.strip()
        if not content:
            return False
        existing = self.load_overview().rstrip()
        self.update_overview(existing + "\n\n" + content + "\n")
        return True

    def upsert_host(self, hostname: str, content: str) -> None:
        path = self.hosts_dir / f"{_slugify(hostname)}.md"
        path.write_text(content, encoding="utf-8")
        self.compact_if_oversized(path)

    def upsert_user(self, username: str, content: str) -> None:
        path = self.users_dir / f"{_slugify(username)}.md"
        path.write_text(content, encoding="utf-8")
        self.compact_if_oversized(path)

    def upsert_hypothesis(self, hyp_id: str, slug: str, content: str) -> None:
        path = self.hypotheses_dir / f"{_slugify(hyp_id)}-{_slugify(slug)}.md"
        path.write_text(content, encoding="utf-8")
        self.compact_if_oversized(path)

    def append_confirmed_fact(self, text: str, evidence_ids: list[str]) -> None:
        body = str(text).strip()
        if not body:
            return
        normalized_ids = [str(item).strip() for item in evidence_ids if str(item).strip()]
        fact_hash = self._fact_hash(body, normalized_ids)
        if fact_hash in self._fact_hashes:
            return
        detail_id = self._next_fact_detail_id()
        preview = body[:120]
        line = self._format_memory_line(f"[{detail_id}] {preview}", normalized_ids)
        if not line:
            return
        if self._append_markdown_line(self.confirmed_facts_path, "# Confirmed Facts", line):
            self._write_fact_detail(detail_id, body, normalized_ids)
            self._fact_hashes.add(fact_hash)
            self.compact_if_oversized(self.confirmed_facts_path)

    def append_timeline_anchor(self, timestamp: str, description: str, evidence_ids: list[str]) -> None:
        timestamp_text = str(timestamp).strip()
        description_text = str(description).strip()
        if not timestamp_text or not description_text:
            return
        line = self._format_memory_line(f"{timestamp_text}: {description_text}", evidence_ids)
        if line and self._append_markdown_line(self.timeline_anchors_path, "# Timeline Anchors", line):
            self._rotate_timeline_anchors()

    def append_open_question(self, question: str, kind: str) -> None:
        question_text = str(question).strip()
        normalized_kind = str(kind).strip()
        if normalized_kind not in {"internal_db_check", "external_lookup", "human_decision"}:
            normalized_kind = "human_decision"
        if not question_text:
            return
        self._append_markdown_line(
            self.open_questions_path,
            "# Open Questions",
            f"- [{normalized_kind}] {question_text}",
        )
        self.compact_if_oversized(self.open_questions_path)

    def append_narrative(self, text: str) -> None:
        body = str(text).strip()
        if not body:
            return
        self._append_markdown_line(self.narrative_path, "# Narrative", f"- {body}")

    def append_refuted_hypothesis(self, hypothesis_id: str, description: str, reason: str) -> None:
        hyp_id = str(hypothesis_id).strip()
        description_text = str(description).strip()
        reason_text = str(reason).strip()
        if not hyp_id or not description_text:
            return
        line = f"- {hyp_id}: {description_text}"
        if reason_text:
            line += f" | reason: {reason_text}"
        self._append_markdown_line(self.refuted_hypotheses_path, "# Refuted Hypotheses", line)

    def append_important_entity(self, entity_type: str, name: str, notes: str) -> None:
        kind = str(entity_type).strip() or "entity"
        entity_name = str(name).strip()
        note_text = str(notes).strip()
        if not entity_name:
            return
        line = f"- [{kind}] {entity_name}"
        if note_text:
            line += f" | {note_text}"
        self._append_markdown_line(self.important_entities_path, "# Important Entities", line)

    def append_suspicious(self, rows: list[dict]) -> bool:
        if not rows:
            return False
        header = "| evidence_id | reason | confidence |\n|---|---|---|\n"
        existing = ""
        seen: set[str] = set()
        if self.suspicious_path.exists():
            existing = self.suspicious_path.read_text(encoding="utf-8")
            for line in existing.splitlines():
                if line.startswith("|") and not line.startswith("| evidence_id ") and not line.startswith("|---"):
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
        self.compact_if_oversized(self.suspicious_path)
        return True

    def _format_memory_line(self, text: str, evidence_ids: list[str]) -> str:
        body = str(text).strip()
        if not body:
            return ""
        normalized_ids = [str(item).strip() for item in evidence_ids if str(item).strip()]
        if normalized_ids:
            body += f" [evidence: {', '.join(normalized_ids)}]"
        return f"- {body}"

    def _append_markdown_line(self, path: Path, heading: str, line: str) -> bool:
        existing = path.read_text(encoding="utf-8").rstrip() if path.exists() else heading
        if not existing:
            existing = heading
        existing_lines = set(existing.splitlines())
        if line in existing_lines:
            return False
        path.write_text(existing + "\n\n" + line + "\n", encoding="utf-8")
        return True

    def _next_fact_detail_id(self) -> str:
        max_n = 0
        for path in self.details_dir.glob("fact-*.md"):
            try:
                max_n = max(max_n, int(path.stem[5:]))
            except ValueError:
                continue
        return f"fact-{max_n + 1:03d}"

    def _write_fact_detail(self, detail_id: str, text: str, evidence_ids: list[str]) -> None:
        lines = [f"# {detail_id}", "", text.strip()]
        if evidence_ids:
            lines.extend(["", "## Evidence", *[f"- {item}" for item in evidence_ids]])
        (self.details_dir / f"{detail_id}.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    def _fact_hash(self, text: str, evidence_ids: list[str]) -> str:
        payload = "\n".join([text.strip(), *evidence_ids])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _parse_fact_detail(self, detail: list[str]) -> tuple[str, list[str]] | None:
        if len(detail) < 3:
            return None
        existing_text = detail[2].strip()
        if not existing_text:
            return None
        evidence_ids: list[str] = []
        in_evidence = False
        for line in detail[3:]:
            stripped = line.strip()
            if stripped == "## Evidence":
                in_evidence = True
                continue
            if in_evidence and stripped.startswith("- "):
                evidence_ids.append(stripped[2:].strip())
        return existing_text, evidence_ids

    def _load_existing_fact_hashes(self) -> None:
        for path in sorted(self.details_dir.glob("fact-*.md")):
            parsed = self._parse_fact_detail(path.read_text(encoding="utf-8").splitlines())
            if parsed is None:
                continue
            text, evidence_ids = parsed
            self._fact_hashes.add(self._fact_hash(text, evidence_ids))

    def _rotate_timeline_anchors(self, max_lines: int = 100, keep_lines: int = 80) -> None:
        if not self.timeline_anchors_path.exists():
            return
        lines = self.timeline_anchors_path.read_text(encoding="utf-8").splitlines()
        anchor_lines = [line for line in lines if line.startswith("- ")]
        if len(anchor_lines) <= max_lines:
            return
        archived = anchor_lines[:-keep_lines]
        retained = anchor_lines[-keep_lines:]
        archive_path = self.details_dir / "timeline_archive.md"
        archive_existing = archive_path.read_text(encoding="utf-8").rstrip() if archive_path.exists() else "# Timeline Archive"
        archive_lines = set(archive_existing.splitlines())
        appendable = [line for line in archived if line not in archive_lines]
        if appendable:
            archive_path.write_text(archive_existing + "\n\n" + "\n".join(appendable) + "\n", encoding="utf-8")
        rebuilt = "# Timeline Anchors"
        if retained:
            rebuilt += "\n\n" + "\n".join(retained)
        self.timeline_anchors_path.write_text(rebuilt.rstrip() + "\n", encoding="utf-8")

    def compact_narrative_if_needed(self, base_url: str, model: str) -> bool:
        if not self.narrative_path.exists() or self.narrative_path.stat().st_size <= self.max_bytes:
            return False
        current = self.narrative_path.read_text(encoding="utf-8").strip()
        if not current:
            return False
        output_language = str(get_llm_settings()["output_language"]).lower()
        language_instruction = f"Write the compressed narrative in {output_language}."
        try:
            body = chat_completion(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Compress the following investigation narrative to 600 words or fewer. "
                            "Preserve conclusions, timeline, and unresolved threads. "
                            "Output only the narrative body. "
                            f"{language_instruction}"
                        ),
                    },
                    {"role": "user", "content": current},
                ],
                model=model,
                base_url=base_url,
            ).strip()
        except Exception:
            logger.exception("narrative compaction failed")
            return False
        if not body:
            return False
        self.narrative_path.write_text(body + "\n", encoding="utf-8")
        return True

    def compact_oversized_with_llm(self, base_url: str, model: str) -> list[str]:
        changed_paths: list[str] = []
        for path in self._llm_compaction_targets():
            if not path.exists() or path.stat().st_size <= self.max_bytes:
                continue
            current = path.read_text(encoding="utf-8").strip()
            if not current:
                continue
            output_language = str(get_llm_settings()["output_language"]).lower()
            language_instruction = f"Write the compressed markdown in {output_language}."
            try:
                body = chat_completion(
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "Compress the following investigation memory markdown so it fits into a smaller context window. "
                                "Preserve the top-level markdown heading, confirmed facts, verdicts, key timeline facts, and unresolved questions. "
                                "Prefer compact bullet points over prose. "
                                "Keep markdown structure valid and output only the rewritten markdown document. "
                                f"{language_instruction}"
                            ),
                        },
                        {"role": "user", "content": current},
                    ],
                    model=model,
                    base_url=base_url,
                ).strip()
            except Exception:
                logger.exception("memory compaction failed: %s", path)
                continue
            if not body:
                continue
            compacted = self._ensure_markdown_heading(body, current)
            encoded = compacted.encode("utf-8")
            if len(encoded) > self.max_bytes:
                compacted = encoded[: self.max_bytes].decode("utf-8", errors="ignore").rstrip() + "\n"
                compacted = self._ensure_markdown_heading(compacted, current)
            path.write_text(compacted, encoding="utf-8")
            changed_paths.append(str(path))
        return changed_paths

    def _llm_compaction_targets(self) -> list[Path]:
        return [
            self.overview_path,
            *sorted(self.hypotheses_dir.glob("*.md")),
            *sorted(self.hosts_dir.glob("*.md")),
            *sorted(self.users_dir.glob("*.md")),
        ]

    def _ensure_markdown_heading(self, body: str, original: str) -> str:
        compacted = body.strip()
        if not compacted.startswith("# "):
            original_heading = next((line.strip() for line in original.splitlines() if line.strip().startswith("# ")), "")
            if original_heading:
                compacted = f"{original_heading}\n\n{compacted}".strip()
            else:
                compacted = f"# Compacted Memory\n\n{compacted}".strip()
        return compacted.rstrip() + "\n"

    def _compact_generic(self, path: Path) -> bool:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        max_chars = max(self.max_bytes // 2, 1024)
        body = "\n".join(lines)
        trimmed = body[:max_chars].rstrip()
        if len(body) > max_chars:
            cut = trimmed.rfind("\n")
            if cut > 0:
                trimmed = trimmed[:cut].rstrip()
        summary = (
            "# Compacted Memory\n\n"
            f"- original_bytes: {len(text.encode('utf-8'))}\n"
            f"- retained_lines: {len(trimmed.splitlines())}\n"
            "- note: oversized memory file was compacted automatically.\n\n"
            "## Retained Excerpt\n"
        )
        compacted = summary + trimmed + "\n"
        encoded = compacted.encode("utf-8")
        if len(encoded) > self.max_bytes:
            compacted = compacted.encode("utf-8")[: self.max_bytes].decode("utf-8", errors="ignore").rstrip() + "\n"
        path.write_text(compacted, encoding="utf-8")
        return True

    def _compact_open_questions(self, path: Path) -> bool:
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
        lines = path.read_text(encoding="utf-8").splitlines()
        question_lines = [line for line in lines if line.startswith("- [")]
        if not question_lines:
            return False
        prefix_lines: list[str] = []
        for line in lines:
            if line.startswith("- ["):
                break
            prefix_lines.append(line)

        keep_lines = question_lines
        while keep_lines:
            remove_count = max(1, ceil(len(keep_lines) * 0.2))
            keep_lines = keep_lines[remove_count:]
            rebuilt = "\n".join(prefix_lines + [""] + keep_lines).strip() + "\n"
            path.write_text(rebuilt, encoding="utf-8")
            if path.stat().st_size <= self.max_bytes or len(keep_lines) <= 1:
                return True
        return True

    def compact_if_oversized(self, path: Path) -> bool:
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
        if path in {
            self.confirmed_facts_path,
            self.timeline_anchors_path,
            self.narrative_path,
            self.refuted_hypotheses_path,
            self.important_entities_path,
        }:
            return False
        if path == self.open_questions_path:
            return self._compact_open_questions(path)
        return False
