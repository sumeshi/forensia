from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from forensia.config import get_llm_settings
from forensia.core.case import Case
from forensia.core.memory_compaction import MemoryCompactionMixin
from forensia.core.memory_context import MemoryContextMixin
from forensia.core.memory_writers import MemoryWriterMixin
from forensia.core.textutil import slugify

logger = logging.getLogger(__name__)


class MemoryPaths:
    """Central registry of memory path conventions used across prompts and MemoryManager."""

    OVERVIEW = "memory/overview.md"
    FACTS = "memory/facts.md"
    TASKS = "memory/tasks.md"
    TIMELINE = "memory/timeline.md"
    SUSPICIOUS_EVIDENCE = "memory/evidence/suspicious.md"

    @staticmethod
    def hypothesis(hypothesis_id: str) -> str:
        return f"memory/hypotheses/{hypothesis_id}.md"

    @staticmethod
    def fact_detail(index: int) -> str:
        return f"memory/details/fact-{index:03d}.md"

    @staticmethod
    def entity(entity_type: str, name: str) -> str:
        return f"memory/entities/{entity_type}/{name}.md"

    @staticmethod
    def keypoint(keypoint_id: str) -> str:
        return f"memory/keypoints/{keypoint_id}.md"


class MemoryManager(MemoryContextMixin, MemoryWriterMixin, MemoryCompactionMixin):
    def __init__(
        self,
        case: Case,
        summarize: Callable[[list[dict[str, str]], str], str] | None = None,
    ):
        self.case = case
        self.base_dir = case.memory_dir
        self.archive_dir = self.base_dir / "archive"
        self.scratch_dir = self.base_dir / "scratch"
        self.entities_dir = self.base_dir / "entities"
        self.entities_user_dir = self.entities_dir / "user"
        self.entities_host_dir = self.entities_dir / "host"
        self.entities_ip_dir = self.entities_dir / "ip"
        self.entities_machine_account_dir = self.entities_dir / "machine_account"
        self.entities_group_dir = self.entities_dir / "group"
        self.entities_process_dir = self.entities_dir / "process"
        self.entities_service_dir = self.entities_dir / "service"
        self.entities_file_dir = self.entities_dir / "file"
        self.entities_registry_dir = self.entities_dir / "registry"
        self.entities_unknown_dir = self.entities_dir / "unknown"
        self.hypotheses_dir = self.base_dir / "hypotheses"
        self.keypoints_dir = self.base_dir / "keypoints"
        self.evidence_dir = self.base_dir / "evidence"
        self.details_dir = self.base_dir / "details"
        self.scratch_archive_dir = self.archive_dir / "scratch"
        for directory in (
            self.base_dir,
            self.archive_dir,
            self.scratch_dir,
            self.scratch_archive_dir,
            self.entities_dir,
            self.entities_user_dir,
            self.entities_host_dir,
            self.entities_ip_dir,
            self.entities_machine_account_dir,
            self.entities_group_dir,
            self.entities_process_dir,
            self.entities_service_dir,
            self.entities_file_dir,
            self.entities_registry_dir,
            self.entities_unknown_dir,
            self.hypotheses_dir,
            self.keypoints_dir,
            self.evidence_dir,
            self.details_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self._fact_hashes: set[str] = set()
        self._next_fact_id = 1
        self._load_existing_fact_hashes()
        self._summarize = summarize

    @property
    def overview_path(self) -> Path:
        return self.base_dir / "overview.md"

    @property
    def facts_path(self) -> Path:
        return self.base_dir / "facts.md"

    @property
    def timeline_path(self) -> Path:
        return self.base_dir / "timeline.md"

    @property
    def tasks_memory_path(self) -> Path:
        return self.base_dir / "tasks.md"

    @property
    def scratch_global_dir(self) -> Path:
        return self.scratch_dir / "global"

    @property
    def refuted_hypotheses_path(self) -> Path:
        return self.archive_dir / "refuted.md"

    @property
    def resolved_gaps_path(self) -> Path:
        return self.archive_dir / "resolved_gaps.md"

    @property
    def untestable_hypotheses_path(self) -> Path:
        return self.archive_dir / "untestable.md"

    @property
    def suspicious_path(self) -> Path:
        return self.evidence_dir / "suspicious.md"

    def has_overview(self) -> bool:
        return self.overview_path.exists()

    @property
    def max_bytes(self) -> int:
        return int(get_llm_settings()["memory_max_bytes"])

    def load_overview(self) -> str:
        """Load the overview file, returning a default placeholder if it does not exist."""
        if not self.overview_path.exists():
            return (
                "# Investigation Overview\n\n"
                "## Case Scope\n- none\n\n"
                "## Key Findings\n- none\n\n"
                "## Investigation Policy\n- preserve evidence fidelity\n\n"
                "## Active Tasks\n- none\n"
            )
        return self.overview_path.read_text(encoding="utf-8")

    def load_context(self, files: list[str]) -> str:
        """Read and concatenate the named memory files, preventing path traversal outside base_dir."""
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

    def _markdown_files(self, directory: Path) -> list[str]:
        """List relative paths of all .md files in a directory, sorted."""
        if not directory.exists():
            return []
        return [
            str(path.relative_to(self.base_dir))
            for path in sorted(directory.rglob("*.md"))
            if path.is_file()
        ]

    def _scratch_key(self, hypothesis_id: str | None) -> str:
        """Derive a scratch directory key from a hypothesis ID, defaulting to 'global'."""
        hyp_id = str(hypothesis_id or "").strip()
        if not hyp_id:
            return "global"
        if hyp_id.upper().startswith("H-"):
            return hyp_id.upper()
        return f"H-{slugify(hyp_id).replace('-', '').upper()}"

    def _hypothesis_scratch_dir(self, hypothesis_id: str | None) -> Path:
        return self.scratch_dir / self._scratch_key(hypothesis_id)

    def _hypothesis_scratch_path(self, hypothesis_id: str | None, name: str) -> Path:
        return self._hypothesis_scratch_dir(hypothesis_id) / f"{name}.md"


class EvidenceOnlyMemory:
    """Wraps MemoryManager exposing only evidence-based context.

    Used for structured-answer blocks to prevent narrative contamination from
    hypotheses, scratch, archive, or investigation overview.
    Only facts, keypoints, entities, and suspicious evidence are loaded.
    """

    def __init__(self, inner: MemoryManager) -> None:
        self._inner = inner

    @property
    def max_bytes(self) -> int:
        return self._inner.max_bytes

    def _evidence_files(self) -> list[str]:
        """List evidence-only memory files (facts, entities, keypoints) excluding narrative context."""
        files: list[str] = ["facts.md"]
        files.extend(self._inner._markdown_files(self._inner.entities_dir))
        files.extend(self._inner._markdown_files(self._inner.keypoints_dir))
        return files

    def load_investigation_context(
        self,
        hypothesis_id: str | None = None,
        **kwargs: object,
    ) -> str:
        """Load only evidence-based context, ignoring narrative files like hypotheses and scratch."""
        return self._inner.load_compact_context(self._evidence_files())


def memory_for_section(
    memory: MemoryManager,
    *,
    structured_mode: bool = False,
    benchmark_mode: bool | None = None,
) -> MemoryManager | EvidenceOnlyMemory:
    """Wrap memory in EvidenceOnlyMemory for structured-answer blocks."""
    if benchmark_mode is not None:
        structured_mode = benchmark_mode
    return EvidenceOnlyMemory(memory) if structured_mode else memory
