from __future__ import annotations

from pathlib import Path
from re import sub

from forensia.core.case import Case
from forensia.config import get_llm_settings


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
        for directory in (
            self.base_dir,
            self.hosts_dir,
            self.users_dir,
            self.hypotheses_dir,
            self.evidence_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @property
    def overview_path(self) -> Path:
        return self.base_dir / "overview.md"

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

    def compact_if_oversized(self, path: Path) -> bool:
        if not path.exists() or path.stat().st_size <= self.max_bytes:
            return False
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
