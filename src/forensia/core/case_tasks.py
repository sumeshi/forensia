from __future__ import annotations

from datetime import UTC, datetime

from forensia.core.case import Case

_ALWAYS_RUN = {"investigate", "report"}


class CaseTasks:
    """
    Reads and writes case_dir/tasks.md.
    Tracks which pipeline steps are done so repeated `forensia run` skips them.
    'investigate' and 'report' are never skipped — each run appends a new record.
    """

    def __init__(self, case: Case) -> None:
        self._path = case.path / "tasks.md"
        self._case_name = case.path.name
        self._done: list[str] = []
        self._todo_lines: list[str] = []
        self._defer_lines: list[str] = []
        self._load()

    def _load(self) -> None:
        """Parse the tasks.md file into DONE, TODO, and DEFER sections."""
        if not self._path.exists():
            return
        current_section: str | None = None
        section_lines: dict[str, list[str]] = {"DONE": [], "TODO": [], "DEFER": []}
        for line in self._path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped == "## DONE":
                current_section = "DONE"
                continue
            if stripped == "## TODO":
                current_section = "TODO"
                continue
            if stripped == "## DEFER":
                current_section = "DEFER"
                continue
            if stripped.startswith("## "):
                current_section = None
                continue
            if current_section is not None:
                section_lines[current_section].append(line)

        for line in self._trim_section_lines(section_lines["DONE"]):
            if line.startswith("- [x] "):
                self._done.append(line[6:].strip())
        self._todo_lines = self._clean_optional_section(section_lines["TODO"])
        self._defer_lines = self._clean_optional_section(section_lines["DEFER"])

    def _write(self) -> None:
        """Write the in-memory state back to the tasks.md file."""
        done_section = (
            "\n".join(f"- [x] {e}" for e in self._done) if self._done else "_none yet_"
        )
        todo_section = "\n".join(self._todo_lines) if self._todo_lines else "_none yet_"
        defer_section = (
            "\n".join(self._defer_lines) if self._defer_lines else "_none yet_"
        )
        self._path.write_text(
            f"# Case Tasks: {self._case_name}\n\n"
            f"## DONE\n\n{done_section}\n\n"
            f"## TODO\n\n{todo_section}\n\n"
            f"## DEFER\n\n{defer_section}\n",
            encoding="utf-8",
        )

    def is_done(self, step: str) -> bool:
        """Check whether a given pipeline step has already been completed."""
        if step in _ALWAYS_RUN:
            return False
        return any(e == step or e.startswith(f"{step} ") for e in self._done)

    def mark_done(self, step: str, note: str = "") -> None:
        """Mark a pipeline step as completed, timestamping the entry."""
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        entry = f"{step} ({ts})"
        if note:
            entry += f" — {note}"
        if step not in _ALWAYS_RUN:
            self._done = [
                e for e in self._done if not (e == step or e.startswith(f"{step} "))
            ]
        self._done.append(entry)
        self._write()

    @classmethod
    def for_case(cls, case: Case) -> CaseTasks:
        return cls(case)

    @staticmethod
    def _trim_section_lines(lines: list[str]) -> list[str]:
        """Remove leading and trailing blank lines from a section."""
        start = 0
        end = len(lines)
        while start < end and not lines[start].strip():
            start += 1
        while end > start and not lines[end - 1].strip():
            end -= 1
        return lines[start:end]

    @classmethod
    def _clean_optional_section(cls, lines: list[str]) -> list[str]:
        """Return an empty list if the section contains only a placeholder line."""
        trimmed = cls._trim_section_lines(lines)
        if len(trimmed) == 1 and trimmed[0].strip() == "_none yet_":
            return []
        return trimmed
