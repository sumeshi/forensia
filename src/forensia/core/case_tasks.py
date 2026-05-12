from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        in_done = False
        for line in self._path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped == "## DONE":
                in_done = True
            elif stripped.startswith("## "):
                in_done = False
            elif in_done and line.startswith("- [x] "):
                self._done.append(line[6:].strip())

    def _write(self) -> None:
        done_section = (
            "\n".join(f"- [x] {e}" for e in self._done)
            if self._done
            else "_none yet_"
        )
        self._path.write_text(
            f"# Case Tasks: {self._case_name}\n\n"
            f"## DONE\n\n{done_section}\n\n"
            f"## TODO\n\n## DEFER\n",
            encoding="utf-8",
        )

    def is_done(self, step: str) -> bool:
        if step in _ALWAYS_RUN:
            return False
        return any(e == step or e.startswith(f"{step} ") for e in self._done)

    def mark_done(self, step: str, note: str = "") -> None:
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        entry = f"{step} ({ts})"
        if note:
            entry += f" — {note}"
        if step not in _ALWAYS_RUN:
            self._done = [e for e in self._done if not (e == step or e.startswith(f"{step} "))]
        self._done.append(entry)
        self._write()

    @classmethod
    def for_case(cls, case: Case) -> "CaseTasks":
        return cls(case)
