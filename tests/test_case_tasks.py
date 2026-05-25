from __future__ import annotations

import tempfile
import unittest

from forensia.core.case import Case
from forensia.core.case_tasks import CaseTasks


class CaseTasksTests(unittest.TestCase):
    def test_mark_done_preserves_manual_todo_and_defer_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            tasks_path = case.path / "tasks.md"
            tasks_path.write_text(
                "# Case Tasks: case\n\n"
                "## DONE\n\n"
                "- [x] ingest (2026-05-25 00:00 UTC)\n\n"
                "## TODO\n\n"
                "- [ ] collect VPN logs\n"
                "- [ ] verify source host owner\n\n"
                "## DEFER\n\n"
                "- ask HR after legal approval\n",
                encoding="utf-8",
            )

            tasks = CaseTasks.for_case(case)
            tasks.mark_done("normalize", "rows=10")

            content = tasks_path.read_text(encoding="utf-8")
            self.assertIn("- [ ] collect VPN logs", content)
            self.assertIn("- [ ] verify source host owner", content)
            self.assertIn("- ask HR after legal approval", content)
            self.assertIn("- [x] normalize (", content)

    def test_reload_restores_preserved_todo_and_defer_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            tasks_path = case.path / "tasks.md"
            tasks_path.write_text(
                "# Case Tasks: case\n\n"
                "## DONE\n\n"
                "_none yet_\n\n"
                "## TODO\n\n"
                "Need customer confirmation for asset owner\n\n"
                "## DEFER\n\n"
                "_none yet_\n",
                encoding="utf-8",
            )

            tasks = CaseTasks.for_case(case)
            tasks.mark_done("ingest", "new_files=1")

            reloaded = CaseTasks.for_case(case)
            reloaded.mark_done("analyze", "findings=2")

            content = tasks_path.read_text(encoding="utf-8")
            self.assertIn("Need customer confirmation for asset owner", content)
            self.assertIn("## DEFER\n\n_none yet_", content)


if __name__ == "__main__":
    unittest.main()
