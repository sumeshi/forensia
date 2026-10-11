from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from forensia.core.case import Case
from forensia.pipeline import UsageError, _overwrite_case
from forensia.report.template_export import (
    export_packaged_report_templates,
    seed_case_report_templates,
)


class CaseSetupTests(unittest.TestCase):
    def test_case_init_creates_allowlist_stub_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            initial = case.allowlist_path.read_text(encoding="utf-8")
            self.assertIn("rules", yaml.safe_load(initial))
            case.allowlist_path.write_text(
                "rules:\n  - rule_id: custom\n", encoding="utf-8"
            )
            Case.init(tmpdir)
            self.assertEqual(
                "rules:\n  - rule_id: custom\n",
                case.allowlist_path.read_text(encoding="utf-8"),
            )

    def test_report_bootstrap_seeds_case_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            seed_case_report_templates(case)
            self.assertTrue((case.report_template_dir / "1_overview.md").exists())
            self.assertTrue(
                (case.report_template_dir / "5_recommendations.md").exists()
            )
            self.assertTrue(
                (case.report_template_dir / "_formats" / "report.yaml").exists()
            )

    def test_export_packaged_report_templates_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir)
            self.assertGreaterEqual(len(written), 5)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())
            self.assertTrue((Path(tmpdir) / "_formats" / "report.yaml").exists())

    def test_overwrite_validates_scope_before_deleting_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            case = Case.init(root / "case")
            input_dir = root / "input"
            input_dir.mkdir()
            nested_input = case.path / "nested-input"
            nested_input.mkdir()
            policy = case.path / "FORENSIA.md"
            policy.write_text("preserve", encoding="utf-8")
            other = root / "not-a-case"
            other.mkdir()
            (other / "keep.txt").write_text("keep", encoding="utf-8")
            linked = root / "linked-case"
            linked.symlink_to(case.path, target_is_directory=True)
            original_manifest = case.manifest_path.read_bytes()

            cases = (
                (case.path, None, {}, "requires an existing input_dir"),
                (case.path, root / "missing", {}, "requires an existing input_dir"),
                (case.path, nested_input, {}, "non-overlapping"),
                (case.path, root, {}, "non-overlapping"),
                (case.path, input_dir, {"forensia_md": policy}, "outside case_dir"),
                (linked, input_dir, {}, "symlinked case directory"),
                (other, input_dir, {}, "without a case manifest"),
            )
            for target, source, paths, reason in cases:
                with self.subTest(target=target, source=source):
                    with self.assertRaisesRegex(UsageError, reason):
                        _overwrite_case(
                            target, str(source) if source else None, paths, None
                        )
                    self.assertEqual(original_manifest, case.manifest_path.read_bytes())
                    self.assertEqual("preserve", policy.read_text(encoding="utf-8"))
                    self.assertEqual(
                        "keep", (other / "keep.txt").read_text(encoding="utf-8")
                    )

            with patch("pathlib.Path.cwd", return_value=case.path):
                with self.assertRaisesRegex(UsageError, "current working directory"):
                    _overwrite_case(case.path, str(input_dir), {}, None)


if __name__ == "__main__":
    unittest.main()
