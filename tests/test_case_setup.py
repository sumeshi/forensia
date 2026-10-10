from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from forensia.cli import app as cli_module
from forensia.config import (
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.template_export import (
    export_packaged_report_templates,
    seed_case_report_templates,
)


def _agent_plan_router(*_args, **kwargs):
    """Route section_agent.request_llm_json by which messages were sent.

    Plan messages → "write" short-circuit (no SQL).
    Check messages → "sufficient" so the loop exits cleanly.
    Used to avoid hitting a real LLM in unit tests.
    """
    messages = kwargs.get("messages")
    if messages is None and _args:
        messages = _args[0]
    system_content = ""
    if messages:
        system_content = str(messages[0].get("content", "")).lower()
    if "section-check" in system_content:
        return {"verdict": "sufficient", "fact_updates": []}
    return {"action": "write", "enough_to_write": True}


class CaseSetupTests(unittest.TestCase):
    """Case init artifacts and packaged template export."""

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def setUp(self) -> None:
        # Patch the owning JSON request implementation.
        llm_json_patch = patch(
            "forensia.llm.json_response.request_llm_json",
            side_effect=_agent_plan_router,
        )
        llm_json_patch.start()
        self.addCleanup(llm_json_patch.stop)

    def test_case_init_creates_allowlist_stub_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            initial = case.allowlist_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(initial)
            self.assertIn("rules", parsed)
            case.allowlist_path.write_text(
                "rules:\n  - rule_id: custom\n", encoding="utf-8"
            )
            Case.init(tmpdir)
            preserved = case.allowlist_path.read_text(encoding="utf-8")
            self.assertEqual("rules:\n  - rule_id: custom\n", preserved)

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

    def test_overwrite_cli_recreates_case_and_reingests_original_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir) / "case"
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            evidence = input_dir / "Security.evtx"
            evidence.write_bytes(b"original evidence")

            class FakeEvtxParser:
                def __init__(self, path):
                    pass

                def close(self):
                    pass

                def gen_records(self, *args):
                    yield [
                        {
                            "@timestamp": "2025-01-01T00:00:00Z",
                            "winlog": {
                                "channel": "Security",
                                "record_id": 1,
                                "event_id": 4624,
                                "computer_name": "HOST-A",
                            },
                        }
                    ]

            runner = CliRunner()
            with (
                patch("forensia.cli.app.resolve_llm_config", return_value=(None, None)),
                patch("forensia.pipeline.load_rules", return_value=[]),
                patch("evtx2es.presenters.Evtx2jsonPresenter.Evtx2es", FakeEvtxParser),
            ):
                args = ["investigate", str(case_dir), str(input_dir)]
                first = runner.invoke(cli_module.app, args)
                self.assertEqual(0, first.exit_code, first.output)
                case = Case.open(case_dir)
                with CaseDB(case) as db:
                    original_id = db.execute(
                        "SELECT evidence_id FROM evtx_events"
                    ).fetchone()[0]
                    db.execute(
                        "INSERT INTO findings (finding_id) VALUES ('old-finding')"
                    )
                    db.execute("CREATE TABLE old_state AS SELECT 1 AS marker")
                old_paths = [
                    case_dir / "FORENSIA.md",
                    case_dir / "REPORT.md",
                    case.raw_dir / "old.jsonl",
                    case.reports_dir / "old.html",
                    case.db_dir / "trace.duckdb",
                    case_dir / "old-extra.txt",
                ]
                for path in old_paths:
                    path.write_text("old case content", encoding="utf-8")
                overwritten = runner.invoke(cli_module.app, [*args, "--overwrite"])
                self.assertEqual(0, overwritten.exit_code, overwritten.output)

            self.assertEqual(b"original evidence", evidence.read_bytes())
            self.assertTrue(all(not path.exists() for path in old_paths))
            self.assertTrue((case.reports_dir / "report.html").is_file())
            with CaseDB(Case.open(case_dir)) as db:
                self.assertEqual(
                    [(original_id,)],
                    db.execute("SELECT evidence_id FROM evtx_events").fetchall(),
                )
                self.assertEqual(
                    1, db.execute("SELECT COUNT(*) FROM ingested_files").fetchone()[0]
                )
                self.assertEqual(
                    0, db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                )
                self.assertEqual(
                    0,
                    db.execute(
                        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'old_state'"
                    ).fetchone()[0],
                )

    def test_overwrite_rejects_unsafe_inputs_without_deleting_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            case = Case.init(root / "case")
            evidence = root / "input"
            evidence.mkdir()
            nested = case.path / "input"
            nested.mkdir()
            policy = case.path / "FORENSIA.md"
            policy.write_text("keep this policy", encoding="utf-8")
            original_manifest = case.manifest_path.read_bytes()
            link = root / "linked-case"
            link.symlink_to(case.path, target_is_directory=True)
            other = root / "not-a-case"
            other.mkdir()
            marker = other / "keep.txt"
            marker.write_text("keep this file", encoding="utf-8")
            variants = (
                (case.path, [], "requires an existing input_dir"),
                (case.path, [str(root / "missing")], "requires an existing input_dir"),
                (case.path, [str(nested)], "non-overlapping"),
                (case.path, [str(root)], "non-overlapping"),
                (
                    case.path,
                    [str(evidence), "--forensia-md", str(policy)],
                    "outside case_dir",
                ),
                (
                    case.path,
                    [str(evidence), "--knowledge", str(root)],
                    "outside case_dir",
                ),
                (
                    case.path,
                    [str(evidence), "--forensia-md", str(root / "missing.md")],
                    "not found",
                ),
                (case.path, [str(evidence), "--rerun"], "cannot be combined"),
                (case.path, [str(evidence), "--report-only"], "cannot be combined"),
                (link, [str(evidence)], "symlinked case directory"),
                (other, [str(evidence)], "without a case manifest"),
            )
            for target, extra, reason in variants:
                with self.subTest(target=target, extra=extra):
                    result = CliRunner().invoke(
                        cli_module.app,
                        ["investigate", str(target), *extra, "--overwrite"],
                    )
                    self.assertEqual(2, result.exit_code, result.output)
                    self.assertIn(reason, result.output)
                    self.assertEqual(original_manifest, case.manifest_path.read_bytes())
                    self.assertEqual(
                        "keep this policy", policy.read_text(encoding="utf-8")
                    )
                    self.assertEqual(
                        "keep this file", marker.read_text(encoding="utf-8")
                    )

            with patch("pathlib.Path.cwd", return_value=case.path):
                result = CliRunner().invoke(
                    cli_module.app,
                    ["investigate", str(case.path), str(evidence), "--overwrite"],
                )
            self.assertEqual(2, result.exit_code, result.output)
            self.assertIn("current working directory", result.output)
            self.assertEqual(original_manifest, case.manifest_path.read_bytes())

    def test_export_packaged_report_templates_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir)
            self.assertGreaterEqual(len(written), 5)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())
            self.assertTrue((Path(tmpdir) / "_formats" / "report.yaml").exists())

    def test_investigate_command_rejects_empty_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            empty_dir = Path(tmpdir) / "empty-templates"
            empty_dir.mkdir()
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "investigate",
                    str(case.path),
                    "--llm-base-url",
                    "http://127.0.0.1:1234",
                    "--model",
                    "test-model",
                    "--template-dir",
                    str(empty_dir),
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("[0-9]*_*.md", result.output)

    def test_run_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            template_dir = Path(tmpdir) / "custom-templates"
            export_packaged_report_templates(template_dir)
            runner = CliRunner()
            captured: dict[str, object] = {}

            def fake_investigate_loop(*args, **kwargs):
                captured["template_root"] = kwargs.get("template_root")
                return {
                    "session_id": "session-test",
                    "status": "completed",
                    "iteration": 1,
                    "summary": "done",
                    "hypotheses": [],
                    "report_sections": {"items": []},
                }

            with (
                patch(
                    "forensia.pipeline.ingest_all",
                    return_value={
                        "new_files": 0,
                        "skipped_files": 0,
                        "evtx_files": 0,
                        "mft_files": 0,
                        "prefetch_files": 0,
                    },
                ),
                patch(
                    "forensia.pipeline.normalize_all",
                    return_value={
                        "evtx_rows": 0,
                        "mft_entries": 0,
                        "mft_timeline_rows": 0,
                        "prefetch_executions": 0,
                    },
                ),
                patch("forensia.pipeline.load_rules", return_value=[]),
                patch(
                    "forensia.pipeline.investigate_loop",
                    side_effect=fake_investigate_loop,
                ),
                patch(
                    "forensia.pipeline.render_written_report",
                    return_value=(
                        output_dir / "reports" / "report.md",
                        output_dir / "reports" / "report.html",
                    ),
                ),
            ):
                result = runner.invoke(
                    cli_module.app,
                    [
                        "investigate",
                        str(output_dir),
                        str(input_dir),
                        "--llm-base-url",
                        "http://127.0.0.1:1234",
                        "--model",
                        "test-model",
                        "--template-dir",
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])


if __name__ == "__main__":
    unittest.main()
