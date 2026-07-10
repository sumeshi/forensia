from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from forensia import cli as cli_module
from forensia.config import (
    resolve_llm_config,
)
from forensia.core.case import Case
from forensia.report_templates import export_packaged_report_templates


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


async def _async_agent_plan_router(*args, **kwargs):
    return _agent_plan_router(*args, **kwargs)


class CaseSetupTests(unittest.TestCase):
    """Case init artifacts and packaged template export."""

    @staticmethod
    def _llm_base_url() -> str:
        return resolve_llm_config()[0] or "http://test-llm.invalid"

    def setUp(self) -> None:
        # llm_gateway is the single seam for LLM JSON calls; patch here.
        llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.request_llm_json",
            side_effect=_agent_plan_router,
        )
        llm_json_patch.start()
        self.addCleanup(llm_json_patch.stop)
        # The async report-refresh path uses async_request_llm_json; mock it too
        # so async tests don't hit the real LLM.
        self._async_llm_json_patch = patch(
            "forensia.ai.llm.llm_gateway.async_request_llm_json",
            side_effect=_async_agent_plan_router,
        )
        self._async_llm_json_patch.start()
        self.addCleanup(self._async_llm_json_patch.stop)

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

    def test_case_init_seeds_report_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
            self.assertTrue((case.report_template_dir / "1_overview.md").exists())
            self.assertTrue(
                (case.report_template_dir / "5_recommendations.md").exists()
            )

    def test_export_packaged_report_templates_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            written = export_packaged_report_templates(tmpdir)
            self.assertGreaterEqual(len(written), 6)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_templates_export_command_writes_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            result = runner.invoke(cli_module.app, ["templates-export", tmpdir])
            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue((Path(tmpdir) / "1_overview.md").exists())

    def test_investigate_command_accepts_template_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            case = Case.init(tmpdir)
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
                    "forensia.cli_stages.investigate_loop", side_effect=fake_investigate_loop
                ),
                patch(
                    "forensia.cli_stages.render_written_report",
                    return_value=(
                        case.path / "reports" / "report.md",
                        case.path / "reports" / "report.html",
                    ),
                ),
            ):
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
                        str(template_dir),
                    ],
                )

            self.assertEqual(0, result.exit_code, result.output)
            self.assertEqual(template_dir.resolve(), captured["template_root"])

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
                    "forensia.cli_stages.ingest_all",
                    return_value={
                        "new_files": 0,
                        "skipped_files": 0,
                        "evtx_files": 0,
                        "mft_files": 0,
                        "prefetch_files": 0,
                    },
                ),
                patch(
                    "forensia.cli_stages.normalize_all",
                    return_value={
                        "evtx_rows": 0,
                        "mft_entries": 0,
                        "mft_timeline_rows": 0,
                        "prefetch_executions": 0,
                    },
                ),
                patch("forensia.cli_stages.load_rules_from_dir", return_value=[]),
                patch(
                    "forensia.cli_stages.investigate_loop",
                    side_effect=fake_investigate_loop,
                ),
                patch(
                    "forensia.cli_stages.render_written_report",
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

    def test_run_command_rejects_unknown_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_dir = Path(tmpdir) / "input"
            input_dir.mkdir()
            output_dir = Path(tmpdir) / "case"
            runner = CliRunner()
            result = runner.invoke(
                cli_module.app,
                [
                    "investigate",
                    str(output_dir),
                    str(input_dir),
                    "--profile",
                    "does-not-exist",
                ],
            )

            self.assertNotEqual(0, result.exit_code)
            self.assertIn("Available profiles", result.output)


if __name__ == "__main__":
    unittest.main()
