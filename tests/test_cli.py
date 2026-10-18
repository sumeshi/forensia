from __future__ import annotations

import tempfile
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.text import Text
from typer.testing import CliRunner

from forensia.cli.app import app
from forensia.config import Settings
from forensia.core.case import Case


@pytest.mark.parametrize("force_color", [None, "1"])
def test_public_cli_includes_rule_setup(force_color: str | None) -> None:
    runner = CliRunner(env={"FORCE_COLOR": force_color})
    help_text = Text.from_ansi(runner.invoke(app, ["--help"]).output).plain
    assert "investigate" in help_text
    assert "attach" in help_text
    assert "setup" in help_text
    assert "add" not in help_text
    assert "report" not in help_text
    assert "templates-export" not in help_text

    investigate_help = Text.from_ansi(
        runner.invoke(app, ["investigate", "--help"]).output
    ).plain
    for option in (
        "--out",
        "--background",
        "--overwrite",
        "--system-prompt",
        "--template",
        "--rules",
    ):
        assert option in investigate_help
    for removed in ("--model", "--llm-base-url", "--rerun", "--report-only"):
        assert removed not in investigate_help


def test_investigate_starts_runtime_with_validated_settings_and_attaches_tui() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        input_dir = root / "input"
        input_dir.mkdir()
        case_dir = root / "case"
        policy = root / "policy.md"
        template = root / "report.md"
        policy.write_text("policy", encoding="utf-8")
        template.write_text("template", encoding="utf-8")
        settings = Settings(
            llm_base_url="http://localhost:8000",
            llm_model="local",
            llm_api_key="secret",
        )
        with (
            patch("forensia.cli.app.load_settings", return_value=settings),
            patch("forensia.cli.app.start_runtime", return_value=object()) as start,
            patch("forensia.cli.app.run_tui") as tui,
        ):
            result = CliRunner().invoke(
                app,
                [
                    "investigate",
                    str(input_dir),
                    "--out",
                    str(case_dir),
                    "--system-prompt",
                    str(policy),
                    "--template",
                    str(template),
                ],
            )

        assert result.exit_code == 0, result.output
        start.assert_called_once_with(
            case_dir.resolve(),
            input_dir=input_dir.resolve(),
            overwrite=False,
            settings=asdict(settings),
            system_prompt=policy.resolve(),
            template=template.resolve(),
            rules=None,
        )
        tui.assert_called_once_with(case_dir.resolve())


def test_investigate_rejects_implicit_existing_case_and_background_skips_tui() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        input_dir = root / "input"
        input_dir.mkdir()
        case = Case.init(root / "case")
        with patch("forensia.cli.app.start_runtime") as start:
            rejected = CliRunner().invoke(
                app, ["investigate", str(input_dir), "--out", str(case.path)]
            )
        assert rejected.exit_code == 2
        assert "attach" in rejected.output.lower()
        start.assert_not_called()

        with (
            patch(
                "forensia.cli.app.load_settings",
                return_value=Settings(
                    llm_base_url="http://localhost:8000", llm_model="local"
                ),
            ),
            patch("forensia.cli.app.start_runtime", return_value=object()) as start,
            patch("forensia.cli.app.run_tui") as tui,
        ):
            background = CliRunner().invoke(
                app,
                [
                    "investigate",
                    str(input_dir),
                    "--out",
                    str(root / "new-case"),
                    "--background",
                ],
            )
        assert background.exit_code == 0, background.output
        assert "Runtime started" in background.output
        assert start.call_args.kwargs["settings"]["llm_api_key"] is None
        tui.assert_not_called()


def test_investigate_preserves_symlink_path_for_shared_overwrite_guard() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source = Case.init(root / "source")
        link = root / "linked-case"
        link.symlink_to(source.path, target_is_directory=True)
        input_dir = root / "input"
        input_dir.mkdir()
        settings = Settings(llm_base_url="http://localhost:8000", llm_model="local")
        with (
            patch("forensia.cli.app.load_settings", return_value=settings),
            patch("forensia.cli.app.start_runtime", return_value=object()) as start,
            patch("forensia.cli.app.run_tui"),
        ):
            result = CliRunner().invoke(
                app,
                [
                    "investigate",
                    str(input_dir),
                    "--out",
                    str(link),
                    "--overwrite",
                    "--background",
                ],
            )
        assert result.exit_code == 0, result.output
        assert start.call_args.args[0] == link.absolute()
        assert start.call_args.args[0].is_symlink()


def test_attach_opens_existing_case_and_uses_shared_tui() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        case = Case.init(tmpdir)
        with (
            patch("forensia.cli.app.probe_runtime", return_value=False),
            patch("forensia.cli.app.run_tui") as tui,
        ):
            result = CliRunner().invoke(app, ["attach", str(case.path)])
        assert result.exit_code == 0, result.output
        tui.assert_called_once_with(case.path.resolve())
