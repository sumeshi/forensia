"""Public commands for starting and attaching to a case Runtime."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import typer
from rich import print

from forensia.config import load_settings
from forensia.core.case import Case
from forensia.runtime import probe_runtime, start_runtime
from forensia.tui import run_tui

app = typer.Typer(help="forensia investigation tool", no_args_is_help=True)


def _existing_case_message(case_dir: Path) -> str:
    return (
        f"Case already exists at {case_dir}. Use 'forensia attach {case_dir}' "
        "and enter /resume to continue it."
    )


def _input_file(value: Path | None, option: str) -> Path | None:
    if value is None:
        return None
    path = value.expanduser().resolve()
    if not path.is_file():
        raise typer.BadParameter(f"{option} must name an existing file: {path}")
    return path


@app.command()
def investigate(
    input_dir: Path,
    case_dir: Path = typer.Option(..., "--out", help="Case directory"),
    background: bool = typer.Option(
        False, "--background", help="Start Runtime and return"
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Replace the entire existing case"
    ),
    system_prompt: Path | None = typer.Option(
        None, "--system-prompt", help="Investigation policy Markdown"
    ),
    template: Path | None = typer.Option(
        None, "--template", help="Report template Markdown"
    ),
) -> None:
    """Start a new investigation in INPUT_DIR and save it under --out CASE."""
    input_path = input_dir.expanduser().resolve()
    # Keep the final path component intact so start_runtime can reject symlinks
    # before it resolves the case location.
    target = case_dir.expanduser().absolute()
    if not input_path.is_dir():
        raise typer.BadParameter(f"input must be an existing directory: {input_path}")
    if (
        target.exists()
        and not target.is_dir()
        and not (overwrite and target.is_symlink())
    ):
        raise typer.BadParameter(f"case output path must be a directory: {target}")
    if (
        not overwrite
        and target.exists()
        and not target.is_symlink()
        and any(target.iterdir())
    ):
        if (target / "manifest.yaml").is_file():
            raise typer.BadParameter(_existing_case_message(target))
        raise typer.BadParameter(
            f"Output directory already contains data: {target}; use --overwrite only for a case you intend to replace"
        )
    policy = _input_file(system_prompt, "--system-prompt")
    report_template = _input_file(template, "--template")
    try:
        settings = load_settings(require_inference=True)
        start_runtime(
            target,
            input_dir=input_path,
            overwrite=overwrite,
            settings=asdict(settings),
            system_prompt=policy,
            template=report_template,
        )
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from None
    if background:
        print(f"Runtime started for {target}")
        return
    run_tui(target)


@app.command()
def attach(case_dir: Path) -> None:
    """View a case or connect to its active Runtime."""
    target = case_dir.expanduser().resolve()
    try:
        Case.open(target)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from None
    if probe_runtime(target):
        print(f"Connected to Runtime for {target}")
    run_tui(target)


if __name__ == "__main__":
    app()
