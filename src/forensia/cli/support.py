"""Display helpers for CLI commands: status printing, case opening, LLM flag resolution.

Pipeline-side helpers (progress recording, stage runners, table reset,
template/knowledge/profile resolution) live in ``forensia.pipeline`` so the
kernel entry stays typer/rich-free.
"""

from pathlib import Path

import typer
from rich import print

from forensia.config import resolve_llm_config
from forensia.core.case import Case, resolve_timezone


def _status(message: str) -> None:
    """Print a colored status message to stdout."""
    print(f"[bold cyan]==>[/bold cyan] {message}")


def _resolve_llm_or_die(base_url: str | None, model: str | None) -> tuple[str, str]:
    """Resolve LLM endpoint and model, raising an error if either is missing."""
    resolved_base_url, resolved_model = resolve_llm_config(base_url, model)
    if not resolved_base_url or not resolved_model:
        raise typer.BadParameter(
            "Set LLM_BASE_URL and LLM_MODEL via .env file or CLI flags."
        )
    return resolved_base_url, resolved_model


def _open_case_or_die(case_dir: str, timezone: str | None = None) -> Case:
    """Open a case directory or raise a CLI error if the manifest is missing."""
    try:
        case = Case.open(case_dir)
        case.source_timezone = resolve_timezone(timezone, case)
        return case
    except FileNotFoundError as exc:
        target = Path(case_dir).resolve()
        raise typer.BadParameter(
            "case_dir must point to an initialized case directory.\n"
            f"missing: {target / 'manifest.yaml'}\n"
            f"initialize with: forensia investigate {target} <input_dir>"
        ) from exc
