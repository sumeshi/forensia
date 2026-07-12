from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from forensia.report.resources import report_templates_dir

if TYPE_CHECKING:
    from forensia.core.case import Case


def _packaged_report_template_root():
    return report_templates_dir()


def _copy_traversable_tree(
    source, destination: Path, written: list[Path], overwrite: bool
) -> None:
    """Recursively copy a traversable resource tree to a filesystem destination."""
    destination.mkdir(parents=True, exist_ok=True)
    for child in source.iterdir():
        child_target = destination / child.name
        if child.is_dir():
            if overwrite and child_target.exists():
                shutil.rmtree(child_target)
            if child_target.exists() and not overwrite:
                continue
            _copy_traversable_tree(child, child_target, written, overwrite)
            continue
        if child_target.exists() and not overwrite:
            continue
        child_target.parent.mkdir(parents=True, exist_ok=True)
        with child.open("rb") as src, child_target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        written.append(child_target)


def export_packaged_report_templates(
    destination: str | Path, overwrite: bool = False
) -> list[Path]:
    """Export bundled report template files to the given directory."""
    target_root = Path(destination).resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for source in _packaged_report_template_root().iterdir():
        target_path = target_root / source.name
        if source.is_dir():
            if overwrite and target_path.exists():
                shutil.rmtree(target_path)
            if target_path.exists():
                continue
            _copy_traversable_tree(source, target_path, written, overwrite)
            continue
        if target_path.exists() and not overwrite:
            continue
        with source.open("rb") as src, target_path.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        written.append(target_path)
    return sorted(written)


def seed_case_report_templates(case: Case, *, overwrite: bool = False) -> list[Path]:
    """Export the packaged report templates into ``case``'s template directory.

    This lives in the reporting layer so the platform-level ``Case`` type does
    not depend on report internals. Interface/workflow bootstrap code calls this
    after ``Case.init``.
    """
    case.report_template_dir.mkdir(parents=True, exist_ok=True)
    return export_packaged_report_templates(
        case.report_template_dir, overwrite=overwrite
    )


def has_report_templates(directory: str | Path) -> bool:
    return any(Path(directory).glob("[0-9]*_*.md"))
