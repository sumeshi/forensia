from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path


def _packaged_report_template_root():
    return resources.files("forensia").joinpath("report_template")


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


def has_report_templates(directory: str | Path) -> bool:
    return any(Path(directory).glob("[0-9]*_*.md"))
