"""Runtime resource discovery and the actual wheel packaging contract."""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from forensia.knowledge.resources import profile_path, rulepacks_dir, schema_dir
from forensia.report.resources import (
    render_templates_dir,
    report_formats_path,
    report_templates_dir,
)
from forensia.web.resources import static_dir


def test_runtime_resources_are_readable() -> None:
    resources = (
        rulepacks_dir() / "windows",
        schema_dir() / "verdict_taxonomy.yaml",
        profile_path("windows-basic"),
        report_templates_dir() / "1_overview.md",
        report_formats_path(),
        render_templates_dir() / "report.html.j2",
        static_dir(),
    )
    for resource in resources:
        assert resource.exists(), resource
        if resource.is_file():
            assert resource.read_text(encoding="utf-8").strip(), resource


@pytest.fixture(scope="session")
def wheel_paths(tmp_path_factory: pytest.TempPathFactory) -> set[str]:
    """Build a fresh wheel in a temp dir and return its file listing."""
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = tmp_path_factory.mktemp("wheel-dist")
    build_dir = repo_root / "build"
    shutil.rmtree(build_dir, ignore_errors=True)
    try:
        subprocess.check_call(
            ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
    wheels = list(dist_dir.glob("*.whl"))
    assert wheels, "wheel not found after build"
    with zipfile.ZipFile(wheels[0]) as zf:
        return set(zf.namelist())


def test_wheel_packages_runtime_resources(wheel_paths: set[str]) -> None:
    required = {
        "forensia/knowledge/rulepacks/_schema/verdict_taxonomy.yaml",
        "forensia/knowledge/profiles/windows-basic.yaml",
        "forensia/report/templates/1_overview.md",
        "forensia/report/templates/_formats/report.yaml",
        "forensia/report/render/templates/report.html.j2",
    }
    assert required <= wheel_paths
    assert any(
        path.startswith("forensia/knowledge/rulepacks/windows/") for path in wheel_paths
    )
    assert any(path.startswith("forensia/web/static/") for path in wheel_paths)
    assert "forensia/report/templates/6_appendix.md" not in wheel_paths
