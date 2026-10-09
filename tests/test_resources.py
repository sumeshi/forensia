"""Runtime resource discovery and the actual wheel packaging contract."""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from forensia.knowledge.resources import (
    schema_dir,
    sigma_bundle_path,
    sigma_license_path,
)
from forensia.report.resources import (
    render_templates_dir,
    report_formats_path,
    report_templates_dir,
)


def test_runtime_resources_are_readable() -> None:
    resources = (
        schema_dir() / "artifact_capabilities.yaml",
        schema_dir() / "verdict_taxonomy.yaml",
        sigma_bundle_path(),
        sigma_license_path(),
        report_templates_dir() / "1_overview.md",
        report_formats_path(),
        render_templates_dir() / "report.html.j2",
    )
    for resource in resources:
        assert resource.exists(), resource
        if resource.is_file():
            assert resource.read_text(encoding="utf-8").strip(), resource


@pytest.fixture(scope="session")
def wheel_paths(tmp_path_factory: pytest.TempPathFactory) -> set[str]:
    """Build a wheel offline from a disposable source copy."""
    repo_root = Path(__file__).resolve().parent.parent
    build_root = tmp_path_factory.mktemp("wheel-source")
    dist_dir = tmp_path_factory.mktemp("wheel-dist")
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(repo_root / name, build_root / name)
    shutil.copytree(
        repo_root / "src" / "forensia",
        build_root / "src" / "forensia",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    subprocess.check_call(
        ["uv", "build", "--offline", "--wheel", "--out-dir", str(dist_dir)],
        cwd=build_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wheels = list(dist_dir.glob("*.whl"))
    assert wheels, "wheel not found after build"
    with zipfile.ZipFile(wheels[0]) as zf:
        return set(zf.namelist())


def test_wheel_packages_runtime_resources(wheel_paths: set[str]) -> None:
    required = {
        "forensia/data/schema/verdict_taxonomy.yaml",
        "forensia/data/schema/artifact_capabilities.yaml",
        "forensia/data/sigma/sigma_bundle.json",
        "forensia/data/sigma/SIGMA_LICENSE.txt",
        "forensia/data/report/1_overview.md",
        "forensia/data/report/_formats/report.yaml",
        "forensia/data/render/report.html.j2",
    }
    assert required <= wheel_paths
    assert not any(
        path.startswith(("forensia/ai/", "scripts/")) for path in wheel_paths
    )
    assert not any(
        path.endswith(("/sigma.yaml", "/question_routing_eval.yaml", "/rules/sigma.py"))
        for path in wheel_paths
    )
