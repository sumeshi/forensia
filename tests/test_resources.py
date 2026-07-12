"""Tests for packaged resource helpers and build artifact inclusion.

Validates that:
1. Each resource helper returns a Path pointing to an existing directory/file.
2. Representative files are readable through the helpers.
3. Package-data globs resolve correctly via importlib.resources (build artifact check).
4. Built wheel contains the expected package-data entries.
"""

from __future__ import annotations

import subprocess
import zipfile
from importlib.resources import files
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# knowledge/resources.py
# ---------------------------------------------------------------------------


class TestKnowledgeResources:
    def test_rulepacks_dir_exists(self) -> None:
        from forensia.knowledge.resources import rulepacks_dir

        d = rulepacks_dir()
        assert isinstance(d, Path)
        assert d.is_dir()

    def test_schema_dir_exists(self) -> None:
        from forensia.knowledge.resources import schema_dir

        d = schema_dir()
        assert isinstance(d, Path)
        assert d.is_dir()

    def test_profiles_dir_exists(self) -> None:
        from forensia.knowledge.resources import profiles_dir

        d = profiles_dir()
        assert isinstance(d, Path)
        assert d.is_dir()

    def test_profile_path_returns_yaml(self) -> None:
        from forensia.knowledge.resources import profile_path

        p = profile_path("windows-basic")
        assert isinstance(p, Path)
        assert p.suffix == ".yaml"
        assert p.exists()

    def test_schema_dir_contains_verdict_taxonomy(self) -> None:
        from forensia.knowledge.resources import schema_dir

        tax = schema_dir() / "verdict_taxonomy.yaml"
        assert tax.exists(), "verdict_taxonomy.yaml must be in _schema/"

    def test_rulepacks_dir_contains_subdirs(self) -> None:
        from forensia.knowledge.resources import rulepacks_dir

        d = rulepacks_dir()
        subdirs = [p.name for p in d.iterdir() if p.is_dir()]
        assert "_schema" in subdirs
        assert "windows" in subdirs


# ---------------------------------------------------------------------------
# report/resources.py
# ---------------------------------------------------------------------------


class TestReportResources:
    def test_report_templates_dir_exists(self) -> None:
        from forensia.report.resources import report_templates_dir

        d = report_templates_dir()
        assert isinstance(d, Path)
        assert d.is_dir()

    def test_report_formats_path_exists(self) -> None:
        from forensia.report.resources import report_formats_path

        p = report_formats_path()
        assert isinstance(p, Path)
        assert p.exists()
        assert p.name == "report.yaml"

    def test_render_templates_dir_exists(self) -> None:
        from forensia.report.resources import render_templates_dir

        d = render_templates_dir()
        assert isinstance(d, Path)
        assert d.is_dir()

    def test_report_templates_contain_section_files(self) -> None:
        from forensia.report.resources import report_templates_dir

        md_files = list(report_templates_dir().glob("[0-9]*_*.md"))
        assert len(md_files) >= 6, "expected at least 6 section templates"

    def test_render_templates_contain_jinja(self) -> None:
        from forensia.report.resources import render_templates_dir

        j2_files = list(render_templates_dir().glob("*.j2"))
        assert len(j2_files) >= 1, "expected at least 1 Jinja template"


# ---------------------------------------------------------------------------
# web/resources.py
# ---------------------------------------------------------------------------


class TestWebResources:
    def test_static_dir_returns_path(self) -> None:
        from forensia.web.resources import static_dir

        d = static_dir()
        assert isinstance(d, Path)

    def test_static_dir_is_dir(self) -> None:
        from forensia.web.resources import static_dir

        d = static_dir()
        assert d.is_dir(), f"static_dir() should exist: {d}"


# ---------------------------------------------------------------------------
# Build artifact inspection — importlib.resources resolution
# ---------------------------------------------------------------------------


class TestBuildArtifacts:
    """Verify that package-data globs resolve via importlib.resources.

    These tests catch missing ``[tool.setuptools.package-data]`` entries and
    broken sdist/wheel builds.  They read through the canonical
    ``importlib.resources.files()`` API so they work in both unpacked-source
    and installed-wheel layouts.
    """

    def test_knowledge_rulepacks_accessible(self) -> None:
        root = files("forensia.knowledge").joinpath("rulepacks")
        children = [c.name for c in root.iterdir() if c.is_dir()]
        assert "_schema" in children
        assert "windows" in children

    def test_schema_yaml_files_accessible(self) -> None:
        schema = files("forensia.knowledge").joinpath("rulepacks", "_schema")
        yaml_names = [c.name for c in schema.iterdir() if c.name.endswith(".yaml")]
        assert "verdict_taxonomy.yaml" in yaml_names
        assert "event_ids.yaml" in yaml_names

    def test_profiles_yaml_files_accessible(self) -> None:
        profiles = files("forensia.knowledge").joinpath("profiles")
        yaml_names = [c.name for c in profiles.iterdir() if c.name.endswith(".yaml")]
        assert "windows-basic.yaml" in yaml_names

    def test_report_templates_accessible(self) -> None:
        templates = files("forensia.report").joinpath("templates")
        names = [c.name for c in templates.iterdir()]
        assert "1_overview.md" in names
        assert "_formats" in names

    def test_report_formats_yaml_accessible(self) -> None:
        fmt = files("forensia.report").joinpath("templates", "_formats", "report.yaml")
        content = fmt.read_text(encoding="utf-8")
        assert "version:" in content

    def test_render_jinja_templates_accessible(self) -> None:
        render = files("forensia.report").joinpath("render", "templates")
        names = [c.name for c in render.iterdir()]
        assert "report.html.j2" in names


# ---------------------------------------------------------------------------
# Wheel artifact inspection — verifies actual build output
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def wheel_paths(tmp_path_factory: pytest.TempPathFactory) -> set[str]:
    """Build a fresh wheel in a temp dir and return its file listing."""
    repo_root = Path(__file__).resolve().parent.parent
    dist_dir = tmp_path_factory.mktemp("wheel-dist")
    subprocess.check_call(
        ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    wheels = list(dist_dir.glob("*.whl"))
    assert wheels, "wheel not found after build"
    with zipfile.ZipFile(wheels[0]) as zf:
        return set(zf.namelist())


class TestWheelArtifact:
    """Verify that the built wheel contains expected package-data entries."""

    def test_wheel_contains_rulepacks(self, wheel_paths: set[str]) -> None:
        assert any("knowledge/rulepacks/windows/" in p for p in wheel_paths)

    def test_wheel_contains_schema_yaml(self, wheel_paths: set[str]) -> None:
        assert any("knowledge/rulepacks/_schema/verdict_taxonomy.yaml" in p for p in wheel_paths)

    def test_wheel_contains_profiles(self, wheel_paths: set[str]) -> None:
        assert any("knowledge/profiles/windows-basic.yaml" in p for p in wheel_paths)

    def test_wheel_contains_report_templates(self, wheel_paths: set[str]) -> None:
        assert any("report/templates/1_overview.md" in p for p in wheel_paths)

    def test_wheel_contains_jinja_templates(self, wheel_paths: set[str]) -> None:
        assert any("report/render/templates/report.html.j2" in p for p in wheel_paths)

    def test_wheel_contains_web_static(self, wheel_paths: set[str]) -> None:
        assert any("web/static/" in p for p in wheel_paths)
