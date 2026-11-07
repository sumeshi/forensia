"""Runtime identification must distinguish uncommitted implementation changes."""

from __future__ import annotations

import json
from importlib import metadata

from forensia.core import provenance


def _package(tmp_path, monkeypatch):
    root = tmp_path / "installed" / "forensia"
    root.mkdir(parents=True)
    (root / "__init__.py").write_text("# installed code\n")
    (root / "data" / "schema").mkdir(parents=True)
    (root / "data" / "schema" / "rules.yaml").write_text("rule: original\n")
    monkeypatch.setattr(provenance, "_PACKAGE_ROOT", root)
    monkeypatch.setattr(provenance.metadata, "version", lambda _: "1.0.0")
    return root


def test_package_identity_detects_code_and_bundled_data_changes_without_version_bump(
    tmp_path, monkeypatch
):
    root = _package(tmp_path, monkeypatch)
    first = provenance.build_runtime_provenance()
    (root / "__init__.py").write_text("# uncommitted implementation change\n")
    changed_code = provenance.build_runtime_provenance()
    (root / "data" / "schema" / "rules.yaml").write_text("rule: changed\n")
    changed_data = provenance.build_runtime_provenance()

    assert first["distributions"] == changed_code["distributions"]
    assert changed_code["distributions"] == changed_data["distributions"]
    assert (
        len(
            {
                item["package_files"]["sha256"]
                for item in (first, changed_code, changed_data)
            }
        )
        == 3
    )
    assert changed_data["package_files"]["status"] == "complete"
    assert changed_data["package_files"]["file_count"] == 2


def test_runtime_snapshot_excludes_case_files_environment_and_cache(
    tmp_path, monkeypatch
):
    root = _package(tmp_path, monkeypatch)
    original = provenance.build_runtime_provenance()
    (tmp_path / "private-case.py").write_text("sensitive evidence")
    (root / "private-case.md").write_text("sensitive case notes")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "cache.py").write_text("cached code")
    monkeypatch.setenv("FORENSIA_PRIVATE_TEST_SECRET", "secret-sentinel")
    observed = provenance.build_runtime_provenance()

    assert observed["package_files"] == original["package_files"]
    serialized = json.dumps(observed)
    assert "secret-sentinel" not in serialized
    assert "sensitive" not in serialized
    assert str(tmp_path) not in serialized


def test_missing_distribution_is_explicitly_unknown(tmp_path, monkeypatch):
    _package(tmp_path, monkeypatch)

    def version(name):
        if name == "forensia":
            raise metadata.PackageNotFoundError(name)
        return "1.0.0"

    monkeypatch.setattr(provenance.metadata, "version", version)
    observed = provenance.build_runtime_provenance()
    assert observed["distributions"]["forensia"] is None
    assert observed["package_files"]["status"] == "complete"


def test_incomplete_package_does_not_claim_complete_content_identity(
    tmp_path, monkeypatch
):
    root = _package(tmp_path, monkeypatch)
    external = tmp_path / "outside.py"
    external.write_text("private external file")
    (root / "linked.py").symlink_to(external)
    observed = provenance.build_runtime_provenance()["package_files"]

    assert observed["status"] == "unavailable"
    assert observed["sha256"] is None
    assert observed["file_count"] == 2
    assert observed["unavailable_paths"] == ["linked.py"]
    assert str(external) not in json.dumps(observed)
