#!/usr/bin/env python3
"""Build the deterministic, validated bundle from the SigmaHQ submodule."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from forensia.knowledge.rules.models import Rule  # noqa: E402
from forensia.knowledge.sigma_bundle import (  # noqa: E402
    SCHEMA_VERSION,
    bundle_build_id,
    canonical_json_bytes,
    sha256_bytes,
    write_bundle_atomic,
)

SOURCE_REPOSITORY = "https://github.com/SigmaHQ/sigma"
DEFAULT_SOURCE_ROOT = ROOT / "knowledge" / "sigmahq"
DEFAULT_DRL_LICENSE = ROOT / "src" / "forensia" / "data" / "sigma" / "SIGMA_LICENSE.txt"
DEFAULT_OUTPUT = ROOT / "src" / "forensia" / "data" / "sigma" / "sigma_bundle.json"
WINDOWS_RULES = Path("rules") / "windows"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_manifest(paths: list[Path], root: Path) -> list[dict[str, str]]:
    return [
        {"path": path.relative_to(root).as_posix(), "sha256": _file_sha256(path)}
        for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix())
    ]


def _tree_sha256(manifest: list[dict[str, str]]) -> str:
    return sha256_bytes(canonical_json_bytes(manifest))


def _git(source: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "")
        raise RuntimeError(
            f"Git source check failed ({' '.join(args)}): {detail or exc}"
        ) from exc
    return result.stdout.strip()


def _source_revision(source_root: Path) -> str:
    """Require the initialized, clean checkout recorded by the parent gitlink."""
    expected_root = DEFAULT_SOURCE_ROOT.resolve()
    if source_root.resolve() != expected_root:
        raise RuntimeError(
            f"Sigma source must be the repository submodule at {expected_root}"
        )
    if not (source_root / ".git").exists():
        raise RuntimeError(
            "SigmaHQ submodule is not initialized; run "
            "`git submodule update --init knowledge/sigmahq`"
        )
    entries = _git(ROOT, "ls-files", "-s", "--", "knowledge/sigmahq").splitlines()
    if len(entries) != 1:
        raise RuntimeError("Parent index has no single SigmaHQ submodule gitlink")
    fields = entries[0].split()
    if len(fields) < 4 or fields[0] != "160000" or fields[2] != "0":
        raise RuntimeError(
            "Parent index entry for knowledge/sigmahq is not a stage-0 gitlink"
        )
    expected = fields[1]
    actual = _git(source_root, "rev-parse", "HEAD")
    if actual != expected:
        raise RuntimeError(
            "SigmaHQ checkout does not match parent gitlink "
            f"(expected {expected}, got {actual})"
        )
    if _git(source_root, "status", "--porcelain"):
        raise RuntimeError("SigmaHQ submodule has modified or untracked source files")
    url = _git(ROOT, "config", "-f", ".gitmodules", "--get", "submodule.sigmahq.url")
    normalized_url = url.rstrip("/").removesuffix(".git")
    if normalized_url != SOURCE_REPOSITORY:
        raise RuntimeError(f"Unexpected SigmaHQ submodule URL: {url}")
    path = _git(ROOT, "config", "-f", ".gitmodules", "--get", "submodule.sigmahq.path")
    if path != "knowledge/sigmahq":
        raise RuntimeError(f"Unexpected SigmaHQ submodule path: {path}")
    return actual


def _source_metadata(source_root: Path, commit: str) -> dict[str, Any]:
    rules_root = source_root / WINDOWS_RULES
    rule_paths = sorted(
        [*rules_root.rglob("*.yml"), *rules_root.rglob("*.yaml")],
        key=lambda item: item.relative_to(rules_root).as_posix(),
    )
    fixture_root = source_root / "regression_data"
    fixture_paths = (
        sorted(
            (item for item in fixture_root.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(source_root).as_posix(),
        )
        if fixture_root.is_dir()
        else []
    )
    if not fixture_paths:
        raise RuntimeError("SigmaHQ regression_data is missing or empty")
    licenses = []
    for name, path, repository in (
        (
            "SigmaHQ repository license notice",
            source_root / "LICENSE",
            SOURCE_REPOSITORY,
        ),
        (
            "Detection Rule License 1.1",
            DEFAULT_DRL_LICENSE,
            "https://github.com/SigmaHQ/Detection-Rule-License",
        ),
    ):
        if not path.is_file():
            raise RuntimeError(f"Required Sigma license text is missing: {path}")
        licenses.append(
            {
                "name": name,
                "repository": repository,
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": _file_sha256(path),
            }
        )
    return {
        "repository": SOURCE_REPOSITORY,
        "commit": commit,
        "tree_sha256": _tree_sha256(
            _tree_manifest([*rule_paths, *fixture_paths], source_root)
        ),
        "licenses": licenses,
    }


def _environment(
    source_root: Path, yaml_paths: list[Path], fixture_paths: list[Path]
) -> dict[str, Any]:
    try:
        from scripts.sigma import converter as sigma
        from scripts.sigma import validation as sigma_validation
    except ImportError as exc:
        raise RuntimeError(
            "Sigma converter and validator modules must be available before building"
        ) from exc

    version_packages = {
        "pysigma": "pysigma",
        "pysigma_pipeline_windows": "pysigma-pipeline-windows",
        "pysigma_pipeline_sysmon": "pysigma-pipeline-sysmon",
        "duckdb": "duckdb",
        "evtx2es": "evtx2es",
        "pyyaml": "PyYAML",
    }
    versions = {"python": sys.version.split()[0]}
    for key, package in version_packages.items():
        try:
            versions[key] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(
                f"Required build dependency {package} is not installed"
            ) from exc

    rules_root = source_root / WINDOWS_RULES
    boundary_files = {
        "bundle_builder": ROOT / "scripts" / "sigma" / "build.py",
        "bundle_contract": ROOT / "src" / "forensia" / "knowledge" / "sigma_bundle.py",
        "evtx_ingest_normalizer": ROOT / "src" / "forensia" / "evidence" / "evtx.py",
        "event_normalizer": ROOT / "src" / "forensia" / "evidence" / "normalize.py",
        "finding_engine": ROOT
        / "src"
        / "forensia"
        / "knowledge"
        / "rules"
        / "engine.py",
        "case_schema": ROOT / "src" / "forensia" / "db" / "schema.py",
        "rule_model": ROOT / "src" / "forensia" / "knowledge" / "rules" / "models.py",
    }
    return {
        "versions": versions,
        "hashes": {
            "uv_lock": _file_sha256(ROOT / "uv.lock"),
            "converter": _file_sha256(Path(sigma.__file__)),
            "validator": _file_sha256(Path(sigma_validation.__file__)),
            "sigma_schema": _file_sha256(ROOT / "scripts" / "sigma" / "schema.yaml"),
            "windows_rules": _tree_sha256(_tree_manifest(yaml_paths, rules_root)),
            "fixtures": _tree_sha256(_tree_manifest(fixture_paths, source_root)),
            **{name: _file_sha256(path) for name, path in boundary_files.items()},
        },
    }


def _read_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return None, f"Cannot parse YAML: {type(exc).__name__}: {exc}"
    if not isinstance(value, dict):
        return None, "Sigma source must contain a YAML mapping"
    return value, None


def _source_binding(data: dict[str, Any] | None) -> dict[str, Any]:
    value = data.get("logsource") if data else None
    if not isinstance(value, dict):
        return {}
    return {
        key: value[key]
        for key in sorted(value)
        if isinstance(value[key], (str, int, float, bool))
    }


def _failure_validation(reason_code: str, reason: str) -> dict[str, Any]:
    return {
        "sql_validation": {
            "status": "failed",
            "reason_code": reason_code,
            "reason": reason,
        },
        "fixture": {
            "status": "error",
            "reason_code": reason_code,
            "reason": reason,
            "fixtures": [],
        },
        "fingerprints": {},
    }


def build(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    source_root = DEFAULT_SOURCE_ROOT.resolve()
    commit = _source_revision(source_root)
    rules_root = source_root / WINDOWS_RULES
    if not rules_root.is_dir():
        raise RuntimeError(f"Sigma source has no {WINDOWS_RULES.as_posix()} directory")
    paths = sorted(
        [*rules_root.rglob("*.yml"), *rules_root.rglob("*.yaml")],
        key=lambda path: path.relative_to(rules_root).as_posix(),
    )
    if not paths:
        raise RuntimeError(f"No Sigma YAML rules found below {rules_root}")

    from scripts.sigma.converter import (  # noqa: PLC0415
        SigmaTargetCompilation,
        compile_sigma_targets,
    )
    from scripts.sigma.validation import (  # noqa: PLC0415
        semantic_contract,
        validate_rule,
    )

    from forensia.knowledge.sigma_bundle import (  # noqa: PLC0415
        binding_admitted,
        bundle_summary,
    )

    common = semantic_contract()
    if common["status"] != "passed":
        raise RuntimeError(f"Shared Sigma semantic contract failed: {common['checks']}")
    parsed = [(path, *_read_yaml(path)) for path in paths]
    id_paths: dict[str, list[Path]] = {}
    for path, data, _error in parsed:
        rule_id = data.get("id") if data else None
        if isinstance(rule_id, str) and rule_id:
            id_paths.setdefault(rule_id, []).append(path)

    bindings: list[dict[str, Any]] = []
    for index, (path, data, parse_error) in enumerate(parsed, 1):
        if index % 250 == 0:
            print(f"Validated {index}/{len(parsed)} source rules", file=sys.stderr)
        relative = path.relative_to(rules_root).as_posix()
        source_sha256 = _file_sha256(path)
        rule_id = (
            str(data.get("id") or f"invalid:{relative}")
            if data
            else f"invalid:{relative}"
        )
        if parse_error:
            targets = [
                SigmaTargetCompilation(
                    target_key="unresolved",
                    target_binding={},
                    sigma_id=rule_id,
                    rule=None,
                    status="failed",
                    reason_code="invalid_source",
                    reason=parse_error,
                )
            ]
        elif data is None:
            continue
        elif len(id_paths.get(rule_id, [])) > 1:
            locations = sorted(
                item.relative_to(rules_root).as_posix() for item in id_paths[rule_id]
            )
            try:
                targets = compile_sigma_targets(data)
            except Exception:
                targets = []
            targets = [
                replace(
                    target,
                    status="failed",
                    reason_code="duplicate_source_rule_id",
                    reason=(
                        f"Sigma rule ID {rule_id} occurs in multiple source files: "
                        f"{', '.join(locations)}"
                    ),
                )
                for target in targets
            ]
            if not targets:
                targets = [
                    SigmaTargetCompilation(
                        target_key="unresolved",
                        target_binding={},
                        sigma_id=rule_id,
                        rule=None,
                        status="failed",
                        reason_code="duplicate_source_rule_id",
                        reason=(
                            f"Sigma rule ID {rule_id} occurs in multiple source files"
                        ),
                    )
                ]
        else:
            try:
                targets = compile_sigma_targets(data)
            except Exception as exc:
                targets = [
                    SigmaTargetCompilation(
                        target_key="unresolved",
                        target_binding={},
                        sigma_id=rule_id,
                        rule=None,
                        status="failed",
                        reason_code="conversion_failed",
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                ]
            if not targets:
                targets = [
                    SigmaTargetCompilation(
                        target_key="unresolved",
                        target_binding={},
                        sigma_id=rule_id,
                        rule=None,
                        status="failed",
                        reason_code="no_target_bindings",
                        reason="Converter produced no target bindings",
                    )
                ]

        for target in targets:
            if data is None or target.status != "converted":
                validation = {}
            else:
                try:
                    validation = validate_rule(
                        source_root,
                        path,
                        data,
                        target.rule,
                        binding=target.target_binding,
                    )
                except Exception as exc:
                    validation = _failure_validation(
                        "validator_failed", f"{type(exc).__name__}: {exc}"
                    )
            record: dict[str, Any] = {
                "rule_id": str(target.sigma_id or f"invalid:{relative}"),
                "target_key": target.target_key,
                "logsource": _source_binding(data),
                "target_binding": target.target_binding,
                "conversion": {
                    "status": target.status,
                    "reason_code": target.reason_code,
                    "reason": target.reason,
                },
                "validation": validation,
                "source_path": relative,
                "source_sha256": source_sha256,
                "rule": None,
            }
            if binding_admitted(record):
                executable_rule = Rule.model_validate(target.rule)
                executable_rule.definition_sha256 = source_sha256
                record["rule"] = executable_rule.model_dump(mode="json")
            bindings.append(record)

    bindings.sort(key=lambda item: (item["source_path"], item["target_key"]))
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": _source_metadata(source_root, commit),
        "semantic_contract": common,
        "environment": _environment(
            source_root,
            paths,
            [
                item
                for item in (source_root / "regression_data").rglob("*")
                if item.is_file()
            ],
        ),
        "summary": bundle_summary(bindings),
        "bindings": bindings,
    }
    bundle["build_id"] = bundle_build_id(bundle)
    write_bundle_atomic(output, bundle)
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        bundle = build(args.output)
    except Exception as exc:
        parser.exit(2, f"Sigma bundle build failed: {type(exc).__name__}: {exc}\n")
    print(f"Wrote {args.output} ({bundle['build_id']})")
    print(f"Summary: {json.dumps(bundle['summary'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
