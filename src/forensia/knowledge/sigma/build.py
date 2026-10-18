"""Compile and validate a local Sigma source using the investigation schema."""

from __future__ import annotations

import importlib.metadata
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from forensia.knowledge.resources import schema_dir
from forensia.knowledge.rules.models import Rule
from forensia.knowledge.sigma_bundle import (
    SCHEMA_VERSION,
    binding_admitted,
    bundle_build_id,
    bundle_summary,
    canonical_json_bytes,
    sha256_bytes,
    validate_bundle,
    write_bundle_atomic,
)


def _file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _tree_sha256(paths: list[Path], root: Path) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _file_sha256(path),
                }
                for path in sorted(paths)
            ]
        )
    )


def _environment() -> dict[str, Any]:
    from forensia.db import schema
    from forensia.evidence import evtx, normalize
    from forensia.knowledge import sigma_bundle
    from forensia.knowledge.rules import engine, models
    from forensia.knowledge.sigma import converter, validation

    modules = {
        "builder": Path(__file__),
        "converter": Path(converter.__file__),
        "validator": Path(validation.__file__),
        "bundle_contract": Path(sigma_bundle.__file__),
        "finding_engine": Path(engine.__file__),
        "rule_model": Path(models.__file__),
        "evtx_normalizer": Path(evtx.__file__),
        "event_normalizer": Path(normalize.__file__),
        "case_schema": Path(schema.__file__),
        "sigma_schema": schema_dir() / "sigma.yaml",
    }
    packages = (
        "pysigma",
        "pysigma-pipeline-windows",
        "pysigma-pipeline-sysmon",
        "duckdb",
        "evtx2es",
        "PyYAML",
    )
    return {
        "versions": {
            "python": sys.version.split()[0],
            **{name: importlib.metadata.version(name) for name in packages},
        },
        "hashes": {name: _file_sha256(path) for name, path in modules.items()},
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


def build(
    source: Path,
    output: Path | None = None,
    *,
    repository: str | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    """Build one file, a rule directory, or a SigmaHQ checkout without requiring git."""
    from forensia.knowledge.sigma.converter import (
        SigmaTargetCompilation,
        compile_sigma_targets,
    )
    from forensia.knowledge.sigma.validation import semantic_contract, validate_rule

    source = source.expanduser().resolve(strict=True)
    source_root = source.parent if source.is_file() else source
    rules_root = (
        source_root / "rules/windows"
        if (source_root / "rules/windows").is_dir()
        else source_root
    )
    paths = (
        [source]
        if source.is_file()
        else sorted([*rules_root.rglob("*.yml"), *rules_root.rglob("*.yaml")])
    )
    if not paths:
        raise ValueError(f"No Sigma YAML rules found in {source}")
    for path in paths:
        if not path.resolve(strict=True).is_relative_to(source_root):
            raise ValueError(f"Sigma rule escapes the supplied source root: {path}")

    def rule_uri(path: Path) -> str:
        if repository and commit:
            return (
                f"{repository}/blob/{commit}/{path.relative_to(source_root).as_posix()}"
            )
        return path.as_uri()

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
        relative = path.relative_to(source_root).as_posix()
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
                item.relative_to(source_root).as_posix() for item in id_paths[rule_id]
            )
            try:
                targets = compile_sigma_targets(data, source_uri=rule_uri(path))
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
                targets = compile_sigma_targets(data, source_uri=rule_uri(path))
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
                "attribution": {
                    "author": str((data or {}).get("author") or ""),
                    "source": rule_uri(path),
                    "license": str((data or {}).get("license") or ""),
                },
                "rule": None,
            }
            if binding_admitted(record):
                executable_rule = Rule.model_validate(target.rule)
                executable_rule.definition_sha256 = source_sha256
                record["rule"] = executable_rule.model_dump(mode="json")
            bindings.append(record)

    bindings.sort(key=lambda item: (item["source_path"], item["target_key"]))
    fixtures = [
        path for path in (source_root / "regression_data").rglob("*") if path.is_file()
    ]
    licenses = []
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.md"):
        path = source_root / name
        if path.is_file():
            licenses.append(
                {
                    "name": name,
                    "uri": rule_uri(path),
                    "sha256": _file_sha256(path),
                    "text": path.read_text(encoding="utf-8"),
                }
            )
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "repository": repository or source.as_uri(),
            "commit": commit,
            "tree_sha256": _tree_sha256([*paths, *fixtures], source_root),
            "licenses": licenses,
        },
        "semantic_contract": common,
        "environment": _environment(),
        "summary": bundle_summary(bindings),
        "bindings": bindings,
    }
    bundle["build_id"] = bundle_build_id(bundle)
    validate_bundle(bundle)
    if not bundle["summary"]["admitted_rules"]:
        reasons = sorted(
            {
                item["conversion"]["reason"] or str(item.get("validation"))
                for item in bindings
            }
        )
        raise ValueError(
            "No executable Sigma rules after validation: " + "; ".join(reasons)[:1500]
        )
    if output is not None:
        write_bundle_atomic(output, bundle)
    return bundle
