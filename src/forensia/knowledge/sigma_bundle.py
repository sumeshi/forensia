"""Shared artifact contract for generated Sigma rules.

The source YAML is development input. Runtime consumers read the generated bundle,
whose build ID binds each executable rule to its source and validation result.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from forensia.knowledge.rules.models import Rule

SCHEMA_VERSION = 2
EXPECTED_SOURCE_REPOSITORY = "https://github.com/SigmaHQ/sigma"
CONVERSION_STATUSES = frozenset({"converted", "unsupported", "failed"})
FIXTURE_STATUSES = frozenset(
    {"passed", "mismatch", "error", "not_applicable", "absent"}
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION_SHA = re.compile(r"^[0-9a-f]{40}$")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically for fingerprints and generated artifacts."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bundle_build_id(bundle: dict[str, Any]) -> str:
    """Return the deterministic ID for a bundle, ignoring its embedded ID."""
    payload = dict(bundle)
    payload.pop("build_id", None)
    return sha256_bytes(canonical_json_bytes(payload))


def binding_admitted(binding: dict[str, Any]) -> bool:
    """Derive admission from conversion and validation; no approval flag is stored."""
    validation = binding.get("validation", {})
    return (
        binding.get("conversion", {}).get("status") == "converted"
        and validation.get("sql_validation", {}).get("status") == "passed"
        and validation.get("fixture", {}).get("status")
        in {"passed", "not_applicable", "absent"}
    )


def bundle_summary(bindings: list[dict[str, Any]]) -> dict[str, Any]:
    """Count original rules separately from independently converted targets."""
    from collections import Counter

    admitted = [item for item in bindings if binding_admitted(item)]
    conversions = Counter(item["conversion"]["status"] for item in bindings)
    fixtures = Counter(
        item.get("validation", {}).get("fixture", {}).get("status", "not_run")
        for item in bindings
    )
    return {
        "total": len({item["source_path"] for item in bindings}),
        "bindings": len(bindings),
        "admitted_rules": len({item["source_path"] for item in admitted}),
        "admitted_bindings": len(admitted),
        "by_conversion": {
            status: conversions[status] for status in sorted(CONVERSION_STATUSES)
        },
        "by_fixture": {
            status: fixtures[status]
            for status in sorted(FIXTURE_STATUSES | {"not_run"})
        },
        "by_target": {
            target: {
                "bindings": sum(item["target_key"] == target for item in bindings),
                "admitted": sum(item["target_key"] == target for item in admitted),
                "fixture_verified": sum(
                    item["target_key"] == target
                    and item.get("validation", {}).get("fixture", {}).get("status")
                    == "passed"
                    for item in bindings
                ),
                "by_conversion": {
                    status: sum(
                        item["target_key"] == target
                        and item["conversion"]["status"] == status
                        for item in bindings
                    )
                    for status in sorted(CONVERSION_STATUSES)
                },
                "by_fixture": {
                    status: sum(
                        item["target_key"] == target
                        and item.get("validation", {})
                        .get("fixture", {})
                        .get("status", "not_run")
                        == status
                        for item in bindings
                    )
                    for status in sorted(FIXTURE_STATUSES | {"not_run"})
                },
            }
            for target in sorted({item["target_key"] for item in bindings})
        },
    }


def _result(result: Any, statuses: set[str] | frozenset[str], label: str) -> None:
    if not isinstance(result, dict) or result.get("status") not in statuses:
        raise ValueError(f"Invalid Sigma {label} status")
    if not isinstance(result.get("reason_code"), str) or not isinstance(
        result.get("reason"), str
    ):
        raise ValueError(f"Sigma {label} has no structured reason")


def validate_bundle(bundle: Any) -> dict[str, Any]:
    """Check artifact integrity and the same admission contract used by the builder."""
    if not isinstance(bundle, dict) or bundle.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported Sigma bundle schema")
    if bundle.get("build_id") != bundle_build_id(bundle):
        raise ValueError("Sigma bundle build ID does not match its contents")
    source = bundle.get("source")
    if (
        not isinstance(source, dict)
        or source.get("repository") != EXPECTED_SOURCE_REPOSITORY
    ):
        raise ValueError("Sigma bundle source is not SigmaHQ")
    if not _REVISION_SHA.fullmatch(str(source.get("commit", ""))):
        raise ValueError("Sigma bundle source commit must be a full Git SHA")
    if not _SHA256.fullmatch(str(source.get("tree_sha256", ""))):
        raise ValueError("Sigma bundle source tree hash is invalid")
    if not isinstance(source.get("licenses"), list) or not source["licenses"]:
        raise ValueError("Sigma bundle source license attribution is missing")
    environment = bundle.get("environment")
    if not isinstance(environment, dict) or not isinstance(
        environment.get("versions"), dict
    ):
        raise ValueError("Sigma bundle build environment is missing")
    hashes = environment.get("hashes")
    if (
        not isinstance(hashes, dict)
        or not hashes
        or any(not _SHA256.fullmatch(str(value)) for value in hashes.values())
    ):
        raise ValueError("Sigma bundle build input hashes are invalid")
    bindings = bundle.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        raise ValueError("Sigma bundle bindings must be a nonempty list")
    semantic = bundle.get("semantic_contract", {})
    if (
        semantic.get("status") != "passed"
        or not semantic.get("checks")
        or any(check.get("status") != "passed" for check in semantic["checks"])
    ):
        raise ValueError("Sigma bundle shared semantic contract did not pass")
    seen: set[tuple[str, str]] = set()
    executable_ids: set[str] = set()
    for item in bindings:
        if not isinstance(item, dict):
            raise ValueError("Sigma bundle binding must be an object")
        for key in ("rule_id", "target_key", "source_path"):
            if not isinstance(item.get(key), str) or not item[key]:
                raise ValueError(f"Sigma binding has no {key}")
        path = Path(item["source_path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Unsafe Sigma source path")
        identity = (item["source_path"], item["target_key"])
        if identity in seen:
            raise ValueError(f"Duplicate Sigma target binding: {identity}")
        seen.add(identity)
        if not _SHA256.fullmatch(str(item.get("source_sha256", ""))):
            raise ValueError("Sigma source hash is invalid")
        if not isinstance(item.get("logsource"), dict) or not isinstance(
            item.get("target_binding"), dict
        ):
            raise ValueError("Sigma binding logsource/target is missing")
        _result(item.get("conversion"), CONVERSION_STATUSES, "conversion")
        validation = item.get("validation")
        if not isinstance(validation, dict):
            raise ValueError("Sigma binding validation is missing")
        if item["conversion"]["status"] == "converted":
            target = item["target_binding"]
            if target.get("target_key") != item["target_key"] or not target.get(
                "channels"
            ):
                raise ValueError("Converted Sigma binding has no concrete target")
            if any(
                not isinstance(target.get(key), list)
                or any(not isinstance(value, str) or not value for value in target[key])
                for key in ("channels", "providers")
            ):
                raise ValueError("Invalid Sigma target channel/provider scope")
            _result(
                validation.get("sql_validation"), {"passed", "failed"}, "SQL validation"
            )
            _result(validation.get("fixture"), FIXTURE_STATUSES, "fixture validation")
            if validation["fixture"]["status"] == "passed" and not validation[
                "fixture"
            ].get("fixtures"):
                raise ValueError("Verified Sigma binding has no fixture evidence")
        raw_rule = item.get("rule")
        if binding_admitted(item):
            if not isinstance(raw_rule, dict):
                raise ValueError("Admitted Sigma binding has no executable Rule")
            rule = Rule.model_validate(raw_rule)
            if (
                rule.rule_format != "sigma"
                or rule.id != f"sigma-{item['rule_id']}-{item['target_key']}"
            ):
                raise ValueError(
                    "Executable Sigma Rule identity does not match binding"
                )
            if rule.id in executable_ids:
                raise ValueError(f"Duplicate executable Sigma Rule ID: {rule.id}")
            executable_ids.add(rule.id)
            if rule.definition_sha256 != item["source_sha256"]:
                raise ValueError(
                    "Executable Sigma Rule source hash does not match binding"
                )
        elif raw_rule is not None:
            raise ValueError("Non-admitted Sigma binding contains an executable Rule")
    if bundle.get("summary") != bundle_summary(bindings):
        raise ValueError("Sigma bundle summary does not match its bindings")
    return bundle


def load_sigma_bundle(path: Path | None = None) -> dict[str, Any]:
    """Load the artifact without importing development-only Sigma packages."""
    if path is None:
        from forensia.knowledge.resources import sigma_bundle_path

        path = sigma_bundle_path()
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot load required Sigma bundle {path}: {exc}") from exc
    return validate_bundle(bundle)


def write_bundle_atomic(path: Path, bundle: dict[str, Any]) -> None:
    """Write a complete validated bundle with an atomic same-directory replace."""
    validate_bundle(bundle)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(bundle) + b"\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
