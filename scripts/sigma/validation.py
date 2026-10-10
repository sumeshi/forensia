"""Development-time validation for generated Sigma bindings.

This module is intentionally outside runtime loading. It validates converter output
and regression fixtures while the bundle is built; it does not create a second rule
catalog or a durable verification authority.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import tempfile
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from scripts.sigma.converter import compile_sigma_targets

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.evidence.evtx import ingest_evtx_file, normalize_evtx
from forensia.knowledge.rules.engine import generate_findings, iter_rule_row_batches
from forensia.knowledge.rules.models import Rule

_SQL_TEMP_DIR: tempfile.TemporaryDirectory[str] | None = None
_SQL_CASE_DB: CaseDB | None = None


class _ExpectedCountMismatch(ValueError):
    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(f"expected exactly {expected} matches, observed {actual}")
        self.expected = expected
        self.actual = actual


def _validate_match_count(expected: int, actual: int) -> None:
    if expected != actual:
        raise _ExpectedCountMismatch(expected, actual)


def _close_sql_case() -> None:
    global _SQL_CASE_DB, _SQL_TEMP_DIR
    if _SQL_CASE_DB is not None:
        _SQL_CASE_DB.close()
        _SQL_CASE_DB = None
    if _SQL_TEMP_DIR is not None:
        _SQL_TEMP_DIR.cleanup()
        _SQL_TEMP_DIR = None


atexit.register(_close_sql_case)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _inside(root: Path, candidate: Path, *, directory: bool = False) -> Path:
    """Resolve a declared path and reject traversal or symlink escape."""
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(
            "declared fixture resolves outside the Sigma source root"
        ) from exc
    if directory:
        if not resolved.is_dir():
            raise ValueError("declared fixture is not a directory")
    elif not resolved.is_file():
        raise ValueError("declared fixture is not a regular file")
    return resolved


def _resolve_rule_path(source_root: Path, rule_path: Path) -> Path:
    root = source_root.resolve(strict=True)
    candidate = rule_path if rule_path.is_absolute() else root / rule_path
    return _inside(root, candidate)


def _declared_fixture_path(rawdata: Mapping[str, Any]) -> str | None:
    """Return Sigma's declared fixture path without guessing adjacent files."""
    value = rawdata.get("regression_tests_path")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("regression_tests_path must be a nonempty relative path")
    return value


def _load_regression_info(
    source_root: str, declaration: str
) -> tuple[Path, dict[str, Any], tuple[Path, ...]]:
    """Parse one upstream info.yml and resolve every declared fixture once."""
    root = Path(source_root).resolve(strict=True)
    relative_info = Path(declaration)
    if relative_info.is_absolute() or ".." in relative_info.parts:
        raise ValueError("regression_tests_path must remain inside source root")
    info_path = _inside(root, root / relative_info)
    info = yaml.safe_load(info_path.read_text(encoding="utf-8"))
    if not isinstance(info, dict):
        raise ValueError("regression info must be a YAML object")
    tests = info.get("regression_tests_info")
    if not isinstance(tests, list) or not tests:
        raise ValueError("regression info has no regression_tests_info entries")
    fixture_paths = []
    for index, test in enumerate(tests):
        if not isinstance(test, dict) or not isinstance(test.get("path"), str):
            raise ValueError(f"regression test entry {index} has no valid fixture path")
        relative_fixture = Path(test["path"])
        if relative_fixture.is_absolute() or ".." in relative_fixture.parts:
            raise ValueError(
                f"regression fixture path escapes source root: {relative_fixture}"
            )
        fixture = (root / relative_fixture).resolve(strict=False)
        try:
            fixture.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"regression fixture path escapes source root: {relative_fixture}"
            ) from exc
        if fixture.exists() and not fixture.is_file():
            raise ValueError(
                f"regression fixture is not a regular file: {relative_fixture}"
            )
        fixture_paths.append(fixture)
    return info_path, info, tuple(fixture_paths)


def validate_declared_fixtures(
    source_root: Path, rule_path: Path, rawdata: dict[str, Any]
) -> dict[str, Any]:
    """Check declared fixture paths before validating a converted target."""
    try:
        root = source_root.resolve(strict=True)
        _resolve_rule_path(root, rule_path)
        declaration = _declared_fixture_path(rawdata)
        if declaration is None:
            return {
                "status": "absent",
                "fixtures": [],
                "fingerprints": {"fixtures_sha256": _json_hash([])},
            }
        info_path, _info, fixture_paths = _load_regression_info(str(root), declaration)
        info = _info
        tests = info["regression_tests_info"]
        fixture_refs = []
        for test, fixture in zip(tests, fixture_paths, strict=True):
            relative = Path(test["path"])
            fixture_refs.append(
                {
                    "path": relative.as_posix(),
                    "format": test.get("type"),
                    "expected_count": test.get("match_count"),
                    "fingerprint": _sha256(fixture) if fixture.is_file() else None,
                    "preflight_status": "present" if fixture.is_file() else "missing",
                }
            )
        return {
            "status": "preflighted",
            "fixtures": fixture_refs,
            "fingerprints": {
                "regression_info_sha256": _sha256(info_path),
                "fixtures_sha256": _json_hash(fixture_refs),
            },
        }
    except Exception as exc:
        return {
            "status": "failed",
            "reason_code": "declared_fixture_missing_or_unsafe",
            "reason": str(exc),
            "fixtures": [
                {
                    "path": str(rawdata.get("regression_tests_path", "")),
                    "status": "failed",
                    "reason_code": "declared_fixture_missing_or_unsafe",
                    "fingerprint": None,
                    "scope": "unverified",
                }
            ],
            "fingerprints": {},
        }


def _run_evtx_fixture(
    fixture: Path,
    test: Mapping[str, Any],
    info: Mapping[str, Any],
    rawdata: Mapping[str, Any],
    binding: Mapping[str, Any] | None,
    compiled_rule: Rule | None,
) -> dict[str, Any]:
    expected = test.get("match_count")
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ValueError(
            "EVTX regression test requires a nonnegative integer match_count"
        )
    provider = test.get("provider")
    if not isinstance(provider, str) or not provider.strip():
        raise ValueError("EVTX regression test requires a provider")

    parsed_rule = rawdata.get("id")
    info_ids = {
        item.get("id")
        for item in info.get("rule_metadata", [])
        if isinstance(item, dict)
    }
    if parsed_rule not in info_ids:
        raise ValueError(
            "regression info rule_metadata does not identify this source rule"
        )

    fixture_sha = _sha256(fixture)
    target_providers = set((binding or {}).get("providers") or [])
    if target_providers and provider not in target_providers:
        return {
            "path": fixture.name,
            "format": "evtx",
            "status": "not_applicable",
            "reason_code": "fixture_provider_mismatch",
            "reason": f"declared provider {provider!r} is outside target providers {sorted(target_providers)!r}",
            "expected_count": expected,
            "actual_count": None,
            "evidence_refs": [],
            "fingerprint": fixture_sha,
            "scope": "fixture metadata identifies another provider; parser/query regression not asserted",
        }
    with tempfile.TemporaryDirectory(prefix="forensia-sigma-fixture-") as temp:
        case = Case.init(temp)
        raw_sha = fixture_sha
        ingest_evtx_file(case, fixture, raw_sha)
        with CaseDB(case) as db:
            inserted = normalize_evtx(case, db)
            if inserted < 1:
                raise ValueError("EVTX parser produced no normalized records")
            rows = db.execute(
                "SELECT json_extract_string(raw_json, '$.winlog.provider.name'), "
                "channel FROM evtx_events ORDER BY record_id"
            ).fetchall()
            providers = {row[0] for row in rows if row[0] is not None}
            if provider not in providers:
                if not target_providers:
                    return {
                        "path": fixture.name,
                        "format": "evtx",
                        "status": "not_applicable",
                        "reason_code": "fixture_provider_mismatch",
                        "reason": f"fixture providers {sorted(providers)!r} do not include declared provider {provider!r}",
                        "expected_count": expected,
                        "actual_count": None,
                        "evidence_refs": [],
                        "fingerprint": fixture_sha,
                        "info_fingerprint": _sha256(Path(info["_path"])),
                        "scope": "native EVTX parsed; declared provider absent",
                    }
                return {
                    "path": fixture.name,
                    "format": "evtx",
                    "status": "error",
                    "reason_code": "fixture_provider_mismatch",
                    "reason": f"target fixture provider {provider!r} is absent from parsed providers {sorted(providers)!r}",
                    "expected_count": expected,
                    "actual_count": None,
                    "evidence_refs": [],
                    "fingerprint": fixture_sha,
                    "info_fingerprint": _sha256(Path(info["_path"])),
                    "scope": "native EVTX parsed; target provider absent",
                }
            channels = {row[1] for row in rows if row[1] is not None}
            target_channels = set((binding or {}).get("channels") or [])
            if not target_channels:
                raise ValueError("converted target binding has no concrete channel")
            if not channels.intersection(target_channels):
                return {
                    "path": fixture.name,
                    "format": "evtx",
                    "status": "not_applicable",
                    "reason_code": "fixture_channel_mismatch",
                    "reason": f"fixture channels {sorted(channels)!r} do not include target channels {sorted(target_channels)!r}",
                    "expected_count": expected,
                    "actual_count": None,
                    "evidence_refs": [],
                    "fingerprint": fixture_sha,
                    "info_fingerprint": _sha256(Path(info["_path"])),
                    "scope": "native EVTX parsed; target channel absent",
                }

            if compiled_rule is None:
                raise ValueError(
                    "no generated Rule is available for applicable fixture validation"
                )

            refs: list[str] = []
            actual = 0
            for result_batch in iter_rule_row_batches(db, compiled_rule):
                findings = generate_findings(
                    compiled_rule,
                    result_batch,
                    first_ordinal=actual + 1,
                )
                for finding in findings:
                    for evidence in finding.evidence:
                        evidence_id = evidence.get("evidence_id")
                        if isinstance(evidence_id, str):
                            refs.append(evidence_id)
                actual += len(findings)
            _validate_match_count(expected, actual)
            if actual and len(refs) != actual:
                raise ValueError(
                    "matched findings did not preserve one Evidence reference each"
                )
            return {
                "path": fixture.name,
                "format": "evtx",
                "status": "passed",
                "expected_count": expected,
                "actual_count": actual,
                "evidence_refs": refs,
                "fingerprint": fixture_sha,
                "info_fingerprint": _sha256(Path(info["_path"])),
                "scope": "native EVTX parser, normalizer, compiled query, Finding Evidence references",
            }


def _semantic_contract() -> dict[str, Any]:
    """Check a small set of shared converter semantics once per build process.

    These examples exercise only supported converter mechanics. Their results never
    count as evidence that any source rule detects correctly.
    """
    checks: list[dict[str, Any]] = []
    examples = [
        (
            "numeric equality",
            {"EventID": 4688},
            "selection",
            [
                ("typed", 4688, None),
                ("wrong", 1102, None),
                ("null", None, None),
            ],
            ["typed"],
        ),
        (
            "literal LIKE escaping",
            {"EventID": 4688, "CommandLine|contains": "literal%_part"},
            "selection",
            [
                ("literal", 4688, "prefix literal%_part suffix"),
                ("wildcard", 4688, "prefix literalZZpart suffix"),
            ],
            ["literal"],
        ),
        (
            "case-sensitive text",
            {"EventID": 4688, "CommandLine|cased": "powershell.exe"},
            "selection",
            [
                ("same-case", 4688, "powershell.exe"),
                ("other-case", 4688, "PowerShell.exe"),
            ],
            ["same-case"],
        ),
        (
            "quoted literal",
            {"EventID": 4688, "CommandLine": "O'Brien"},
            "selection",
            [
                ("quoted", 4688, "O'Brien"),
                ("other", 4688, "OBrien"),
            ],
            ["quoted"],
        ),
        (
            "Sigma wildcard",
            {"EventID": 4688, "CommandLine": "powershell*"},
            "selection",
            [
                ("prefix", 4688, "powershell.exe -NoProfile"),
                ("middle", 4688, "x powershell.exe"),
            ],
            ["prefix"],
        ),
        (
            "NULL-safe negation",
            {"CommandLine|contains": "needle"},
            "not selection",
            [
                ("hit", 4688, "needle"),
                ("clean", 4688, "clean"),
                ("null", 4688, None),
            ],
            ["clean", "null"],
        ),
        (
            "OR branches",
            {"CommandLine|contains": "needle"},
            "event or selection",
            [
                ("event", 1102, "clean"),
                ("selection", 4688, "needle"),
                ("neither", 4688, "clean"),
            ],
            ["event", "selection"],
        ),
        (
            "field existence",
            {"EventID": 4688, "CommandLine|exists": True},
            "selection",
            [
                ("present", 4688, "x"),
                ("absent", 4688, None),
            ],
            ["present"],
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="forensia-sigma-contract-") as temp:
        case = Case.init(temp)
        with CaseDB(case) as db:
            for index, (label, selection, condition, rows, expected_ids) in enumerate(
                examples
            ):
                detection = (
                    {
                        "event": {"EventID": 4688},
                        "selection": selection,
                        "condition": "event and not selection",
                    }
                    if label == "NULL-safe negation"
                    else {
                        "event": {"EventID": 1102},
                        "selection": selection,
                        "condition": condition,
                    }
                    if label == "OR branches"
                    else {"selection": selection, "condition": condition}
                )
                data = {
                    "title": f"shared converter contract {index}",
                    "id": f"00000000-0000-4000-8000-{index:012d}",
                    "logsource": {"product": "windows", "service": "security"},
                    "detection": detection,
                }
                try:
                    targets = compile_sigma_targets(data)
                    target = next(
                        (
                            item
                            for item in targets
                            if item.status == "converted"
                            and item.target_binding.get("channels") == ["Security"]
                        ),
                        None,
                    )
                    if target is None or target.rule is None:
                        raise AssertionError(
                            "Security logsource did not produce an executable Security target"
                        )
                    rule = target.rule
                    db.execute("DELETE FROM evtx_events")
                    db.insert_many(
                        "INSERT INTO evtx_events "
                        "(evidence_id, source_file, channel, event_id, raw_json) "
                        "VALUES (?, 'contract', 'Security', ?, ?)",
                        [
                            (
                                evidence_id,
                                event_id,
                                json.dumps(
                                    {
                                        "winlog": {
                                            "channel": "Security",
                                            "provider": {
                                                "name": (
                                                    "Microsoft-Windows-Eventlog"
                                                    if event_id == 1102
                                                    else "Microsoft-Windows-Security-Auditing"
                                                )
                                            },
                                            "event_data": (
                                                {"CommandLine": command}
                                                if command is not None
                                                else {}
                                            ),
                                        }
                                    },
                                    ensure_ascii=False,
                                ),
                            )
                            for evidence_id, event_id, command in rows
                        ],
                    )
                    db.execute("EXPLAIN " + rule.query).fetchall()
                    actual_ids = sorted(
                        row[0] for row in db.execute(rule.query).fetchall()
                    )
                    if actual_ids != sorted(expected_ids):
                        raise AssertionError(
                            f"expected controlled contract rows {expected_ids}, got {actual_ids}"
                        )
                    checks.append({"name": label, "status": "passed"})
                except Exception as exc:  # validation reports a structured failure
                    checks.append(
                        {"name": label, "status": "failed", "reason": str(exc)}
                    )
            for service, channel, provider in (
                ("security", "Security", "Microsoft-Windows-Security-Auditing"),
                (
                    "sysmon",
                    "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-Sysmon",
                ),
            ):
                try:
                    data = {
                        "title": f"{service} logsource contract",
                        "id": f"10000000-0000-4000-8000-{len(checks):012d}",
                        "logsource": {"product": "windows", "service": service},
                        "detection": {
                            "selection": {"EventID": 1},
                            "condition": "selection",
                        },
                    }
                    target = next(
                        (
                            item
                            for item in compile_sigma_targets(data)
                            if item.target_key == service and item.status == "converted"
                        ),
                        None,
                    )
                    if target is None or target.rule is None:
                        raise AssertionError(f"{service} produced no executable target")
                    if target.target_binding.get("channels") != [channel]:
                        raise AssertionError(
                            f"{service} resolved to unexpected channel(s): {target.target_binding.get('channels')}"
                        )
                    if provider not in target.target_binding.get("providers", []):
                        raise AssertionError(
                            f"{service} resolved to unexpected provider(s): {target.target_binding.get('providers')}"
                        )
                    db.execute("EXPLAIN " + target.rule.query).fetchall()
                    db.execute(target.rule.query).fetchall()
                    checks.append({"name": f"{service} logsource", "status": "passed"})
                except Exception as exc:
                    checks.append(
                        {
                            "name": f"{service} logsource",
                            "status": "failed",
                            "reason": str(exc),
                        }
                    )
    failed = [item for item in checks if item["status"] != "passed"]
    return {
        "status": "failed" if failed else "passed",
        "checks": checks,
    }


@lru_cache(maxsize=1)
def semantic_contract() -> dict[str, Any]:
    """Return a process-cached shared semantic check, computed once per build."""
    return _semantic_contract()


def _validation_db() -> CaseDB:
    global _SQL_CASE_DB, _SQL_TEMP_DIR
    if _SQL_CASE_DB is None:
        _SQL_TEMP_DIR = tempfile.TemporaryDirectory(prefix="forensia-sigma-sql-")
        case = Case.init(_SQL_TEMP_DIR.name)
        _SQL_CASE_DB = CaseDB(case)
        # Empty rows check SQL/schema compatibility. Shared contract tests and
        # native fixtures separately check behavior.
    return _SQL_CASE_DB


def _sql_viability(compiled_rule: Rule) -> dict[str, Any]:
    db = _validation_db()
    db.execute("DELETE FROM evtx_events")
    explained = db.execute("EXPLAIN " + compiled_rule.query).fetchall()
    result_rows = db.execute(compiled_rule.query).fetchall()
    return {
        "status": "passed" if explained else "failed",
        "reason_code": "sql_explained_and_executed",
        "reason": "generated SQL was explained and executed against the native schema",
        "execution_scope": "schema_only; shared semantic contract carries behavior checks",
        "input_rows": int(db.execute("SELECT COUNT(*) FROM evtx_events").fetchone()[0]),
        "result_rows": len(result_rows),
    }


def validate_rule(
    source_root: Path,
    rule_path: Path,
    rawdata: dict[str, Any],
    compiled_rule: Rule | None,
    *,
    binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate generated SQL and fixtures for one converted target.

    Conversion support belongs to the converter. This result keeps SQL and fixture
    evidence separate so neither result can overwrite the other.
    """
    try:
        rule_file = _resolve_rule_path(source_root, rule_path)
        source_hash = _sha256(rule_file)
        binding_hash = _json_hash(binding or {})
        declaration = _declared_fixture_path(rawdata)
    except Exception as exc:
        error = {
            "status": "failed",
            "reason_code": "invalid_source_path",
            "reason": str(exc),
        }
        return {
            "sql_validation": error,
            "fixture": {**error, "status": "error", "fixtures": []},
            "fingerprints": {},
        }

    common = semantic_contract()
    fingerprints = {
        "rule_sha256": source_hash,
        "binding_sha256": binding_hash,
        "dependency_fingerprint_scope": "bundle.environment records build dependencies and converter/validator hashes; per-target fingerprints cover source, binding, and regression fixtures",
    }
    preflight = validate_declared_fixtures(source_root, rule_file, rawdata)
    fingerprints.update(preflight.get("fingerprints", {}))
    if preflight.get("status") == "failed":
        fixture_result: dict[str, Any] = {
            "status": "error",
            "reason_code": str(
                preflight.get("reason_code", "fixture_preflight_failed")
            ),
            "reason": str(preflight.get("reason", "declared fixture preflight failed")),
            "fixtures": preflight.get("fixtures", []),
        }
    elif declaration is None:
        fixture_result = {
            "status": "absent",
            "reason_code": "no_declared_fixtures",
            "reason": "source rule declares no regression fixture",
            "fixtures": [],
        }
    else:
        fixture_result = {"status": "error", "fixtures": []}

    if compiled_rule is None:
        sql_result = {
            "status": "failed",
            "reason_code": "generated_sql_missing",
            "reason": "converter did not produce an executable Rule for this target",
        }
    elif common["status"] != "passed":
        sql_result = {
            "status": "failed",
            "reason_code": "semantic_contract_failed",
            "reason": "one or more shared converter contract checks failed",
        }
    else:
        try:
            sql_result = _sql_viability(compiled_rule)
        except Exception as exc:
            sql_result = {
                "status": "failed",
                "reason_code": "sql_validation_failed",
                "reason": f"EXPLAIN or execution failed: {exc}",
            }

    info_path: Path | None = None
    info: dict[str, Any] = {}
    fixture_paths: tuple[Path, ...] = ()
    if declaration is not None and preflight.get("status") != "failed":
        try:
            info_path, info, fixture_paths = _load_regression_info(
                str(source_root.resolve(strict=True)), declaration
            )
        except Exception as exc:
            fixture_result = {
                "status": "error",
                "reason_code": "declared_fixture_missing_or_unsafe",
                "reason": str(exc),
                "fixtures": [],
            }

    if declaration is not None and info_path is not None:
        tests = info["regression_tests_info"]
        rule_id = rawdata.get("id")
        metadata_ids = {
            entry.get("id")
            for entry in info.get("rule_metadata", [])
            if isinstance(entry, dict)
        }
        info_hash = _sha256(info_path)
        outcomes: list[str] = []
        fixture_rows: list[dict[str, Any]] = []
        if rule_id not in metadata_ids:
            fixture_rows.append(
                {
                    "path": declaration,
                    "format": "unknown",
                    "status": "error",
                    "reason_code": "fixture_rule_binding_unresolved",
                    "reason": "regression info rule_metadata does not identify this source rule",
                    "fingerprint": None,
                    "scope": "unverified",
                }
            )
            outcomes.append("error")
        else:
            for index, (test, fixture_path) in enumerate(
                zip(tests, fixture_paths, strict=True)
            ):
                path_value = test.get("path") if isinstance(test, dict) else None
                kind = test.get("type") if isinstance(test, dict) else None
                fixture_hash = _sha256(fixture_path) if fixture_path.is_file() else None
                if (
                    not isinstance(test, dict)
                    or not isinstance(path_value, str)
                    or not path_value
                ):
                    fixture_rows.append(
                        {
                            "path": declaration,
                            "format": str(kind or "unknown"),
                            "status": "error",
                            "reason_code": "invalid_fixture_metadata",
                            "reason": f"regression test entry {index} has invalid metadata",
                            "fingerprint": fixture_hash,
                            "info_fingerprint": info_hash,
                            "scope": "unverified",
                        }
                    )
                    outcomes.append("error")
                    continue

                target_providers = set((binding or {}).get("providers") or [])
                target_channels = set((binding or {}).get("channels") or [])
                declared_provider = test.get("provider")
                declared_channels_raw = test.get("channels", test.get("channel"))
                declared_channels = (
                    {declared_channels_raw}
                    if isinstance(declared_channels_raw, str)
                    else set(declared_channels_raw or [])
                )
                unrelated_provider = (
                    bool(target_providers)
                    and isinstance(declared_provider, str)
                    and declared_provider not in target_providers
                )
                unrelated_channel = (
                    bool(target_channels)
                    and bool(declared_channels)
                    and not declared_channels.intersection(target_channels)
                )
                if unrelated_provider or unrelated_channel:
                    fixture_rows.append(
                        {
                            "path": path_value,
                            "format": str(kind or "unknown"),
                            "status": "not_applicable",
                            "reason_code": (
                                "fixture_provider_mismatch"
                                if unrelated_provider
                                else "fixture_channel_mismatch"
                            ),
                            "reason": "declared fixture metadata identifies telemetry outside this target",
                            "expected_count": test.get("match_count"),
                            "actual_count": None,
                            "evidence_refs": [],
                            "fingerprint": fixture_hash,
                            "info_fingerprint": info_hash,
                            "scope": "fixture metadata only; parser/query regression not asserted",
                        }
                    )
                    outcomes.append("not_applicable")
                    continue
                if not fixture_path.is_file():
                    fixture_rows.append(
                        {
                            "path": path_value,
                            "format": str(kind or "unknown"),
                            "status": "error",
                            "reason_code": "declared_fixture_missing",
                            "reason": "applicable or unclassified declared fixture file is missing",
                            "expected_count": test.get("match_count"),
                            "actual_count": None,
                            "evidence_refs": [],
                            "fingerprint": None,
                            "info_fingerprint": info_hash,
                            "scope": "fixture file unavailable; query regression not asserted",
                        }
                    )
                    outcomes.append("error")
                    continue

                unresolved = next(
                    (
                        (key, scope)
                        for key in ("pipeline", "filter")
                        if (scope := test.get(key, info.get(key)))
                        and dict(binding or {}).get(f"resolved_fixture_{key}") != scope
                    ),
                    None,
                )
                try:
                    if unresolved:
                        key, scope = unresolved
                        raise ValueError(
                            f"declared fixture {key} cannot be reproduced: {scope}"
                        )
                    if kind != "evtx":
                        raise ValueError(
                            f"unsupported declared fixture format: {kind!r}"
                        )
                    result = _run_evtx_fixture(
                        fixture_path,
                        test,
                        {**info, "_path": str(info_path)},
                        rawdata,
                        binding,
                        compiled_rule,
                    )
                    result["path"] = path_value
                    result["info_fingerprint"] = info_hash
                    if result["status"] == "passed":
                        result["reason_code"] = "expected_count_and_evidence_match"
                    fixture_rows.append(result)
                    outcomes.append(str(result["status"]))
                except Exception as exc:
                    status = (
                        "mismatch"
                        if isinstance(exc, _ExpectedCountMismatch)
                        else "error"
                    )
                    fixture_rows.append(
                        {
                            "path": path_value,
                            "format": str(kind or "unknown"),
                            "status": status,
                            "reason_code": (
                                "fixture_count_mismatch"
                                if status == "mismatch"
                                else "fixture_validation_failed"
                            ),
                            "reason": str(exc),
                            "expected_count": test.get("match_count"),
                            "actual_count": getattr(exc, "actual", None),
                            "evidence_refs": [],
                            "fingerprint": fixture_hash,
                            "info_fingerprint": info_hash,
                            "scope": "native EVTX validation attempted",
                        }
                    )
                    outcomes.append(status)

        fingerprints["fixtures_sha256"] = _json_hash(
            [
                {
                    "path": item.get("path"),
                    "fingerprint": item.get("fingerprint"),
                    "info_fingerprint": item.get("info_fingerprint"),
                }
                for item in fixture_rows
            ]
        )
        if "error" in outcomes:
            fixture_result = {
                "status": "error",
                "reason_code": "fixture_validation_failed",
                "reason": "one or more declared fixtures could not be validated",
                "fixtures": fixture_rows,
            }
        elif "mismatch" in outcomes:
            fixture_result = {
                "status": "mismatch",
                "reason_code": "fixture_count_mismatch",
                "reason": "an applicable fixture did not match its declared expected count",
                "fixtures": fixture_rows,
            }
        elif "passed" in outcomes:
            fixture_result = {
                "status": "passed",
                "reason_code": "fixtures_matched",
                "reason": "applicable native EVTX fixtures matched exact counts and retained Evidence references",
                "fixtures": fixture_rows,
            }
        else:
            fixture_result = {
                "status": "not_applicable",
                "reason_code": "no_fixture_matches_target",
                "reason": "declared fixtures contain no events for this target provider/channel",
                "fixtures": fixture_rows,
            }

    return {
        "sql_validation": sql_result,
        "fixture": fixture_result,
        "fingerprints": fingerprints,
    }
