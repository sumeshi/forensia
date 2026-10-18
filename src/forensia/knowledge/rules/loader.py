from __future__ import annotations

import hashlib
from functools import cache
from pathlib import Path

import yaml

from forensia.knowledge.resources import rules_dir, schema_dir
from forensia.knowledge.rules.models import Rule
from forensia.knowledge.sigma_bundle import binding_admitted, load_sigma_bundle


def _expand_rule_query(rule: Rule) -> Rule:
    """Expand catalog SQL placeholders ({{catalog_exe_sql:...}}) in a rule's query."""
    from forensia.knowledge.catalog import expand_catalog_sql_placeholders

    rule.query = expand_catalog_sql_placeholders(rule.query)
    return rule


@cache
def _cached_rule_map(build_id: str) -> dict[str, Rule]:
    """Build the cached mapping of rule ID to executable Rule."""
    rules = load_rules()
    return {rule.id: rule for rule in rules}


def _get_rule_cache() -> dict[str, Rule]:
    return _cached_rule_map(load_sigma_bundle()["build_id"])


def load_rule_by_id(rule_id: str) -> Rule | None:
    """Load a rule by ID from the process-local rule mapping."""
    cache = _get_rule_cache()
    return cache.get(rule_id)


def load_rules() -> list[Rule]:
    """Load the installed SQL rules and admitted Sigma bundle as one set."""
    sql_rules = load_rules_from_dir(rules_dir())
    bundle = load_sigma_bundle()
    sigma_rules = [
        Rule.model_validate(binding["rule"])
        for binding in bundle["bindings"]
        if binding_admitted(binding)
    ]
    rules = [*sql_rules, *sigma_rules]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"Duplicate executable rule ID: {rule.id}")
        seen.add(rule.id)
    return rules


def load_rules_from_dir(directory: str | Path) -> list[Rule]:
    """Load SQL rule declarations from a directory.

    This generic loader remains available for extension directories. Sigma rules are loaded only from the validated executable bundle.
    """
    directory = Path(directory)
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for path in sorted(directory.rglob("*.yaml")):
        content = path.read_bytes()
        data = yaml.safe_load(content)
        if isinstance(data, dict) and str(data.get("kind") or "").startswith(
            "allowlist"
        ):
            continue
        if data:
            try:
                if "logsource" in data or "detection" in data or "correlation" in data:
                    raise ValueError(
                        "Sigma declarations are build inputs; runtime loads only sigma_bundle.json"
                    )
                rule = _expand_rule_query(Rule.model_validate(data))
            except Exception as exc:
                raise ValueError(f"Invalid rule {path}: {exc}") from exc
            rule.definition_sha256 = hashlib.sha256(content).hexdigest()
            if rule.id in seen_ids:
                raise ValueError(f"Duplicate rule ID {rule.id}: {path}")
            seen_ids.add(rule.id)
            rules.append(rule)
    return rules


def detect_artifact_families(db) -> set[str]:
    """Detect which artifact families are present in the case data.

    Queries prefetch_executions and mft_entries for patterns defined in
    dfir_ioc_catalog.yaml (cloud sync executables, mailbox data files, etc.).
    Returns a set of family names (e.g. {'cloud_sync', 'mailbox', 'mft_user_files'}).
    """
    families: set[str] = set()
    ioc_path = schema_dir() / "dfir_ioc_catalog.yaml"
    if not ioc_path.exists():
        return families
    ioc = yaml.safe_load(ioc_path.read_text(encoding="utf-8")) or {}

    if _has_table(db, "prefetch_executions"):
        cloud_sync = ioc.get("cloud_sync_artifacts", [])
        prefetch_like: list[str] = []
        for artifact in cloud_sync:
            for name in artifact.get("prefetch_names") or []:
                pattern = name.replace("*", "%").lower()
                if pattern and not pattern.startswith("%"):
                    pattern = f"%{pattern}"
                prefetch_like.append(pattern)
        if prefetch_like:
            clauses = " OR ".join(
                "LOWER(executable_name) LIKE ?" for _ in prefetch_like
            )
            params = [p.lower() for p in prefetch_like]
            row = db.execute(
                f"SELECT COUNT(*) FROM prefetch_executions WHERE {clauses}",
                params,
            ).fetchone()
            if row and row[0] > 0:
                families.add("cloud_sync")

        email_artifacts = ioc.get("email_artifacts", [])
        email_prefetch: list[str] = []
        for artifact in email_artifacts:
            for name in artifact.get("prefetch_names") or []:
                pattern = name.replace("*", "%").lower()
                if pattern and not pattern.startswith("%"):
                    pattern = f"%{pattern}"
                email_prefetch.append(pattern)
        if email_prefetch:
            clauses = " OR ".join(
                "LOWER(executable_name) LIKE ?" for _ in email_prefetch
            )
            params = [p.lower() for p in email_prefetch]
            row = db.execute(
                f"SELECT COUNT(*) FROM prefetch_executions WHERE {clauses}",
                params,
            ).fetchone()
            if row and row[0] > 0:
                families.add("mailbox")

    if _has_table(db, "mft_entries"):
        email_artifacts = ioc.get("email_artifacts", [])
        ext_patterns: set[str] = set()
        for artifact in email_artifacts:
            for data_file in artifact.get("data_files") or []:
                ext = Path(data_file).suffix.lower()
                if ext:
                    ext_patterns.add(ext)
        if ext_patterns:
            clauses = " OR ".join("LOWER(file_name) LIKE ?" for _ in ext_patterns)
            params = [f"%{ext}" for ext in ext_patterns]
            row = db.execute(
                f"SELECT COUNT(*) FROM mft_entries WHERE {clauses}",
                params,
            ).fetchone()
            if row and row[0] > 0:
                families.add("mailbox")

        row = db.execute(
            "SELECT COUNT(*) FROM mft_entries WHERE LOWER(file_path) LIKE '%/users/%'"
        ).fetchone()
        if row and row[0] > 0:
            families.add("mft_user_files")

        row = db.execute("SELECT COUNT(*) FROM mft_entries").fetchone()
        if row and row[0] > 0:
            families.add("mft_filesystem")

    if _has_table(db, "registry_artifacts"):
        row = db.execute("SELECT COUNT(*) FROM registry_artifacts").fetchone()
        if row and row[0] > 0:
            families.add("registry")

    if _has_table(db, "prefetch_executions"):
        row = db.execute("SELECT COUNT(*) FROM prefetch_executions").fetchone()
        if row and row[0] > 0:
            families.add("prefetch")

    return families


def _has_table(db, table_name: str) -> bool:
    """Check whether a table exists in the database."""
    try:
        db.execute(f"SELECT 1 FROM {table_name} LIMIT 0")
        return True
    except Exception:
        return False
