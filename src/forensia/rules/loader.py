from __future__ import annotations

from functools import cache
from pathlib import Path

import yaml

from forensia.rules.models import Rule, RulePackMetadata


def _expand_rule_query(rule: Rule) -> Rule:
    """Expand catalog SQL placeholders ({{catalog_exe_sql:...}}) in a rule's query."""
    from forensia.knowledge.catalog import expand_catalog_sql_placeholders

    rule.query = expand_catalog_sql_placeholders(rule.query)
    return rule


# REFACTOR-21: Cache id → Rule mapping for O(1) lookup
@cache
def _get_rule_cache() -> dict[str, Rule]:
    """Build and cache a mapping of rule_id to Rule objects.

    Called once on first use, then cached indefinitely.
    """
    rules = _load_all_rules()
    return {rule.id: rule for rule in rules}


def _load_all_rules() -> list[Rule]:
    """Internal function to load all rules without caching."""
    rulepacks_dir = Path(__file__).parent.parent / "rulepacks"
    rules: list[Rule] = []
    for path in sorted(rulepacks_dir.rglob("*.yaml")):
        if "_schema" in path.parts:
            continue
        if path.name == "pack.yaml":
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and str(data.get("kind") or "").startswith(
            "allowlist"
        ):
            continue
        if data:
            rule = Rule.model_validate(data)
            _expand_rule_query(rule)
            rules.append(rule)
    return rules


def load_rule_by_id(rule_id: str) -> Rule | None:
    """Load a single rule by its ID from the cached rule mapping (DESIGN-A5).

    Rules are loaded once from the packaged rulepacks/ directory and cached.
    """
    cache = _get_rule_cache()
    return cache.get(rule_id)


def load_rules_from_dir(
    directory: str | Path, profile_path: str | Path | None = None
) -> list[Rule]:
    """Load Rule objects from YAML files, optionally filtered by a profile.

    Profile filtering supports both rulepack directory scoping and explicit
    rule_id allowlists. Files in _schema directories and allowlist-kind YAML
    files are always skipped regardless of profile settings.
    """
    from forensia.rules.models import Rule

    directory = Path(directory)
    allowed_paths: set[str] | None = None
    allowed_rule_ids: set[str] | None = None
    if profile_path:
        profile = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8")) or {}
        packs = profile.get("rulepacks") or []
        allowed_paths = {str(pack).strip("/") for pack in packs if str(pack).strip("/")}
        rule_ids = profile.get("rule_ids")
        if rule_ids:
            allowed_rule_ids = {
                str(rule_id).strip() for rule_id in rule_ids if str(rule_id).strip()
            }

    rules: list[Rule] = []
    for path in sorted(directory.rglob("*.yaml")):
        if "_schema" in path.parts:
            continue
        if path.name == "pack.yaml":
            continue
        rel_path = str(path.relative_to(directory))
        rel_parent = str(path.parent.relative_to(directory))
        if allowed_paths is not None:
            matched = False
            for allowed in allowed_paths:
                if rel_path == allowed or rel_path.startswith(f"{allowed}/"):
                    matched = True
                    break
                if rel_parent == allowed or rel_parent.startswith(f"{allowed}/"):
                    matched = True
                    break
            if not matched:
                continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and str(data.get("kind") or "").startswith(
            "allowlist"
        ):
            continue
        if data:
            rule = Rule.model_validate(data)
            _expand_rule_query(rule)
            if allowed_rule_ids is not None and rule.id not in allowed_rule_ids:
                continue
            rules.append(rule)
    return rules


def load_all_pack_metadata() -> dict[str, RulePackMetadata]:
    """Load pack.yaml metadata from all rulepack directories.

    Returns a mapping of pack_id → RulePackMetadata.
    """
    rulepacks_dir = Path(__file__).parent.parent / "rulepacks"
    packs: dict[str, RulePackMetadata] = {}
    for pack_dir in sorted(rulepacks_dir.iterdir()):
        if not pack_dir.is_dir() or pack_dir.name.startswith("_"):
            continue
        pack_yaml = pack_dir / "pack.yaml"
        if not pack_yaml.exists():
            continue
        data = yaml.safe_load(pack_yaml.read_text(encoding="utf-8"))
        if data:
            meta = RulePackMetadata.model_validate(data)
            packs[meta.id] = meta
    return packs


@cache
def _get_pack_map() -> dict[str, str]:
    """Build a mapping of rule_id → pack_id from the directory structure.

    Cached indefinitely after first call.
    """
    rulepacks_dir = Path(__file__).parent.parent / "rulepacks"
    pack_map: dict[str, str] = {}
    for pack_dir in sorted(rulepacks_dir.iterdir()):
        if not pack_dir.is_dir() or pack_dir.name.startswith("_"):
            continue
        pack_id = pack_dir.name
        for path in pack_dir.rglob("*.yaml"):
            if "_schema" in path.parts or path.name == "pack.yaml":
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and not str(data.get("kind") or "").startswith(
                "allowlist"
            ):
                rule_id = data.get("id")
                if rule_id:
                    pack_map[str(rule_id)] = pack_id
    return pack_map


def detect_artifact_families(db) -> set[str]:
    """Detect which artifact families are present in the case data.

    Queries prefetch_executions and mft_entries for patterns defined in
    dfir_ioc_catalog.yaml (cloud sync executables, mailbox data files, etc.).
    Returns a set of family names (e.g. {'cloud_sync', 'mailbox', 'mft_user_files'}).
    """
    families: set[str] = set()
    rulepacks_dir = Path(__file__).parent.parent / "rulepacks"
    ioc_path = rulepacks_dir / "_schema" / "dfir_ioc_catalog.yaml"
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

    return families


def resolve_active_packs(
    profile_path: str | Path | None, db, auto_rulepacks: bool = True
) -> set[str]:
    """Resolve the set of active rulepack IDs.

    Starts with the profile's declared rulepacks, then auto-enables packs whose
    applies_when.artifact_families intersect detected artifact families.
    """
    packs: set[str] = set()
    if profile_path:
        profile = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8")) or {}
        for pack in profile.get("rulepacks") or []:
            pack_id = str(pack).strip().strip("/")
            if pack_id:
                packs.add(pack_id)
    if auto_rulepacks:
        all_meta = load_all_pack_metadata()
        if all_meta:
            detected = detect_artifact_families(db)
            for pack_id, meta in all_meta.items():
                if pack_id in packs:
                    continue
                required = (
                    meta.applies_when.get("artifact_families")
                    if meta.applies_when
                    else None
                )
                if required and detected & set(required):
                    packs.add(pack_id)
    return packs


def _has_table(db, table_name: str) -> bool:
    """Check whether a table exists in the database."""
    try:
        db.execute(f"SELECT 1 FROM {table_name} LIMIT 0")
        return True
    except Exception:
        return False
