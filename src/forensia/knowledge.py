from __future__ import annotations

import fnmatch
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_SCHEMA_DIR = Path(__file__).parent / "rulepacks" / "_schema"


# ── DFIR YAML bulk loader ──────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_dfir_yamls() -> dict[str, Any]:
    """Load all DFIR YAML schemas from _schema/ directory with caching."""

    def _load_yaml(name: str) -> dict:
        path = _SCHEMA_DIR / name
        if not path.exists():
            return {}
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    return {
        "evtx_events": _load_yaml("evtx_events.yaml"),
        "logon_types": _load_yaml("logon_types.yaml"),
        "event_ids": _load_yaml("event_ids.yaml"),
        "app_catalog": _load_yaml("app_catalog.yaml"),
        "fp_rules": _load_yaml("false_positive_rules.yaml"),
        "artifact_inference": _load_yaml("artifact_inference.yaml"),
        "dfir_ioc_catalog": _load_yaml("dfir_ioc_catalog.yaml"),
    }


# ── Event ID hints ─────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_event_id_hints() -> dict[int, dict[str, Any]]:
    """Load event ID hints from _schema/event_ids.yaml keyed by integer event ID."""
    path = _SCHEMA_DIR / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    events: dict[int, dict[str, Any]] = {}
    raw_events = data.get("events") if isinstance(data, dict) else {}
    if not isinstance(raw_events, dict):
        return {}
    for key, value in raw_events.items():
        try:
            event_id = int(key)
        except TypeError, ValueError:
            continue
        if isinstance(value, dict):
            events[event_id] = value
    return events


# ── Benign context rules ───────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_benign_context_rules() -> list[dict[str, Any]]:
    """Load benign-context rules from false_positive_rules.yaml."""
    yamls = load_dfir_yamls()
    fp_rules = yamls.get("fp_rules", {})
    if isinstance(fp_rules, dict):
        rules = fp_rules.get("benign_context_rules") or []
        return list(rules) if isinstance(rules, list) else []
    return []


@lru_cache(maxsize=1)
def load_finding_benign_context_rules() -> list[dict[str, Any]]:
    """Load finding-level benign context rules from false_positive_rules.yaml."""
    fp_path = _SCHEMA_DIR / "false_positive_rules.yaml"
    if not fp_path.exists():
        return []
    try:
        data = yaml.safe_load(fp_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    return data.get("finding_benign_context") or []


# ── Schema hints (table-aware) ─────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_schema_hints() -> dict[str, dict[str, Any]]:
    """Load schema hints from rulepacks/_schema/*.yaml for planner guidance."""
    hints: dict[str, dict[str, Any]] = {}
    if not _SCHEMA_DIR.exists():
        return hints
    for path in _SCHEMA_DIR.glob("*.yaml"):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data and isinstance(data, dict):
                table_name = data.get("table")
                if table_name:
                    hints[str(table_name)] = data
        except Exception:
            continue
    return hints


# ── Question routing ───────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_question_routing_raw() -> dict[str, Any]:
    """Load raw question-routing schema from _schema/question_routing.yaml."""
    routing_path = _SCHEMA_DIR / "question_routing.yaml"
    try:
        raw = yaml.safe_load(routing_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return raw
    except Exception:
        pass
    return {}


# ── IOC catalog ────────────────────────────────────────────────────────────


def _sql_like_any(column: str, *patterns: str) -> str:
    """Build a LOWER(col) LIKE any pattern OR chain."""
    clauses = [f"LOWER({column}) LIKE '{p.lower()}'" for p in patterns]
    return " OR ".join(clauses) if clauses else "FALSE"


@lru_cache(maxsize=1)
def ioc_catalog() -> dict[str, Any]:
    """Load IOC catalog from dfir_ioc_catalog.yaml."""
    path = _SCHEMA_DIR / "dfir_ioc_catalog.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _catalog_entries(section: str) -> list[dict[str, Any]]:
    entries = ioc_catalog().get(section) or []
    return [entry for entry in entries if isinstance(entry, dict)]


def catalog_exe_globs(*sections: str) -> tuple[str, ...]:
    """Lowercase executable glob patterns from the named catalog sections."""
    globs: list[str] = []
    for section in sections:
        for entry in _catalog_entries(section):
            for pattern in entry.get("exe_patterns") or []:
                lowered = str(pattern).strip().lower()
                if lowered and lowered not in globs:
                    globs.append(lowered)
    return tuple(globs)


def catalog_names(section: str, key: str = "name") -> tuple[str, ...]:
    names: list[str] = []
    for entry in _catalog_entries(section):
        value = str(entry.get(key) or "").strip()
        if value and value not in names:
            names.append(value)
    return tuple(names)


def catalog_path_terms(*sections: str) -> tuple[str, ...]:
    """Significant lowercase path fragments from catalog paths/mft_patterns."""
    terms: list[str] = []
    for section in sections:
        for entry in _catalog_entries(section):
            for raw in list(entry.get("paths") or []) + list(
                entry.get("mft_patterns") or []
            ):
                cleaned = (
                    re.sub(r"%[^%]+%", "", str(raw))
                    .replace("\\", "/")
                    .strip("/ ")
                    .lower()
                )
                if len(cleaned) >= 4 and cleaned not in terms:
                    terms.append(cleaned)
    return tuple(terms)


def catalog_artifact_names(*sections: str) -> tuple[str, ...]:
    names: list[str] = []
    for section in sections:
        for entry in _catalog_entries(section):
            for raw in entry.get("artifact_names") or []:
                lowered = str(raw).strip().lower()
                if lowered and lowered not in names:
                    names.append(lowered)
            tool = str(entry.get("name") or "").strip().lower()
            if tool and f"{tool}.lnk" not in names:
                names.append(f"{tool}.lnk")
    return tuple(names)


def exe_glob_sql(column: str, globs: tuple[str, ...]) -> str:
    """OR-joined LIKE predicate for executable names from glob patterns."""
    if not globs:
        return "FALSE"
    return _sql_like_any(column, *[glob.replace("*", "%") for glob in globs])


def matches_exe_globs(name: str, globs: tuple[str, ...]) -> bool:
    """Check if a name matches any of the executable glob patterns."""
    lowered = str(name or "").strip().lower()
    return any(fnmatch.fnmatch(lowered, glob) for glob in globs)


# ── Event class definitions ────────────────────────────────────────────────


@lru_cache(maxsize=1)
def load_event_class_definitions() -> dict[str, dict[str, Any]]:
    """Load event_class groupings from event_ids.yaml."""
    path = _SCHEMA_DIR / "event_ids.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    classes = data.get("event_classes") if isinstance(data, dict) else {}
    if not isinstance(classes, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for class_name, class_def in classes.items():
        if not isinstance(class_def, dict):
            continue
        event_ids = class_def.get("event_ids", [])
        if isinstance(event_ids, list) and event_ids:
            entry: dict[str, Any] = {"event_ids": [int(eid) for eid in event_ids]}
            logon_types = class_def.get("logon_types")
            if logon_types and isinstance(logon_types, list):
                entry["logon_types"] = [int(lt) for lt in logon_types]
            result[class_name] = entry
    return result


# ── Cache management ───────────────────────────────────────────────────────


def clear_caches() -> None:
    """Clear all cached schema loads. Call in test teardowns to avoid cross-test leakage."""
    load_dfir_yamls.cache_clear()
    load_event_id_hints.cache_clear()
    load_benign_context_rules.cache_clear()
    load_finding_benign_context_rules.cache_clear()
    load_schema_hints.cache_clear()
    load_question_routing_raw.cache_clear()
    ioc_catalog.cache_clear()
    load_event_class_definitions.cache_clear()
