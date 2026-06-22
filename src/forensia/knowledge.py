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


def _sql_in_any(column: str, values: tuple[str, ...]) -> str:
    if not values:
        return "FALSE"
    literals = ", ".join(f"'{value.lower()}'" for value in values if value)
    return f"LOWER(COALESCE({column}, '')) IN ({literals})" if literals else "FALSE"


def _sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


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


def catalog_entries(section: str) -> list[dict[str, Any]]:
    """Catalog entries for a named dfir_ioc_catalog.yaml section."""
    return list(_catalog_entries(section))


def catalog_values(entry: dict[str, Any], *keys: str) -> list[str]:
    """String values from one catalog entry, preserving key order."""
    values: list[str] = []
    for key in keys:
        raw = entry.get(key)
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            text = str(item or "").strip()
            if text:
                values.append(text)
    return values


def catalog_label(entry: dict[str, Any], *keys: str) -> str:
    """Human label for one catalog entry, preferring explicit display_name."""
    for key in ("display_name", *keys, "name", "service", "client"):
        value = str(entry.get(key) or "").strip()
        if value:
            return value
    return ""


def catalog_marker(value: str) -> str:
    """Normalize a catalog pattern into a casefolded text marker."""
    text = str(value or "").strip().casefold().replace("\\", "/")
    text = re.sub(r"%[^%]+%", "", text)
    text = text.replace("*", "").strip("/ ")
    return text


def _unique_text(values: list[str] | tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for value in values:
        text = str(value or "").strip().casefold()
        if text and text not in out:
            out.append(text)
    return out


def _glob_pattern_markers(pattern: str) -> list[str]:
    text = str(pattern or "").strip().casefold().replace("\\", "/")
    if not text:
        return []
    if "*" not in text:
        marker = catalog_marker(text)
        return [marker] if marker else []
    markers: list[str] = []
    for part in text.split("*"):
        marker = catalog_marker(part)
        if marker and len(marker) >= 3:
            markers.append(marker)
    if text.startswith("*."):
        markers.append(text[1:])
    return _unique_text(markers)


def catalog_marker_map(
    section: str,
    label_key: str,
    *value_keys: str,
) -> dict[str, tuple[str, ...]]:
    """Label -> text markers for classifying rows against catalog entries."""
    marker_map: dict[str, tuple[str, ...]] = {}
    for entry in _catalog_entries(section):
        label = catalog_label(entry, label_key)
        if not label:
            continue
        markers: list[str] = [label]
        for raw in catalog_values(entry, label_key, *value_keys):
            if "*" in raw:
                markers.extend(_glob_pattern_markers(raw))
                continue
            marker = catalog_marker(raw)
            if marker:
                markers.append(marker)
            basename = marker.rstrip("/").rsplit("/", 1)[-1] if marker else ""
            if "." in basename:
                markers.append(basename)
        marker_map[label] = tuple(_unique_text(markers))
    return marker_map


def catalog_file_patterns(section: str, *keys: str) -> tuple[str, ...]:
    """Lowercase SQL LIKE patterns derived from catalog file/path-like values."""
    patterns: list[str] = []
    for entry in _catalog_entries(section):
        for raw in catalog_values(entry, *keys):
            text = str(raw or "").strip().replace("\\", "/")
            if "/" in text:
                basename = text.rstrip("/").rsplit("/", 1)[-1]
                if "." in basename:
                    patterns.append(f"%{basename.lower()}")
                continue
            patterns.append(text.lower().replace("*", "%"))
    return tuple(_unique_text(patterns))


def catalog_data_file_extensions(section: str) -> tuple[str, ...]:
    """File extensions implied by catalog data_files globs."""
    extensions: list[str] = []
    for pattern in catalog_file_patterns(section, "data_files"):
        lowered = pattern.strip().lower()
        if lowered.startswith("%."):
            extensions.append(lowered[2:])
    return tuple(_unique_text(extensions))


def catalog_path_patterns(*sections: str) -> tuple[str, ...]:
    """SQL LIKE patterns for catalog path fragments, with slash/backslash forms."""
    patterns: list[str] = []
    for term in catalog_path_terms(*sections):
        patterns.append(f"%{term}%")
        if "/" in term:
            backslash_term = term.replace("/", "\\")
            patterns.append(f"%{backslash_term}%")
    return tuple(_unique_text(patterns))


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
    """Significant lowercase path fragments from catalog path-like fields."""
    terms: list[str] = []
    for section in sections:
        for entry in _catalog_entries(section):
            path_values = []
            for key in ("paths", "mft_patterns", "version_sources"):
                path_values.extend(entry.get(key) or [])
            for raw in path_values:
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


def catalog_like_sql(column: str, patterns: tuple[str, ...]) -> str:
    """OR-joined LIKE predicate for already-normalized catalog patterns."""
    return _sql_like_any(column, *patterns) if patterns else "FALSE"


def catalog_path_sql(column: str, *sections: str) -> str:
    """OR-joined LIKE predicate for path fragments from catalog sections."""
    return catalog_like_sql(column, catalog_path_patterns(*sections))


def catalog_extension_sql(column: str, section: str) -> str:
    """IN predicate for extensions from a catalog section's data_files."""
    return _sql_in_any(column, catalog_data_file_extensions(section))


def catalog_label_case_sql(
    section: str,
    label_key: str,
    value_keys: tuple[str, ...],
    columns: tuple[str, ...],
    alias: str = "",
) -> str:
    """CASE expression that classifies rows against a catalog marker map."""
    if not columns:
        return f"{_sql_literal('')} AS {alias}" if alias else _sql_literal("")
    whens: list[str] = []
    for label, markers in catalog_marker_map(section, label_key, *value_keys).items():
        checks: list[str] = []
        for column in columns:
            for marker in markers:
                if marker:
                    checks.append(
                        f"LOWER(COALESCE({column}, '')) LIKE "
                        f"{_sql_literal('%' + marker.lower() + '%')}"
                    )
        if checks:
            whens.append(f"WHEN {' OR '.join(checks)} THEN {_sql_literal(label)}")
    expr = "CASE " + " ".join(whens) + f" ELSE {_sql_literal('')} END"
    return f"{expr} AS {alias}" if alias else expr


def exe_glob_sql(column: str, globs: tuple[str, ...]) -> str:
    """OR-joined LIKE predicate for executable names from glob patterns."""
    if not globs:
        return "FALSE"
    return _sql_like_any(column, *[glob.replace("*", "%") for glob in globs])


_CATALOG_SQL_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*catalog_(?P<kind>[a-z_]+):(?P<body>[^{}]+?)\s*\}\}"
)


def expand_catalog_sql_placeholders(sql: str) -> str:
    """Expand catalog SQL placeholders used by declarative evidence chains.

    Supported forms:
    - ``{{catalog_exe_sql:section:column}}``
    - ``{{catalog_path_sql:section:column}}``
    - ``{{catalog_file_sql:section:key1,key2:column}}``
    - ``{{catalog_data_file_sql:section:column}}``
    - ``{{catalog_extension_sql:section:column}}``
    - ``{{catalog_artifact_sql:section:column}}``
    - ``{{catalog_label_sql:section:label_key:value_keys:columns:alias}}``
    """

    def repl(match: re.Match[str]) -> str:
        kind = match.group("kind")
        parts = [part.strip() for part in match.group("body").split(":")]
        if kind == "exe_sql" and len(parts) == 2:
            section, column = parts
            return exe_glob_sql(column, catalog_exe_globs(section))
        if kind == "path_sql" and len(parts) == 2:
            section, column = parts
            return catalog_path_sql(column, section)
        if kind == "file_sql" and len(parts) == 3:
            section, keys_text, column = parts
            keys = [key.strip() for key in keys_text.split(",") if key.strip()]
            return catalog_like_sql(column, catalog_file_patterns(section, *keys))
        if kind == "data_file_sql" and len(parts) == 2:
            section, column = parts
            return catalog_like_sql(
                column, catalog_file_patterns(section, "data_files")
            )
        if kind == "extension_sql" and len(parts) == 2:
            section, column = parts
            return catalog_extension_sql(column, section)
        if kind == "artifact_sql" and len(parts) == 2:
            section, column = parts
            return catalog_like_sql(column, catalog_artifact_names(section))
        if kind == "label_sql" and len(parts) == 5:
            section, label_key, value_keys_text, columns_text, alias = parts
            value_keys = tuple(
                key.strip() for key in value_keys_text.split(",") if key.strip()
            )
            columns = tuple(
                column.strip() for column in columns_text.split(",") if column.strip()
            )
            return catalog_label_case_sql(
                section, label_key, value_keys, columns, alias
            )
        return match.group(0)

    return _CATALOG_SQL_PLACEHOLDER_RE.sub(repl, str(sql or ""))


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
