#!/usr/bin/env python3
"""Audit coverage of _schema/event_ids.yaml and question_routing.yaml against rulepacks and templates.

Usage:
    python scripts/audit_schema_coverage.py
    python scripts/audit_schema_coverage.py --strict  # fail on any uncovered entry
"""

import argparse
import sys
from pathlib import Path

try:
    import sqlglot
except ImportError:
    sqlglot = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "src" / "forensia" / "rulepacks" / "_schema"
RULES_DIR = REPO_ROOT / "src" / "forensia" / "rulepacks" / "windows"
TEMPLATES_DIR = REPO_ROOT / "src" / "forensia" / "report" / "templates"


def _load_yaml(path: Path) -> dict:
    import yaml
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _extract_event_ids_from_sql(sql: str) -> set[int]:
    """Extract numeric event_id values from a SQL query using sqlglot."""
    ids: set[int] = set()
    if not sql:
        return ids
    try:
        parsed = sqlglot.parse_one(sql)
        for node in parsed.walk():
            if isinstance(node, sqlglot.exp.EQ):
                col = node.left
                right = node.right
                if isinstance(col, sqlglot.exp.Column) and col.name.lower() == "event_id" and isinstance(right, sqlglot.exp.Literal):
                    try:
                        ids.add(int(right.this))
                    except (ValueError, TypeError):
                        pass
            if isinstance(node, sqlglot.exp.In):
                col = node.this
                if isinstance(col, sqlglot.exp.Column) and col.name.lower() == "event_id":
                    for expr in node.expressions:
                        if isinstance(expr, sqlglot.exp.Literal):
                            try:
                                ids.add(int(expr.this))
                            except (ValueError, TypeError):
                                pass
    except Exception:
        pass
    return ids


def _collect_rule_event_ids(rules_dir: Path) -> set[int]:
    """Extract all event_id values from rule YAML query fields using sqlglot."""
    event_ids: set[int] = set()
    for yaml_path in sorted(rules_dir.glob("*.yaml")):
        data = _load_yaml(yaml_path)
        if not data:
            continue
        query = data.get("query", "")
        event_ids.update(_extract_event_ids_from_sql(query))
    return event_ids


def _list_schema_questions(schema_file: str) -> set[str]:
    """Return question_type names from question_routing.yaml question_types list."""
    data = _load_yaml(SCHEMA_DIR / schema_file)
    qtypes = data.get("question_types", [])
    return {str(item["name"]) for item in qtypes if isinstance(item, dict) and "name" in item}


def _list_schema_event_ids(schema_file: str) -> set[int]:
    """Return event_ids defined in event_ids.yaml (keys of the 'events' dict)."""
    data = _load_yaml(SCHEMA_DIR / schema_file)
    events = data.get("events", {})
    ids: set[int] = set()
    for key in events:
        try:
            ids.add(int(key))
        except (ValueError, TypeError):
            pass
    return ids


def _list_schema_questions(schema_file: str) -> set[str]:
    """Return question_type names from question_routing.yaml."""
    data = _load_yaml(SCHEMA_DIR / schema_file)
    qtypes = data.get("question_types", [])
    return {str(item["name"]) for item in qtypes if isinstance(item, dict) and "name" in item}


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit schema coverage")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on any uncovered entry")
    args = parser.parse_args()

    if sqlglot is None:
        print("✗ sqlglot not available. Install with: pip install sqlglot")
        sys.exit(1)

    coverage_issues = 0

    schema_event_ids = _list_schema_event_ids("event_ids.yaml")
    rule_event_ids = _collect_rule_event_ids(RULES_DIR)

    uncovered_rules = rule_event_ids - schema_event_ids
    unused_schema = schema_event_ids - rule_event_ids

    if uncovered_rules:
        print(f"\n⚠  Event IDs in rules but NOT in _schema/event_ids.yaml ({len(uncovered_rules)} uncovered):")
        for eid in sorted(uncovered_rules):
            print(f"   - {eid}")
        coverage_issues += len(uncovered_rules)
    else:
        print("\n✓ All rule-event IDs are covered in event_ids.yaml")

    if unused_schema:
        print(f"  Schema entries not referenced by any rule: {sorted(unused_schema)}")

    schema_questions = _list_schema_questions("question_routing.yaml")
    if schema_questions:
        print(f"\n✓ Question routing defines {len(schema_questions)} types: {sorted(schema_questions)}")
    else:
        print("\n⚠  No question types found in _schema/question_routing.yaml")
        coverage_issues += 1

    print()
    if coverage_issues:
        print(f"Found {coverage_issues} coverage issue(s).")
        if args.strict:
            sys.exit(1)
    else:
        print("All schema coverage checks pass.")


if __name__ == "__main__":
    main()
