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
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from forensia.knowledge.catalog import expand_catalog_sql_placeholders

SCHEMA_DIR = REPO_ROOT / "src" / "forensia" / "rulepacks" / "_schema"
RULES_DIR = REPO_ROOT / "src" / "forensia" / "rulepacks"
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
                if (
                    isinstance(col, sqlglot.exp.Column)
                    and col.name.lower() == "event_id"
                    and isinstance(right, sqlglot.exp.Literal)
                ):
                    try:
                        ids.add(int(right.this))
                    except ValueError, TypeError:
                        pass
            if isinstance(node, sqlglot.exp.In):
                col = node.this
                if (
                    isinstance(col, sqlglot.exp.Column)
                    and col.name.lower() == "event_id"
                ):
                    for expr in node.expressions:
                        if isinstance(expr, sqlglot.exp.Literal):
                            try:
                                ids.add(int(expr.this))
                            except ValueError, TypeError:
                                pass
    except Exception:
        pass
    return ids


def _collect_rule_event_ids(rules_dir: Path) -> set[int]:
    """Extract all event_id values from rule YAML query fields using sqlglot."""
    event_ids: set[int] = set()
    for yaml_path in sorted(rules_dir.rglob("*.yaml")):
        if "_schema" in yaml_path.parts:
            continue
        data = _load_yaml(yaml_path)
        if not data:
            continue
        query = data.get("query", "")
        event_ids.update(_extract_event_ids_from_sql(query))
    return event_ids


def _list_schema_event_ids(schema_file: str) -> set[int]:
    """Return event_ids defined in event_ids.yaml (keys of the 'events' dict)."""
    data = _load_yaml(SCHEMA_DIR / schema_file)
    events = data.get("events", {})
    ids: set[int] = set()
    for key in events:
        try:
            ids.add(int(key))
        except ValueError, TypeError:
            pass
    return ids


def _list_schema_questions(schema_file: str) -> set[str]:
    """Return question_type names from question_routing.yaml."""
    data = _load_yaml(SCHEMA_DIR / schema_file)
    qtypes = data.get("question_types", [])
    return {
        str(item["name"])
        for item in qtypes
        if isinstance(item, dict) and "name" in item
    }


def _schema_table_columns() -> dict[str, set[str]]:
    tables: dict[str, set[str]] = {}
    for path in sorted(SCHEMA_DIR.glob("*.yaml")):
        data = _load_yaml(path)
        table = str(data.get("table") or path.stem).strip()
        if not table:
            continue
        columns: set[str] = set()
        raw_columns = data.get("columns") or data.get("core_columns") or {}
        if isinstance(raw_columns, dict):
            columns.update(str(key) for key in raw_columns)
        elif isinstance(raw_columns, list):
            for item in raw_columns:
                if isinstance(item, str):
                    columns.add(item)
                elif isinstance(item, dict):
                    name = item.get("name") or item.get("column")
                    if name:
                        columns.add(str(name))
        if columns:
            tables[table] = columns
    return tables


def _select_output_names(sql: str) -> set[str]:
    names: set[str] = set()
    sql = expand_catalog_sql_placeholders(sql)
    try:
        parsed = sqlglot.parse_one(sql, read="duckdb")
    except Exception:
        return names
    for expr in parsed.expressions:
        alias = getattr(expr, "alias", None)
        if alias:
            names.add(str(alias))
            continue
        if isinstance(expr, sqlglot.exp.Column):
            names.add(expr.name)
        elif isinstance(expr, sqlglot.exp.Star):
            names.add("*")
    return names


def _validate_question_sql(sql: str, table_columns: dict[str, set[str]]) -> list[str]:
    sql = expand_catalog_sql_placeholders(sql)
    if not sql.strip():
        return ["empty evidence_chain query"]
    try:
        parsed = sqlglot.parse_one(sql, read="duckdb")
    except Exception as exc:
        return [f"SQL parse error: {exc}"]
    tables = {table.name for table in parsed.find_all(sqlglot.exp.Table) if table.name}
    issues: list[str] = []
    if not tables:
        issues.append("query references no table")
    known_columns: set[str] = set()
    for table in tables:
        if table not in table_columns:
            issues.append(f"unknown table {table}")
            continue
        known_columns.update(table_columns[table])
    for column in parsed.find_all(sqlglot.exp.Column):
        name = column.name
        table = column.table
        if not name or name == "*":
            continue
        if table and table in table_columns:
            if name not in table_columns[table]:
                issues.append(f"unknown column {table}.{name}")
        elif known_columns and name not in known_columns:
            # SQL aliases in GROUP/ORDER expressions are allowed.
            output_names = _select_output_names(sql)
            if name not in output_names:
                issues.append(f"unknown column {name}")
    return sorted(set(issues))


def _structured_builder_specs() -> set[str]:
    try:
        from forensia.report.answers.answer_registry import (
            structured_answer_builder_names,
        )

        return set(structured_answer_builder_names())
    except Exception:
        return set()


def _audit_question_specs() -> list[str]:
    data = _load_yaml(SCHEMA_DIR / "question_routing.yaml")
    qtypes = data.get("question_types", [])
    if not isinstance(qtypes, list):
        return ["question_routing.yaml has no question_types list"]
    table_columns = _schema_table_columns()
    builder_specs = _structured_builder_specs()
    seen_names: set[str] = set()
    seen_specs: set[str] = set()
    issues: list[str] = []
    for index, item in enumerate(qtypes, start=1):
        if not isinstance(item, dict):
            issues.append(f"question_types[{index}] is not an object")
            continue
        name = str(item.get("name") or "").strip()
        answer_spec = str(item.get("answer_spec") or "").strip()
        label = name or f"index {index}"
        if not name:
            issues.append(f"question_types[{index}] missing name")
            continue
        if name in seen_names:
            issues.append(f"{label}: duplicate name")
        seen_names.add(name)
        if not answer_spec:
            # Non-structured helper specs are allowed, but they still need keypoints.
            if not item.get("keypoints"):
                issues.append(f"{label}: missing answer_spec and keypoints")
            continue
        normalized_spec = answer_spec.casefold().replace("-", "_")
        if normalized_spec in seen_specs:
            issues.append(f"{label}: duplicate answer_spec {answer_spec}")
        seen_specs.add(normalized_spec)
        evidence_chain = item.get("evidence_chain")
        if normalized_spec not in builder_specs and not evidence_chain:
            issues.append(
                f"{label}: answer_spec {answer_spec} has no Python builder and no evidence_chain"
            )
        for field in ("required_fields", "render_columns", "keywords", "keypoints"):
            value = item.get(field)
            if field in {"required_fields", "render_columns"} and not value:
                issues.append(f"{label}: missing {field}")
            if value is not None and not isinstance(value, list):
                issues.append(f"{label}: {field} must be a list")
        status_rules = item.get("status_rules") or {}
        if not isinstance(status_rules, dict):
            issues.append(f"{label}: status_rules must be an object")
        elif status_rules.get("empty_status") and status_rules["empty_status"] not in {
            "answered",
            "partial",
            "not_found",
            "not_searched",
            "insufficient_evidence",
            "wrong_query",
        }:
            issues.append(
                f"{label}: invalid empty_status {status_rules['empty_status']}"
            )
        output_names: set[str] = set()
        if isinstance(evidence_chain, list):
            for chain_index, chain in enumerate(evidence_chain, start=1):
                if not isinstance(chain, dict):
                    issues.append(
                        f"{label}: evidence_chain[{chain_index}] must be an object"
                    )
                    continue
                query = str(chain.get("query") or "")
                source = str(chain.get("source") or f"chain[{chain_index}]")
                for sql_issue in _validate_question_sql(query, table_columns):
                    issues.append(f"{label}:{source}: {sql_issue}")
                output_names.update(_select_output_names(query))
        if (
            normalized_spec not in builder_specs
            and output_names
            and "*" not in output_names
        ):
            declared = {
                str(field)
                for field in (item.get("required_fields") or [])
                + (item.get("render_columns") or [])
                if str(field).strip()
            }
            missing = declared - output_names
            if missing:
                issues.append(
                    f"{label}: generic evidence_chain does not output declared fields {sorted(missing)}"
                )
    return sorted(set(issues))


def _audit_question_routing_eval() -> list[str]:
    path = SCHEMA_DIR / "question_routing_eval.yaml"
    if not path.exists():
        return ["question_routing_eval.yaml is missing"]
    data = _load_yaml(path)
    cases = data.get("cases", [])
    if not isinstance(cases, list) or not cases:
        return ["question_routing_eval.yaml has no cases"]
    try:
        from forensia.knowledge.questions import resolve_question_spec
    except Exception as exc:
        return [f"could not import question registry: {exc}"]
    issues: list[str] = []
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            issues.append(f"eval case {index} is not an object")
            continue
        expected = str(case.get("answer_spec") or "").strip()
        if not expected:
            issues.append(f"eval case {index} missing answer_spec")
            continue
        spec, confidence = resolve_question_spec(
            block_heading=str(case.get("heading") or ""),
            template_body=str(case.get("body") or ""),
            question=str(case.get("question") or ""),
            answer_spec=str(case.get("explicit_answer_spec") or ""),
        )
        actual = spec.answer_spec if spec is not None else ""
        min_confidence = float(case.get("min_confidence") or 0.2)
        if actual != expected:
            issues.append(
                f"eval case {index}: expected {expected}, got {actual or '<none>'}"
            )
        if confidence < min_confidence:
            issues.append(
                f"eval case {index}: confidence {confidence:.2f} below {min_confidence:.2f}"
            )
    return issues


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit schema coverage")
    parser.add_argument(
        "--strict", action="store_true", help="Exit 1 on any uncovered entry"
    )
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
        print(
            f"\n⚠  Event IDs in rules but NOT in _schema/event_ids.yaml ({len(uncovered_rules)} uncovered):"
        )
        for eid in sorted(uncovered_rules):
            print(f"   - {eid}")
        coverage_issues += len(uncovered_rules)
    else:
        print("\n✓ All rule-event IDs are covered in event_ids.yaml")

    if unused_schema:
        print(f"  Schema entries not referenced by any rule: {sorted(unused_schema)}")

    schema_questions = _list_schema_questions("question_routing.yaml")
    if schema_questions:
        print(
            f"\n✓ Question routing defines {len(schema_questions)} types: {sorted(schema_questions)}"
        )
    else:
        print("\n⚠  No question types found in _schema/question_routing.yaml")
        coverage_issues += 1

    question_issues = _audit_question_specs()
    if question_issues:
        print(f"\n⚠  QuestionSpec contract issues ({len(question_issues)}):")
        for issue in question_issues:
            print(f"   - {issue}")
        coverage_issues += len(question_issues)
    else:
        print("\n✓ QuestionSpec contracts are internally consistent")

    routing_eval_issues = _audit_question_routing_eval()
    if routing_eval_issues:
        print(f"\n⚠  Question routing eval issues ({len(routing_eval_issues)}):")
        for issue in routing_eval_issues:
            print(f"   - {issue}")
        coverage_issues += len(routing_eval_issues)
    else:
        print("\n✓ Question routing mutation corpus passes")

    print()
    if coverage_issues:
        print(f"Found {coverage_issues} coverage issue(s).")
        if args.strict:
            sys.exit(1)
    else:
        print("All schema coverage checks pass.")


if __name__ == "__main__":
    main()
