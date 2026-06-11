"""Check intra-package import layer contract.

Usage: python scripts/check_imports.py  (from repo root)
"""

import ast
import sys
from pathlib import Path

PACKAGES = frozenset({"core", "ai", "report", "db", "rules", "api", "knowledge"})

FORBIDDEN = [
    ("core", "ai"),
    ("core", "report"),
    ("report", "ai"),
    ("db", "ai"),
    ("db", "report"),
]

ALLOWED_REPORT_AI_FILES = frozenset({"writer.py"})

MAX_LINES = 2500


def _pkg_of(file: Path, root: Path) -> str | None:
    """Return the top-level package name for a file under src/forensia/."""
    rel = file.relative_to(root)
    parts = rel.parts
    if len(parts) < 2:
        return None
    pkg = parts[0]
    return pkg if pkg in PACKAGES else None


def _import_targets(tree: ast.AST) -> list[str]:
    """Yield top-level forensia sub-packages imported by this file."""
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                parts = alias.name.split(".")
                if len(parts) >= 2 and parts[0] == "forensia" and parts[1] in PACKAGES:
                    targets.append(parts[1])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                parts = node.module.split(".")
                if len(parts) >= 2 and parts[0] == "forensia" and parts[1] in PACKAGES:
                    targets.append(parts[1])
    return targets


def _check_forbidden(
    source_pkg: str, file_name: str, targets: list[str]
) -> list[str]:
    errors: list[str] = []
    for src, tgt in FORBIDDEN:
        if source_pkg == src and tgt in targets:
            if src == "report" and tgt == "ai" and file_name in ALLOWED_REPORT_AI_FILES:
                continue
            errors.append(f"  FORBIDDEN: {src} → {tgt}  ({file_name})")
    return errors


def main() -> int:
    root = Path("src/forensia")
    if not root.is_dir():
        print("ERROR: run from repo root (src/forensia/ not found)", file=sys.stderr)
        return 1

    files = sorted(root.rglob("*.py"))
    errors: list[str] = []
    warnings: list[str] = []

    for file in files:
        source_pkg = _pkg_of(file, root)
        if source_pkg is None:
            continue

        source = file.read_text(encoding="utf-8")
        lines = source.count("\n")

        if lines > MAX_LINES:
            warnings.append(f"  WARNING: {file.relative_to(root)} ({lines} lines)")

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            errors.append(f"  SYNTAX ERROR: {file.relative_to(root)}: {exc}")
            continue

        targets = _import_targets(tree)
        if not targets:
            continue

        file_name = file.name
        errors.extend(_check_forbidden(source_pkg, file_name, targets))

    if warnings:
        print("Soft warnings (files > {} lines):".format(MAX_LINES))
        for w in warnings:
            print(w)
        print()

    if errors:
        print("Forbidden import edges found:")
        for e in errors:
            print(e)
        print()
        print("FAILED")
        return 1

    print("OK — no forbidden import edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
