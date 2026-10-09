"""Enforce the declared dependency direction between forensia layers."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Larger numbers are closer to users. Code may depend on the same or a lower
# layer; dependencies pointing upward require an exact, documented exception.
# "pipeline" is the display-agnostic run entry (V2-02): it sits with cli in the
# interface layer so adapters may call it, but kernel layers may not import it.
LAYERS: tuple[tuple[str, frozenset[str]], ...] = (
    ("platform", frozenset({"core", "db", "config"})),
    ("evidence", frozenset({"evidence"})),
    ("knowledge", frozenset({"knowledge"})),
    ("reporting", frozenset({"report"})),
    ("workflow", frozenset({"ai"})),
    ("interface", frozenset({"cli", "pipeline"})),
)

PACKAGE_LAYER = {
    package: index
    for index, (_layer_name, packages) in enumerate(LAYERS)
    for package in packages
}

# (source path relative to src/forensia, imported top-level package).
# Every entry must correspond to a real upward edge; stale exceptions fail.
KNOWN_EXCEPTIONS: frozenset[tuple[str, str]] = frozenset()


def _package_of(file: Path, root: Path) -> str | None:
    rel = file.relative_to(root)
    if len(rel.parts) == 1:
        return rel.stem if rel.stem in PACKAGE_LAYER else None
    return rel.parts[0] if rel.parts[0] in PACKAGE_LAYER else None


def _import_targets(tree: ast.AST, package: tuple[str, ...]) -> set[str]:
    targets: set[str] = set()
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - node.level + 1]
                module = (*base, *node.module.split(".")) if node.module else base
                modules.append(".".join(module))
                if node.module is None:
                    modules.extend(
                        ".".join((*module, alias.name)) for alias in node.names
                    )
            elif node.module:
                modules.append(node.module)
        for module in modules:
            parts = module.split(".")
            if len(parts) >= 2 and parts[0] == "forensia":
                target = parts[1]
                if target in PACKAGE_LAYER:
                    targets.add(target)
    return targets


def _upward_edges(root: Path) -> tuple[set[tuple[str, str]], list[str]]:
    edges: set[tuple[str, str]] = set()
    errors: list[str] = []
    for file in sorted(root.rglob("*.py")):
        source_package = _package_of(file, root)
        if source_package is None:
            continue
        relative = file.relative_to(root).as_posix()
        source = file.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            errors.append(f"SYNTAX: {relative}: {exc}")
            continue
        package = ("forensia", *file.relative_to(root).parts[:-1])
        for target_package in _import_targets(tree, package):
            if PACKAGE_LAYER[source_package] < PACKAGE_LAYER[target_package]:
                edges.add((relative, target_package))
    return edges, errors


def main() -> int:
    root = Path("src/forensia")
    if not root.is_dir():
        print("ERROR: run from repo root (src/forensia/ not found)", file=sys.stderr)
        return 1

    upward_edges, errors = _upward_edges(root)
    for source, target in sorted(upward_edges - KNOWN_EXCEPTIONS):
        errors.append(f"UNDECLARED: {source} -> {target}")
    for source, target in sorted(KNOWN_EXCEPTIONS - upward_edges):
        errors.append(f"STALE EXCEPTION: {source} -> {target}")

    if errors:
        print("Import layer contract violations:")
        for error in errors:
            print(f"  {error}")
        return 1

    print(
        "OK — layer direction enforced; "
        f"{len(KNOWN_EXCEPTIONS)} documented exception(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
