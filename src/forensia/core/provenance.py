"""Identify the installed runtime and package files observed at session startup.

This is an identification record, not an archive or a deterministic replay claim.
Only installed package files are read; case data, credentials and environment
variables are outside its scope.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from importlib import metadata
from pathlib import Path
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_DISTRIBUTIONS = (
    "forensia",
    "duckdb",
    "evtx2es",
    "httpx",
    "jinja2",
    "mft2es",
    "prefetch2es",
    "reg2es",
    "pydantic",
    "python-dotenv",
    "pyyaml",
    "rich",
    "sqlglot",
    "typer",
    "textual",
)
_DATA_SUFFIXES = frozenset({".j2", ".md", ".yaml", ".yml", ".json", ".txt"})


def _package_files(root: Path) -> dict[str, Any]:
    """Hash paths and contents without following links outside the package."""
    entries: list[tuple[str, str]] = []
    unavailable: set[str] = set()

    def walk_error(error: OSError) -> None:
        # Keep recorded paths relative; never disclose an external target.
        try:
            label = Path(error.filename or root).relative_to(root).as_posix()
        except ValueError:
            label = "."
        unavailable.add(label)

    if not root.is_dir() or root.is_symlink():
        unavailable.add(".")
    else:
        for directory, subdirs, files in os.walk(root, onerror=walk_error):
            parent = Path(directory)
            for name in list(subdirs):
                path = parent / name
                if name == "__pycache__":
                    subdirs.remove(name)
                elif path.is_symlink():
                    unavailable.add(path.relative_to(root).as_posix())
                    subdirs.remove(name)
            for name in files:
                path = parent / name
                relative = path.relative_to(root)
                if path.suffix != ".py" and not (
                    relative.parts[0] == "data" and path.suffix in _DATA_SUFFIXES
                ):
                    continue
                label = relative.as_posix()
                try:
                    if path.is_symlink():
                        unavailable.add(label)
                        continue
                    before = path.stat()
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            digest.update(chunk)
                    after = path.stat()
                    if (before.st_size, before.st_mtime_ns) != (
                        after.st_size,
                        after.st_mtime_ns,
                    ):
                        unavailable.add(label)
                        continue
                    entries.append((label, digest.hexdigest()))
                except OSError:
                    unavailable.add(label)

    complete = bool(entries) and not unavailable
    return {
        "scope": "package .py files and bundled data/* (.j2,.md,.yaml,.yml,.json,.txt)",
        "observation": "files on disk at session startup; not loaded bytecode",
        "algorithm": "sha256 of sorted JSON [relative path, file sha256] entries",
        "sha256": (
            hashlib.sha256(
                json.dumps(
                    sorted(entries), ensure_ascii=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            if complete
            else None
        ),
        "file_count": len(entries),
        "status": "complete" if complete else "unavailable",
        "unavailable_count": len(unavailable),
        "unavailable_paths": sorted(unavailable)[:20],
        "omitted_unavailable_paths": max(0, len(unavailable) - 20),
    }


def build_runtime_provenance() -> dict[str, Any]:
    """Return a bounded snapshot of runtime versions and installed file identity."""
    distributions: dict[str, str | None] = {}
    for name in _DISTRIBUTIONS:
        try:
            distributions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            distributions[name] = None
    return {
        "version": "1",
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "distributions": distributions,
        "package_files": _package_files(_PACKAGE_ROOT),
        "limitations": [
            "Missing distribution versions are unknown, not inferred from source.",
            "File hashes identify disk contents; they do not archive the contents or loaded bytecode.",
            "Model weights, server build, hardware and random state are not captured; identical LLM output is not guaranteed.",
        ],
    }
