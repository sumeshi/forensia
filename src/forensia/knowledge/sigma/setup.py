"""Acquire a fixed upstream revision and compile rules into user storage."""

from __future__ import annotations

import hashlib
import tarfile
import tempfile
from pathlib import Path

import httpx

from forensia.knowledge.resources import sigma_bundle_path
from forensia.knowledge.sigma.build import build
from forensia.knowledge.sigma_bundle import load_sigma_bundle, write_bundle_atomic

UPSTREAM_REPOSITORY = "https://github.com/SigmaHQ/sigma"
UPSTREAM_REVISION = "8a4813404ea3074890e0cda9272d4d1a8b2941d6"
UPSTREAM_ARCHIVE_SHA256 = (
    "dc505bf6ab67d28d54f72f53fdff9850ca4994f6515dfff1fd41a9797c6fd2fe"
)
UPSTREAM_ARCHIVE_URL = (
    f"https://codeload.github.com/SigmaHQ/sigma/tar.gz/{UPSTREAM_REVISION}"
)
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def _download_archive(path: Path) -> None:
    digest = hashlib.sha256()
    total = 0
    with httpx.stream(
        "GET", UPSTREAM_ARCHIVE_URL, follow_redirects=True, timeout=60
    ) as response:
        response.raise_for_status()
        with path.open("wb") as output:
            for block in response.iter_bytes():
                total += len(block)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("Sigma archive exceeds the download limit")
                digest.update(block)
                output.write(block)
    if digest.hexdigest() != UPSTREAM_ARCHIVE_SHA256:
        raise ValueError("Sigma archive SHA-256 does not match the pinned revision")


def prepare_rule_bundle(source: Path | None = None, *, install: bool = False) -> Path:
    """Compile explicit YAML locally, or install the default rules once."""
    destination = sigma_bundle_path()
    if source is not None:
        bundle = build(source)
        if not install:
            destination = destination.parent / f"{bundle['build_id']}.json"
    elif destination.is_file():
        load_sigma_bundle(destination)
        return destination
    else:
        with tempfile.TemporaryDirectory(prefix="forensia-sigma-") as directory:
            root = Path(directory)
            archive = root / "sigma.tar.gz"
            _download_archive(archive)
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(root / "source", filter="data")
            source_root = root / "source" / f"sigma-{UPSTREAM_REVISION}"
            bundle = build(
                source_root, repository=UPSTREAM_REPOSITORY, commit=UPSTREAM_REVISION
            )
    write_bundle_atomic(destination, bundle)
    return destination
