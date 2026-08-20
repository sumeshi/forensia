from __future__ import annotations

import hashlib
import logging
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tqdm import tqdm

from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.db.evidence_sources import register_evidence_source
from forensia.evidence.artifacts import get_artifact_adapters
from forensia.evidence.registry import (
    RegistryArtifactAdapter,
    register_registry_dataset,
)

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest_all(
    case: Case,
    input_dir: str | Path,
    db: CaseDB | None = None,
    force: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    base = Path(input_dir)
    if not base.exists():
        raise FileNotFoundError(f"Input directory not found: {base}")

    counts = {
        "evtx_files": 0,
        "mft_files": 0,
        "prefetch_files": 0,
        "registry_files": 0,
        "new_files": 0,
        "skipped_files": 0,
        # Raw JSONL filenames include this key. Passing only newly generated
        # keys to normalization avoids re-reading every artifact in the case.
        "new_source_keys": [],
    }
    adapters = get_artifact_adapters()
    candidates: list[tuple[Path, object]] = []
    registry_paths: list[Path] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        adapter = next((item for item in adapters if item.can_handle(path)), None)
        if adapter is None:
            continue
        if isinstance(adapter, RegistryArtifactAdapter):
            registry_paths.append(path)
            continue
        candidates.append((path, adapter))

    owns_db = db is None
    db = db or CaseDB(case)
    try:
        iterator = tqdm(
            candidates,
            total=len(candidates),
            desc="Ingest",
            unit="file",
            disable=not sys.stderr.isatty(),
        )

        # Filter per-file callbacks so the tqdm bar isn't drowned in routine
        # "Parsing X" / "Wrote JSONL" lines. Warnings still surface via the
        # parent progress_callback (which the CLI prints). Routine per-file
        # messages are dropped entirely when the bar is active on a TTY.
        def adapter_callback(message: str) -> None:
            if progress_callback is None:
                return
            is_noisy = message.startswith(("Parsing ", "Parsed ", "Wrote JSONL"))
            if is_noisy and sys.stderr.isatty():
                return
            progress_callback(message)

        # Registry is the only grouped artifact family.  Keep this small
        # dispatch seam here so existing one-file adapters retain their exact
        # behavior and no second ingest framework is introduced.
        registry = next(
            (item for item in adapters if isinstance(item, RegistryArtifactAdapter)),
            None,
        )
        if registry is not None and registry_paths:
            for dataset in registry.group_candidates(registry_paths):
                members = list(dataset.members)
                member_shas = {
                    member.path: _sha256_file(member.path) for member in members
                }
                if not force and all(
                    db.execute(
                        "SELECT 1 FROM ingested_files WHERE sha256 = ?", [sha]
                    ).fetchone()
                    for sha in member_shas.values()
                ):
                    counts["skipped_files"] += len(members)
                    continue
                try:
                    result = registry.ingest_dataset(
                        case,
                        dataset,
                        source_ids=member_shas,
                        progress_callback=adapter_callback,
                    )
                    register_registry_dataset(
                        db,
                        dataset,
                        source_ids=member_shas,
                        raw_path=result.raw_path,
                    )
                except Exception as exc:
                    counts["skipped_files"] += len(members)
                    register_registry_dataset(
                        db,
                        dataset,
                        source_ids=member_shas,
                        raw_path=None,
                        ingest_status="failed",
                        error_code="parser_error",
                        error_summary=str(exc),
                    )
                    for member in members:
                        register_evidence_source(
                            db,
                            source_id=member_shas[member.path],
                            artifact_family=registry.name,
                            display_path=member.path.name,
                            ingest_status="failed",
                            parser_name=registry.parser_name,
                            parser_version=registry.parser_version,
                            error_summary=str(exc),
                        )
                    continue
                for member in members:
                    sha256 = member_shas[member.path]
                    db.execute(
                        """INSERT INTO ingested_files (sha256, path, source_kind, size, ingested_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT (sha256) DO UPDATE SET path=excluded.path,
                        source_kind=excluded.source_kind, size=excluded.size,
                        ingested_at=excluded.ingested_at""",
                        (
                            sha256,
                            str(member.path.resolve()),
                            registry.name,
                            member.path.stat().st_size,
                            datetime.now(UTC).replace(tzinfo=None),
                        ),
                    )
                    register_evidence_source(
                        db,
                        source_id=sha256,
                        artifact_family=registry.name,
                        display_path=member.path.name,
                        ingest_status="parsed",
                        parser_name=registry.parser_name,
                        parser_version=registry.parser_version,
                    )
                    counts["new_files"] += 1
                    counts["registry_files"] += 1
                    counts["new_source_keys"].append(sha256[:12])

        for path, adapter in iterator:
            iterator.set_postfix_str(f"{adapter.name}:{path.name}"[:60], refresh=False)
            sha256 = _sha256_file(path)
            if not force:
                existing = db.execute(
                    "SELECT 1 FROM ingested_files WHERE sha256 = ?",
                    (sha256,),
                ).fetchone()
                if existing is not None:
                    counts["skipped_files"] += 1
                    if progress_callback:
                        progress_callback(
                            f"Skipping already ingested {adapter.name.upper()}: {path}"
                        )
                    continue

            try:
                result = adapter.ingest(
                    case, path, source_sha=sha256, progress_callback=adapter_callback
                )
            except Exception as exc:
                counts["skipped_files"] += 1
                try:
                    register_evidence_source(
                        db,
                        source_id=sha256,
                        artifact_family=adapter.name,
                        display_path=path.name,
                        ingest_status="failed",
                        parser_name=adapter.name,
                        error_summary=str(exc),
                    )
                except Exception:
                    logger.debug(
                        "Failed to register failed-ingest evidence source record",
                        exc_info=True,
                    )
                if progress_callback:
                    progress_callback(f"ERROR ingesting {adapter.name}: {path}: {exc}")
                continue

            if result.raw_path is None:
                counts["skipped_files"] += 1
                register_evidence_source(
                    db,
                    source_id=sha256,
                    artifact_family=adapter.name,
                    display_path=path.name,
                    ingest_status="empty",
                    parser_name=adapter.name,
                    row_count=0,
                )
                if progress_callback:
                    progress_callback(
                        f"WARNING: {adapter.name} produced no records: {path}"
                    )
                continue
            counts[f"{adapter.name}_files"] += 1
            counts["new_source_keys"].append(sha256[:12])

            db.execute(
                """
                INSERT INTO ingested_files (sha256, path, source_kind, size, ingested_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (sha256) DO UPDATE SET
                    path = excluded.path,
                    source_kind = excluded.source_kind,
                    size = excluded.size,
                    ingested_at = excluded.ingested_at
                """,
                (
                    sha256,
                    str(path.resolve()),
                    adapter.name,
                    path.stat().st_size,
                    datetime.now(UTC).replace(tzinfo=None),
                ),
            )
            counts["new_files"] += 1
            try:
                register_evidence_source(
                    db,
                    source_id=sha256,
                    artifact_family=adapter.name,
                    display_path=path.name,
                    ingest_status="parsed",
                    parser_name=adapter.name,
                    row_count=0,
                )
            except Exception:
                logger.warning(
                    "Failed to register parsed evidence source record; "
                    "evidence_sources status may be stale for %s",
                    path,
                    exc_info=True,
                )
    finally:
        if owns_db:
            db.close()
    return counts
