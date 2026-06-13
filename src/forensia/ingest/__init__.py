from __future__ import annotations

import hashlib
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from tqdm import tqdm

from forensia.artifacts import get_artifact_adapters
from forensia.core.case import Case
from forensia.db.database import CaseDB


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
) -> dict[str, int]:
    base = Path(input_dir)
    if not base.exists():
        raise FileNotFoundError(f"Input directory not found: {base}")

    counts = {
        "evtx_files": 0,
        "mft_files": 0,
        "prefetch_files": 0,
        "new_files": 0,
        "skipped_files": 0,
    }
    adapters = get_artifact_adapters()
    candidates: list[tuple[Path, object]] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        adapter = next((item for item in adapters if item.can_handle(path)), None)
        if adapter is None:
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

            result = adapter.ingest(
                case, path, source_sha=sha256, progress_callback=adapter_callback
            )
            if result.raw_path is None:
                counts["skipped_files"] += 1
                if progress_callback:
                    progress_callback(
                        f"WARNING: {adapter.name} produced no records: {path}"
                    )
                continue
            counts[f"{adapter.name}_files"] += 1

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
    finally:
        if owns_db:
            db.close()
    return counts
