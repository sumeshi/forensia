from __future__ import annotations

from pathlib import Path
from typing import Callable

from forensia.core.case import Case
from forensia.ingest.evtx import ingest_evtx_file
from forensia.ingest.mft import ingest_mft_file


def ingest_all(
    case: Case,
    input_dir: str | Path,
    progress_callback: Callable[[str], None] | None = None,
) -> dict[str, int]:
    base = Path(input_dir)
    if not base.exists():
        raise FileNotFoundError(f"Input directory not found: {base}")

    counts = {"evtx_files": 0, "mft_files": 0}
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        lower_name = path.name.lower()
        if path.suffix.lower() == ".evtx":
            if progress_callback:
                progress_callback(f"Ingesting EVTX: {path}")
            ingest_evtx_file(case, path, progress_callback=progress_callback)
            counts["evtx_files"] += 1
        elif lower_name == "$mft" or lower_name == "mft":
            if progress_callback:
                progress_callback(f"Ingesting MFT: {path}")
            ingest_mft_file(case, path, progress_callback=progress_callback)
            counts["mft_files"] += 1
    return counts
