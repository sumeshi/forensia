from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

_EVTX_NAME = re.compile(r"evtx-([0-9a-f]{64})-records\.jsonl\Z")
_MFT_NAME = re.compile(r"mft-entries-([0-9a-f]{64})\.jsonl\Z")
_PREFETCH_NAME = re.compile(r"prefetch-entries-([0-9a-f]{64})\.jsonl\Z")


def duckdb_path_literal(path: Path) -> str:
    """Escape a JSONL path for a DuckDB string literal."""
    return path.as_posix().replace("'", "''")


def export_jsonl(
    presenter_type: type,
    input_path: str | Path,
    output_path: str | Path,
    *,
    require_records: bool = False,
    **kwargs: Any,
) -> None:
    """Export native parser JSONL to a temporary file, then publish atomically."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=output.parent, prefix=f".{output.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
        presenter = presenter_type(
            input_path=str(input_path),
            output_path=str(temporary),
            output_format="jsonl",
            is_quiet=True,
            **kwargs,
        )
        presenter.export_json()
        if require_records and temporary.stat().st_size == 0:
            raise ValueError(f"parser returned empty JSONL for {input_path}")
        temporary.replace(output)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def raw_source_hash(path: str | Path) -> str:
    """Read the full SHA-256 identity encoded in an authoritative raw filename."""
    name = Path(path).name
    match = (
        _EVTX_NAME.fullmatch(name)
        or _MFT_NAME.fullmatch(name)
        or _PREFETCH_NAME.fullmatch(name)
    )
    if match is None:
        raise ValueError(f"invalid raw evidence filename: {name}")
    return match.group(1)
