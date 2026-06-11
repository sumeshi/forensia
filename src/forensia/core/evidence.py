from __future__ import annotations

from forensia.core.textutil import strict_slugify as _slugify_core


def _slugify(value: str) -> str:
    """Backward-compat re-export: return empty string for empty/special-only input."""
    result = _slugify_core(value)
    return "" if result == "unknown" else result


def make_evtx_evidence_id(channel: str, record_number: int) -> str:
    return f"evtx-{_slugify(channel)}-{record_number:012d}"


def make_mft_evidence_id(record_number: int, sequence_number: int) -> str:
    return f"mft-{record_number:012d}-{sequence_number:02d}"


def make_prefetch_evidence_id(executable_name: str, prefetch_hash: str) -> str:
    return f"prefetch-{_slugify(executable_name)}-{prefetch_hash.lower()}"
