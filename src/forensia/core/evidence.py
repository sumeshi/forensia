from __future__ import annotations


def _slugify(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")


def make_evtx_evidence_id(channel: str, record_number: int) -> str:
    return f"evtx-{_slugify(channel)}-{record_number:012d}"


def make_mft_evidence_id(record_number: int, sequence_number: int) -> str:
    return f"mft-{record_number:012d}-{sequence_number:02d}"
