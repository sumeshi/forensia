from __future__ import annotations

from forensia.core.textutil import strict_slugify


def _source_identity(source_sha: str) -> str:
    """Validate and return a complete SHA-256 source identity."""
    identity = str(source_sha).strip().lower()
    if len(identity) != 64 or any(char not in "0123456789abcdef" for char in identity):
        raise ValueError("source identity must be a full SHA-256 hex digest")
    return identity


def make_prefetch_evidence_id(
    source_sha: str, executable_name: str, prefetch_hash: str
) -> str:
    return f"prefetch-{_source_identity(source_sha)}-{strict_slugify(executable_name)}-{prefetch_hash.lower()}"
