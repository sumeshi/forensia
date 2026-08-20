from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from forensia.core.case import Case
from forensia.db.database import CaseDB


@dataclass(frozen=True, slots=True)
class IngestResult:
    source_kind: str
    raw_path: Path | None


@dataclass(frozen=True, slots=True)
class NormalizeResult:
    source_kind: str
    rows: int
    aux_rows: int = 0


class ArtifactAdapter(Protocol):
    name: str

    def can_handle(self, path: Path) -> bool: ...

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult: ...

    def normalize(
        self,
        case: Case,
        db: CaseDB,
        source_keys: Collection[str] | None = None,
    ) -> NormalizeResult: ...


class EvtxArtifactAdapter:
    name = "evtx"

    def can_handle(self, path: Path) -> bool:
        return path.suffix.lower() == ".evtx"

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult:
        from forensia.evidence.evtx import ingest_evtx_file

        return IngestResult(
            source_kind=self.name,
            raw_path=ingest_evtx_file(
                case, path, source_sha=source_sha, progress_callback=progress_callback
            ),
        )

    def normalize(
        self,
        case: Case,
        db: CaseDB,
        source_keys: Collection[str] | None = None,
    ) -> NormalizeResult:
        from forensia.evidence.evtx import normalize_evtx

        return NormalizeResult(
            source_kind=self.name,
            rows=normalize_evtx(case, db, source_keys=source_keys),
            aux_rows=0,
        )


class MftArtifactAdapter:
    name = "mft"

    def can_handle(self, path: Path) -> bool:
        return "mft" in path.name.lower()

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult:
        from forensia.evidence.mft import ingest_mft_file

        entries_path, _timeline_path = ingest_mft_file(
            case, path, source_sha=source_sha, progress_callback=progress_callback
        )
        return IngestResult(
            source_kind=self.name,
            raw_path=entries_path,
        )

    def normalize(
        self,
        case: Case,
        db: CaseDB,
        source_keys: Collection[str] | None = None,
    ) -> NormalizeResult:
        from forensia.evidence.mft import normalize_mft

        entries, timeline_rows = normalize_mft(case, db, source_keys=source_keys)
        return NormalizeResult(
            source_kind=self.name, rows=entries, aux_rows=timeline_rows
        )


class PrefetchArtifactAdapter:
    name = "prefetch"

    def can_handle(self, path: Path) -> bool:
        return path.suffix.lower() == ".pf"

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult:
        from forensia.evidence.prefetch import ingest_prefetch_file

        entries_path, _timeline_path = ingest_prefetch_file(
            case, path, source_sha=source_sha, progress_callback=progress_callback
        )
        return IngestResult(
            source_kind=self.name,
            raw_path=entries_path,
        )

    def normalize(
        self,
        case: Case,
        db: CaseDB,
        source_keys: Collection[str] | None = None,
    ) -> NormalizeResult:
        from forensia.evidence.prefetch import normalize_prefetch

        entries, timeline_rows = normalize_prefetch(case, db, source_keys=source_keys)
        return NormalizeResult(
            source_kind=self.name, rows=entries, aux_rows=timeline_rows
        )


ArtifactAdapterFactory = Callable[[], ArtifactAdapter]

_ARTIFACT_ADAPTER_FACTORIES: list[ArtifactAdapterFactory] = [
    EvtxArtifactAdapter,
    MftArtifactAdapter,
    PrefetchArtifactAdapter,
]

# Imported after the protocol and built-in adapters to keep the registry
# module independent of import order.  reg2es itself remains a lazy import in
# the adapter, so existing EVTX/MFT/Prefetch use does not require it at import
# time.
from forensia.evidence.registry import RegistryArtifactAdapter

_ARTIFACT_ADAPTER_FACTORIES.append(RegistryArtifactAdapter)


def register_artifact_adapter(
    factory: ArtifactAdapterFactory, *, prepend: bool = False
) -> None:
    """Register one artifact adapter factory at the ingest dispatch point."""
    candidate = factory()
    if not candidate.name or any(
        existing().name == candidate.name for existing in _ARTIFACT_ADAPTER_FACTORIES
    ):
        raise ValueError(f"artifact adapter already registered: {candidate.name!r}")
    if prepend:
        _ARTIFACT_ADAPTER_FACTORIES.insert(0, factory)
    else:
        _ARTIFACT_ADAPTER_FACTORIES.append(factory)


def get_artifact_adapters() -> tuple[ArtifactAdapter, ...]:
    return tuple(factory() for factory in _ARTIFACT_ADAPTER_FACTORIES)
