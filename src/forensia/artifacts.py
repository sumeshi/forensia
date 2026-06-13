from __future__ import annotations

from collections.abc import Callable
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

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult: ...


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
        from forensia.ingest.evtx import ingest_evtx_file

        return IngestResult(
            source_kind=self.name,
            raw_path=ingest_evtx_file(
                case, path, source_sha=source_sha, progress_callback=progress_callback
            ),
        )

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult:
        from forensia.normalize.evtx import normalize_evtx

        return NormalizeResult(
            source_kind=self.name, rows=normalize_evtx(case, db), aux_rows=0
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
        from forensia.ingest.mft import ingest_mft_file

        entries_path, _timeline_path = ingest_mft_file(
            case, path, source_sha=source_sha, progress_callback=progress_callback
        )
        return IngestResult(
            source_kind=self.name,
            raw_path=entries_path,
        )

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult:
        from forensia.normalize.mft import normalize_mft

        entries, timeline_rows = normalize_mft(case, db)
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
        from forensia.ingest.prefetch import ingest_prefetch_file

        entries_path, _timeline_path = ingest_prefetch_file(
            case, path, source_sha=source_sha, progress_callback=progress_callback
        )
        return IngestResult(
            source_kind=self.name,
            raw_path=entries_path,
        )

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult:
        from forensia.normalize.prefetch import normalize_prefetch

        entries, timeline_rows = normalize_prefetch(case, db)
        return NormalizeResult(
            source_kind=self.name, rows=entries, aux_rows=timeline_rows
        )


def get_artifact_adapters() -> tuple[ArtifactAdapter, ...]:
    return (
        EvtxArtifactAdapter(),
        MftArtifactAdapter(),
        PrefetchArtifactAdapter(),
    )
