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
    raw_path: Path


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
            raw_path=ingest_evtx_file(case, path, source_sha=source_sha, progress_callback=progress_callback),
        )

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult:
        from forensia.normalize.evtx import normalize_evtx

        return NormalizeResult(source_kind=self.name, rows=normalize_evtx(case, db), aux_rows=0)


class MftArtifactAdapter:
    name = "mft"

    def can_handle(self, path: Path) -> bool:
        lower_name = path.name.lower()
        return lower_name == "$mft" or lower_name == "mft"

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult:
        from forensia.ingest.mft import ingest_mft_file

        return IngestResult(
            source_kind=self.name,
            raw_path=ingest_mft_file(case, path, source_sha=source_sha, progress_callback=progress_callback),
        )

    def normalize(self, case: Case, db: CaseDB) -> NormalizeResult:
        from forensia.normalize.mft import normalize_mft

        entries, timeline_rows = normalize_mft(case, db)
        return NormalizeResult(source_kind=self.name, rows=entries, aux_rows=timeline_rows)


def get_artifact_adapters() -> tuple[ArtifactAdapter, ...]:
    return (
        EvtxArtifactAdapter(),
        MftArtifactAdapter(),
    )
