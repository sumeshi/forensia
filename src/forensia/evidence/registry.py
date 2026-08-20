"""Small, conservative boundary between reg2es and the evidence pipeline.

This module owns the narrow Registry adapter boundary: conservative hive and
dataset admission, pinned reg2es streaming, and lossless raw-record/timeline
projection. Identity is never inferred from a directory name; parser
completeness remains unknown unless the parser explicitly proves it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from forensia.core.case import Case
from forensia.db.evidence_sources import register_evidence_source

if TYPE_CHECKING:
    from forensia.db.database import CaseDB
    from forensia.evidence.artifacts import IngestResult

REG2ES_VERSION = "2.0.0"
_PARSER_CONFIG = {"error_policy": "raise", "primary_only_inputs": True}


class _MalformedRegistryRaw(ValueError):
    """Raw JSONL cannot be safely projected into derived Registry rows."""


def _dataset_id(dataset: RegistryDataset, source_ids: Mapping[Path, str] | None) -> str:
    members = source_ids or {}
    member_ids = sorted(str(members.get(member.path, "")) for member in dataset.members)
    member_blob = "\0".join(member_ids)
    canonical_config = json.dumps(_PARSER_CONFIG, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(
        f"{REG2ES_VERSION}\0{canonical_config}\0{dataset.identity}\0{member_blob}".encode()
    ).hexdigest()


def _parse_registry_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _source_id(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _registry_member_paths(db: CaseDB, source_ids: object) -> frozenset[str] | None:
    """Resolve source IDs to their operational ingest paths.

    The source path is used only to identify replacement lineage.  It is not
    used to group Registry candidates into a dataset (directory co-location
    remains deliberately non-authoritative).
    """
    if isinstance(source_ids, str):
        try:
            source_ids = json.loads(source_ids)
        except TypeError, ValueError:
            return None
    if not isinstance(source_ids, (list, tuple, set)):
        return None
    ids = tuple(dict.fromkeys(str(source_id) for source_id in source_ids if source_id))
    if not ids:
        return None
    placeholders = ", ".join("?" for _ in ids)
    rows = db.execute(
        f"SELECT sha256, path FROM ingested_files WHERE sha256 IN ({placeholders})",
        ids,
    ).fetchall()
    if len(rows) != len(ids) or any(not path for _source_id, path in rows):
        return None
    return frozenset(str(path) for _source_id, path in rows)


@dataclass(frozen=True, slots=True)
class RegistryCandidate:
    path: Path
    kind: str  # ``primary`` or ``transaction_log``
    reason: str


@dataclass(frozen=True, slots=True)
class RegistryDataset:
    """An admitted unit of parsing, with an explicit conservative reason."""

    members: tuple[RegistryCandidate, ...]
    identity: str
    reason: str

    @property
    def primary(self) -> RegistryCandidate:
        return next(item for item in self.members if item.kind == "primary")


def _looks_like_log(path: Path) -> bool:
    return path.suffix.upper() in {".LOG", ".LOG1", ".LOG2"}


def detect_registry_candidate(path: Path) -> RegistryCandidate | None:
    """Detect REGF by content; names alone are not sufficient.

    Transaction logs are classified separately and are only admitted when a
    primary hive is present in the same candidate set.
    """
    if not path.is_file():
        return None
    if _looks_like_log(path):
        # Empty transaction logs all share the same content identity and add no
        # parser input.  Keeping them out of the admitted dataset avoids
        # ambiguous source lineage without hiding a usable companion log.
        try:
            if path.stat().st_size == 0:
                return None
        except OSError:
            return None
        return RegistryCandidate(path, "transaction_log", "REGF companion log suffix")
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return None
    if magic != b"regf":
        return None
    return RegistryCandidate(path, "primary", "REGF signature")


def _log_belongs_to(primary: Path, log: Path) -> bool:
    # LOG files conventionally use the hive basename as their prefix.  Do not
    # attach an unrelated log merely because it happens to share a directory.
    expected = {
        f"{primary.name}.LOG".casefold(),
        f"{primary.name}.LOG1".casefold(),
        f"{primary.name}.LOG2".casefold(),
    }
    return log.name.casefold() in expected


def _project_registry_source_state(
    db: CaseDB,
    source_ids: Sequence[str],
    *,
    ingest_status: str,
    row_count: int = 0,
    error_code: str = "",
    error_summary: str = "",
) -> None:
    """Project one dataset outcome onto its traceable member sources.

    Registry records name the full dataset contributor set, so a record count
    cannot be honestly attributed to an individual hive or transaction log.
    Store the dataset count on one stable representative only; copying it to
    every member would make source-level aggregation multiply the result.
    """
    ordered_ids = list(dict.fromkeys(str(item) for item in source_ids if item))
    member_status = ingest_status if row_count > 0 else (
        "empty" if ingest_status == "normalized" else ingest_status
    )
    for index, source_id in enumerate(ordered_ids):
        register_evidence_source(
            db,
            source_id=source_id,
            artifact_family="registry",
            display_path="",
            ingest_status=member_status,
            parser_name="reg2es",
            parser_version=REG2ES_VERSION,
            row_count=row_count if index == 0 else 0,
            error_code=error_code,
            error_summary=error_summary,
        )


def admit_registry_datasets(
    paths: Iterable[Path],
    *,
    identities: Mapping[Path, str] | None = None,
) -> tuple[RegistryDataset, ...]:
    """Create conservative dataset candidates from paths.

    Explicit, non-empty identity values may join companion hives.  Without
    such evidence every primary remains separate, even in one directory.
    Distinct or otherwise unconfirmed identities remain separate.
    """
    candidates = [
        candidate for path in paths if (candidate := detect_registry_candidate(path))
    ]
    primaries = [item for item in candidates if item.kind == "primary"]
    logs = [item for item in candidates if item.kind == "transaction_log"]
    identity_map = identities or {}
    result: list[RegistryDataset] = []
    by_identity: dict[str, int] = {}
    for primary in primaries:
        identity = str(identity_map.get(primary.path, "")).strip()
        members = [primary]
        members.extend(
            log
            for log in logs
            if log.path.parent == primary.path.parent
            and _log_belongs_to(primary.path, log.path)
        )
        if identity:
            reason = "explicit non-conflicting acquisition/host identity"
        else:
            reason = (
                "directory used only for companion-log candidate; identity unproven"
            )
        dataset_identity = identity
        if identity and identity in by_identity:
            index = by_identity[identity]
            previous = result[index]
            result[index] = RegistryDataset(
                previous.members
                + tuple(
                    item
                    for item in members
                    if item.path not in {member.path for member in previous.members}
                ),
                identity,
                "explicit non-conflicting acquisition/host identity joins companion hives",
            )
        else:
            if identity:
                by_identity[identity] = len(result)
            result.append(RegistryDataset(tuple(members), dataset_identity, reason))
    # Logs without a primary are not admitted. They cannot be parsed as a
    # registry dataset and must not become standalone evidence.
    return tuple(result)


def register_registry_dataset(
    db: CaseDB,
    dataset: RegistryDataset,
    *,
    source_ids: Mapping[Path, str],
    raw_path: Path | None,
    ingest_status: str = "parsed",
    row_count: int = 0,
    error_code: str = "",
    error_summary: str = "",
) -> str:
    """Persist the dataset admission boundary and parser provenance."""
    now = datetime.now(UTC).replace(tzinfo=None)
    dataset_id = _dataset_id(dataset, source_ids)
    members = [source_ids.get(member.path, "") for member in dataset.members]
    with db.transaction():
        db.execute(
            """
        INSERT INTO registry_datasets (
            dataset_id, identity, admission_state, grouping_reason,
            member_source_ids, parser_name, parser_version, parser_config,
            raw_path, ingest_status, error_code, error_summary, row_count,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (dataset_id) DO UPDATE SET
            identity = EXCLUDED.identity,
            admission_state = EXCLUDED.admission_state,
            grouping_reason = EXCLUDED.grouping_reason,
            member_source_ids = EXCLUDED.member_source_ids,
            parser_name = EXCLUDED.parser_name,
            parser_version = EXCLUDED.parser_version,
            raw_path = CASE
                WHEN EXCLUDED.ingest_status = 'failed' AND EXCLUDED.raw_path = ''
                THEN registry_datasets.raw_path ELSE EXCLUDED.raw_path END,
            ingest_status = EXCLUDED.ingest_status,
            error_code = EXCLUDED.error_code,
            error_summary = EXCLUDED.error_summary,
            row_count = CASE
                WHEN EXCLUDED.ingest_status = 'failed'
                THEN registry_datasets.row_count ELSE EXCLUDED.row_count END,
            updated_at = EXCLUDED.updated_at
        """,
            [
                dataset_id,
                dataset.identity,
                "admitted",
                dataset.reason,
                json.dumps(members),
                "reg2es",
                REG2ES_VERSION,
                json.dumps(_PARSER_CONFIG, sort_keys=True, separators=(",", ":")),
                str(raw_path) if raw_path else "",
                ingest_status,
                error_code,
                error_summary,
                row_count,
                now,
                now,
            ],
        )
    return dataset_id


def normalize_registry(
    case: Case,
    db: CaseDB,
    source_keys: Sequence[str] | None = None,
) -> int:
    """Load raw reg2es records losslessly and project only safe timestamps.

    Raw input is parsed completely before replacing derived rows. A malformed
    stream therefore leaves any previously normalized dataset untouched.
    """
    del case  # raw paths are persisted in registry_datasets
    rows = db.execute(
        "SELECT dataset_id, raw_path, member_source_ids FROM registry_datasets "
        "WHERE raw_path IS NOT NULL AND raw_path != '' ORDER BY dataset_id"
    ).fetchall()
    selected = {str(key) for key in (source_keys or ()) if key}
    total = 0
    for dataset_id, raw_path, member_source_ids in rows:
        # A newer dataset with the same trusted identity may have replaced this
        # row earlier in the same normalization pass. ``rows`` is a snapshot,
        # so do not resurrect a dataset that is no longer current.
        if (
            db.execute(
                "SELECT 1 FROM registry_datasets WHERE dataset_id = ?", [dataset_id]
            ).fetchone()
            is None
        ):
            continue
        source_ids = (
            json.loads(member_source_ids)
            if isinstance(member_source_ids, str)
            else member_source_ids or []
        )
        if selected and not any(
            str(source).startswith(tuple(selected)) for source in source_ids
        ):
            continue
        path = Path(str(raw_path))
        if not path.exists():
            error_summary = f"Registry raw parser output is missing: {path}"
            with db.transaction():
                db.execute(
                    "UPDATE registry_datasets SET ingest_status = 'failed', "
                    "error_code = 'raw_missing', error_summary = ?, updated_at = ? "
                    "WHERE dataset_id = ?",
                    [
                        error_summary,
                        datetime.now(UTC).replace(tzinfo=None),
                        dataset_id,
                    ],
                )
                _project_registry_source_state(
                    db,
                    source_ids,
                    ingest_status="failed",
                    error_code="raw_missing",
                    error_summary=error_summary,
                )
            continue
        dataset_total = 0
        try:
            with db.transaction():
                db.execute(
                    "DELETE FROM case_timeline WHERE source = 'registry' "
                    "AND entry_id IN (SELECT timeline_id FROM registry_timeline WHERE dataset_id = ?)",
                    [dataset_id],
                )
                db.execute(
                    "DELETE FROM registry_timeline WHERE dataset_id = ?", [dataset_id]
                )
                db.execute(
                    "DELETE FROM registry_artifacts WHERE dataset_id = ?", [dataset_id]
                )
                with path.open(encoding="utf-8") as raw_handle:
                    for ordinal, line in enumerate(raw_handle):
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise _MalformedRegistryRaw(
                                f"line {ordinal}: invalid JSON ({exc.msg})"
                            ) from exc
                        if not isinstance(record, dict):
                            raise _MalformedRegistryRaw(
                                f"line {ordinal}: record is not an object"
                            )
                        canonical = json.dumps(
                            record,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        registry = record.get("registry") or {}
                        reg2es = record.get("reg2es") or {}
                        source = reg2es.get("source") or {}
                        plugin = reg2es.get("plugin") or {}
                        raw_timestamp = record.get("@timestamp")
                        timestamp = _parse_registry_timestamp(raw_timestamp)
                        artifact_seed = json.dumps(
                            [
                                dataset_id,
                                ordinal,
                                str(plugin.get("name") or ""),
                                str(source.get("hive") or registry.get("hive") or ""),
                                str(
                                    source.get("key_path") or registry.get("path") or ""
                                ),
                                str(registry.get("value") or ""),
                                raw_timestamp,
                            ],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        artifact_id = (
                            "registry-"
                            + hashlib.sha256(artifact_seed.encode()).hexdigest()
                        )
                        db.execute(
                            """INSERT INTO registry_artifacts (
                                artifact_id, dataset_id, source_ids, plugin, hive, key_path,
                                value_name, timestamp, timestamp_kind, raw_json, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            [
                                artifact_id,
                                dataset_id,
                                json.dumps(source_ids),
                                str(plugin.get("name") or ""),
                                str(source.get("hive") or registry.get("hive") or ""),
                                str(
                                    source.get("key_path") or registry.get("path") or ""
                                ),
                                str(registry.get("value") or ""),
                                timestamp,
                                "parser:@timestamp" if timestamp else "",
                                canonical,
                                datetime.now(UTC).replace(tzinfo=None),
                            ],
                        )
                        if timestamp is not None:
                            timeline_id = (
                                "registry-timeline-"
                                + hashlib.sha256(
                                    f"{artifact_id}\0{raw_timestamp}".encode()
                                ).hexdigest()
                            )
                            db.execute(
                                """INSERT INTO registry_timeline (
                                    timeline_id, artifact_id, dataset_id, source_ids,
                                    timestamp, timestamp_kind, raw_timestamp, summary
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                [
                                    timeline_id,
                                    artifact_id,
                                    dataset_id,
                                    json.dumps(source_ids),
                                    timestamp,
                                    "parser:@timestamp",
                                    str(raw_timestamp),
                                    str(
                                        record.get("event", {}).get("action")
                                        or plugin.get("name")
                                        or "registry"
                                    ),
                                ],
                            )
                        dataset_total += 1
                db.execute(
                    """INSERT INTO case_timeline (
                        entry_id, timestamp, source, ref_id, host, summary, evidence_id
                    )
                    SELECT timeline_id, timestamp, 'registry', artifact_id, '', summary, artifact_id
                    FROM registry_timeline WHERE dataset_id = ?""",
                    [dataset_id],
                )
                db.execute(
                    "UPDATE registry_datasets SET ingest_status = 'normalized', "
                    "error_code = '', error_summary = '', row_count = ?, updated_at = ? "
                    "WHERE dataset_id = ?",
                    [dataset_total, datetime.now(UTC).replace(tzinfo=None), dataset_id],
                )
                _project_registry_source_state(
                    db,
                    source_ids,
                    ingest_status="normalized",
                    row_count=dataset_total,
                )
                identity = db.execute(
                    "SELECT identity FROM registry_datasets WHERE dataset_id = ?",
                    [dataset_id],
                ).fetchone()[0]
                if identity:
                    old_rows = db.execute(
                        "SELECT dataset_id FROM registry_datasets WHERE identity = ? "
                        "AND parser_name = 'reg2es' AND dataset_id != ? "
                        "AND ingest_status = 'normalized'",
                        [identity, dataset_id],
                    ).fetchall()
                else:
                    # An unattributed dataset has no trusted identity with
                    # which to establish replacement lineage.  The exact
                    # operational member paths are the remaining evidence
                    # that this ingest target replaced an older dataset.
                    # Never use directory co-location here: unrelated hives
                    # in one directory must remain separate datasets.
                    current_paths = _registry_member_paths(db, source_ids)
                    old_rows = []
                    if current_paths:
                        candidates = db.execute(
                            "SELECT dataset_id, identity, member_source_ids "
                            "FROM registry_datasets "
                            "WHERE parser_name = 'reg2es' AND dataset_id != ? "
                            "AND ingest_status = 'normalized'",
                            [dataset_id],
                        ).fetchall()
                        old_rows = [
                            (old_id,)
                            for old_id, old_identity, old_sources in candidates
                            if not str(old_identity or "").strip()
                            and _registry_member_paths(db, old_sources) == current_paths
                        ]
                for (old_id,) in old_rows:
                    db.execute(
                        "DELETE FROM case_timeline WHERE source = 'registry' "
                        "AND entry_id IN (SELECT timeline_id FROM registry_timeline WHERE dataset_id = ?)",
                        [old_id],
                    )
                    db.execute(
                        "DELETE FROM registry_timeline WHERE dataset_id = ?",
                        [old_id],
                    )
                    db.execute(
                        "DELETE FROM registry_artifacts WHERE dataset_id = ?",
                        [old_id],
                    )
                    db.execute(
                        "DELETE FROM registry_datasets WHERE dataset_id = ?",
                        [old_id],
                    )
        except _MalformedRegistryRaw as exc:
            with db.transaction():
                db.execute(
                    "UPDATE registry_datasets SET ingest_status = 'partial', "
                    "error_code = 'raw_malformed', error_summary = ?, updated_at = ? "
                    "WHERE dataset_id = ?",
                    [str(exc), datetime.now(UTC).replace(tzinfo=None), dataset_id],
                )
                _project_registry_source_state(
                    db,
                    source_ids,
                    ingest_status="partial",
                    error_code="raw_malformed",
                    error_summary=str(exc),
                )
            continue
        except Exception as exc:
            with db.transaction():
                db.execute(
                    "UPDATE registry_datasets SET ingest_status = 'failed', "
                    "error_code = 'normalize_error', error_summary = ?, updated_at = ? "
                    "WHERE dataset_id = ?",
                    [str(exc), datetime.now(UTC).replace(tzinfo=None), dataset_id],
                )
                _project_registry_source_state(
                    db,
                    source_ids,
                    ingest_status="failed",
                    error_code="normalize_error",
                    error_summary=str(exc),
                )
            raise
        total += dataset_total
    return total


def _iter_reg2es_records(paths: Sequence[Path]) -> Iterable[Mapping[str, Any]]:
    """Flatten pinned ``Reg2es.gen_records`` chunks with cleanup.

    Reg2es discovers matching ``.LOG1``/``.LOG2`` files beside each primary
    and owns dirty-hive recovery. Passing logs as independent inputs would
    make them invalid primary candidates, so only primary paths are supplied.
    """
    from reg2es.models.Reg2es import Reg2es

    with Reg2es(
        input_paths=[str(path) for path in paths],
        chunk_size=100,
        error_policy="raise",
    ) as runner:
        for chunk in runner.gen_records():
            if not isinstance(chunk, Sequence):
                raise TypeError("reg2es gen_records() yielded a non-sequence chunk")
            for record in chunk:
                if not isinstance(record, Mapping):
                    raise TypeError("reg2es record is not a mapping")
                yield record


class RegistryArtifactAdapter:
    name = "registry"
    parser_name = "reg2es"
    parser_version = REG2ES_VERSION

    def can_handle(self, path: Path) -> bool:
        return detect_registry_candidate(path) is not None

    def group_candidates(self, paths: Iterable[Path]) -> tuple[RegistryDataset, ...]:
        return admit_registry_datasets(paths)

    def ingest_dataset(
        self,
        case: Case,
        dataset: RegistryDataset,
        *,
        source_ids: Mapping[Path, str] | None = None,
        progress_callback: Callable[[str], None] | None = None,
    ) -> IngestResult:
        from forensia.evidence.artifacts import IngestResult

        digest = _dataset_id(dataset, source_ids)[:12]
        output_path = case.raw_dir / f"registry-{digest}.jsonl"
        temporary_path = output_path.with_suffix(".jsonl.tmp")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with temporary_path.open("w", encoding="utf-8") as handle:
                for record in _iter_reg2es_records(
                    [item.path for item in dataset.members if item.kind == "primary"]
                ):
                    handle.write(
                        json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
            temporary_path.replace(output_path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        if progress_callback:
            progress_callback(f"Parsed registry dataset: {dataset.primary.path}")
        return IngestResult(source_kind=self.name, raw_path=output_path)

    def ingest(
        self,
        case: Case,
        path: Path,
        source_sha: str | None = None,
        progress_callback=None,
    ) -> IngestResult:
        from forensia.evidence.artifacts import IngestResult

        candidate = detect_registry_candidate(path)
        if candidate is None or candidate.kind != "primary":
            return IngestResult(source_kind=self.name, raw_path=None)
        dataset = RegistryDataset((candidate,), "", "single unattributed primary")
        return self.ingest_dataset(
            case,
            dataset,
            source_ids={path: source_sha or _source_id(path)},
            progress_callback=progress_callback,
        )

    def normalize(self, case, db, source_keys=None):
        from forensia.evidence.artifacts import NormalizeResult

        rows = normalize_registry(case, db, source_keys=source_keys)
        return NormalizeResult(source_kind=self.name, rows=rows)
