from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

ALLOWLIST_STUB = """# Rule-scoped suppression rules.
# Each entry matches one rule_id and one or more row fields from finding.evidence[0].
#
# rules:
#   - rule_id: win-logon-4624-rdp
#     when:
#       target_user:
#         - svc_backup
#       src_ip:
#         - 10.0.0.10
#       process_name:
#         - C:\\Windows\\System32\\svchost.exe
rules: []
"""

EPOCH_GAP_DAYS = 90


def detect_epochs(
    conn, epoch_gap_days: int = EPOCH_GAP_DAYS
) -> dict[str, list[dict[str, Any]]]:
    """Aggregate an ordered stream into host epochs without retaining evidence rows.

    The first observed host spelling is the display name. A gap strictly
    greater than ``epoch_gap_days`` closes a pre-deployment epoch; the final
    epoch for each canonical host remains active.
    """
    cursor = conn.execute("""
        SELECT UPPER(TRIM(computer)) AS host_canonical, computer, timestamp
        FROM evtx_events
        WHERE computer IS NOT NULL AND TRIM(computer) != ''
          AND timestamp IS NOT NULL
        ORDER BY host_canonical, timestamp
    """)
    result: dict[str, list[dict[str, Any]]] = {}
    previous_host = None
    previous_time = None
    cluster = None
    display_name = ""
    while batch := cursor.fetchmany(1024):
        for host, display, timestamp in batch:
            new_host = host != previous_host
            new_epoch = new_host or (
                (timestamp - previous_time).total_seconds() / 86400 > epoch_gap_days
            )
            if new_host:
                result[host] = []
                display_name = str(display)
            if new_epoch:
                if not new_host:
                    cluster["label"] = "pre-deployment"
                cluster = {
                    "label": "active",
                    "display_name": display_name,
                    "first_seen": str(timestamp),
                    "last_seen": str(timestamp),
                    "event_count": 0,
                }
                result[host].append(cluster)
            cluster["last_seen"] = str(timestamp)
            cluster["event_count"] += 1
            previous_host, previous_time = host, timestamp
    return result


@dataclass(slots=True)
class Case:
    path: Path
    source_timezone: str = "UTC"
    _time_range_earliest: str = ""
    _time_range_latest: str = ""
    _dominant_time_range_earliest: str = ""
    _dominant_time_range_latest: str = ""
    _epoch_info: dict[str, Any] = field(default_factory=dict)

    @property
    def time_range(self) -> dict[str, str]:
        """Return the default (dominant epoch) time range as {earliest, latest} ISO strings.

        Excludes pre-deployment epochs so planners do not dilute time filters
        with stale factory/sysprep data. Falls back to the full range when no
        dominant epoch has been computed.
        """
        if self._dominant_time_range_earliest and self._dominant_time_range_latest:
            return {
                "earliest": self._dominant_time_range_earliest,
                "latest": self._dominant_time_range_latest,
            }
        if self._time_range_earliest and self._time_range_latest:
            return {
                "earliest": self._time_range_earliest,
                "latest": self._time_range_latest,
            }
        return {}

    @property
    def full_time_range(self) -> dict[str, str]:
        """Return the full evidence time range including pre-deployment epochs."""
        if self._time_range_earliest and self._time_range_latest:
            return {
                "earliest": self._time_range_earliest,
                "latest": self._time_range_latest,
            }
        return {}

    def extract_time_range(self, conn) -> None:
        """Query evtx_events MIN/MAX and compute the dominant epoch via detect_epochs()."""
        try:
            row = conn.execute(
                "SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM evtx_events"
            ).fetchone()
            if row:
                self._time_range_earliest = (
                    str(row[0] or "") if row[0] is not None else ""
                )
                self._time_range_latest = (
                    str(row[1] or "") if row[1] is not None else ""
                )
        except Exception:
            logger.debug("Failed to extract time range from evtx_events", exc_info=True)

        # Compute dominant epoch from non-pre-deployment clusters
        try:
            self._epoch_info = detect_epochs(conn)
            active_clusters = [
                c
                for clusters in self._epoch_info.values()
                for c in clusters
                if c["label"] == "active"
            ]
            if active_clusters:
                self._dominant_time_range_earliest = min(
                    c["first_seen"] for c in active_clusters
                )
                self._dominant_time_range_latest = max(
                    c["last_seen"] for c in active_clusters
                )
            else:
                self._dominant_time_range_earliest = ""
                self._dominant_time_range_latest = ""
        except Exception:
            self._epoch_info = {}
            self._dominant_time_range_earliest = ""
            self._dominant_time_range_latest = ""

    @property
    def raw_dir(self) -> Path:
        return self.path / "raw"

    @property
    def db_dir(self) -> Path:
        return self.path / "db"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def report_template_dir(self) -> Path:
        return self.path / "report_template"

    @property
    def allowlist_path(self) -> Path:
        return self.path / "allowlist.yaml"

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.yaml"

    @property
    def database_path(self) -> Path:
        return self.db_dir / "case.duckdb"

    @property
    def timezone_info(self) -> str:
        """Return formatted timezone string for display."""
        tz = self.source_timezone or "UTC"
        return f"{tz} (DST observed for appropriate regions)"

    def clear_runtime_outputs(
        self,
        drop_database: bool = True,
        preserve_raw: bool = False,
    ) -> None:
        """Remove runtime outputs, optionally preserving raw evidence and the DB.

        ``preserve_raw=True`` keeps the ingested JSONL under ``raw/``. This is the
        right choice for ``--rerun`` (re-run AI investigation without losing the
        already-ingested evidence). ``preserve_raw=False`` (default) wipes raw and
        requires a fresh ingest from ``input_dir``.
        """
        cleared = (self.reports_dir,)
        if not preserve_raw:
            cleared = (self.raw_dir, *cleared)
        for directory in cleared:
            if directory.exists():
                shutil.rmtree(directory)
            directory.mkdir(parents=True, exist_ok=True)

        if drop_database:
            if self.database_path.exists():
                self.database_path.unlink()

    @classmethod
    def init(cls, path: str | Path, source_timezone: str = "UTC") -> Case:
        """Create a new case directory with all required subdirectories and default files."""
        case = cls(Path(path).resolve(), source_timezone=source_timezone)
        case.path.mkdir(parents=True, exist_ok=True)
        for directory in (
            case.raw_dir,
            case.db_dir,
            case.reports_dir,
            case.report_template_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        if not case.manifest_path.exists():
            manifest = {
                "case_name": case.path.name,
                "created_at": datetime.now(UTC).isoformat(),
                "source_timezone": source_timezone,
                "paths": {
                    "raw": str(case.raw_dir.relative_to(case.path)),
                    "db": str(case.db_dir.relative_to(case.path)),
                    "reports": str(case.reports_dir.relative_to(case.path)),
                    "report_template": str(
                        case.report_template_dir.relative_to(case.path)
                    ),
                },
            }
            case.manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        if not case.allowlist_path.exists():
            case.allowlist_path.write_text(ALLOWLIST_STUB, encoding="utf-8")
        return case

    @classmethod
    def open(cls, path: str | Path) -> Case:
        """Open an existing case by verifying its manifest file exists."""
        case = cls(Path(path).resolve())
        if not case.manifest_path.exists():
            raise FileNotFoundError(f"Case manifest not found: {case.manifest_path}")
        manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError(f"Case manifest must be a mapping: {case.manifest_path}")
        timezone = manifest.get("source_timezone")
        if not isinstance(timezone, str) or not timezone.strip():
            raise ValueError(
                f"Case manifest has no source_timezone: {case.manifest_path}"
            )
        case.source_timezone = timezone
        return case


def case_timezone(case: Case | None) -> str:
    """Return the case manifest timezone, falling back to UTC (e.g. pre-init)."""
    val = getattr(case, "source_timezone", "UTC") if case is not None else "UTC"
    return str(val or "UTC")


def resolve_timezone(tz: object, case: Case | None) -> str:
    """Prefer an explicitly provided timezone string over the manifest value."""
    if isinstance(tz, str):
        return tz if tz else case_timezone(case)
    return case_timezone(case)
