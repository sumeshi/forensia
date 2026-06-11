from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import shutil
from typing import Any

import yaml

from collections import defaultdict

from forensia.report_templates import export_packaged_report_templates

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


def _parse_dt(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string to a datetime object."""
    cleaned = str(ts_str).replace("T", " ").split(".")[0].split("+")[0].split("Z")[0].strip()
    return datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S")


def _days_between(ts1: str, ts2: str) -> float:
    """Return absolute number of days between two ISO timestamp strings."""
    try:
        dt1 = _parse_dt(ts1)
        dt2 = _parse_dt(ts2)
        return abs((dt1 - dt2).total_seconds()) / 86400.0
    except (ValueError, TypeError):
        return 0.0


def detect_epochs(conn, epoch_gap_days: int = EPOCH_GAP_DAYS) -> dict[str, list[dict[str, Any]]]:
    """Cluster each host's event timestamps and label pre-deployment epochs.

    Returns a dict keyed by canonical host name (UPPER(TRIM(computer))) with
    per-host epoch clusters sorted by first_seen::

        {
          "HOST-A": [
            {
              "label": "pre-deployment" | "active" | "inactive",
              "display_name": str,
              "first_seen": str,
              "last_seen": str,
              "event_count": int,
            }
          ]
        }

    Clusters are formed by sorting each host's event timestamps and splitting
    on gaps > epoch_gap_days. The latest cluster (by last_seen) is labeled
    'active'; clusters entirely before it (separated by > epoch_gap_days)
    are 'pre-deployment'; others are 'active'.
    """
    rows = conn.execute("""
        SELECT UPPER(TRIM(computer)) AS host_canonical,
               computer AS display_name,
               timestamp
        FROM evtx_events
        WHERE computer IS NOT NULL AND TRIM(computer) != ''
          AND timestamp IS NOT NULL
        ORDER BY host_canonical, timestamp
    """).fetchall()

    if not rows:
        return {}

    # Group timestamps by host
    host_timestamps: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for host_canon, disp, ts in rows:
        host_timestamps[str(host_canon)].append((str(host_canon), str(disp), str(ts)))

    result: dict[str, list[dict[str, Any]]] = {}

    for host_canon, entries in host_timestamps.items():
        # Sort by timestamp
        entries.sort(key=lambda x: x[2])
        display_name = entries[0][1]

        # Cluster: split on gaps > epoch_gap_days
        clusters: list[list[tuple[str, str, str]]] = []
        current_cluster: list[tuple[str, str, str]] = [entries[0]]

        for i in range(1, len(entries)):
            gap = _days_between(entries[i-1][2], entries[i][2])
            if gap > epoch_gap_days:
                clusters.append(current_cluster)
                current_cluster = [entries[i]]
            else:
                current_cluster.append(entries[i])
        if current_cluster:
            clusters.append(current_cluster)

        # Label each cluster
        host_clusters: list[dict[str, Any]] = []
        for cl in clusters:
            first = cl[0][2]
            last = cl[-1][2]
            count = len(cl)
            host_clusters.append({
                "label": "active",
                "display_name": display_name,
                "first_seen": first,
                "last_seen": last,
                "event_count": count,
            })

        # The latest cluster (by last_seen) is the active anchor
        if host_clusters:
            latest = max(host_clusters, key=lambda c: c["last_seen"])
            latest["label"] = "active"
            for cluster in host_clusters:
                if cluster is latest:
                    continue
                # If this cluster ends before the latest cluster begins
                # (with gap > epoch_gap_days), it's pre-deployment
                if cluster["last_seen"] < latest["first_seen"]:
                    if _days_between(cluster["last_seen"], latest["first_seen"]) > epoch_gap_days:
                        cluster["label"] = "pre-deployment"
                    else:
                        cluster["label"] = "active"
                else:
                    cluster["label"] = "active"

        result[host_canon] = host_clusters

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
            return {"earliest": self._dominant_time_range_earliest, "latest": self._dominant_time_range_latest}
        if self._time_range_earliest and self._time_range_latest:
            return {"earliest": self._time_range_earliest, "latest": self._time_range_latest}
        return {}

    @property
    def full_time_range(self) -> dict[str, str]:
        """Return the full evidence time range including pre-deployment epochs."""
        if self._time_range_earliest and self._time_range_latest:
            return {"earliest": self._time_range_earliest, "latest": self._time_range_latest}
        return {}

    def extract_time_range(self, conn) -> None:
        """Query evtx_events MIN/MAX and compute the dominant epoch via detect_epochs()."""
        try:
            row = conn.execute("SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM evtx_events").fetchone()
            if row:
                self._time_range_earliest = str(row[0] or "") if row[0] is not None else ""
                self._time_range_latest = str(row[1] or "") if row[1] is not None else ""
        except Exception:
            pass

        # Compute dominant epoch from non-pre-deployment clusters
        try:
            self._epoch_info = detect_epochs(conn)
            active_clusters = [
                c for clusters in self._epoch_info.values() for c in clusters
                if c["label"] == "active"
            ]
            if active_clusters:
                self._dominant_time_range_earliest = min(c["first_seen"] for c in active_clusters)
                self._dominant_time_range_latest = max(c["last_seen"] for c in active_clusters)
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
    def findings_dir(self) -> Path:
        return self.path / "findings"

    @property
    def ai_logs_dir(self) -> Path:
        return self.path / "ai_logs"

    @property
    def reports_dir(self) -> Path:
        return self.path / "reports"

    @property
    def memory_dir(self) -> Path:
        return self.path / "memory"

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
    def trace_database_path(self) -> Path:
        return self.db_dir / "trace.duckdb"

    @property
    def timezone_info(self) -> str:
        """Return formatted timezone string for display."""
        tz = self.source_timezone or "UTC"
        return f"{tz} (DST observed for appropriate regions)"

    def ensure_report_templates(self, overwrite: bool = False) -> list[Path]:
        """Export packaged report templates into the case directory."""
        self.report_template_dir.mkdir(parents=True, exist_ok=True)
        return export_packaged_report_templates(self.report_template_dir, overwrite=overwrite)

    def clear_runtime_outputs(
        self,
        preserve_memory: bool = True,
        preserve_ai_logs: bool = True,
        drop_database: bool = True,
        preserve_raw: bool = False,
    ) -> None:
        """Remove runtime outputs (raw, findings, reports, DB, memory, AI logs)
        while optionally preserving memory, AI logs, raw evidence, and/or the database.

        ``preserve_raw=True`` keeps the ingested JSONL under ``raw/``. This is the
        right choice for ``--rerun`` (re-run AI investigation without losing the
        already-ingested evidence). ``preserve_raw=False`` (default) wipes raw and
        requires a fresh ingest from ``input_dir``.
        """
        cleared = (self.findings_dir, self.reports_dir)
        if not preserve_raw:
            cleared = (self.raw_dir, *cleared)
        for directory in cleared:
            if directory.exists():
                shutil.rmtree(directory)
            directory.mkdir(parents=True, exist_ok=True)

        if drop_database:
            for database_path in (self.database_path, self.trace_database_path):
                if database_path.exists():
                    database_path.unlink()

        if not preserve_ai_logs:
            if self.ai_logs_dir.exists():
                shutil.rmtree(self.ai_logs_dir)
            self.ai_logs_dir.mkdir(parents=True, exist_ok=True)

        if not preserve_memory:
            if self.memory_dir.exists():
                shutil.rmtree(self.memory_dir)
            self.memory_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def init(cls, path: str | Path, source_timezone: str = "UTC") -> "Case":
        """Create a new case directory with all required subdirectories and default files."""
        case = cls(Path(path).resolve(), source_timezone=source_timezone)
        case.path.mkdir(parents=True, exist_ok=True)
        for directory in (
            case.raw_dir,
            case.db_dir,
            case.findings_dir,
            case.ai_logs_dir,
            case.reports_dir,
            case.memory_dir,
            case.report_template_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        case.ensure_report_templates()

        if not case.manifest_path.exists():
            manifest = {
                "case_name": case.path.name,
                "created_at": datetime.now(UTC).isoformat(),
                "source_timezone": source_timezone,
                "paths": {
                    "raw": str(case.raw_dir.relative_to(case.path)),
                    "db": str(case.db_dir.relative_to(case.path)),
                    "findings": str(case.findings_dir.relative_to(case.path)),
                    "ai_logs": str(case.ai_logs_dir.relative_to(case.path)),
                    "reports": str(case.reports_dir.relative_to(case.path)),
                    "memory": str(case.memory_dir.relative_to(case.path)),
                    "report_template": str(case.report_template_dir.relative_to(case.path)),
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
    def open(cls, path: str | Path) -> "Case":
        """Open an existing case by verifying its manifest file exists."""
        case = cls(Path(path).resolve())
        if not case.manifest_path.exists():
            raise FileNotFoundError(f"Case manifest not found: {case.manifest_path}")
        try:
            manifest = yaml.safe_load(case.manifest_path.read_text(encoding="utf-8")) or {}
            case.source_timezone = str(manifest.get("source_timezone") or "UTC")
        except Exception:
            case.source_timezone = "UTC"
        return case
