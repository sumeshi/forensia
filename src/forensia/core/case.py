from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import shutil

import yaml

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


@dataclass(slots=True)
class Case:
    path: Path
    source_timezone: str = "UTC"
    _time_range_earliest: str = ""
    _time_range_latest: str = ""

    @property
    def time_range(self) -> dict[str, str]:
        """Return the evidence time range as {earliest, latest} ISO strings.
        Populated by extract_time_range() after ingestion.
        """
        if self._time_range_earliest and self._time_range_latest:
            return {"earliest": self._time_range_earliest, "latest": self._time_range_latest}
        return {}

    def extract_time_range(self, conn) -> None:
        """Query evtx_events MIN/MAX timestamp via an active DuckDB connection."""
        try:
            row = conn.execute("SELECT MIN(timestamp) AS earliest, MAX(timestamp) AS latest FROM evtx_events").fetchone()
            if row:
                self._time_range_earliest = str(row[0] or "") if row[0] is not None else ""
                self._time_range_latest = str(row[1] or "") if row[1] is not None else ""
        except Exception:
            pass

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
        self.report_template_dir.mkdir(parents=True, exist_ok=True)
        return export_packaged_report_templates(self.report_template_dir, overwrite=overwrite)

    def clear_runtime_outputs(
        self,
        preserve_memory: bool = True,
        preserve_ai_logs: bool = True,
        drop_database: bool = True,
    ) -> None:
        for directory in (self.raw_dir, self.findings_dir, self.reports_dir):
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
    def init(cls, path: str | Path) -> "Case":
        case = cls(Path(path).resolve())
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
        case = cls(Path(path).resolve())
        if not case.manifest_path.exists():
            raise FileNotFoundError(f"Case manifest not found: {case.manifest_path}")
        return case
