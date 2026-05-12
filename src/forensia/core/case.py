from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import shutil

import yaml


@dataclass(slots=True)
class Case:
    path: Path

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

        if drop_database and self.database_path.exists():
            self.database_path.unlink()

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

        package_report_template_dir = Path(__file__).resolve().parent.parent / "report_template"
        if package_report_template_dir.exists():
            for source in package_report_template_dir.iterdir():
                destination = case.report_template_dir / source.name
                if destination.exists():
                    continue
                if source.is_dir():
                    shutil.copytree(source, destination)
                else:
                    shutil.copy2(source, destination)

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
        return case

    @classmethod
    def open(cls, path: str | Path) -> "Case":
        case = cls(Path(path).resolve())
        if not case.manifest_path.exists():
            raise FileNotFoundError(f"Case manifest not found: {case.manifest_path}")
        return case
