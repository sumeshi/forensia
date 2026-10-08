"""Full/volatile report snapshots follow durable case data, not mocked DTOs."""

import json

from forensia.api.cache import load_snapshot
from forensia.core.case import Case
from forensia.db.database import CaseDB
from forensia.report.api_snapshot import write_all_snapshots, write_volatile_snapshots


def test_full_snapshots_include_current_report_and_case_data(tmp_path):
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        write_all_snapshots(case, db)
        assert load_snapshot(case, "report_sections.json") == []
        db.execute(
            "INSERT INTO report_sections (section_key, title, body, status) VALUES (?, ?, ?, ?)",
            (
                "1_overview",
                "Overview",
                "| Host | Events |\n| --- | --- |\n| HOST-1 | 1 |",
                "draft",
            ),
        )
        write_all_snapshots(case, db)
        sections = load_snapshot(case, "report_sections.json")
        assert len(sections) == 1
        assert sections[0]["section_key"] == "1_overview"
        assert "<table>" in sections[0]["body_html"]
        assert load_snapshot(case, "stats.json")["report_draft_count"] == 1
        assert load_snapshot(case, "report_brief.json") == json.loads(
            (case.reports_dir / "report_brief.json").read_text()
        )
        assert load_snapshot(case, "snapshot_metadata.json")["state"] == "current"


def test_volatile_snapshots_refresh_sections_and_preserve_full_brief(tmp_path):
    case = Case.init(tmp_path)
    with CaseDB(case) as db:
        write_volatile_snapshots(case, db)
        assert load_snapshot(case, "report_brief.json") is None
        write_all_snapshots(case, db)
        before = (case.reports_dir / "api/report_brief.json").read_bytes()
        old_revision = load_snapshot(case, "snapshot_metadata.json")[
            "generation_revision"
        ]
        db.execute(
            "INSERT INTO report_sections (section_key, title, body, status) VALUES (?, ?, ?, ?)",
            ("1_overview", "Overview", "New case observations.", "ai_exhausted"),
        )
        write_volatile_snapshots(case, db)
        section = load_snapshot(case, "report_sections.json")[0]
        assert section["body"] == "New case observations."
        assert section["status"] == "ai_exhausted"
        assert load_snapshot(case, "stats.json")["report_ai_exhausted"] == 1
        assert (case.reports_dir / "api/report_brief.json").read_bytes() == before
        assert (
            load_snapshot(case, "snapshot_metadata.json")["generation_revision"]
            != old_revision
        )
